package com.phishshield.ai

import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.HttpURLConnection
import java.net.URL

/**
 * PhishShield AI — minimal companion client.
 *
 * Talks to the same REST API the web console uses. Login persists the
 * session cookie (CookieManager) and the CSRF token (SharedPreferences);
 * every mutating request sends X-CSRF-Token. We only do one thing: check
 * URLs against the analyzer. No telemetry, no background scanning.
 */
class MainActivity : AppCompatActivity() {

    private val scope = CoroutineScope(Dispatchers.Main)
    private val cookies = CookieManager().apply { setCookiePolicy(CookiePolicy.ACCEPT_ALL) }

    private var csrf: String? = null

    private var urlInput: EditText? = null
    private var loginEmail: EditText? = null
    private var loginPass: EditText? = null
    private var verdict: TextView? = null
    private var evidence: TextView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        csrf = getSharedPreferences("phishshield", MODE_PRIVATE).getString("csrf", null)
        render()
    }

    private fun base(): String = getString(R.string.api_base)

    // --- UI --------------------------------------------------------------------

    private fun render() {
        val host = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }
        host.addView(TextView(this).apply {
            text = getString(R.string.app_name)
            textSize = 22f
            setPadding(0, 0, 0, 24)
        })
        if (csrf == null) host.addView(buildLogin()) else host.addView(buildScan())
        setContentView(ScrollView(this).apply { addView(host) })
    }

    private fun buildLogin(): View {
        val wrap = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        loginEmail = EditText(this).apply {
            hint = getString(R.string.email_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        }
        loginPass = EditText(this).apply {
            hint = getString(R.string.password_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        wrap.addView(loginEmail)
        wrap.addView(loginPass)
        wrap.addView(Button(this).apply {
            text = getString(R.string.login)
            setOnClickListener { doLogin() }
        })
        wrap.addView(TextView(this).apply {
            text = "No session — sign in with your PhishShield AI console account."
            textSize = 12f
            setPadding(0, 12, 0, 0)
        })
        return wrap
    }

    private fun buildScan(): View {
        val wrap = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        urlInput = EditText(this).apply { hint = getString(R.string.url_hint) }
        wrap.addView(urlInput)
        wrap.addView(Button(this).apply {
            text = getString(R.string.scan)
            setOnClickListener { doScan() }
        })
        verdict = TextView(this).apply { textSize = 18f; setPadding(0, 16, 0, 0) }
        evidence = TextView(this).apply { textSize = 13f }
        wrap.addView(verdict)
        wrap.addView(evidence)
        wrap.addView(Button(this).apply {
            text = getString(R.string.logout)
            setOnClickListener {
                getSharedPreferences("phishshield", MODE_PRIVATE).edit().clear().apply()
                csrf = null
                render()
            }
        })
        return wrap
    }

    // --- API calls (IO dispatch, java.net only) --------------------------------

    private fun api(method: String, path: String, body: JSONObject?): JSONObject {
        val conn = URL("${base()}$path").openConnection() as HttpURLConnection
        return try {
            conn.requestMethod = method
            conn.connectTimeout = 10000
            conn.readTimeout = 30000
            conn.setRequestProperty("Accept", "application/json")
            if (body != null) {
                conn.setRequestProperty("Content-Type", "application/json")
                csrf?.let { conn.setRequestProperty("X-CSRF-Token", it) }
                conn.doOutput = true
                conn.outputStream.buffered().use { it.write(body.toString().toByteArray()) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val raw = stream?.bufferedReader()?.use { it.readText() } ?: "{}"
            JSONObject(if (raw.isBlank()) "{}" else raw)
        } finally {
            conn.disconnect()
        }
    }

    private fun doLogin() {
        val email = loginEmail?.text?.toString()?.trim().orEmpty()
        val pass = loginPass?.text?.toString().orEmpty()
        if (email.isEmpty() || pass.isEmpty()) return
        scope.launch {
            try {
                val body = JSONObject().put("email", email).put("password", pass).put("tenant_slug", "default")
                val res = withContext(Dispatchers.IO) { api("POST", "/auth/login", body) }
                if (res.has("csrf_token")) {
                    csrf = res.getString("csrf_token")
                    getSharedPreferences("phishshield", MODE_PRIVATE)
                        .edit().putString("csrf", csrf).apply()
                    runOnUiThread { render() }
                } else {
                    toast(res.optString("detail", "login failed"))
                }
            } catch (e: Exception) {
                toast("Cannot reach API: ${e.message}")
            }
        }
    }

    private fun doScan() {
        val url = urlInput?.text?.toString()?.trim().orEmpty()
        if (url.isEmpty()) return
        verdict?.text = "scanning…"
        evidence?.text = ""
        scope.launch {
            try {
                val body = JSONObject().put("url", url)
                val res = withContext(Dispatchers.IO) { api("POST", "/scans/url", body) }
                if (res.has("result")) {
                    val r = res.getJSONObject("result")
                    val text = "verdict ${r.getString("verdict")}" +
                        "\nscore ${r.getInt("score")}" +
                        "\nseverity ${r.getString("severity")}" +
                        "\n\n${r.getString("recommended_action")}"
                    verdict?.text = text
                    val ev = r.getJSONArray("evidence")
                    val sb = StringBuilder()
                    for (i in 0 until ev.length()) {
                        val e = ev.getJSONObject(i)
                        sb.append("• ").append(e.getString("title"))
                            .append(" [").append(e.getString("severity")).append("]\n")
                    }
                    evidence?.text = sb.toString()
                } else {
                    verdict?.text = "API: ${res.optString("detail", "error")}"
                }
            } catch (e: Exception) {
                verdict?.text = "Cannot reach API: ${e.message}"
            }
        }
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}