// PhishShield AI — popup logic.

const $status = document.getElementById("status");
const $alert = document.getElementById("alert");
const $scan = document.getElementById("scan");
const $options = document.getElementById("options");

const CFG = { apiBase: "http://localhost:8000/api/v1", enabled: true };

chrome.storage.local.get(CFG, (stored) => Object.assign(CFG, stored));

function showResult(r) {
  const cls = r.verdict === "benign" ? "ok" : r.verdict === "suspicious" ? "warn" : "bad";
  $status.innerHTML =
    `<span class="verdict ${cls}">${r.verdict}</span> · score <span class="score">${r.score}</span>` +
    `<br><span class="muted">${(r.metadata && r.metadata.note) || "…"}</span>` +
    `<br><span style="font-size:12px">${r.recommended_action}</span>`;
  const ev = r.evidence || [];
  if (ev.length) {
    const ul = document.createElement("ul");
    ul.className = "chain";
    ev.slice(0, 6).forEach((e) => {
      const li = document.createElement("li");
      li.textContent = `${e.title} (${e.severity})`;
      ul.appendChild(li);
    });
    $status.appendChild(ul);
  }
}

async function scan(url) {
  if (!CFG.enabled) {
    $status.textContent = "Disabled in options.";
    return;
  }
  $status.textContent = "Scanning…";
  const res = await fetch(`${CFG.apiBase}/scans/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  }).catch((e) => null);
  if (!res) {
    $status.textContent = "Cannot reach PhishShield API. Check Options → API base URL.";
    $alert.classList.remove("hidden");
    return;
  }
  const body = await res.json();
  if (body.detail) {
    $status.textContent = `API: ${JSON.stringify(body.detail)}`;
    $alert.textContent = `API: ${JSON.stringify(body.detail)}`;
    $alert.classList.remove("hidden");
    return;
  }
  showResult(body.result);
  $alert.classList.add("hidden");
  chrome.storage.local.set({ lastCheck: { url, at: Date.now(), verdict: body.result.verdict } });
}

chrome.storage.local.get(["pendingCheck"], (stored) => {
  if (stored.pendingCheck) {
    scan(stored.pendingCheck);
    chrome.storage.local.remove("pendingCheck");
  } else {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0] ? tabs[0].url || "" : "";
      scan(url);
    });
  }
});

$scan.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    scan(tabs[0] ? tabs[0].url : "");
  });
});
$options.addEventListener("click", () => chrome.runtime.openOptionsPage());