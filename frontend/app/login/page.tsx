"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api, ApiError, setCsrf } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [needsBootstrap, setNeedsBootstrap] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api("/auth/bootstrap-status")
      .then((b) => setNeedsBootstrap(b.needs_bootstrap))
      .catch(() => setNeedsBootstrap(false));
  }, []);

  async function submit(form: FormData) {
    setBusy(true);
    setError("");
    try {
      const path = needsBootstrap ? "/auth/bootstrap" : "/auth/login";
      const body = needsBootstrap
        ? {
            tenant_name: form.get("tenant_name"),
            email: form.get("email"),
            full_name: form.get("full_name"),
            password: form.get("password"),
          }
        : { email: form.get("email"), password: form.get("password") };
      const res = await api(path, { method: "POST", body });
      setCsrf(res.csrf_token);
      router.replace("/");
    } catch (err) {
      if (err instanceof ApiError) setError(err.message);
      else setError("Unexpected error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: "40px auto" }}>
      <h1>PhishShield AI</h1>
      <p>{needsBootstrap ? "Set up your organisation" : "Sign in"}</p>
      {error && <p style={{ color: "#b71c1c" }}>{error}</p>}
      <form action={submit} style={{ display: "grid", gap: 10 }}>
        {needsBootstrap && (
          <>
            <input name="tenant_name" placeholder="Organisation name" required />
            <input name="full_name" placeholder="Your name" required />
          </>
        )}
        <input name="email" type="email" placeholder="Email" required />
        <input name="password" type="password" placeholder="Password" required />
        <button type="submit" disabled={busy}>
          {busy ? "Please wait…" : needsBootstrap ? "Create account" : "Sign in"}
        </button>
      </form>
    </div>
  );
}