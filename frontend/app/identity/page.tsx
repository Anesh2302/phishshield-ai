"use client";

import { useCallback, useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { ErrorBox, Panel } from "@/components/ui";

export default function IdentityPage() {
  useMe();
  const [overview, setOverview] = useState<any>(null);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  const refresh = useCallback(async () => {
    api("/identity/overview").then(setOverview).catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function simulate() {
    setError("");
    try {
      const res = await api("/identity/simulate", {
        method: "POST",
        body: { scenario: "bruteforce", attempts: 6, target_email: "victim@acme-security.com" },
      });
      setMsg(
        `Simulated ${res.simulated_events} (labelled simulated) → ${res.correlation.alerts_created} alert(s).`
      );
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Simulation failed");
    }
  }

  return (
    <div>
      <h1>Identity &amp; Access Security</h1>
      {overview && (
        <>
          <Panel title="Overview">
            <p>
              Failed auth events total: <strong>{overview.failed_events_total}</strong>
            </p>
            <p>
              Active sessions: <strong>{overview.session_inventory?.active_sessions}</strong>
            </p>
            <p>
              Users: <strong>{overview.role_posture?.users}</strong> · roles:{" "}
              {JSON.stringify(overview.role_posture?.roles)}
            </p>
            <p>
              MFA optional (TOTP RFC 6238) — not enforced by default. Recommended:{" "}
              {overview.role_posture?.recommendation}
            </p>
          </Panel>
          <Panel title="Recent identity events">
            <ul>
              {overview.recent_events?.map((e: any) => (
                <li key={e.id}>
                  {e.event_type} | success={String(e.success)} | {e.email} | {e.ip || "—"}@{" "}
                  {new Date(e.created_at).toLocaleString()}
                </li>
              ))}
            </ul>
          </Panel>
        </>
      )}
      <Panel title="Safe simulation (no credentials touched)">
        <button onClick={simulate}>Simulate brute force (labelled demo)</button>
        {error && <ErrorBox message={error} />}
        {msg && <p>{msg}</p>}
      </Panel>
    </div>
  );
}