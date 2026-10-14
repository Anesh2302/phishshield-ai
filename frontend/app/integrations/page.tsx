"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { Badge, ErrorBox, Panel } from "@/components/ui";
import type { IntegrationAccount } from "@/lib/types";

const PROVIDERS = ["mock_gmail", "mock_outlook"] as const;

export default function IntegrationsPage() {
  useMe();
  const [accounts, setAccounts] = useState<IntegrationAccount[]>([]);
  const [config, setConfig] = useState<any>(null);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    refresh();
  }, []);

  async function refresh() {
    api("/integrations/accounts").then((b) => setAccounts(b || [])).catch(() => {});
    api("/integrations/config").then(setConfig).catch(() => {});
  }

  async function connect(provider: string) {
    setError("");
    try {
      const res = await api(`/integrations/${provider}/connect`, { method: "POST" });
      const cb = await api(`/integrations/${provider}/callback-json`, {
        method: "POST",
        body: { code: "analyst@acme-security.com", state: res.state },
      });
      setMsg(`Connected ${provider} (${cb.email_address}). State: ${cb.state}.`);
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Connect failed");
    }
  }

  async function sync(id: string) {
    const res = await api(`/integrations/accounts/${id}/sync`, { method: "POST" });
    setMsg(`Sync: processed=${res.result.processed} duplicates=${res.result.duplicates}`);
    refresh();
  }

  async function disconnect(id: string) {
    await api(`/integrations/accounts/${id}/disconnect`, { method: "POST" });
    refresh();
  }

  return (
    <div>
      <h1>Email Provider Integrations</h1>
      <Panel title="Configuration (honest status)">
        {config && (
          <p>
            Gmail configured: <strong>{String(config.gmail?.configured)}</strong>{" "}
            · Outlook configured: <strong>{String(config.outlook?.configured)}</strong>{" "}
            · mock providers enabled:{" "}
            <strong>{String(config.mock_providers_enabled)}</strong>
          </p>
        )}
        <p>
          <em>
            Real Gmail/Outlook require OAuth credentials and a public HTTPS webhook
            endpoint. The mock providers let you exercise the full lifecycle locally.
          </em>
        </p>
      </Panel>

      <Panel title="Connect a provider">
        <div style={{ display: "flex", gap: 8 }}>
          {PROVIDERS.map((p) => (
            <button key={p} onClick={() => connect(p)}>
              Connect {p}
            </button>
          ))}
        </div>
        {error && <ErrorBox message={error} />}
        {msg && <p>{msg}</p>}
      </Panel>

      <Panel title="Accounts">
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th>Provider</th>
              <th>Mailbox</th>
              <th>State</th>
              <th>Monitoring</th>
              <th>Last sync</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a) => (
              <tr key={a.id} style={{ borderTop: "1px solid #eee" }}>
                <td>
                  {a.provider} {a.mock ? "(mock)" : ""}
                </td>
                <td>{a.email_address}</td>
                <td><Badge value={a.state} /></td>
                <td>{a.monitoring_active ? "yes" : "no"}</td>
                <td>{a.last_sync_at ? new Date(a.last_sync_at).toLocaleString() : "never"}</td>
                <td>
                  <button onClick={() => sync(a.id)}>Sync</button>{" "}
                  <button onClick={() => disconnect(a.id)}>Disconnect</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {accounts.length === 0 && <p>No accounts yet. Connect a provider above.</p>}
      </Panel>
    </div>
  );
}