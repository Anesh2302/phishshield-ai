"use client";

import { useCallback, useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { Badge, ErrorBox, Panel } from "@/components/ui";
import type { AlertItem } from "@/lib/types";

export default function AlertsPage() {
  useMe();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    api("/alerts").then((b) => setAlerts(b.items || [])).catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function act(id: string, action: "acknowledge" | "close") {
    setError("");
    try {
      await api(`/alerts/${id}/${action}`, { method: "POST" });
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Action failed");
    }
  }

  return (
    <div>
      <h1>Alerts</h1>
      {error && <ErrorBox message={error} />}
      <Panel title={`Open alerts (${alerts.filter((a) => a.status === "open").length})`}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th>Severity</th>
              <th>Source</th>
              <th>Title</th>
              <th>Status</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id} style={{ borderTop: "1px solid #eee" }}>
                <td><Badge value={a.severity} /></td>
                <td>{a.source_module}</td>
                <td>{a.title}</td>
                <td>{a.status}</td>
                <td>{new Date(a.created_at).toLocaleString()}</td>
                <td>
                  {a.status === "open" && (
                    <button onClick={() => act(a.id, "acknowledge")}>Acknowledge</button>
                  )}{" "}
                  {a.status !== "closed" && (
                    <button onClick={() => act(a.id, "close")}>Close</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}