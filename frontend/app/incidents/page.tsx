"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { Badge, ErrorBox, Panel } from "@/components/ui";

interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  created_at: string;
}

export default function IncidentsPage() {
  useMe();
  const [items, setItems] = useState<Incident[]>([]);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [error, setError] = useState("");

  useEffect(() => {
    refresh();
  }, []);

  async function refresh() {
    api("/incidents").then((b) => setItems(b.items || [])).catch(() => {});
  }

  async function create() {
    setError("");
    try {
      await api("/incidents", {
        method: "POST",
        body: { title, severity, summary: "" },
      });
      setTitle("");
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Create failed");
    }
  }

  return (
    <div>
      <h1>Incident Response</h1>
      <Panel title="Open an incident">
        <div style={{ display: "flex", gap: 8, maxWidth: 560 }}>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Title"
            style={{ flex: 1 }}
          />
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
          <button onClick={create}>Create</button>
        </div>
        {error && <ErrorBox message={error} />}
      </Panel>
      <Panel title="Incidents">
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th>Severity</th>
              <th>Title</th>
              <th>Status</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {items.map((i) => (
              <tr key={i.id} style={{ borderTop: "1px solid #eee" }}>
                <td><Badge value={i.severity} /></td>
                <td>{i.title}</td>
                <td>{i.status}</td>
                <td>{new Date(i.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}