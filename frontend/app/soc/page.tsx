"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { Badge, ErrorBox, Panel } from "@/components/ui";

interface SOCEvent {
  id: string;
  source: string;
  severity: string;
  category: string;
  asset: string | null;
  actor: string | null;
  message: string;
  simulated: boolean;
  event_time: string;
}

export default function SocPage() {
  useMe();
  const [payload, setPayload] = useState("");
  const [format, setFormat] = useState("auto");
  const [events, setEvents] = useState<SOCEvent[]>([]);
  const [sensors, setSensors] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    refresh();
  }, []);

  async function refresh() {
    api("/soc/events").then((b) => setEvents(b.items || [])).catch(() => {});
    api("/soc/sensors").then((b) => setSensors(b.sensors || [])).catch(() => {});
  }

  async function ingest() {
    setError("");
    try {
      const body = { format, payload };
      await api("/soc/events/ingest", { method: "POST", body });
      setPayload("");
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Ingest failed");
    }
  }

  async function correlate() {
    setError("");
    try {
      const res = await api("/soc/correlate", {
        method: "POST",
        body: { window_minutes: 30, brute_force_threshold: 5 },
      });
      setMsg(`Correlation: ${res.proposals} proposals, ${res.alerts_created} alerts created.`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Correlation failed");
    }
  }

  return (
    <div>
      <h1>SOC / SIEM Console</h1>
      <Panel title="Ingest one event">
        <div style={{ display: "flex", gap: 8 }}>
          <select value={format} onChange={(e) => setFormat(e.target.value)}>
            <option value="auto">auto</option>
            <option value="native">native</option>
            <option value="suricata">suricata</option>
            <option value="zeek">zeek</option>
            <option value="syslog">syslog</option>
            <option value="authlog">authlog</option>
          </select>
          <input
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder={'{"source":"phishshield","message":"...","severity":"high"}'}
            style={{ flex: 1, fontFamily: "monospace" }}
          />
          <button onClick={ingest}>Ingest</button>
        </div>
        {error && <ErrorBox message={error} />}
        <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
          <button onClick={correlate}>Run correlation</button>
          <button
            onClick={async () => {
              await api("/soc/demo", {
                method: "POST",
                body: { scenario: "brute_force", count: 6 },
              }).catch(console.error);
              refresh();
            }}
          >
            Generate labelled demo events
          </button>
        </div>
        {msg && <p>{msg}</p>}
      </Panel>

      <Panel title="Sensors">
        <ul>
          {sensors.map((s) => (
            <li key={s.sensor}>
              {s.sensor} — {s.status} ({s.events_total} events)
            </li>
          ))}
        </ul>
      </Panel>

      <Panel title="Recent events">
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th>Time</th>
              <th>Source</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} style={{ borderTop: "1px solid #eee" }}>
                <td>{new Date(e.event_time).toLocaleString()}</td>
                <td>{e.source}</td>
                <td>
                  <Badge value={e.severity} />
                </td>
                <td>{e.category}</td>
                <td>
                  {e.message}
                  {e.simulated ? " [SIMULATED]" : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}