"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { Badge, ErrorBox, Panel } from "@/components/ui";
import type { DetectionResult, Scan } from "@/lib/types";

export default function ScannerPage() {
  useMe();
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [recent, setRecent] = useState<Scan[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/scans?module=url").then((b) => setRecent(b.items || [])).catch(() => {});
  }, []);

  async function scan() {
    setError("");
    setResult(null);
    try {
      const res = await api("/scans/url", { method: "POST", body: { url } });
      setResult(res.result);
      api("/scans?module=url").then((b) => setRecent(b.items || [])).catch(() => {});
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Scan failed");
    }
  }

  return (
    <div>
      <h1>URL Scanner</h1>
      <Panel title="Analyse a URL">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            scan();
          }}
          style={{ display: "flex", gap: 8 }}
        >
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/link"
            style={{ flex: 1 }}
            required
          />
          <button type="submit">Scan</button>
        </form>
        {error && <ErrorBox message={error} />}
      </Panel>

      {result && (
        <Panel title={`Result — ${result.verdict}`}>
          <p>
            score <strong>{result.score}</strong> · severity{" "}
            <Badge value={result.severity} />
          </p>
          <p>
            <em>{String(result.metadata?.note ?? "")}</em>
          </p>
          <ul>
            {result.evidence.map((e) => (
              <li key={e.rule_id}>
                {e.title} <Badge value={e.severity} /> (weight {e.weight})
              </li>
            ))}
          </ul>
          <p>
            <strong>Recommendation:</strong> {result.recommended_action}
          </p>
        </Panel>
      )}

      <Panel title="Recent URL scans">
        <ul>
          {recent.map((s) => (
            <li key={s.id}>
              <Badge value={s.severity} /> {s.target} — {s.score}/100 (
              {new Date(s.created_at).toLocaleString()})
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}