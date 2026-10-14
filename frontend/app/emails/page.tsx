"use client";

import { useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { Badge, ErrorBox, Panel } from "@/components/ui";
import type { DetectionResult } from "@/lib/types";

export default function EmailsPage() {
  useMe();
  const [raw, setRaw] = useState("");
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [error, setError] = useState("");

  async function analyze() {
    setError("");
    setResult(null);
    try {
      const res = await api("/emails/analyze", { method: "POST", body: { raw } });
      setResult(res.result);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Analysis failed");
    }
  }

  return (
    <div>
      <h1>Email Security</h1>
      <Panel title="Paste an email (raw .eml)">
        <textarea
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          rows={12}
          placeholder={"From: ...\nTo: ...\nSubject: ...\n\nbody"}
          style={{ width: "100%", fontFamily: "monospace" }}
        />
        <div style={{ marginTop: 8 }}>
          <button onClick={analyze}>Analyse email</button>
        </div>
        {error && <ErrorBox message={error} />}
      </Panel>

      {result && (
        <Panel title={`Result — ${result.verdict}`}>
          <p>
            score <strong>{result.score}</strong> · severity{" "}
            <Badge value={result.severity} />
          </p>
          <p>
            sender is stored as <em>{result.metadata?.body_stored === false ? "saved without full body" : "part of raw scan"}</em>
          </p>
          <ul>
            {result.evidence.map((e) => (
              <li key={e.rule_id}>
                {e.title} <Badge value={e.severity} />
              </li>
            ))}
          </ul>
          <p>
            <strong>Recommendation:</strong> {result.recommended_action}
          </p>
        </Panel>
      )}
      <p>
        Note: this form analyses raw RFC-822 text only. Connect a mailbox on the{" "}
        <a href="/integrations">Integrations</a> page to monitor inbound mail.
      </p>
    </div>
  );
}