"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { ErrorBox, Panel } from "@/components/ui";

export default function MlPage() {
  useMe();
  const [info, setInfo] = useState<any>(null);
  const [url, setUrl] = useState("");
  const [pred, setPred] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/ml/model").then(setInfo).catch(() => {});
  }, []);

  async function predict() {
    setError("");
    try {
      const res = await api("/ml/predict", { method: "POST", body: { url } });
      setPred(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Prediction failed");
    }
  }

  return (
    <div>
      <h1>ML URL Classifier</h1>
      {info && (
        <Panel title="Model status">
          <p>
            available: <strong>{String(info.available)}</strong> · algorithm:{" "}
            {info.algorithm || "—"} · feature schema: {info.feature_schema}
          </p>
          {info.metrics?.dataset && (
            <p>
              <em>
                Metrics are on the in-repo synthetic benchmark ({info.metrics.dataset.source}),
                not real-world traffic.
              </em>
            </p>
          )}
          {info.error && <p>error: {info.error}</p>}
          <p>fallback when unavailable: {info.fallback || "none — rules always active"}</p>
        </Panel>
      )}
      <Panel title="Predict">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            predict();
          }}
          style={{ display: "flex", gap: 8 }}
        >
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="URL"
            style={{ flex: 1 }}
            required
          />
          <button type="submit">Predict</button>
        </form>
        {error && <ErrorBox message={error} />}
        {pred && (
          <p>
            P(malicious) = <strong>{pred.probability?.toFixed(4)}</strong>{" "}
            {pred.probability === null ? "(model unavailable — rules engine only)" : ""}
          </p>
        )}
      </Panel>
    </div>
  );
}