"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, apiForm, ApiError } from "@/lib/api";
import { Badge, ErrorBox, Panel } from "@/components/ui";
import type { DetectionResult } from "@/lib/types";

interface FileItem {
  id: string;
  original_name: string;
  size: number;
  sha256: string;
  detected_type: string;
  severity: string;
  score: number;
  created_at: string;
}

export default function FilesPage() {
  useMe();
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [error, setError] = useState("");
  const [files, setFiles] = useState<FileItem[]>([]);

  useEffect(() => {
    api("/files").then((b) => setFiles(b.items || [])).catch(() => {});
  }, []);

  async function upload() {
    setError("");
    setResult(null);
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await apiForm("/files/upload", form);
      setResult(res.result);
      api("/files").then((b) => setFiles(b.items || [])).catch(() => {});
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Upload failed");
    }
  }

  return (
    <div>
      <h1>File &amp; Malware Analysis</h1>
      <Panel title="Upload a file (static analysis only)">
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />
        <div style={{ marginTop: 8 }}>
          <button onClick={upload} disabled={!file}>
            Analyse file
          </button>
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
            <em>
              {String(result.metadata?.note || "")}
            </em>
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

      <Panel title="Analysed uploads">
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th>Name</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Score</th>
              <th>Uploaded</th>
            </tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id} style={{ borderTop: "1px solid #eee" }}>
                <td>{f.original_name}</td>
                <td>{f.detected_type}</td>
                <td>
                  <Badge value={f.severity} />
                </td>
                <td>{f.score}</td>
                <td>{new Date(f.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}