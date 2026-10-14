"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, apiForm, ApiError } from "@/lib/api";
import { ErrorBox, Panel } from "@/components/ui";

interface EvidenceItem {
  id: string;
  case_name: string;
  title: string;
  source: string;
  sha256: string;
  size: number;
  acquired_at: string;
}

export default function ForensicsPage() {
  useMe();
  const [items, setItems] = useState<EvidenceItem[]>([]);
  const [caseName, setCaseName] = useState("");
  const [title, setTitle] = useState("");
  const [source, setSource] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState("");
  const [detail, setDetail] = useState<any>(null);

  useEffect(() => {
    api("/forensics/evidence").then((b) => setItems(b.items || [])).catch(() => {});
  }, []);

  async function register() {
    setError("");
    const form = new FormData();
    form.append("case_name", caseName);
    form.append("title", title);
    form.append("source", source);
    if (file) form.append("file", file);
    try {
      await apiForm("/forensics/evidence", form);
      api("/forensics/evidence").then((b) => setItems(b.items || [])).catch(() => {});
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Registration failed");
    }
  }

  async function inspect(id: string) {
    const d = await api(`/forensics/evidence/${id}`);
    setDetail(d);
  }

  return (
    <div>
      <h1>Digital Forensics</h1>
      <Panel title="Register evidence">
        <div style={{ display: "grid", gap: 8, maxWidth: 480 }}>
          <input value={caseName} onChange={(e) => setCaseName(e.target.value)} placeholder="Case name (e.g. INC-2026-001)" />
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title" />
          <input value={source} onChange={(e) => setSource(e.target.value)} placeholder="Source (e.g. laptop-01)" />
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
          <button onClick={register}>Register</button>
        </div>
        {error && <ErrorBox message={error} />}
        <p>
          <em>
            This is bookkeeping and integrity aid. It does not establish legal
            admissibility; independent forensic validation is required.
          </em>
        </p>
      </Panel>

      {detail && (
        <Panel title={`${detail.evidence.title} — custody chain`}>
          <p>
            sha256 <code>{detail.evidence.sha256}</code>
          </p>
          <ul>
            {detail.custody.map((c: any) => (
              <li key={c.created_at}>
                {c.action} — {c.note} ({new Date(c.created_at).toLocaleString()})
              </li>
            ))}
          </ul>
          <button
            onClick={async () => {
              const v = await api(`/forensics/evidence/${detail.evidence.id}/verify`, {
                method: "POST",
              });
              alert(`Integrity verify: ${v.match ? "PASSED" : "FAILED"}`);
            }}
          >
            Verify integrity
          </button>
        </Panel>
      )}

      <Panel title="Evidence register">
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th>Case</th>
              <th>Title</th>
              <th>SHA-256</th>
              <th>Acquired</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((e) => (
              <tr key={e.id} style={{ borderTop: "1px solid #eee" }}>
                <td>{e.case_name}</td>
                <td>{e.title}</td>
                <td>
                  <code>{e.sha256.slice(0, 16)}…</code>
                </td>
                <td>{new Date(e.acquired_at).toLocaleString()}</td>
                <td>
                  <button onClick={() => inspect(e.id)}>Inspect</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}