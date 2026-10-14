"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { Badge, ErrorBox, Panel } from "@/components/ui";

interface Finding {
  id: string;
  cve: string | null;
  title: string;
  severity: string;
  priority: string;
  package: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  status: string;
}

interface Asset {
  id: string;
  name: string;
  criticality: string;
  exposure: string;
  tags: string[];
}

const SAMPLE_OSV = {
  results: [
    {
      source: { path: "requirements.txt" },
      packages: [
        {
          package: { name: "demo-lib", version: "1.2.3", ecosystem: "PyPI" },
          vulnerabilities: [
            {
              id: "GHSA-demo",
              aliases: ["CVE-2024-0000"],
              summary: "Demo vulnerability for testing the import pipeline",
              database_specific: { severity: "HIGH" },
            },
          ],
        },
      ],
    },
  ],
};

export default function VulnPage() {
  useMe();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    refresh();
  }, []);

  async function refresh() {
    api("/vuln/assets").then((b) => setAssets(b.items || [])).catch(() => {});
    api("/vuln/findings").then((b) => setFindings(b.items || [])).catch(() => {});
    api("/vuln/scanners")
      .then((b) => setMsg(`Scanners available: ${JSON.stringify(b.scanners)}`))
      .catch(() => {});
  }

  async function addAsset(form: FormData) {
    setError("");
    try {
      await api("/vuln/assets", {
        method: "POST",
        body: { name: form.get("name"), criticality: form.get("criticality") || "medium", exposure: form.get("exposure") || "internal" },
      });
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed");
    }
  }

  async function importSample() {
    setError("");
    try {
      const res = await api("/vuln/findings/import", {
        method: "POST",
        body: { tool: "osv", data: SAMPLE_OSV, authorized: true, scope_note: "documented sample import for testing" },
      });
      setMsg(`Imported ${res.imported} finding(s).`);
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Import failed");
    }
  }

  return (
    <div>
      <h1>Vulnerability &amp; Asset Management</h1>
      <Panel title="Add asset">
        <form
          action={addAsset}
          style={{ display: "flex", gap: 8, maxWidth: 640 }}
        >
          <input name="name" placeholder="Asset name (e.g. web-01)" required style={{ flex: 1 }} />
          <select name="criticality" defaultValue="medium">
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
          <select name="exposure" defaultValue="internal">
            <option value="internal">internal</option>
            <option value="public">public</option>
          </select>
          <button type="submit">Add</button>
        </form>
        <p>{msg}</p>
        {error && <ErrorBox message={error} />}
        <button onClick={importSample}>Import sample OSV findings (labelled demo)</button>
      </Panel>

      <Panel title="Assets">
        <ul>
          {assets.map((a) => (
            <li key={a.id}>
              {a.name} — {a.criticality} / {a.exposure}
            </li>
          ))}
        </ul>
      </Panel>

      <Panel title="Findings">
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th>CVE</th>
              <th>Package</th>
              <th>Severity</th>
              <th>Priority</th>
              <th>Status</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} style={{ borderTop: "1px solid #eee" }}>
                <td>{f.cve || "—"}</td>
                <td>
                  {f.package || "—"} {f.installed_version ? `@${f.installed_version}` : ""}
                </td>
                <td><Badge value={f.severity} /></td>
                <td>{f.priority}</td>
                <td>{f.status}</td>
                <td>{f.title}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}