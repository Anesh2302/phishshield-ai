"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useMe } from "@/lib/auth";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui";

interface ModuleStatus {
  name: string;
  available: boolean;
  detail?: string;
}

export default function DashboardPage() {
  const { me, loading } = useMe();
  const [modules, setModules] = useState<ModuleStatus[]>([]);
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    api("/status/modules").then((b) => setModules(b.modules)).catch(() => {});
    api("/health").then(setHealth).catch(() => {});
  }, []);

  if (loading) return <p>Checking session…</p>;

  return (
    <div>
      <h1>Dashboard</h1>
      <Panel title="Signed in">
        <p>
          {me?.full_name} ({me?.email}) — role <strong>{me?.role}</strong>
        </p>
      </Panel>
      {health && (
        <Panel title="Platform health">
          <p>
            status={health.status} · environment={health.environment} · version={health.version}
            {" "}· database={health.components?.database?.status}
          </p>
        </Panel>
      )}
      <Panel title="Detection modules">
        <ul>
          {modules.map((m) => (
            <li key={m.name}>
              <strong>{m.name}</strong> — {m.available ? "available" : "unavailable"}
              {m.detail ? <em> ({m.detail})</em> : null}
            </li>
          ))}
        </ul>
        <p>
          Open a module from the navigation:{" "}
          <Link href="/scanner">URL Scanner</Link>,{" "}
          <Link href="/emails">Email Security</Link>,{" "}
          <Link href="/files">File Analysis</Link>,{" "}
          <Link href="/soc">SOC/SIEM</Link>,{" "}
          <Link href="/forensics">Forensics</Link>,{" "}
          <Link href="/vuln">Vulnerabilities</Link>.
        </p>
      </Panel>
    </div>
  );
}