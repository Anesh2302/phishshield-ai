import type { Metadata } from "next";
import Link from "next/link";
import LogoutButton from "@/components/LogoutButton";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishShield AI",
  description: "Multi-domain phishing defence platform",
};

const NAV = [
  ["/", "Dashboard"],
  ["/scanner", "URL Scanner"],
  ["/emails", "Email Security"],
  ["/files", "File Analysis"],
  ["/soc", "SOC / SIEM"],
  ["/forensics", "Forensics"],
  ["/vuln", "Vulnerabilities"],
  ["/integrations", "Integrations"],
  ["/identity", "Identity"],
  ["/alerts", "Alerts"],
  ["/incidents", "Incidents"],
  ["/ml", "ML Model"],
] as const;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <header
          style={{
            display: "flex",
            gap: 12,
            alignItems: "center",
            padding: "8px 16px",
            background: "#0b2545",
            color: "#fff",
            flexWrap: "wrap",
          }}
        >
          <strong>PhishShield AI</strong>
          <nav style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {NAV.map(([href, label]) => (
              <Link key={href} href={href} style={{ color: "#cfe3ff" }}>
                {label}
              </Link>
            ))}
          </nav>
          <LogoutButton />
        </header>
        <main style={{ padding: 16, maxWidth: 1100, margin: "0 auto" }}>{children}</main>
      </body>
    </html>
  );
}