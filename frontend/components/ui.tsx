import type { ReactNode } from "react";

export function Badge({ value }: { value: string }) {
  const color =
    value === "critical" || value === "malicious"
      ? "red"
      : value === "high" || value === "suspicious"
        ? "orange"
        : value === "medium"
          ? "yellow"
          : value === "monitoring" || value === "connected" || value === "ok"
            ? "green"
            : "gray";
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: 12,
        fontSize: 12,
        fontWeight: 600,
        color: "#111",
        background: COLOR[color],
      }}
    >
      {value}
    </span>
  );
}

const COLOR: Record<string, string> = {
  red: "#ffcdd2",
  orange: "#ffe0b2",
  yellow: "#fff9c4",
  green: "#c8e6c9",
  gray: "#e0e0e0",
};

export function Panel({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section
      style={{
        border: "1px solid #ddd",
        borderRadius: 8,
        padding: 16,
        marginBottom: 16,
        background: "#fff",
      }}
    >
      <h2 style={{ marginTop: 0, fontSize: 18 }}>{title}</h2>
      {children}
    </section>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <p style={{ color: "#b71c1c", background: "#ffebee", padding: 10, borderRadius: 6 }}>
      {message}
    </p>
  );
}