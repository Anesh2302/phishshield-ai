"use client";

import { useRouter } from "next/navigation";
import { api, setCsrf } from "@/lib/api";

export default function LogoutButton() {
  const router = useRouter();
  return (
    <button
      onClick={async () => {
        try {
          await api("/auth/logout", { method: "POST" });
        } catch {
          // ignore, still clear local state and go to login
        }
        setCsrf(null);
        router.replace("/login");
      }}
      style={{
        marginLeft: "auto",
        background: "#e74c3c",
        color: "#fff",
        border: 0,
        borderRadius: 4,
        padding: "4px 10px",
        cursor: "pointer",
      }}
    >
      Logout
    </button>
  );
}