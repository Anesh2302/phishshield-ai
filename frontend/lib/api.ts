"use client";

export type ApiErrorPayload =
  | string
  | { detail?: string; errors?: { loc: string[]; msg: string }[] };

export class ApiError extends Error {
  status: number;
  payload: ApiErrorPayload;
  constructor(status: number, payload: ApiErrorPayload) {
    super(
      typeof payload === "string"
        ? payload
        : payload?.detail || `Request failed (${status})`
    );
    this.status = status;
    this.payload = payload;
  }
}

const BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000/api/v1";

let _csrf: string | null = null;

export function setCsrf(token: string | null) {
  _csrf = token;
}

export async function api(
  path: string,
  options: { method?: string; body?: unknown; headers?: Record<string, string> } = {}
): Promise<any> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.headers || {}),
  };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (_csrf) headers["X-CSRF-Token"] = _csrf;

  const res = await fetch(`${BASE}${path}`, {
    method: options.method || "GET",
    credentials: "include",
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  if (res.status === 204) return null;
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json")
    ? await res.json()
    : await res.text();
  if (!res.ok) throw new ApiError(res.status, data as ApiErrorPayload);
  return data;
}

export async function apiForm(
  path: string,
  form: FormData,
  method = "POST"
): Promise<any> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (_csrf) headers["X-CSRF-Token"] = _csrf;
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: "include",
    headers,
    body: form,
  });
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json")
    ? await res.json()
    : await res.text();
  if (!res.ok) throw new ApiError(res.status, data as ApiErrorPayload);
  return data;
}