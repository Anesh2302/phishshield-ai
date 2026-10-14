export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface Evidence {
  rule_id: string;
  title: string;
  description: string;
  weight: number;
  severity: string;
  detail: Record<string, unknown>;
  source: string;
}

export interface DetectionResult {
  module: string;
  target: string;
  score: number;
  severity: string;
  verdict: string;
  evidence: Evidence[];
  recommended_action: string;
  metadata: Record<string, unknown>;
}

export interface Scan {
  id: string;
  module: string;
  target: string;
  status: string;
  score: number;
  severity: string;
  verdict: string;
  source: string;
  created_at: string;
}

export interface AlertItem {
  id: string;
  source_module: string;
  rule_id: string;
  title: string;
  severity: string;
  category: string;
  asset: string | null;
  status: string;
  created_at: string;
}

export interface IntegrationAccount {
  id: string;
  provider: string;
  email_address: string;
  status: string;
  state: string;
  monitoring_active: boolean;
  scopes: string[];
  last_sync_at: string | null;
  watch_expires_at: string | null;
  subscription_expires_at: string | null;
  subscription_id: string | null;
  last_error: string | null;
  mock: boolean;
}

export interface UserMe {
  id: string;
  email: string;
  full_name: string;
  role: string;
  mfa_enabled: boolean;
  tenant_id: string;
}