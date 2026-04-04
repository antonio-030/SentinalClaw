// ── SentinelClaw API type definitions ────────────────────────────────

/** Severity levels returned by the scanner, ordered from most to least critical. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ── Core resources ───────────────────────────────────────────────────

export interface Scan {
  id: string;
  target: string;
  scan_type: string;
  status: string;
  tokens_used: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_job_id: string;
  title: string;
  severity: Severity;
  cvss_score: number;
  cve_id: string | null;
  target_host: string;
  target_port: number | null;
  service: string | null;
  description: string;
  recommendation: string;
  evidence?: string;
}

export interface ScanPhase {
  id: string;
  phase_number: number;
  name: string;
  status: string;
  duration_seconds: number;
  hosts_found: number;
  ports_found: number;
  findings_found: number;
}

export interface ScanProfile {
  name: string;
  description: string;
  ports: string;
  max_escalation_level: number;
  estimated_duration_minutes: number;
}

// ── System / operational ─────────────────────────────────────────────

export interface SystemStatus {
  system: {
    version: string;
    llm_provider: string;
    claude_cli: boolean;
    openclaw_sdk: boolean;
    docker: string;
    sandbox_running: boolean;
    kill_switch_active: boolean;
  };
  scans: {
    running: number;
    total: number;
  };
}

export interface HealthResponse {
  status: string;
  version: string;
  provider: string;
  sandbox_running: boolean;
  db_connected: boolean;
}

export interface AuditEntry {
  id: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown>;
  triggered_by: string;
  created_at: string;
}

// ── Composite response shapes ────────────────────────────────────────

export interface OpenPort {
  host: string;
  port: number;
  protocol: string;
  service: string | null;
  version: string | null;
}

export interface ScanDetail {
  scan: Scan;
  phases: ScanPhase[];
  findings: Finding[];
  open_ports: OpenPort[];
}

export interface CreateScanRequest {
  target: string;
  ports?: string;
  profile?: string;
}

export interface CreateScanResponse {
  scan_id: string;
}

export interface KillResponse {
  status: string;
}

export interface ComparePort {
  host: string;
  port: number;
  protocol: string;
  service: string | null;
}

export interface CompareFinding {
  title: string;
  severity: string;
  cvss_score?: number;
  target_host?: string;
  target_port?: number | null;
}

export interface CompareResult {
  new_findings: CompareFinding[];
  fixed_findings: CompareFinding[];
  unchanged_findings: CompareFinding[];
  new_ports: ComparePort[];
  closed_ports: ComparePort[];
}

// ── Chat ────────────────────────────────────────────────────────────

export interface ChatMessage {
  id: string;
  role: 'user' | 'agent' | 'system';
  content: string;
  message_type: string;
  created_at: string;
  scan_id?: string;
}

export interface ChatResponse {
  response: string;
  scan_started: boolean;
  scan_id?: string;
}
