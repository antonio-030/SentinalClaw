// ── SentinelClaw API client ──────────────────────────────────────────
//
// All paths are relative — Vite's dev-server proxy forwards /api and
// /health to the backend at localhost:3001.

import type {
  AuditEntry,
  ChatMessage,
  ChatResponse,
  CompareResult,
  CreateScanRequest,
  CreateScanResponse,
  Finding,
  HealthResponse,
  KillResponse,
  LoginResponse,
  ScanDetail,
  Scan,
  ScanPhase,
  ScanProfile,
  SystemStatus,
  User,
} from '../types/api';

const BASE = ''; // Vite proxy handles routing to localhost:3001

// ── Generic fetch wrapper ────────────────────────────────────────────

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string>),
  };

  const token = localStorage.getItem('sc_token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Timeout: 6 Min für Chat (Agent braucht Zeit), 30s für Rest
  const timeoutMs = url.includes('/chat') ? 360_000 : 30_000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(`${BASE}${url}`, {
      ...init,
      headers,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new Error('Zeitüberschreitung — die Anfrage hat zu lange gedauert. Versuche es erneut.');
    }
    throw err;
  }
  clearTimeout(timeoutId);

  if (res.status === 401 && !url.includes('/auth/login')) {
    // Token abgelaufen — ausloggen (kein Reload, App zeigt Login-Seite)
    localStorage.removeItem('sc_token');
    localStorage.removeItem('sc_user');
    // Zustand-Store direkt updaten
    try {
      const { useAuthStore } = await import('../stores/authStore');
      useAuthStore.getState().logout();
    } catch {
      // Store nicht verfügbar — Seite wird trotzdem Login zeigen beim nächsten Render
    }
    throw new Error('Session abgelaufen');
  }

  if (!res.ok) {
    const body = await res.text().catch(() => 'Unknown error');
    throw new Error(`API Error ${res.status}: ${body}`);
  }

  // Handle 204 No Content (DELETE responses, etc.)
  if (res.status === 204) {
    return undefined as T;
  }

  return res.json();
}

// ── Typed API surface ────────────────────────────────────────────────

export const api = {
  /** GET /health */
  health: () => fetchJson<HealthResponse>('/health'),

  /** GET /api/v1/status */
  status: () => fetchJson<SystemStatus>('/api/v1/status'),

  // ── Scans ────────────────────────────────────────────────────────

  scans: {
    /** GET /api/v1/scans — list all scans */
    list: () => fetchJson<Scan[]>('/api/v1/scans'),

    /** GET /api/v1/scans/:id — full scan detail with phases, findings, ports */
    get: (id: string) => fetchJson<ScanDetail>(`/api/v1/scans/${id}`),

    /** POST /api/v1/scans — start a new scan */
    create: (data: CreateScanRequest) =>
      fetchJson<CreateScanResponse>('/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify(data),
      }),

    /** DELETE /api/v1/scans/:id */
    delete: (id: string) =>
      fetchJson<void>(`/api/v1/scans/${id}`, { method: 'DELETE' }),

    /** PUT /api/v1/scans/:id/cancel */
    cancel: (id: string) =>
      fetchJson<void>(`/api/v1/scans/${id}/cancel`, { method: 'PUT' }),

    /** GET /api/v1/scans/:id/phases */
    phases: (id: string) =>
      fetchJson<ScanPhase[]>(`/api/v1/scans/${id}/phases`),

    /** GET /api/v1/scans/:id/hosts */
    hosts: (id: string) =>
      fetchJson<unknown[]>(`/api/v1/scans/${id}/hosts`),

    /** GET /api/v1/scans/:id/ports */
    ports: (id: string) =>
      fetchJson<unknown[]>(`/api/v1/scans/${id}/ports`),

    /** GET /api/v1/scans/:id/export?format=... */
    export: (id: string, format?: string) =>
      fetch(`${BASE}/api/v1/scans/${id}/export${format ? `?format=${encodeURIComponent(format)}` : ''}`).then((r) => {
        if (!r.ok) throw new Error(`Export failed: ${r.status}`);
        return r.blob();
      }),

    /** POST /api/v1/scans/compare — compare two scans */
    compare: (data: { scan_id_a: string; scan_id_b: string }) =>
      fetchJson<CompareResult>('/api/v1/scans/compare', {
        method: 'POST',
        body: JSON.stringify(data),
      }),

    /** GET /api/v1/scans/:id/report?type=... — returns raw text/HTML */
    report: (id: string, type: string) =>
      fetch(`${BASE}/api/v1/scans/${id}/report?type=${encodeURIComponent(type)}`).then(
        (r) => {
          if (!r.ok) throw new Error(`Report failed: ${r.status}`);
          return r.text();
        },
      ),
  },

  // ── Findings ─────────────────────────────────────────────────────

  findings: {
    /** GET /api/v1/findings */
    list: (severity?: string) =>
      fetchJson<Finding[]>(
        `/api/v1/findings${severity ? `?severity=${encodeURIComponent(severity)}` : ''}`,
      ),

    /** GET /api/v1/findings/:id */
    get: (id: string) => fetchJson<Finding>(`/api/v1/findings/${id}`),

    /** DELETE /api/v1/findings/:id */
    delete: (id: string) =>
      fetchJson<void>(`/api/v1/findings/${id}`, { method: 'DELETE' }),
  },

  // ── Profiles ─────────────────────────────────────────────────────

  /** GET /api/v1/profiles */
  profiles: () => fetchJson<ScanProfile[]>('/api/v1/profiles'),

  // ── Audit log ────────────────────────────────────────────────────

  /** GET /api/v1/audit?limit=N */
  audit: (limit?: number) =>
    fetchJson<AuditEntry[]>(`/api/v1/audit?limit=${limit ?? 50}`),

  // ── Kill switch ──────────────────────────────────────────────────

  /** POST /api/v1/kill — emergency stop all scans */
  kill: (reason: string) =>
    fetchJson<KillResponse>('/api/v1/kill', {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),

  // ── Chat ──────────────────────────────────────────────────────────

  chat: {
    /** POST /api/v1/chat — send message to agent, get response */
    send: (message: string, scanId?: string) =>
      fetchJson<ChatResponse>('/api/v1/chat', {
        method: 'POST',
        body: JSON.stringify({ message, scan_id: scanId }),
      }),

    /** GET /api/v1/chat/history — get chat messages, optionally filtered by scan_id */
    history: (scanId?: string) =>
      fetchJson<ChatMessage[]>(
        `/api/v1/chat/history${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ''}`,
      ),
  },

  // ── Auth ──────────────────────────────────────────────────────────

  auth: {
    /** POST /api/v1/auth/login — authenticate and receive JWT + user */
    login: (email: string, password: string) =>
      fetchJson<LoginResponse>('/api/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }),

    /** GET /api/v1/auth/me — current authenticated user */
    me: () => fetchJson<User>('/api/v1/auth/me'),

    /** GET /api/v1/auth/users — list all users (admin only) */
    users: () => fetchJson<User[]>('/api/v1/auth/users'),
  },
};
