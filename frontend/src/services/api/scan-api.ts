// ── SentinelClaw API — Scan-Domäne ──────────────────────────────────
//
// API-Methoden für Scans, Findings und Scan-Profile.

import type {
  CompareResult,
  CreateScanRequest,
  CreateScanResponse,
  Finding,
  Scan,
  ScanDetail,
  ScanProfile,
} from '../../types/api';

import { BASE, fetchJson } from './core';

// ── Scans ────────────────────────────────────────────────────────────

export const scansApi = {
  /** GET /api/v1/scans — alle Scans auflisten */
  list: () => fetchJson<Scan[]>('/api/v1/scans'),

  /** GET /api/v1/scans/:id — Scan-Detail mit Phasen, Findings, Ports */
  get: (id: string) => fetchJson<ScanDetail>(`/api/v1/scans/${id}`),

  /** POST /api/v1/scans — neuen Scan starten */
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

  /** GET /api/v1/scans/:id/export?format=... */
  export: (id: string, format?: string) =>
    fetch(
      `${BASE}/api/v1/scans/${id}/export${format ? `?format=${encodeURIComponent(format)}` : ''}`,
      { credentials: 'include' },
    ).then((r) => {
      if (!r.ok) throw new Error(`Export failed: ${r.status}`);
      return r.blob();
    }),

  /** POST /api/v1/scans/compare — zwei Scans vergleichen */
  compare: (data: { scan_id_a: string; scan_id_b: string }) =>
    fetchJson<CompareResult>('/api/v1/scans/compare', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  /** GET /api/v1/scans/:id/report?type=... — Markdown-Report als Text */
  report: (id: string, type: string) =>
    fetch(
      `${BASE}/api/v1/scans/${id}/report?type=${encodeURIComponent(type)}`,
      { credentials: 'include' },
    ).then((r) => {
      if (!r.ok) throw new Error(`Report failed: ${r.status}`);
      return r.text();
    }),

  /** GET /api/v1/scans/:id/report/pdf?type=... — PDF-Download */
  reportPdf: (id: string, type: string) =>
    fetch(
      `${BASE}/api/v1/scans/${id}/report/pdf?type=${encodeURIComponent(type)}`,
      { credentials: 'include' },
    ).then((r) => {
      if (!r.ok) throw new Error(`PDF-Export failed: ${r.status}`);
      return r.blob();
    }),
};

// ── Findings ─────────────────────────────────────────────────────────

export const findingsApi = {
  /** GET /api/v1/findings — optional nach Severity und/oder Scan-ID filtern */
  list: (severity?: string, scanId?: string) => {
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (scanId) params.set('scan_id', scanId);
    const query = params.toString();
    return fetchJson<Finding[]>(`/api/v1/findings${query ? `?${query}` : ''}`);
  },

  /** GET /api/v1/findings/:id */
  get: (id: string) => fetchJson<Finding>(`/api/v1/findings/${id}`),

  /** DELETE /api/v1/findings/:id */
  delete: (id: string) =>
    fetchJson<void>(`/api/v1/findings/${id}`, { method: 'DELETE' }),
};

// ── Profile ──────────────────────────────────────────────────────────

export const profilesApi = {
  /** GET /api/v1/profiles — alle Profile (builtin + custom) */
  list: () => fetchJson<ScanProfile[]>('/api/v1/profiles'),

  /** POST /api/v1/profiles — neues Profil erstellen */
  create: (data: Omit<ScanProfile, 'id' | 'is_builtin' | 'created_by' | 'updated_at'>) =>
    fetchJson<ScanProfile>('/api/v1/profiles', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  /** DELETE /api/v1/profiles/:id — Custom-Profil löschen */
  delete: (id: string) =>
    fetchJson<void>(`/api/v1/profiles/${id}`, { method: 'DELETE' }),
};
