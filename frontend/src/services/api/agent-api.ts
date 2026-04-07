// ── SentinelClaw API — Agent-Domäne ─────────────────────────────────
//
// API-Methoden für Chat, Agent-Reports, Agent-Tools,
// Workspace-Dateien und NemoClaw-Setup.

import type {
  AgentReport,
  AgentReportDetail,
  AgentTool,
  AgentToolActionResponse,
  ChatMessage,
  ChatResponse,
  NemoClawSetupStatus,
} from '../../types/api';

import { fetchJson } from './core';

// ── Chat ─────────────────────────────────────────────────────────────

export const chatApi = {
  /** POST /api/v1/chat — Nachricht an Agent senden, Antwort erhalten */
  send: (message: string, scanId?: string) =>
    fetchJson<ChatResponse>('/api/v1/chat', {
      method: 'POST',
      body: JSON.stringify({ message, scan_id: scanId }),
    }),

  /** GET /api/v1/chat/history — Chat-Verlauf, optional nach scan_id gefiltert */
  history: (scanId?: string) =>
    fetchJson<ChatMessage[]>(
      `/api/v1/chat/history${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ''}`,
    ),
};

// ── Agent-Reports ────────────────────────────────────────────────────

export const agentReportsApi = {
  /** GET /api/v1/chat/reports/agent — alle Agent-Reports */
  list: () =>
    fetchJson<AgentReport[]>('/api/v1/chat/reports/agent'),

  /** GET /api/v1/chat/reports/agent/:id — einzelner Report mit Inhalt */
  get: (id: string) =>
    fetchJson<AgentReportDetail>(`/api/v1/chat/reports/agent/${id}`),

  /** DELETE /api/v1/chat/reports/agent/:id — Report löschen */
  delete: (id: string) =>
    fetchJson<{ status: string }>(`/api/v1/chat/reports/agent/${id}`, {
      method: 'DELETE',
    }),
};

// ── Agent-Tools ──────────────────────────────────────────────────────

export const agentToolsApi = {
  /** GET /api/v1/agent/tools — alle Tools mit Status */
  list: () => fetchJson<AgentTool[]>('/api/v1/agent/tools'),

  /** POST /api/v1/agent/tools/:name/install */
  install: (name: string) =>
    fetchJson<AgentToolActionResponse>(`/api/v1/agent/tools/${name}/install`, {
      method: 'POST',
    }),

  /** DELETE /api/v1/agent/tools/:name */
  uninstall: (name: string) =>
    fetchJson<AgentToolActionResponse>(`/api/v1/agent/tools/${name}`, {
      method: 'DELETE',
    }),
};

// ── Workspace (NemoClaw Agent-Konfiguration) ─────────────────────────

export const workspaceApi = {
  /** GET /api/v1/workspace — alle Workspace-Dateien */
  list: () =>
    fetchJson<{ name: string; content: string; size: number; modified_at: string }[]>(
      '/api/v1/workspace',
    ),

  /** GET /api/v1/workspace/:name — einzelne Datei */
  get: (name: string) =>
    fetchJson<{ name: string; content: string; size: number; modified_at: string }>(
      `/api/v1/workspace/${encodeURIComponent(name)}`,
    ),

  /** PUT /api/v1/workspace/:name — Datei aktualisieren */
  update: (name: string, content: string) =>
    fetchJson<{ name: string; content: string; updated_at: string }>(
      `/api/v1/workspace/${encodeURIComponent(name)}`,
      {
        method: 'PUT',
        body: JSON.stringify({ content }),
      },
    ),
};

// ── NemoClaw Setup ───────────────────────────────────────────────────

export const nemoclawApi = {
  /** GET /api/v1/nemoclaw/setup-status — Gateway, Token, Provider prüfen */
  setupStatus: () =>
    fetchJson<NemoClawSetupStatus>('/api/v1/nemoclaw/setup-status'),

  /** POST /api/v1/nemoclaw/token — Claude-Token speichern und validieren */
  saveToken: (token: string) =>
    fetchJson<{ valid: boolean; message: string }>('/api/v1/nemoclaw/token', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }),

  /** POST /api/v1/nemoclaw/provider — LLM-Provider konfigurieren */
  setProvider: (provider: string, model: string) =>
    fetchJson<{ success: boolean; message: string; provider: string; model: string }>(
      '/api/v1/nemoclaw/provider',
      {
        method: 'POST',
        body: JSON.stringify({ provider, model }),
      },
    ),

  /** POST /api/v1/nemoclaw/sync-config — Agent-Konfiguration in Sandbox synchronisieren */
  syncConfig: () =>
    fetchJson<{ success: boolean; message: string }>('/api/v1/nemoclaw/sync-config', {
      method: 'POST',
    }),

  /** POST /api/v1/nemoclaw/pull-memory — Agent-Erinnerungen aus Sandbox holen */
  pullMemory: () =>
    fetchJson<{ success: boolean; message: string }>('/api/v1/nemoclaw/pull-memory', {
      method: 'POST',
    }),
};
