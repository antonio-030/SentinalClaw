// ── SentinelClaw API — Admin-Domäne ─────────────────────────────────
//
// API-Methoden für Auth, Settings, Whitelist, Audit-Log und Kill-Switch.

import type {
  AuditEntry,
  AuthorizedTarget,
  ChangePasswordResponse,
  HealthResponse,
  KillResponse,
  LoginResponse,
  MfaActionResponse,
  MfaLoginResponse,
  MfaSetupResponse,
  SystemSetting,
  SystemStatus,
  User,
} from '../../types/api';

import { fetchJson } from './core';

// ── Health & Status ──────────────────────────────────────────────────

/** GET /health */
export const healthApi = () => fetchJson<HealthResponse>('/health');

/** GET /api/v1/status */
export const statusApi = () => fetchJson<SystemStatus>('/api/v1/status');

// ── Auth ─────────────────────────────────────────────────────────────

export const authApi = {
  /** POST /api/v1/auth/login — Authentifizierung mit JWT + User */
  login: (email: string, password: string) =>
    fetchJson<LoginResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  /** POST /api/v1/auth/logout — serverseitiges Logout (Cookie wird gelöscht) */
  logout: () =>
    fetchJson<{ status: string }>('/api/v1/auth/logout', {
      method: 'POST',
    }),

  /** GET /api/v1/auth/me — aktuell eingeloggter User */
  me: () => fetchJson<User>('/api/v1/auth/me'),

  /** GET /api/v1/auth/users — alle User auflisten (nur Admin) */
  users: () => fetchJson<User[]>('/api/v1/auth/users'),

  /** POST /api/v1/auth/mfa/login — MFA-Code nach Passwort-Login prüfen */
  mfaLogin: (mfaSession: string, token: string) =>
    fetchJson<MfaLoginResponse>('/api/v1/auth/mfa/login', {
      method: 'POST',
      body: JSON.stringify({ mfa_session: mfaSession, token }),
    }),

  /** POST /api/v1/auth/mfa/setup — MFA für eigenen Account einrichten */
  mfaSetup: () =>
    fetchJson<MfaSetupResponse>('/api/v1/auth/mfa/setup', { method: 'POST' }),

  /** POST /api/v1/auth/mfa/verify — Ersten TOTP-Code bestätigen */
  mfaVerify: (secret: string, token: string) =>
    fetchJson<MfaActionResponse>('/api/v1/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ secret, token }),
    }),

  /** POST /api/v1/auth/mfa/disable — MFA deaktivieren */
  mfaDisable: (token: string) =>
    fetchJson<MfaActionResponse>('/api/v1/auth/mfa/disable', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }),

  /** POST /api/v1/auth/change-password — Eigenes Passwort ändern */
  changePassword: (oldPassword: string, newPassword: string) =>
    fetchJson<ChangePasswordResponse>('/api/v1/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    }),
};

// ── Settings ─────────────────────────────────────────────────────────

export const settingsApi = {
  /** GET /api/v1/settings — alle Einstellungen */
  list: () => fetchJson<SystemSetting[]>('/api/v1/settings'),

  /** PUT /api/v1/settings — Batch-Update */
  update: (settings: Record<string, string>) =>
    fetchJson<{ updated: number }>('/api/v1/settings', {
      method: 'PUT',
      body: JSON.stringify({ settings }),
    }),
};

// ── Whitelist (Autorisierte Ziele) ───────────────────────────────────

export const whitelistApi = {
  /** GET /api/v1/whitelist — alle autorisierten Ziele */
  list: () => fetchJson<AuthorizedTarget[]>('/api/v1/whitelist'),

  /** POST /api/v1/whitelist — Ziel autorisieren */
  authorize: (target: string, confirmation: string, notes?: string) =>
    fetchJson<AuthorizedTarget>('/api/v1/whitelist', {
      method: 'POST',
      body: JSON.stringify({ target, confirmation, notes: notes ?? '' }),
    }),

  /** DELETE /api/v1/whitelist/:id — Autorisierung widerrufen */
  revoke: (id: string) =>
    fetchJson<void>(`/api/v1/whitelist/${id}`, { method: 'DELETE' }),

  /** GET /api/v1/whitelist/policy — Policy-Status */
  policy: () => fetchJson<Record<string, string>>('/api/v1/whitelist/policy'),
};

// ── Audit-Log ────────────────────────────────────────────────────────

/** GET /api/v1/audit?limit=N */
export const auditApi = (limit?: number) =>
  fetchJson<AuditEntry[]>(`/api/v1/audit?limit=${limit ?? 50}`);

// ── Kill-Switch ──────────────────────────────────────────────────────

/** POST /api/v1/kill — Notfall-Stopp aller Scans */
export const killApi = (reason: string) =>
  fetchJson<KillResponse>('/api/v1/kill', {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });

/** POST /api/v1/kill/reset — Kill-Switch zurücksetzen + Sandbox starten */
export const killResetApi = () =>
  fetchJson<{ status: string; sandbox_started: boolean; message: string }>(
    '/api/v1/kill/reset',
    { method: 'POST' },
  );
