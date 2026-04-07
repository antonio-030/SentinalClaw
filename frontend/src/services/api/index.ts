// ── SentinelClaw API — Barrel Export ────────────────────────────────
//
// Setzt das einheitliche `api`-Objekt aus den Domänen-Modulen zusammen.
// Alle bestehenden Imports (`import { api } from '../services/api'`)
// funktionieren weiterhin ohne Änderung.

import { scansApi, findingsApi, profilesApi } from './scan-api';
import { chatApi, agentReportsApi, agentToolsApi, workspaceApi, nemoclawApi } from './agent-api';
import {
  healthApi,
  statusApi,
  authApi,
  settingsApi,
  whitelistApi,
  auditApi,
  killApi,
  killResetApi,
} from './admin-api';

export const api = {
  health: healthApi,
  status: statusApi,
  scans: scansApi,
  findings: findingsApi,
  profiles: profilesApi,
  settings: settingsApi,
  audit: auditApi,
  kill: killApi,
  killReset: killResetApi,
  chat: chatApi,
  agentReports: agentReportsApi,
  agentTools: agentToolsApi,
  workspace: workspaceApi,
  whitelist: whitelistApi,
  nemoclaw: nemoclawApi,
  auth: authApi,
};
