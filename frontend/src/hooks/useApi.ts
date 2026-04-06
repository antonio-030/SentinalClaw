// ── SentinelClaw React Query hooks ───────────────────────────────────

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../services/api';

// ── Query keys (centralised to avoid typos) ──────────────────────────

export const queryKeys = {
  status: ['status'] as const,
  scans: ['scans'] as const,
  scan: (id: string) => ['scan', id] as const,
  findings: (severity?: string) => ['findings', severity] as const,
  profiles: ['profiles'] as const,
  audit: ['audit'] as const,
  health: ['health'] as const,
  agentTools: ['agentTools'] as const,
  whitelist: ['whitelist'] as const,
  settings: ['settings'] as const,
};

// ── Queries ──────────────────────────────────────────────────────────

/** System status — polls every 10 s. */
export function useStatus() {
  return useQuery({
    queryKey: queryKeys.status,
    queryFn: api.status,
    refetchInterval: 10_000,
  });
}

/** Health check. */
export function useHealth() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: api.health,
    refetchInterval: 30_000,
  });
}

/** All scans — polls every 5 s to keep the dashboard live. */
export function useScans() {
  return useQuery({
    queryKey: queryKeys.scans,
    queryFn: api.scans.list,
    refetchInterval: 5_000,
  });
}

/** Single scan with phases, findings, and open ports. */
export function useScan(id: string) {
  return useQuery({
    queryKey: queryKeys.scan(id),
    queryFn: () => api.scans.get(id),
    enabled: !!id,
    refetchInterval: 5_000,
  });
}

/** Findings list, optionally filtered by severity. */
export function useFindings(severity?: string) {
  return useQuery({
    queryKey: queryKeys.findings(severity),
    queryFn: () => api.findings.list(severity),
  });
}

/** Available scan profiles (builtin + custom). */
export function useProfiles() {
  return useQuery({
    queryKey: queryKeys.profiles,
    queryFn: api.profiles.list,
    staleTime: 60_000,
  });
}

/** Profil erstellen. */
export function useCreateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.profiles.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.profiles });
    },
  });
}

/** Profil löschen. */
export function useDeleteProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.profiles.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.profiles });
    },
  });
}

/** Audit log entries. */
export function useAudit() {
  return useQuery({
    queryKey: queryKeys.audit,
    queryFn: () => api.audit(),
  });
}

// ── Mutations ────────────────────────────────────────────────────────

/** Start a new scan. Invalidates the scans list on success. */
export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.scans.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.scans });
    },
  });
}

/** Cancel a running scan. */
export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.scans.cancel(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.scans });
    },
  });
}

/** Delete a scan. */
export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.scans.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.scans });
    },
  });
}

/** Delete a finding. */
export function useDeleteFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.findings.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.findings() });
    },
  });
}

/** Agent tools — verfuegbare Security-Tools in der Sandbox. */
export function useAgentTools() {
  return useQuery({
    queryKey: queryKeys.agentTools,
    queryFn: api.agentTools.list,
    staleTime: 30_000,
  });
}

/** Tool in der Sandbox installieren. */
export function useInstallTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.agentTools.install(name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.agentTools });
    },
  });
}

/** Tool aus der Sandbox deinstallieren. */
export function useUninstallTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.agentTools.uninstall(name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.agentTools });
    },
  });
}

/** Autorisierte Scan-Ziele. */
export function useWhitelist() {
  return useQuery({
    queryKey: queryKeys.whitelist,
    queryFn: api.whitelist.list,
    staleTime: 30_000,
  });
}

/** Ziel autorisieren. */
export function useAuthorizeTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ target, confirmation, notes }: {
      target: string; confirmation: string; notes?: string;
    }) => api.whitelist.authorize(target, confirmation, notes),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.whitelist });
    },
  });
}

/** Ziel-Autorisierung widerrufen. */
export function useRevokeTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.whitelist.revoke(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.whitelist });
    },
  });
}

/** Systemeinstellungen laden. */
export function useSettings() {
  return useQuery({
    queryKey: queryKeys.settings,
    queryFn: api.settings.list,
    staleTime: 30_000,
  });
}

/** Einstellungen aktualisieren. */
export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (settings: Record<string, string>) => api.settings.update(settings),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.settings });
    },
  });
}

/** Emergency kill switch — stops all scans and invalidates relevant caches. */
export function useKill() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.kill,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.scans });
      qc.invalidateQueries({ queryKey: queryKeys.status });
    },
  });
}
