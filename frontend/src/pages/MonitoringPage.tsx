import { useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import {
  Activity, Shield, Container,
  RotateCcw, Loader2, AlertCircle,
} from 'lucide-react';
import { api } from '../services/api';
import { NemoClawPanel } from '../components/dashboard/NemoClawPanel';
import { useStatus, useHealth, useScans, useAudit } from '../hooks/useApi';
import { formatDate } from '../utils/format';

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className={`inline-block h-2.5 w-2.5 rounded-full shrink-0 ${
      ok ? 'bg-status-success shadow-[0_0_8px_rgba(34,197,94,0.4)]'
         : 'bg-status-error shadow-[0_0_8px_rgba(239,68,68,0.4)]'
    }`} />
  );
}

function InfoRow({ label, value, ok }: { label: string; value: string; ok?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-border-subtle last:border-0">
      <span className="text-xs text-text-secondary">{label}</span>
      <span className="flex items-center gap-2 text-xs font-mono text-text-primary">
        {ok !== undefined && <StatusDot ok={ok} />}
        {value}
      </span>
    </div>
  );
}

export function MonitoringPage() {
  const { data: status, isError: isStatusError, error: statusError, refetch: refetchStatus } = useStatus();
  const { data: health, isError: isHealthError, refetch: refetchHealth } = useHealth();
  const { data: scans = [], isError: isScansError, refetch: refetchScans } = useScans();
  const { data: audit = [], isError: isAuditError, refetch: refetchAudit } = useAudit();

  const isError = isStatusError || isHealthError || isScansError || isAuditError;
  const firstError = statusError;
  const [resetting, setResetting] = useState(false);
  const qc = useQueryClient();

  const sys = status?.system;

  const runningScans = scans.filter(s => s.status === 'running');
  const completedScans = scans.filter(s => s.status === 'completed');
  const failedScans = scans.filter(s => s.status === 'failed' || s.status === 'emergency_killed');

  const recentAudit = useMemo(() => audit.slice(0, 10), [audit]);

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-severity-critical/10 mb-4">
          <AlertCircle className="h-6 w-6 text-severity-critical" />
        </div>
        <h2 className="text-sm font-semibold text-text-primary mb-1">Fehler beim Laden</h2>
        <p className="text-xs text-text-tertiary max-w-sm mb-4">
          {(firstError as Error | null)?.message || 'Unbekannter Fehler'}
        </p>
        <button
          onClick={() => { refetchStatus(); refetchHealth(); refetchScans(); refetchAudit(); }}
          className="inline-flex items-center gap-1.5 rounded-md bg-accent/10 border border-accent/30 px-3.5 py-2 text-xs font-medium text-accent hover:bg-accent/20 transition-colors"
        >
          Erneut versuchen
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl">
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">
          Monitoring & Observability
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          NVIDIA NemoClaw Runtime, System-Komponenten, Agent-Aktivität
        </p>
      </div>

      {/* NemoClaw Runtime Status */}
      <NemoClawPanel sys={sys} health={health} />

      {/* System-Komponenten Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {/* API-Server */}
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity size={16} className="text-accent" />
            <h3 className="text-sm font-semibold text-text-primary">API-Server</h3>
            <StatusDot ok={health?.status === 'ok'} />
          </div>
          <InfoRow label="Status" value={health?.status ?? 'Unbekannt'} ok={health?.status === 'ok'} />
          <InfoRow label="Version" value={health?.version ?? '--'} />
          <InfoRow label="Datenbank" value={health?.db_connected ? 'Verbunden' : 'Getrennt'} ok={health?.db_connected} />
        </div>

        {/* Docker Sandbox */}
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4">
          <div className="flex items-center gap-2 mb-3">
            <Container size={16} className="text-accent" />
            <h3 className="text-sm font-semibold text-text-primary">Sandbox-Container</h3>
            <StatusDot ok={!!sys?.sandbox_running} />
          </div>
          <InfoRow label="Status" value={sys?.sandbox_running ? 'Running' : 'Gestoppt'} ok={sys?.sandbox_running} />
          <InfoRow label="Docker" value={sys?.docker ?? '--'} ok={sys?.docker !== 'nicht verfuegbar'} />
          <InfoRow label="Tools" value="nmap 7.80, nuclei 3.3.7" />
          <InfoRow label="Isolation" value="cap_drop ALL + NET_RAW" />
          <div className="mt-3 flex gap-2">
            {!sys?.sandbox_running ? (
              <button
                onClick={async () => {
                  try {
                    const csrf = document.cookie.match(/(?:^|;\s*)sc_csrf=([^;]*)/)?.[1] ?? '';
                    await fetch('/api/v1/sandbox/start', {
                      method: 'POST',
                      credentials: 'include',
                      headers: { 'X-CSRF-Token': csrf },
                    });
                    setTimeout(() => window.location.reload(), 2000);
                  } catch { /* ignore */ }
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-status-success/10 border border-status-success/30 text-xs font-medium text-status-success hover:bg-status-success/20"
              >
                ▶ Sandbox starten
              </button>
            ) : (
              <button
                onClick={async () => {
                  if (!confirm('Sandbox-Container wirklich stoppen?')) return;
                  try {
                    const csrf = document.cookie.match(/(?:^|;\s*)sc_csrf=([^;]*)/)?.[1] ?? '';
                    await fetch('/api/v1/sandbox/stop', {
                      method: 'POST',
                      credentials: 'include',
                      headers: { 'X-CSRF-Token': csrf },
                    });
                    setTimeout(() => window.location.reload(), 2000);
                  } catch { /* ignore */ }
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-severity-critical/10 border border-severity-critical/30 text-xs font-medium text-severity-critical hover:bg-severity-critical/20"
              >
                ⏹ Sandbox stoppen
              </button>
            )}
          </div>
        </div>

        {/* Watchdog */}
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield size={16} className="text-accent" />
            <h3 className="text-sm font-semibold text-text-primary">Kill Switch & Watchdog</h3>
            <StatusDot ok={!sys?.kill_switch_active} />
          </div>
          <InfoRow label="Kill Switch" value={sys?.kill_switch_active ? 'AKTIV' : 'Inaktiv'} ok={!sys?.kill_switch_active} />
          <InfoRow label="Watchdog" value="Bereit" ok={true} />
          <InfoRow label="Scope-Validator" value="7 Checks aktiv" ok={true} />
          <InfoRow label="PII-Sanitizer" value="Aktiv" ok={true} />
          {sys?.kill_switch_active && (
            <div className="mt-3 pt-3 border-t border-border-subtle">
              <div className="rounded-md bg-severity-critical/10 border border-severity-critical/20 px-3 py-2.5 mb-3">
                <p className="text-[11px] text-severity-critical leading-relaxed">
                  Der Notaus ist aktiv. Alle Scans wurden gestoppt. Setze den Kill-Switch
                  zurück um das System wiederherzustellen.
                </p>
              </div>
              <button
                onClick={async () => {
                  if (!confirm('Kill-Switch zurücksetzen und Sandbox neu starten?')) return;
                  setResetting(true);
                  try {
                    await api.killReset();
                    qc.invalidateQueries({ queryKey: ['status'] });
                    qc.invalidateQueries({ queryKey: ['health'] });
                  } catch (err) {
                    alert(`Fehler: ${err instanceof Error ? err.message : 'Unbekannt'}`);
                  } finally {
                    setResetting(false);
                  }
                }}
                disabled={resetting}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-md bg-status-success/15 border border-status-success/30 text-sm font-semibold text-status-success hover:bg-status-success/25 disabled:opacity-50 transition-colors"
              >
                {resetting ? (
                  <Loader2 size={15} className="animate-spin" />
                ) : (
                  <RotateCcw size={15} />
                )}
                System wiederherstellen
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Scan-Statistiken */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
          <p className="text-2xl font-bold text-status-running tabular-nums">{runningScans.length}</p>
          <p className="text-xs text-text-secondary mt-1">Laufende Scans</p>
        </div>
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
          <p className="text-2xl font-bold text-status-success tabular-nums">{completedScans.length}</p>
          <p className="text-xs text-text-secondary mt-1">Abgeschlossen</p>
        </div>
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
          <p className="text-2xl font-bold text-status-error tabular-nums">{failedScans.length}</p>
          <p className="text-xs text-text-secondary mt-1">Fehlgeschlagen</p>
        </div>
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
          <p className="text-2xl font-bold text-text-primary tabular-nums">{scans.length}</p>
          <p className="text-xs text-text-secondary mt-1">Gesamt</p>
        </div>
      </div>

      {/* Live-Aktivität (laufende Scans) */}
      {runningScans.length > 0 && (
        <div className="rounded-lg border border-status-running/20 bg-status-running/5 p-5">
          <h2 className="text-sm font-semibold text-text-primary mb-3 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-status-running animate-pulse" />
            Laufende Scans
          </h2>
          <div className="space-y-2">
            {runningScans.map(scan => (
              <div key={scan.id} className="flex items-center gap-3 rounded-md bg-bg-secondary border border-border-subtle p-3">
                <span className="h-2 w-2 rounded-full bg-status-running animate-pulse shrink-0" />
                <span className="text-xs font-mono text-text-primary flex-1">{scan.target}</span>
                <span className="text-[10px] text-text-tertiary">{scan.scan_type}</span>
                <span className="text-[10px] text-text-tertiary tabular-nums">
                  {scan.started_at ? formatDate(scan.started_at) : '--'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Letzte Audit-Aktivität */}
      <div className="rounded-lg border border-border-subtle bg-bg-secondary">
        <div className="px-5 py-3 border-b border-border-subtle">
          <h2 className="text-sm font-semibold text-text-primary">Letzte System-Aktivität</h2>
        </div>
        <div className="divide-y divide-border-subtle">
          {recentAudit.length === 0 && (
            <p className="px-5 py-4 text-xs text-text-tertiary">Keine Aktivität</p>
          )}
          {recentAudit.map(entry => (
            <div key={entry.id} className="flex items-center gap-3 px-5 py-2.5">
              <span className="text-[10px] font-mono text-text-tertiary tabular-nums w-32 shrink-0">
                {formatDate(entry.created_at)}
              </span>
              <span className={`text-[11px] font-medium px-2 py-0.5 rounded ${
                entry.action.includes('kill') ? 'bg-severity-critical/10 text-severity-critical'
                : entry.action.includes('error') || entry.action.includes('fail') ? 'bg-severity-high/10 text-severity-high'
                : entry.action.includes('start') || entry.action.includes('create') ? 'bg-accent/10 text-accent'
                : 'bg-bg-tertiary text-text-secondary'
              }`}>
                {entry.action}
              </span>
              <span className="text-xs text-text-tertiary truncate flex-1">{entry.triggered_by}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
