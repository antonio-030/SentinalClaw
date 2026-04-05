import { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Loader2,
  OctagonX,
  ArrowRight,
  Monitor,
  Wifi,
  Bug,
  Clock,
  CheckCircle2,
  Circle,
  Play,
} from 'lucide-react';
import { api } from '../services/api';
import { useCancelScan, queryKeys } from '../hooks/useApi';
import type { ScanPhase } from '../types/api';

function formatElapsed(seconds: number) {
  const sec = Math.floor(seconds);
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${s.toString().padStart(2, '0')}`;
}

function phaseStatusIcon(status: string) {
  switch (status) {
    case 'completed':
      return <CheckCircle2 size={14} className="text-status-success shrink-0" />;
    case 'running':
      return <Play size={14} className="text-accent animate-pulse shrink-0" />;
    case 'failed':
      return <OctagonX size={14} className="text-status-error shrink-0" />;
    default:
      return <Circle size={14} className="text-text-tertiary shrink-0" />;
  }
}

function phaseStatusLabel(status: string) {
  switch (status) {
    case 'completed': return 'Abgeschlossen';
    case 'running':   return 'Laeuft';
    case 'failed':    return 'Fehlgeschlagen';
    case 'pending':   return 'Wartend';
    default:          return status;
  }
}

export function LiveScanPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const cancelScan = useCancelScan();

  const [elapsed, setElapsed] = useState(0);

  const { data, isLoading, isError } = useQuery({
    queryKey: queryKeys.scan(id ?? ''),
    queryFn: () => api.scans.get(id!),
    enabled: !!id,
    refetchInterval: 3_000,
  });

  const scan = data?.scan;
  const phases = data?.phases ?? [];
  const findings = data?.findings ?? [];
  const openPorts = data?.open_ports ?? [];

  const isRunning = scan?.status === 'running' || scan?.status === 'pending';

  // KEIN Auto-Redirect — User will den Endzustand sehen

  // Elapsed time counter
  useEffect(() => {
    if (!isRunning || !scan?.started_at) return;
    const start = new Date(scan.started_at).getTime();

    function tick() {
      setElapsed(Math.floor((Date.now() - start) / 1000));
    }

    tick();
    const interval = setInterval(tick, 1_000);
    return () => clearInterval(interval);
  }, [isRunning, scan?.started_at]);

  // Compute counters
  const { totalHosts, totalPorts, totalFindings, completedPhases, progressPct } = useMemo(() => {
    const hosts = phases.reduce((s: number, p: ScanPhase) => s + p.hosts_found, 0);
    const ports = openPorts.length || phases.reduce((s: number, p: ScanPhase) => s + p.ports_found, 0);
    const fCount = findings.length || phases.reduce((s: number, p: ScanPhase) => s + p.findings_found, 0);
    const completed = phases.filter((p: ScanPhase) => p.status === 'completed').length;
    const pct = phases.length > 0 ? Math.round((completed / phases.length) * 100) : 0;
    return { totalHosts: hosts, totalPorts: ports, totalFindings: fCount, completedPhases: completed, progressPct: pct };
  }, [phases, openPorts, findings]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 size={24} className="animate-spin text-text-tertiary" />
      </div>
    );
  }

  if (isError || !scan) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-3">
        <p className="text-sm text-text-tertiary">Scan nicht gefunden</p>
        <Link to="/scans" className="text-xs text-accent hover:underline">
          Zurueck zur Scan-Liste
        </Link>
      </div>
    );
  }

  function handleKill() {
    if (!id) return;
    cancelScan.mutate(id);
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">
            Live Scan
          </h1>
          <p className="mt-1 text-sm text-text-secondary font-mono">{scan.target}</p>
        </div>
        <div className="flex items-center gap-2">
          {isRunning && (
            <button
              onClick={handleKill}
              disabled={cancelScan.isPending}
              className="flex items-center gap-2 rounded-md bg-severity-critical/90 px-4 py-2.5 text-xs font-bold text-white tracking-wider transition-colors hover:bg-severity-critical disabled:opacity-50"
            >
              <OctagonX size={14} strokeWidth={2.5} />
              NOTAUS
            </button>
          )}
          {!isRunning && (
            <Link
              to={`/scans/${id}`}
              className="flex items-center gap-2 rounded-md bg-accent px-4 py-2.5 text-xs font-semibold text-white tracking-wide transition-colors hover:bg-accent-hover"
            >
              Zum Ergebnis
              <ArrowRight size={14} />
            </Link>
          )}
        </div>
      </div>

      {/* Status-Banner */}
      {isRunning && (
        <div className="rounded-lg border border-accent/30 bg-accent/5 p-3 flex items-center gap-3">
          <span className="flex gap-0.5 shrink-0">
            <span className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
            <span className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
            <span className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
          </span>
          <div>
            <p className="text-sm font-medium text-text-primary">Scan läuft — {formatElapsed(elapsed)}</p>
            <p className="text-xs text-text-secondary">Agent führt Phasen autonom aus. Die Seite aktualisiert sich alle 3 Sekunden.</p>
          </div>
        </div>
      )}
      {scan?.status === 'completed' && (
        <div className="rounded-lg border border-status-success/30 bg-status-success/5 p-3 flex items-center gap-3">
          <CheckCircle2 size={18} className="text-status-success shrink-0" />
          <div>
            <p className="text-sm font-medium text-text-primary">Scan abgeschlossen</p>
            <p className="text-xs text-text-secondary">{totalHosts} Hosts, {totalPorts} Ports, {totalFindings} Findings in {formatElapsed(elapsed)}</p>
          </div>
          <Link to={`/scans/${id}`} className="ml-auto text-xs text-accent hover:underline shrink-0">Details →</Link>
        </div>
      )}
      {scan?.status === 'failed' && (
        <div className="rounded-lg border border-status-error/30 bg-status-error/5 p-3 flex items-center gap-3">
          <OctagonX size={18} className="text-status-error shrink-0" />
          <div>
            <p className="text-sm font-medium text-text-primary">Scan fehlgeschlagen</p>
            <p className="text-xs text-text-secondary">Einige Phasen konnten nicht abgeschlossen werden.</p>
          </div>
        </div>
      )}

      {/* Live counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
          <Monitor size={16} className="mx-auto mb-1.5 text-text-tertiary" strokeWidth={1.8} />
          <p className="text-2xl font-semibold text-text-primary tabular-nums">{totalHosts}</p>
          <p className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">Hosts</p>
        </div>
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
          <Wifi size={16} className="mx-auto mb-1.5 text-text-tertiary" strokeWidth={1.8} />
          <p className="text-2xl font-semibold text-text-primary tabular-nums">{totalPorts}</p>
          <p className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">Offene Ports</p>
        </div>
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
          <Bug size={16} className="mx-auto mb-1.5 text-text-tertiary" strokeWidth={1.8} />
          <p className="text-2xl font-semibold text-text-primary tabular-nums">{totalFindings}</p>
          <p className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">Findings</p>
        </div>
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
          <Clock size={16} className="mx-auto mb-1.5 text-text-tertiary" strokeWidth={1.8} />
          <p className="text-2xl font-semibold text-text-primary tabular-nums font-mono">
            {formatElapsed(elapsed)}
          </p>
          <p className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">Laufzeit</p>
        </div>
      </div>

      {/* Progress bar */}
      <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-text-secondary">Fortschritt</span>
          <span className="text-xs text-text-tertiary tabular-nums">
            {completedPhases} / {phases.length} Phasen ({progressPct}%)
          </span>
        </div>
        <div className="h-2 rounded-full bg-bg-tertiary overflow-hidden">
          <div
            className="h-full rounded-full bg-accent transition-all duration-500 ease-out"
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </div>

      {/* Phase cards */}
      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-text-primary tracking-wide">Phasen</h2>
        {phases.length === 0 && (
          <div className="rounded-lg border border-border-subtle bg-bg-secondary px-5 py-8 text-center">
            <Loader2 size={18} className="mx-auto mb-2 animate-spin text-text-tertiary" />
            <p className="text-xs text-text-tertiary">Warte auf Phasen-Daten...</p>
          </div>
        )}
        {phases.map((phase: ScanPhase) => (
          <div
            key={phase.id}
            className={`rounded-lg border bg-bg-secondary px-5 py-4 transition-colors ${
              phase.status === 'running'
                ? 'border-accent/40 bg-accent/5'
                : 'border-border-subtle'
            }`}
          >
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-2.5 min-w-0">
                {phaseStatusIcon(phase.status)}
                <span className="text-sm font-medium text-text-primary truncate">
                  {phase.name}
                </span>
                <span
                  className={`text-[10px] uppercase tracking-wider font-medium px-1.5 py-0.5 rounded ${
                    phase.status === 'running'
                      ? 'bg-accent/15 text-accent'
                      : phase.status === 'completed'
                        ? 'bg-status-success/15 text-status-success'
                        : phase.status === 'failed'
                          ? 'bg-status-error/15 text-status-error'
                          : 'bg-bg-tertiary text-text-tertiary'
                  }`}
                >
                  {phaseStatusLabel(phase.status)}
                </span>
              </div>
              {phase.duration_seconds > 0 && (
                <span className="text-xs text-text-tertiary tabular-nums font-mono shrink-0">
                  {formatElapsed(phase.duration_seconds)}
                </span>
              )}
            </div>
            {/* Ergebnis-Zähler */}
            {(phase.hosts_found > 0 || phase.ports_found > 0 || phase.findings_found > 0) && (
              <div className="mt-2.5 flex items-center gap-4 text-xs text-text-secondary">
                {phase.hosts_found > 0 && (
                  <span>🖥 {phase.hosts_found} Host{phase.hosts_found !== 1 ? 's' : ''}</span>
                )}
                {phase.ports_found > 0 && (
                  <span>🔌 {phase.ports_found} Port{phase.ports_found !== 1 ? 's' : ''}</span>
                )}
                {phase.findings_found > 0 && (
                  <span>⚠ {phase.findings_found} Finding{phase.findings_found !== 1 ? 's' : ''}</span>
                )}
              </div>
            )}
            {/* Laufende Phase: Live-Info */}
            {phase.status === 'running' && (
              <div className="mt-2.5 flex items-center gap-2 text-xs text-accent">
                <span className="flex gap-0.5">
                  <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                  <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                  <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </span>
                <span>Claude Agent arbeitet — nmap/nuclei wird in der Sandbox ausgeführt...</span>
              </div>
            )}
            {/* Fehlgeschlagene Phase: Fehlermeldung */}
            {phase.status === 'failed' && (
              <div className="mt-2.5 text-xs text-status-error">
                Phase fehlgeschlagen — Agent versucht nächste Phase
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
