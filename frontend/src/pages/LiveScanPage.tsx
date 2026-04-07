import { useEffect, useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Loader2, OctagonX, ArrowRight } from 'lucide-react';
import { api } from '../services/api';
import { useCancelScan, queryKeys } from '../hooks/useApi';
import { ScanStatusBanner } from '../components/live-scan/ScanStatusBanner';
import { LiveCounters } from '../components/live-scan/LiveCounters';
import { PhaseProgressDisplay } from '../components/live-scan/PhaseProgressDisplay';
import type { ScanPhase } from '../types/api';

function formatElapsed(seconds: number) {
  const sec = Math.floor(seconds);
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${s.toString().padStart(2, '0')}`;
}

export function LiveScanPage() {
  const { id } = useParams<{ id: string }>();
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

  // Vergangene Zeit zählen
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

  // Zähler berechnen
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
          Zurück zur Scan-Liste
        </Link>
      </div>
    );
  }

  function handleKill() {
    if (!id) return;
    cancelScan.mutate(id);
  }

  const elapsedFormatted = formatElapsed(elapsed);

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
      <ScanStatusBanner
        status={scan.status}
        scanId={id!}
        elapsed={elapsedFormatted}
        totalHosts={totalHosts}
        totalPorts={totalPorts}
        totalFindings={totalFindings}
      />

      {/* Live-Zähler */}
      <LiveCounters
        totalHosts={totalHosts}
        totalPorts={totalPorts}
        totalFindings={totalFindings}
        elapsed={elapsedFormatted}
      />

      {/* Fortschritt + Phasen */}
      <PhaseProgressDisplay
        phases={phases}
        completedPhases={completedPhases}
        progressPct={progressPct}
      />
    </div>
  );
}
