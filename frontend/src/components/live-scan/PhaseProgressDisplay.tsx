import {
  Loader2,
  OctagonX,
  CheckCircle2,
  Circle,
  Play,
} from 'lucide-react';
import type { ScanPhase } from '../../types/api';

// ── Hilfsfunktionen für Phasen-Darstellung ─────────────────────────

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
    case 'running':   return 'Läuft';
    case 'failed':    return 'Fehlgeschlagen';
    case 'pending':   return 'Wartend';
    default:          return status;
  }
}

function formatElapsed(seconds: number) {
  const sec = Math.floor(seconds);
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${s.toString().padStart(2, '0')}`;
}

// ── Props-Interface ────────────────────────────────────────────────
interface PhaseProgressDisplayProps {
  phases: ScanPhase[];
  completedPhases: number;
  progressPct: number;
}

/**
 * Fortschrittsbalken und Phasen-Karten für den Live-Scan.
 * Zeigt den aktuellen Fortschritt und Details zu jeder Phase.
 */
export function PhaseProgressDisplay({ phases, completedPhases, progressPct }: PhaseProgressDisplayProps) {
  return (
    <>
      {/* Fortschrittsbalken */}
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

      {/* Phasen-Karten */}
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
    </>
  );
}
