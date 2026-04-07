/**
 * NemoClaw-Status-Panel für die Monitoring-Seite.
 *
 * Zeigt den aktuellen Runtime-Status (Verfügbar / Degradiert / Offline)
 * mit farbcodiertem Badge, aktivem Provider und letzter Prüfung.
 */

import { Brain, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import type { HealthResponse, SystemStatus } from '../../types/api';
import { formatDate } from '../../utils/format';

// ── Zustandsermittlung ──────────────────────────────────────────────

type NemoClawState = 'available' | 'degraded' | 'offline';

function getNemoClawState(
  sys: SystemStatus['system'] | undefined,
  health: HealthResponse | undefined,
): NemoClawState {
  const nemoclaw = health?.nemoclaw;
  if (nemoclaw?.available && sys?.nemoclaw_available) return 'available';
  if (nemoclaw?.provider && nemoclaw.provider !== 'nemoclaw' && nemoclaw.provider !== 'keiner') {
    return 'degraded';
  }
  if (sys?.nemoclaw_available) return 'available';
  return 'offline';
}

const STATE_CONFIG: Record<NemoClawState, {
  label: string;
  border: string;
  bg: string;
  badge: string;
}> = {
  available: {
    label: 'Verfügbar',
    border: 'border-accent/20',
    bg: 'bg-accent/5',
    badge: 'bg-status-success/15 text-status-success',
  },
  degraded: {
    label: 'Degradiert',
    border: 'border-severity-medium/30',
    bg: 'bg-severity-medium/5',
    badge: 'bg-severity-medium/15 text-severity-medium',
  },
  offline: {
    label: 'Offline',
    border: 'border-severity-critical/20',
    bg: 'bg-severity-critical/5',
    badge: 'bg-severity-critical/15 text-severity-critical',
  },
};

// ── Hilfskomponente ─────────────────────────────────────────────────

function StateIcon({ state }: { state: NemoClawState }) {
  if (state === 'available') return <CheckCircle size={12} />;
  if (state === 'degraded') return <AlertTriangle size={12} />;
  return <XCircle size={12} />;
}

// ── Haupt-Komponente ────────────────────────────────────────────────

interface NemoClawPanelProps {
  sys: SystemStatus['system'] | undefined;
  health: HealthResponse | undefined;
}

export function NemoClawPanel({ sys, health }: NemoClawPanelProps) {
  const state = getNemoClawState(sys, health);
  const cfg = STATE_CONFIG[state];
  const nemoclaw = health?.nemoclaw;
  const activeProvider = nemoclaw?.provider ?? sys?.llm_provider ?? '--';

  return (
    <div className={`rounded-lg border ${cfg.border} ${cfg.bg} p-5`}>
      {/* Header mit Badge */}
      <div className="flex items-center gap-3 mb-4">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-accent/10">
          <Brain size={22} className="text-accent" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-text-primary">NVIDIA NemoClaw</h2>
          <p className="text-xs text-text-secondary">Agent Runtime & Sandbox Orchestrierung</p>
        </div>
        <div className="ml-auto">
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ${cfg.badge}`}>
            <StateIcon state={state} />
            {cfg.label}
          </span>
        </div>
      </div>

      {/* Degradation-Hinweis */}
      {state === 'degraded' && (
        <div className="rounded-md bg-severity-medium/10 border border-severity-medium/20 px-3 py-2.5 mb-4">
          <p className="text-[11px] text-severity-medium leading-relaxed">
            NemoClaw ist nicht erreichbar. Das System verwendet <strong>{activeProvider}</strong> als
            Fallback-Provider. Sandbox-Isolation ist eingeschränkt.
          </p>
        </div>
      )}
      {state === 'offline' && (
        <div className="rounded-md bg-severity-critical/10 border border-severity-critical/20 px-3 py-2.5 mb-4">
          <p className="text-[11px] text-severity-critical leading-relaxed">
            NemoClaw und alle Fallback-Provider sind offline. Agent-Funktionen sind nicht verfügbar.
            {nemoclaw?.reason ? ` Grund: ${nemoclaw.reason}` : ''}
          </p>
        </div>
      )}

      {/* Detail-Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="rounded-md bg-bg-secondary border border-border-subtle p-3">
          <p className="text-[10px] font-semibold text-text-tertiary uppercase tracking-wider mb-1">OpenClaw Agent</p>
          <p className="text-sm font-mono text-text-primary">
            {sys?.nemoclaw_available ? (sys?.nemoclaw_version || 'Aktiv') : 'Nicht verbunden'}
          </p>
        </div>
        <div className="rounded-md bg-bg-secondary border border-border-subtle p-3">
          <p className="text-[10px] font-semibold text-text-tertiary uppercase tracking-wider mb-1">Aktiver Provider</p>
          <p className="text-sm font-mono text-text-primary">{activeProvider}</p>
        </div>
        <div className="rounded-md bg-bg-secondary border border-border-subtle p-3">
          <p className="text-[10px] font-semibold text-text-tertiary uppercase tracking-wider mb-1">OpenShell</p>
          <p className="text-sm font-mono text-text-primary">
            {sys?.openshell_available ? 'Landlock + seccomp' : 'Nicht installiert'}
          </p>
        </div>
        <div className="rounded-md bg-bg-secondary border border-border-subtle p-3">
          <p className="text-[10px] font-semibold text-text-tertiary uppercase tracking-wider mb-1">Letzte Prüfung</p>
          <p className="text-sm font-mono text-text-primary">
            {nemoclaw?.last_check ? formatDate(nemoclaw.last_check) : '--'}
          </p>
        </div>
      </div>
    </div>
  );
}
