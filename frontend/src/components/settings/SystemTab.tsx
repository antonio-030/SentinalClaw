// System-Status-Tab: LLM-Provider, System-Info, Scan-Status, Kill-Switch

import {
  Brain,
  Server,
  Radar,
  ShieldOff,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { useStatus, useHealth } from '../../hooks/useApi';
import { Card, StatusRow, Dot } from './SettingsCard';

/** Zeigt den aktuellen Systemzustand als Karten-Übersicht */
export function SystemTab() {
  const { data: status } = useStatus();
  const { data: health } = useHealth();
  const sys = status?.system;
  const scans = status?.scans;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card title="LLM Provider" icon={Brain}>
        <StatusRow label="Provider" value={sys?.llm_provider ?? '--'} mono />
        <StatusRow label="Modell" value={health?.provider ?? sys?.llm_provider ?? '--'} mono />
        <StatusRow label="Verbindung" value={
          <span className="inline-flex items-center gap-1.5">
            <Dot ok={!!health?.status} />
            <span>{health?.status === 'ok' ? 'Verbunden' : 'Getrennt'}</span>
          </span>
        } />
        <StatusRow label="OpenShell" value={
          <span className="inline-flex items-center gap-1.5">
            <Dot ok={!!sys?.openshell_available} />
            <span>{sys?.openshell_available ? 'Installiert' : 'Nicht installiert'}</span>
          </span>
        } />
      </Card>

      <Card title="System Info" icon={Server}>
        <StatusRow label="Version" value={sys?.version ?? health?.version ?? '--'} mono />
        <StatusRow label="Docker" value={
          <span className="inline-flex items-center gap-1.5">
            <Dot ok={!!sys?.docker} />
            <span className="font-mono">{sys?.docker || 'Nicht verfügbar'}</span>
          </span>
        } />
        <StatusRow label="Sandbox" value={
          <span className="inline-flex items-center gap-1.5">
            <Dot ok={!!(sys?.sandbox_running ?? health?.sandbox_running)} />
            <span>{(sys?.sandbox_running ?? health?.sandbox_running) ? 'Aktiv' : 'Inaktiv'}</span>
          </span>
        } />
        <StatusRow label="Datenbank" value={
          <span className="inline-flex items-center gap-1.5">
            <Dot ok={!!health?.db_connected} />
            <span>{health?.db_connected ? 'Verbunden' : 'Getrennt'}</span>
          </span>
        } />
      </Card>

      <Card title="Scan-Status" icon={Radar}>
        <StatusRow label="Laufende Scans" value={scans?.running ?? 0} />
        <StatusRow label="Scans insgesamt" value={scans?.total ?? 0} />
      </Card>

      <Card title="Kill Switch" icon={ShieldOff}>
        <StatusRow label="Status" value={
          sys?.kill_switch_active ? (
            <span className="inline-flex items-center gap-1.5 text-severity-critical">
              <XCircle size={13} /> <span className="font-semibold">AKTIV</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-status-success">
              <CheckCircle2 size={13} /> <span>Inaktiv</span>
            </span>
          )
        } />
      </Card>
    </div>
  );
}
