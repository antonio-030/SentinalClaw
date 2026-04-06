import { useStatus, useHealth } from '../hooks/useApi';
import {
  Brain,
  Server,
  Radar,
  ShieldOff,
  CheckCircle2,
  XCircle,
  Loader2,
} from 'lucide-react';

function Dot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full shrink-0 ${
        ok ? 'bg-status-success' : 'bg-status-error'
      }`}
    />
  );
}

function SettingRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 border-b border-border-subtle last:border-0">
      <span className="text-xs text-text-secondary">{label}</span>
      <span
        className={`text-xs text-text-primary text-right ${mono ? 'font-mono' : ''}`}
      >
        {value}
      </span>
    </div>
  );
}

function Card({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border-subtle bg-bg-secondary">
      <div className="flex items-center gap-2.5 px-5 py-4 border-b border-border-subtle">
        <Icon size={16} strokeWidth={1.8} className="text-text-tertiary shrink-0" />
        <h2 className="text-sm font-semibold text-text-primary tracking-wide">
          {title}
        </h2>
      </div>
      <div className="px-5 py-3">{children}</div>
    </section>
  );
}

export function SettingsPage() {
  const { data: status, isLoading: statusLoading } = useStatus();
  const { data: health, isLoading: healthLoading } = useHealth();

  const isLoading = statusLoading || healthLoading;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 size={24} className="animate-spin text-text-tertiary" />
      </div>
    );
  }

  const sys = status?.system;
  const scans = status?.scans;

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">
          Einstellungen
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Systemkonfiguration und Status (schreibgeschuetzt)
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* LLM Provider */}
        <Card title="LLM Provider" icon={Brain}>
          <SettingRow
            label="Provider"
            value={sys?.llm_provider ?? '--'}
            mono
          />
          <SettingRow
            label="Modell"
            value={health?.provider ?? sys?.llm_provider ?? '--'}
            mono
          />
          <SettingRow
            label="Verbindung"
            value={
              <span className="inline-flex items-center gap-1.5">
                <Dot ok={!!health?.status} />
                <span>{health?.status === 'ok' ? 'Verbunden' : 'Getrennt'}</span>
              </span>
            }
          />
          <SettingRow
            label="OpenShell"
            value={
              <span className="inline-flex items-center gap-1.5">
                <Dot ok={!!sys?.openshell_available} />
                <span>{sys?.openshell_available ? 'Installiert' : 'Nicht installiert'}</span>
              </span>
            }
          />
        </Card>

        {/* System Info */}
        <Card title="System Info" icon={Server}>
          <SettingRow
            label="SentinelClaw Version"
            value={sys?.version ?? health?.version ?? '--'}
            mono
          />
          <SettingRow
            label="Docker"
            value={
              <span className="inline-flex items-center gap-1.5">
                <Dot ok={!!sys?.docker} />
                <span className="font-mono">{sys?.docker || 'Nicht verfuegbar'}</span>
              </span>
            }
          />
          <SettingRow
            label="Sandbox Container"
            value={
              <span className="inline-flex items-center gap-1.5">
                <Dot ok={!!(sys?.sandbox_running ?? health?.sandbox_running)} />
                <span>
                  {(sys?.sandbox_running ?? health?.sandbox_running)
                    ? 'Aktiv'
                    : 'Inaktiv'}
                </span>
              </span>
            }
          />
          <SettingRow
            label="NemoClaw Runtime"
            value={
              <span className="inline-flex items-center gap-1.5">
                <Dot ok={!!sys?.nemoclaw_available} />
                <span>{sys?.nemoclaw_available ? `Verbunden${sys?.nemoclaw_version ? ` (${sys.nemoclaw_version})` : ''}` : 'Nicht erreichbar'}</span>
              </span>
            }
          />
          <SettingRow
            label="Datenbank"
            value={
              <span className="inline-flex items-center gap-1.5">
                <Dot ok={!!health?.db_connected} />
                <span>{health?.db_connected ? 'Verbunden' : 'Getrennt'}</span>
              </span>
            }
          />
        </Card>

        {/* Scan Configuration */}
        <Card title="Scan-Konfiguration" icon={Radar}>
          <SettingRow
            label="Laufende Scans"
            value={scans?.running ?? 0}
          />
          <SettingRow
            label="Scans insgesamt"
            value={scans?.total ?? 0}
          />
          <SettingRow
            label="Status"
            value={
              <span className="inline-flex items-center gap-1.5">
                {(scans?.running ?? 0) > 0 ? (
                  <>
                    <span className="h-2 w-2 rounded-full bg-status-running animate-pulse" />
                    <span>Scans aktiv</span>
                  </>
                ) : (
                  <>
                    <span className="h-2 w-2 rounded-full bg-text-tertiary" />
                    <span>Bereit</span>
                  </>
                )}
              </span>
            }
          />
        </Card>

        {/* Kill Switch Status */}
        <Card title="Kill Switch" icon={ShieldOff}>
          <SettingRow
            label="Status"
            value={
              sys?.kill_switch_active ? (
                <span className="inline-flex items-center gap-1.5 text-severity-critical">
                  <XCircle size={13} />
                  <span className="font-semibold">AKTIV</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-status-success">
                  <CheckCircle2 size={13} />
                  <span>Inaktiv</span>
                </span>
              )
            }
          />
          {sys?.kill_switch_active && (
            <>
              <SettingRow
                label="Auswirkung"
                value="Alle Scans gestoppt"
              />
              <div className="mt-2 rounded-md bg-severity-critical/10 border border-severity-critical/20 px-3 py-2.5">
                <p className="text-xs text-severity-critical leading-relaxed">
                  Der Notaus-Schalter ist aktiviert. Alle laufenden Scans wurden
                  gestoppt und neue Scans koennen nicht gestartet werden, bis der
                  Schalter zurueckgesetzt wird.
                </p>
              </div>
            </>
          )}
          {!sys?.kill_switch_active && (
            <SettingRow
              label="Beschreibung"
              value="Kein Notaus aktiv"
            />
          )}
        </Card>
      </div>
    </div>
  );
}
