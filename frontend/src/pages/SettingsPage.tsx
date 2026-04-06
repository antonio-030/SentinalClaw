import { useState } from 'react';
import { useStatus, useHealth, useSettings, useUpdateSettings } from '../hooks/useApi';
import {
  Brain,
  Server,
  Radar,
  ShieldOff,
  CheckCircle2,
  XCircle,
  Loader2,
  Timer,
  Bot,
  Box,
  ScanLine,
  Cpu,
  Save,
} from 'lucide-react';
import type { SystemSetting } from '../types/api';

// ── Hilfskomponenten ────────────────────────────────────────────────

function Dot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full shrink-0 ${
        ok ? 'bg-status-success' : 'bg-status-error'
      }`}
    />
  );
}

function StatusRow({ label, value, mono = false }: {
  label: string; value: React.ReactNode; mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 border-b border-border-subtle last:border-0">
      <span className="text-xs text-text-secondary">{label}</span>
      <span className={`text-xs text-text-primary text-right ${mono ? 'font-mono' : ''}`}>
        {value}
      </span>
    </div>
  );
}

function Card({ title, icon: Icon, children }: {
  title: string; icon: React.ElementType; children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border-subtle bg-bg-secondary">
      <div className="flex items-center gap-2.5 px-5 py-4 border-b border-border-subtle">
        <Icon size={16} strokeWidth={1.8} className="text-text-tertiary shrink-0" />
        <h2 className="text-sm font-semibold text-text-primary tracking-wide">{title}</h2>
      </div>
      <div className="px-5 py-3">{children}</div>
    </section>
  );
}

// ── Tab-Konfiguration ───────────────────────────────────────────────

const TABS = [
  { id: 'system', label: 'System', icon: Server },
  { id: 'tool_timeouts', label: 'Tool-Timeouts', icon: Timer },
  { id: 'agent', label: 'Agent', icon: Bot },
  { id: 'sandbox', label: 'Sandbox', icon: Box },
  { id: 'scan', label: 'Scan', icon: ScanLine },
  { id: 'llm', label: 'LLM', icon: Cpu },
] as const;

type TabId = (typeof TABS)[number]['id'];

// ── Einstellungs-Formular für eine Kategorie ────────────────────────

function SettingsCategoryForm({ settings, category }: {
  settings: SystemSetting[]; category: string;
}) {
  const filtered = settings.filter((s) => s.category === category);
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(filtered.map((s) => [s.key, s.value])),
  );
  const [saved, setSaved] = useState(false);
  const updateMutation = useUpdateSettings();

  function handleChange(key: string, val: string) {
    setValues((prev) => ({ ...prev, [key]: val }));
    setSaved(false);
  }

  async function handleSave() {
    // Nur geänderte Werte senden
    const changed: Record<string, string> = {};
    for (const s of filtered) {
      if (values[s.key] !== s.value) changed[s.key] = values[s.key];
    }
    if (Object.keys(changed).length === 0) { setSaved(true); return; }
    await updateMutation.mutateAsync(changed);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }

  if (filtered.length === 0) {
    return <p className="text-xs text-text-tertiary py-4">Keine Einstellungen in dieser Kategorie.</p>;
  }

  return (
    <div className="space-y-3">
      {filtered.map((s) => (
        <div key={s.key} className="rounded-md border border-border-subtle bg-bg-primary px-4 py-3">
          <label className="block text-xs font-medium text-text-primary mb-1">{s.label}</label>
          <p className="text-[10px] text-text-tertiary mb-2">{s.description}</p>
          <input
            type={s.value_type === 'int' || s.value_type === 'float' ? 'number' : 'text'}
            step={s.value_type === 'float' ? '0.1' : undefined}
            value={values[s.key] ?? ''}
            onChange={(e) => handleChange(s.key, e.target.value)}
            className="w-full rounded-md border border-border-default bg-bg-secondary px-3 py-1.5 text-xs text-text-primary font-mono focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
      ))}

      <div className="flex items-center gap-3 pt-2">
        <button
          onClick={handleSave}
          disabled={updateMutation.isPending}
          className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-2 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50 transition-colors"
        >
          {updateMutation.isPending ? (
            <Loader2 size={12} className="animate-spin" />
          ) : (
            <Save size={12} />
          )}
          Speichern
        </button>
        {saved && (
          <span className="flex items-center gap-1 text-xs text-status-success">
            <CheckCircle2 size={12} /> Gespeichert
          </span>
        )}
        {updateMutation.isError && (
          <span className="text-xs text-severity-critical">
            Fehler: {updateMutation.error?.message}
          </span>
        )}
      </div>
    </div>
  );
}

// ── System-Status-Tab (bisherige Anzeige) ───────────────────────────

function SystemTab() {
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

// ── Hauptseite ──────────────────────────────────────────────────────

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>('system');
  const { data: settings = [], isLoading } = useSettings();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 size={24} className="animate-spin text-text-tertiary" />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">Einstellungen</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Systemkonfiguration und Laufzeit-Parameter
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border-subtle overflow-x-auto">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium whitespace-nowrap border-b-2 transition-colors ${
                isActive
                  ? 'border-accent text-accent'
                  : 'border-transparent text-text-tertiary hover:text-text-secondary'
              }`}
            >
              <Icon size={13} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab-Inhalt */}
      {activeTab === 'system' ? (
        <SystemTab />
      ) : (
        <SettingsCategoryForm settings={settings} category={activeTab} />
      )}
    </div>
  );
}
