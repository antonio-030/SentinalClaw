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
  Shield,
  Eye,
  Layers,
  Database,
  AlertCircle,
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
  { id: 'security', label: 'Sicherheit', icon: Shield },
  { id: 'watchdog', label: 'Watchdog', icon: Eye },
  { id: 'phases', label: 'Phasen', icon: Layers },
  { id: 'nemoclaw', label: 'NemoClaw', icon: Brain },
  { id: 'backup', label: 'Backup', icon: Database },
  { id: 'dsgvo', label: 'DSGVO', icon: Shield },
] as const;

type TabId = (typeof TABS)[number]['id'];

// ── Kategorie-Beschreibungen + Doku-Links ──────────────────────────

interface CategoryInfo {
  title: string;
  description: string;
  links?: Array<{ url: string; label: string }>;
}

const CATEGORY_INFO: Record<string, CategoryInfo> = {
  agent: {
    title: 'Agent-Konfiguration',
    description: 'Steuert was der AI-Agent darf: erlaubte/blockierte Binaries, maximale Eskalationsstufe, '
      + 'Genehmigungsschwelle für gefährliche Tools, verbotene Aktionen (DoS, Ransomware), und ob der Agent selbst Tools installieren darf. '
      + 'Änderungen wirken sofort auf den nächsten Agent-Aufruf.',
  },
  nemoclaw: {
    title: 'NemoClaw / OpenShell Sandbox',
    description: 'Konfiguration der NemoClaw-Sandbox in der der Agent isoliert läuft. '
      + 'Diese Einstellungen basieren auf den NVIDIA NemoClaw Security Best Practices: '
      + 'Prozess-Limits (Fork-Bomb-Schutz), Read-Only Dateisystem, Capability-Drops, '
      + 'Credential-Isolation (API-Keys werden nie an die Sandbox übergeben), und Netzwerk-Policy.',
    links: [
      { url: 'https://docs.nvidia.com/nemoclaw/latest/security/best-practices.html', label: 'Security Best Practices' },
      { url: 'https://docs.nvidia.com/nemoclaw/latest/deployment/sandbox-hardening.html', label: 'Sandbox Hardening' },
      { url: 'https://docs.nvidia.com/nemoclaw/latest/network-policy/customize-network-policy.html', label: 'Network Policy' },
      { url: 'https://docs.nvidia.com/nemoclaw/latest/reference/commands.html', label: 'CLI-Referenz' },
      { url: 'https://docs.nvidia.com/nemoclaw/latest/inference/inference-options.html', label: 'Inference-Provider' },
    ],
  },
  security: {
    title: 'Authentifizierung & Sicherheit',
    description: 'JWT-Token-Lebensdauer, Cookie-Konfiguration, Session-Inaktivitäts-Timeout, '
      + 'MFA-Einstellungen und API-Rate-Limits. Alle Authentifizierungsparameter die bestimmen '
      + 'wie lange Sessions gültig sind und wie viele Anfragen pro Minute erlaubt sind.',
  },
  sandbox: {
    title: 'Docker Sandbox-Ressourcen',
    description: 'Ressourcen-Limits für den Docker-Sandbox-Container: Arbeitsspeicher (RAM), '
      + 'CPU-Kerne, maximale Prozessanzahl (PID-Limit) und Timeout. Diese Werte begrenzen '
      + 'was ein einzelner Scan maximal verbrauchen kann.',
  },
  llm: {
    title: 'LLM / AI-Provider',
    description: 'Token-Budgets und Timeouts für den AI-Provider. Das Token-Budget pro Scan verhindert '
      + 'unkontrollierte Kosten — bei 80% wird gewarnt, bei 100% wird der Scan gestoppt. '
      + 'Das monatliche Limit schützt vor Kostenexplosion.',
  },
  tool_timeouts: {
    title: 'Tool-Timeouts',
    description: 'Maximale Laufzeit pro Security-Tool in Sekunden. Wenn ein Tool länger braucht, '
      + 'wird es abgebrochen. Verhindert hängende Prozesse in der Sandbox.',
  },
  watchdog: {
    title: 'Watchdog-Überwachung',
    description: 'Der Watchdog ist ein unabhängiger Prozess der alle N Sekunden prüft ob '
      + 'die Anwendung gesund ist. Nach mehreren fehlgeschlagenen Health-Checks wird der Kill-Switch '
      + 'automatisch aktiviert. Auch die maximale Scan-Dauer wird hier überwacht.',
  },
  scan: {
    title: 'Scan-Konfiguration',
    description: 'Allgemeine Scan-Parameter: Wie viele Scans gleichzeitig laufen dürfen '
      + 'und welcher Port-Bereich standardmäßig gescannt wird wenn kein Profil gewählt ist.',
  },
  phases: {
    title: 'Scan-Phasen-Timeouts',
    description: 'Jeder Scan durchläuft mehrere Phasen (Host-Discovery, Port-Scan, Vulnerability-Scan, Report). '
      + 'Hier wird die maximale Dauer pro Phase konfiguriert.',
  },
  dsgvo: {
    title: 'DSGVO / Datenschutz',
    description: 'Datenschutz-Einstellungen gemäß DSGVO: Aufbewahrungsfristen für Scan-Daten '
      + '(ältere Scans werden automatisch gelöscht) und AVV-Warnung wenn der AI-Provider '
      + 'Daten in die USA überträgt (z.B. bei Claude/Anthropic).',
  },
  backup: {
    title: 'Backup & Wiederherstellung',
    description: 'Automatische Backups werden bei jedem Server-Start erstellt. '
      + 'Ältere Backups werden nach der konfigurierten Frist automatisch gelöscht. '
      + 'Manuelle Backups können über System → Backup ausgelöst werden.',
  },
};

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

  const info = CATEGORY_INFO[category];

  return (
    <div className="space-y-3">
      {/* Kategorie-Info mit Beschreibung + optionalem Doku-Link */}
      {info && (
        <div className="rounded-lg border border-accent/20 bg-accent/5 px-4 py-3 mb-4">
          <p className="text-xs font-medium text-accent mb-1">{info.title}</p>
          <p className="text-[11px] text-text-secondary leading-relaxed">{info.description}</p>
          {info.links && info.links.length > 0 && (
            <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
              {info.links.map((link) => (
                <a
                  key={link.url}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-[11px] text-accent hover:text-accent-hover transition-colors"
                >
                  <svg viewBox="0 0 16 16" fill="currentColor" className="w-3 h-3 shrink-0"><path d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/><path d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/></svg>
                  {link.label}
                </a>
              ))}
            </div>
          )}
        </div>
      )}

      {filtered.map((s) => (
        <div key={s.key} className="rounded-md border border-border-subtle bg-bg-primary px-4 py-3">
          <label className="block text-xs font-medium text-text-primary mb-1">{s.label}</label>
          <p className="text-[10px] text-text-tertiary mb-2">{s.description}</p>
          {s.value_type === 'boolean' ? (
            <button
              type="button"
              onClick={() => handleChange(s.key, values[s.key] === 'true' ? 'false' : 'true')}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${
                values[s.key] === 'true' ? 'bg-accent' : 'bg-border-default'
              }`}
              role="switch"
              aria-checked={values[s.key] === 'true'}
              aria-label={s.label}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-sm transition-transform ${
                  values[s.key] === 'true' ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          ) : (
            <input
              type={s.value_type === 'int' || s.value_type === 'float' ? 'number' : 'text'}
              step={s.value_type === 'float' ? '0.1' : undefined}
              value={values[s.key] ?? ''}
              onChange={(e) => handleChange(s.key, e.target.value)}
              className="w-full rounded-md border border-border-default bg-bg-secondary px-3 py-1.5 text-xs text-text-primary font-mono focus:outline-none focus:ring-1 focus:ring-accent"
            />
          )}
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
  const { data: settings = [], isLoading, isError, error, refetch } = useSettings();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 size={24} className="animate-spin text-text-tertiary" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-severity-critical/10 mb-4">
          <AlertCircle className="h-6 w-6 text-severity-critical" />
        </div>
        <h2 className="text-sm font-semibold text-text-primary mb-1">Fehler beim Laden</h2>
        <p className="text-xs text-text-tertiary max-w-sm mb-4">
          {(error as Error | null)?.message || 'Unbekannter Fehler'}
        </p>
        <button
          onClick={() => refetch()}
          className="inline-flex items-center gap-1.5 rounded-md bg-accent/10 border border-accent/30 px-3.5 py-2 text-xs font-medium text-accent hover:bg-accent/20 transition-colors"
        >
          Erneut versuchen
        </button>
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
