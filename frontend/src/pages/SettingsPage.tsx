// Hauptseite für Systemeinstellungen mit Tab-Navigation

import { useState } from 'react';
import { useSettings } from '../hooks/useApi';
import {
  Brain,
  Server,
  Timer,
  Bot,
  Box,
  ScanLine,
  Cpu,
  Shield,
  Eye,
  Layers,
  Database,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { NemoClawSetupWizard } from '../components/settings/NemoClawSetupWizard';
import { SystemTab } from '../components/settings/SystemTab';
import { SettingsCategoryForm } from '../components/settings/SettingsCategoryForm';

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
        <>
          {/* Setup-Wizard oberhalb der NemoClaw-Einstellungen */}
          {activeTab === 'nemoclaw' && <NemoClawSetupWizard />}
          <SettingsCategoryForm settings={settings} category={activeTab} />
        </>
      )}
    </div>
  );
}
