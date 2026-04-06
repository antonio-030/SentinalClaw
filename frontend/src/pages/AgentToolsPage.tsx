// ── Agent Tools — Security-Tool-Verwaltung fuer die OpenShell-Sandbox ────

import { useState } from 'react';
import { Package, Radar, AlertTriangle, Search, Wrench, Download, Trash2 } from 'lucide-react';
import { useAgentTools, useInstallTool, useUninstallTool } from '../hooks/useApi';
import { showToast } from '../components/shared/NotificationToast';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import type { ToolCategory } from '../types/api';

const CATEGORY_META: Record<string, { label: string; icon: typeof Package }> = {
  reconnaissance: { label: 'Reconnaissance', icon: Radar },
  vulnerability:  { label: 'Vulnerability',  icon: AlertTriangle },
  analysis:       { label: 'Analysis',       icon: Search },
  utility:        { label: 'Utility',        icon: Wrench },
};

const TABS: { key: ToolCategory | 'all'; label: string }[] = [
  { key: 'all',             label: 'Alle' },
  { key: 'reconnaissance',  label: 'Recon' },
  { key: 'vulnerability',   label: 'Vuln' },
  { key: 'analysis',        label: 'Analyse' },
  { key: 'utility',         label: 'Utility' },
];

export function AgentToolsPage() {
  const { data: tools, isLoading } = useAgentTools();
  const installMut = useInstallTool();
  const uninstallMut = useUninstallTool();
  const [filter, setFilter] = useState<ToolCategory | 'all'>('all');
  const [busyTool, setBusyTool] = useState<string | null>(null);

  const filtered = tools?.filter(
    (t) => filter === 'all' || t.category === filter,
  );

  async function handleInstall(name: string) {
    setBusyTool(name);
    try {
      const res = await installMut.mutateAsync(name);
      showToast('success', `${name} installiert`, `Dauer: ${res.duration_seconds}s`);
    } catch (err) {
      showToast('error', 'Installation fehlgeschlagen',
        err instanceof Error ? err.message : 'Unbekannter Fehler');
    } finally {
      setBusyTool(null);
    }
  }

  async function handleUninstall(name: string) {
    setBusyTool(name);
    try {
      await uninstallMut.mutateAsync(name);
      showToast('success', `${name} deinstalliert`);
    } catch (err) {
      showToast('error', 'Deinstallation fehlgeschlagen',
        err instanceof Error ? err.message : 'Unbekannter Fehler');
    } finally {
      setBusyTool(null);
    }
  }

  const installed  = tools?.filter((t) => t.installed).length  ?? 0;
  const total      = tools?.length ?? 0;

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">
            Agent Tools
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            Security-Tools in der OpenShell-Sandbox verwalten
          </p>
        </div>
        <div className="shrink-0 rounded-lg bg-bg-secondary border border-border-subtle px-3 py-2 text-center">
          <p className="text-2xl font-semibold tabular-nums text-text-primary">{installed}/{total}</p>
          <p className="text-[10px] text-text-tertiary uppercase tracking-wider">Installiert</p>
        </div>
      </div>

      {/* Kategorie-Tabs */}
      <div className="flex gap-1 rounded-lg bg-bg-secondary border border-border-subtle p-1">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setFilter(tab.key)}
            className={`flex-1 rounded-md px-3 py-2 text-xs font-medium transition-colors ${
              filter === tab.key
                ? 'bg-accent/15 text-accent border border-accent/30'
                : 'text-text-secondary hover:text-text-primary hover:bg-bg-tertiary border border-transparent'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tool-Liste */}
      {isLoading ? (
        <div className="flex justify-center py-16">
          <LoadingSpinner size="lg" />
        </div>
      ) : (
        <div className="space-y-2">
          {filtered?.map((tool) => {
            const meta = CATEGORY_META[tool.category];
            const Icon = meta?.icon ?? Package;
            const busy = busyTool === tool.name;

            return (
              <div
                key={tool.name}
                className="flex items-center gap-4 rounded-lg border border-border-subtle bg-bg-secondary px-5 py-4 hover:bg-bg-tertiary/30 transition-colors"
              >
                {/* Icon + Status-Dot */}
                <div className="relative shrink-0">
                  <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-bg-tertiary">
                    <Icon size={17} strokeWidth={1.8} className="text-text-secondary" />
                  </div>
                  <span className={`absolute -top-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-bg-secondary ${
                    tool.installed ? 'bg-status-success' : 'bg-text-tertiary'
                  }`} />
                </div>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-text-primary">{tool.display_name}</span>
                    <span className="text-[10px] text-text-tertiary uppercase tracking-wider">
                      {meta?.label}
                    </span>
                  </div>
                  <p className="text-xs text-text-secondary mt-0.5 truncate">{tool.description}</p>
                  {tool.installed && tool.check_output && (
                    <p className="text-[10px] font-mono text-text-tertiary mt-1 truncate">
                      {tool.check_output.split('\n')[0]}
                    </p>
                  )}
                </div>

                {/* Aktion */}
                <div className="shrink-0">
                  {tool.preinstalled ? (
                    <span className="text-[10px] text-text-tertiary uppercase tracking-wider">
                      Basis
                    </span>
                  ) : tool.installed ? (
                    <button
                      onClick={() => handleUninstall(tool.name)}
                      disabled={busy}
                      className="inline-flex items-center gap-1.5 rounded-md border border-border-default px-3 py-1.5 text-xs text-text-secondary hover:border-status-error/40 hover:text-status-error transition-colors disabled:opacity-40"
                    >
                      {busy ? <LoadingSpinner size="sm" /> : <Trash2 size={13} />}
                      Entfernen
                    </button>
                  ) : (
                    <button
                      onClick={() => handleInstall(tool.name)}
                      disabled={busy}
                      className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/85 active:scale-95 transition-all disabled:opacity-40"
                    >
                      {busy ? <LoadingSpinner size="sm" /> : <Download size={13} />}
                      Installieren
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
