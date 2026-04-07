import { useMemo } from 'react';
import { Radar, AlertTriangle, ShieldAlert, Activity, AlertCircle } from 'lucide-react';
import { useStatus, useScans, useFindings } from '../hooks/useApi';
import { MetricCard } from '../components/shared/MetricCard';
import { StatusBadge } from '../components/shared/StatusBadge';
import { SeverityBadge } from '../components/shared/SeverityBadge';
import { SeverityChart } from '../components/dashboard/SeverityChart';
import { SystemHealth } from '../components/dashboard/SystemHealth';
import { SecurityLayers } from '../components/dashboard/SecurityLayers';
import { formatDateShort, compareSeverity } from '../utils/format';
import type { Scan, Finding } from '../types/api';

export function DashboardPage() {
  const { data: status, isLoading: isLoadingStatus, isError: isStatusError, error: statusError, refetch: refetchStatus } = useStatus();

  const { data: scans = [], isLoading: isLoadingScans, isError: isScansError, error: scansError, refetch: refetchScans } = useScans();

  const { data: findings = [], isLoading: isLoadingFindings, isError: isFindingsError, error: findingsError, refetch: refetchFindings } = useFindings();

  const isLoading = isLoadingStatus || isLoadingScans || isLoadingFindings;
  const isError = isStatusError || isScansError || isFindingsError;
  const firstError = statusError || scansError || findingsError;

  const runningScans = status?.scans.running ?? 0;
  const criticalFindings = findings.filter((f: Finding) => f.severity === 'critical').length;
  const systemOnline = !!status;

  const recentScans = useMemo(() =>
    [...scans].sort(
      (a: Scan, b: Scan) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    ).slice(0, 5),
    [scans]
  );

  const recentFindings = useMemo(() =>
    [...findings].sort(
      (a: Finding, b: Finding) => compareSeverity(a.severity, b.severity),
    ).slice(0, 5),
    [findings]
  );

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" />
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
          {(firstError as Error | null)?.message || 'Unbekannter Fehler'}
        </p>
        <button
          onClick={() => { refetchStatus(); refetchScans(); refetchFindings(); }}
          className="inline-flex items-center gap-1.5 rounded-md bg-accent/10 border border-accent/30 px-3.5 py-2 text-xs font-medium text-accent hover:bg-accent/20 transition-colors"
        >
          Erneut versuchen
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">Dashboard</h1>
        <p className="mt-1 text-sm text-text-secondary">System overview and recent activity</p>
      </div>

      {/* Metric cards — 2 Spalten auf Mobile, 4 auf Desktop */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <MetricCard
          label="Laufende Scans"
          value={runningScans}
          icon={Radar}
          color="text-accent"
          iconColor="text-accent"
        />
        <MetricCard
          label="Findings gesamt"
          value={findings.length}
          icon={AlertTriangle}
          color="text-severity-medium"
          iconColor="text-severity-medium"
        />
        <MetricCard
          label="Kritische Findings"
          value={criticalFindings}
          icon={ShieldAlert}
          color="text-severity-critical"
          iconColor="text-severity-critical"
        />
        <MetricCard
          label="System-Status"
          value={systemOnline ? 'Online' : 'Offline'}
          icon={Activity}
          color={systemOnline ? 'text-status-success' : 'text-status-error'}
          iconColor={systemOnline ? 'text-status-success' : 'text-status-error'}
        />
      </div>

      {/* Tables row */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <section className="rounded-lg border border-border-subtle bg-bg-secondary">
          <div className="px-5 py-4 border-b border-border-subtle">
            <h2 className="text-sm font-semibold text-text-primary tracking-wide">Recent Scans</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border-subtle text-left">
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Status</th>
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Target</th>
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Type</th>
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {recentScans.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-5 py-8 text-center text-sm text-text-tertiary">
                      Noch keine Scans
                    </td>
                  </tr>
                )}
                {recentScans.map((scan: Scan) => (
                  <tr key={scan.id} className="hover:bg-bg-tertiary/30 transition-colors">
                    <td className="px-5 py-3">
                      <StatusBadge status={scan.status} compact />
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-text-primary">{scan.target}</td>
                    <td className="px-5 py-3 text-xs text-text-secondary">{scan.scan_type}</td>
                    <td className="px-5 py-3 text-xs text-text-tertiary tabular-nums">{formatDateShort(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Recent Findings */}
        <section className="rounded-lg border border-border-subtle bg-bg-secondary">
          <div className="px-5 py-4 border-b border-border-subtle">
            <h2 className="text-sm font-semibold text-text-primary tracking-wide">Recent Findings</h2>
          </div>
          <div className="divide-y divide-border-subtle">
            {recentFindings.length === 0 && (
              <div className="px-5 py-8 text-center text-sm text-text-tertiary">
                Noch keine Findings
              </div>
            )}
            {recentFindings.map((finding: Finding) => (
              <div key={finding.id} className="flex items-center gap-4 px-5 py-3 hover:bg-bg-tertiary/30 transition-colors">
                <SeverityBadge severity={finding.severity} />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-text-primary truncate">{finding.title}</p>
                  <p className="text-xs text-text-tertiary font-mono mt-0.5">
                    {finding.target_host}
                    {finding.target_port ? `:${finding.target_port}` : ''}
                  </p>
                </div>
                {finding.cvss_score > 0 && (
                  <span className="text-xs font-medium text-text-secondary tabular-nums">
                    CVSS {finding.cvss_score.toFixed(1)}
                  </span>
                )}
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Dritte Reihe: Severity-Verteilung + System-Health */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <section className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
          <h2 className="text-sm font-semibold text-text-primary tracking-wide mb-4">Severity-Verteilung</h2>
          <SeverityChart findings={findings} />
        </section>

        <section className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
          <h2 className="text-sm font-semibold text-text-primary tracking-wide mb-4">System-Health</h2>
          <SystemHealth />
        </section>
      </div>

      {/* Vierte Reihe: Sicherheitsschichten-Visualisierung */}
      <section className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
        <SecurityLayers />
      </section>
    </div>
  );
}
