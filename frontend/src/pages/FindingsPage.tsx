import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { useFindings } from '../hooks/useApi';
import { SeverityBadge } from '../components/shared/SeverityBadge';
import { CvssScore } from '../components/shared/CvssScore';
import { compareSeverity } from '../utils/format';
import type { Finding, Severity } from '../types/api';

const severityTabs: Array<{ label: string; value: string }> = [
  { label: 'Alle', value: '' },
  { label: 'Kritisch', value: 'critical' },
  { label: 'Hoch', value: 'high' },
  { label: 'Mittel', value: 'medium' },
  { label: 'Niedrig', value: 'low' },
];

export function FindingsPage() {
  const navigate = useNavigate();
  const [activeFilter, setActiveFilter] = useState('');

  const { data: findings = [], isLoading } = useFindings(activeFilter || undefined);

  const sorted = useMemo(() =>
    [...findings].sort((a: Finding, b: Finding) => {
      const diff = compareSeverity(a.severity, b.severity);
      if (diff !== 0) return diff;
      return b.cvss_score - a.cvss_score;
    }),
    [findings]
  );

  if (isLoading) return <div className="flex justify-center py-16"><div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" /></div>;

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">Findings</h1>
        <p className="mt-1 text-sm text-text-secondary">Vulnerabilities and security issues discovered across scans</p>
      </div>

      {/* Filter tabs */}
      <div className="flex items-center gap-1 p-1 rounded-lg bg-bg-secondary border border-border-subtle w-fit">
        {severityTabs.map((tab) => (
          <button
            key={tab.value}
            onClick={() => setActiveFilter(tab.value)}
            className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors ${
              activeFilter === tab.value
                ? 'bg-bg-tertiary text-text-primary shadow-sm'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border-subtle bg-bg-secondary overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-subtle text-left">
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Severity</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Title</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Host:Port</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">CVE</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider text-right">CVSS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-5 py-12 text-center">
                    <AlertTriangle size={28} className="mx-auto mb-3 text-text-tertiary" strokeWidth={1.5} />
                    <p className="text-sm text-text-tertiary">Keine Findings</p>
                    <p className="text-xs text-text-tertiary mt-1">
                      {activeFilter ? `Keine ${activeFilter}-Findings gefunden` : 'Starte einen Scan um Schwachstellen zu finden'}
                    </p>
                  </td>
                </tr>
              )}
              {sorted.map((finding: Finding) => (
                <tr key={finding.id} className="hover:bg-bg-tertiary/30 transition-colors cursor-pointer" onClick={() => navigate(`/findings/${finding.id}`)} tabIndex={0} role="link" onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/findings/${finding.id}`); }}>
                  <td className="px-5 py-3.5">
                    <SeverityBadge severity={finding.severity as Severity} />
                  </td>
                  <td className="px-5 py-3.5 text-sm text-text-primary max-w-xs truncate">
                    {finding.title}
                  </td>
                  <td className="px-5 py-3.5 font-mono text-xs text-text-secondary">
                    {finding.target_host}
                    {finding.target_port ? `:${finding.target_port}` : ''}
                  </td>
                  <td className="px-5 py-3.5 font-mono text-xs text-text-secondary">
                    {finding.cve_id ?? '--'}
                  </td>
                  <td className="px-5 py-3.5 text-right">
                    <CvssScore score={finding.cvss_score} compact />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
