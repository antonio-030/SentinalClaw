import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, FileText, Download, Trash2, XCircle } from 'lucide-react';
import { useScan } from '../hooks/useApi';
import { api } from '../services/api';
import { showToast } from '../components/shared/NotificationToast';
import { SeverityBadge } from '../components/shared/SeverityBadge';
import { StatusBadge } from '../components/shared/StatusBadge';
import { CvssScore } from '../components/shared/CvssScore';
import { formatDate } from '../utils/format';
import type { Finding, OpenPort, ScanPhase, Severity } from '../types/api';

type Tab = 'ports' | 'findings' | 'report';

function phaseIcon(status: string) {
  switch (status) {
    case 'completed': return '\u2705';
    case 'running':   return '\u23F3';
    case 'failed':    return '\u274C';
    default:          return '\u26AA';
  }
}

function duration(start: string | null, end: string | null): string {
  if (!start) return '--';
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const secs = Math.round((e - s) / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ${secs % 60}s`;
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useScan(id ?? '');
  const [activeTab, setActiveTab] = useState<Tab>('ports');
  const [reportHtml, setReportHtml] = useState<string | null>(null);

  const deleteMutation = useMutation({
    mutationFn: () => api.scans.delete(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      showToast('success', 'Scan gelöscht');
      navigate('/scans');
    },
    onError: (err: Error) => {
      showToast('error', 'Löschen fehlgeschlagen', err.message);
    },
  });

  const cancelMutation = useMutation({
    mutationFn: () => api.scans.cancel(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', id] });
      showToast('success', 'Scan abgebrochen');
    },
    onError: (err: Error) => {
      showToast('error', 'Abbrechen fehlgeschlagen', err.message);
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="space-y-4 max-w-7xl">
        <Link to="/scans" className="inline-flex items-center gap-1.5 text-xs text-text-secondary hover:text-text-primary transition-colors">
          <ArrowLeft size={14} /> Back to Scans
        </Link>
        <p className="text-sm text-severity-critical">Failed to load scan details.</p>
      </div>
    );
  }

  const { scan, phases, findings, open_ports } = data;

  async function handleReport() {
    try {
      const html = await api.scans.report(id!, 'technical');
      setReportHtml(html);
      setActiveTab('report');
    } catch {
      alert('Report generation failed.');
    }
  }

  async function handleExport() {
    try {
      const blob = await api.scans.export(id!);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-${id}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('CSV export failed.');
    }
  }

  function handleDelete() {
    if (window.confirm('Scan wirklich loeschen? Diese Aktion kann nicht rueckgaengig gemacht werden.')) {
      deleteMutation.mutate();
    }
  }

  function handleCancel() {
    if (window.confirm('Laufenden Scan wirklich abbrechen?')) {
      cancelMutation.mutate();
    }
  }

  const tabs: Array<{ key: Tab; label: string; count?: number }> = [
    { key: 'ports', label: 'Open Ports', count: open_ports.length },
    { key: 'findings', label: 'Findings', count: findings.length },
    { key: 'report', label: 'Report' },
  ];

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Back link */}
      <Link to="/scans" className="inline-flex items-center gap-1.5 text-xs text-text-secondary hover:text-text-primary transition-colors">
        <ArrowLeft size={14} /> Back to Scans
      </Link>

      {/* Header card */}
      <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="space-y-1">
            <h1 className="text-lg font-semibold text-text-primary font-mono">{scan.target}</h1>
            <div className="flex flex-wrap items-center gap-3 text-xs text-text-secondary">
              <StatusBadge status={scan.status} compact />
              <span>{scan.scan_type}</span>
              <span>{duration(scan.started_at, scan.completed_at)}</span>
              <span>{scan.tokens_used.toLocaleString()} tokens</span>
              <span>{formatDate(scan.created_at)}</span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button onClick={handleReport} className="inline-flex items-center gap-1.5 rounded-md border border-border-subtle bg-bg-tertiary px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary transition-colors">
              <FileText size={13} /> Report generieren
            </button>
            <button onClick={handleExport} className="inline-flex items-center gap-1.5 rounded-md border border-border-subtle bg-bg-tertiary px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary transition-colors">
              <Download size={13} /> Export CSV
            </button>
            {scan.status === 'running' && (
              <button onClick={handleCancel} disabled={cancelMutation.isPending} className="inline-flex items-center gap-1.5 rounded-md border border-severity-medium/30 bg-severity-medium/10 px-3 py-1.5 text-xs font-medium text-severity-medium hover:bg-severity-medium/20 transition-colors">
                <XCircle size={13} /> Abbrechen
              </button>
            )}
            <button onClick={handleDelete} disabled={deleteMutation.isPending} className="inline-flex items-center gap-1.5 rounded-md border border-severity-critical/30 bg-severity-critical/10 px-3 py-1.5 text-xs font-medium text-severity-critical hover:bg-severity-critical/20 transition-colors">
              <Trash2 size={13} /> Scan loeschen
            </button>
          </div>
        </div>
      </div>

      {/* Phase Timeline */}
      <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-4">Phase Timeline</h2>
        <div className="space-y-0">
          {phases.map((phase: ScanPhase, idx: number) => (
            <div key={phase.id} className="flex gap-4">
              {/* Vertical line + icon */}
              <div className="flex flex-col items-center">
                <span className="text-base leading-none">{phaseIcon(phase.status)}</span>
                {idx < phases.length - 1 && (
                  <div className="w-px flex-1 bg-border-subtle my-1" />
                )}
              </div>
              {/* Content */}
              <div className="pb-4 min-w-0">
                <p className="text-sm font-medium text-text-primary">
                  Phase {phase.phase_number}: {phase.name}
                </p>
                <div className="flex flex-wrap gap-3 mt-1 text-xs text-text-tertiary">
                  <span>{phase.duration_seconds}s</span>
                  {phase.hosts_found > 0 && <span>{phase.hosts_found} hosts</span>}
                  {phase.ports_found > 0 && <span>{phase.ports_found} ports</span>}
                  {phase.findings_found > 0 && <span>{phase.findings_found} findings</span>}
                </div>
              </div>
            </div>
          ))}
          {phases.length === 0 && (
            <p className="text-xs text-text-tertiary">No phases recorded yet.</p>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 p-1 rounded-lg bg-bg-secondary border border-border-subtle w-fit">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors ${
              activeTab === tab.key
                ? 'bg-bg-tertiary text-text-primary shadow-sm'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span className="ml-1.5 text-text-tertiary">{tab.count}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'ports' && (
        <div className="rounded-lg border border-border-subtle bg-bg-secondary overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border-subtle text-left">
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Host</th>
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Port</th>
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Protocol</th>
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Service</th>
                  <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {open_ports.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-5 py-10 text-center text-xs text-text-tertiary">No open ports found</td>
                  </tr>
                )}
                {open_ports.map((p: OpenPort, i: number) => (
                  <tr key={`${p.host}-${p.port}-${i}`} className="hover:bg-bg-tertiary/30 transition-colors">
                    <td className="px-5 py-3 font-mono text-xs text-text-primary">{p.host}</td>
                    <td className="px-5 py-3 font-mono text-xs text-text-primary">{p.port}</td>
                    <td className="px-5 py-3 text-xs text-text-secondary">{p.protocol}</td>
                    <td className="px-5 py-3 text-xs text-text-secondary">{p.service ?? '--'}</td>
                    <td className="px-5 py-3 text-xs text-text-secondary">{p.version ?? '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'findings' && (
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
                {findings.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-5 py-10 text-center text-xs text-text-tertiary">No findings for this scan</td>
                  </tr>
                )}
                {findings.map((f: Finding) => (
                  <tr
                    key={f.id}
                    className="hover:bg-bg-tertiary/30 transition-colors cursor-pointer"
                    onClick={() => navigate(`/findings/${f.id}`)}
                    tabIndex={0}
                    role="link"
                    onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/findings/${f.id}`); }}
                  >
                    <td className="px-5 py-3.5">
                      <SeverityBadge severity={f.severity as Severity} />
                    </td>
                    <td className="px-5 py-3.5 text-sm text-text-primary max-w-xs truncate">{f.title}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-text-secondary">
                      {f.target_host}{f.target_port ? `:${f.target_port}` : ''}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-xs text-text-secondary">{f.cve_id ?? '--'}</td>
                    <td className="px-5 py-3.5 text-right">
                      <CvssScore score={f.cvss_score} compact />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'report' && (
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
          {reportHtml ? (
            <pre className="text-sm text-text-secondary whitespace-pre-wrap font-mono p-4 bg-bg-primary rounded-lg border border-border-subtle overflow-x-auto">
              {reportHtml}
            </pre>
          ) : (
            <p className="text-xs text-text-tertiary">Click "Report generieren" to generate a technical report.</p>
          )}
        </div>
      )}
    </div>
  );
}
