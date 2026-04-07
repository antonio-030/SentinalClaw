import { useState, useMemo } from 'react';
import { GitCompare, Loader2, Plus, Minus, Equal, AlertCircle } from 'lucide-react';
import { useScans } from '../hooks/useApi';
import { api } from '../services/api';
import { formatDate } from '../utils/format';
import type { Scan, CompareResult } from '../types/api';

export function ComparePage() {
  const { data: scans = [], isLoading, isError: isScansError, error: scansError, refetch } = useScans();
  const [scanIdA, setScanIdA] = useState('');
  const [scanIdB, setScanIdB] = useState('');
  const [result, setResult] = useState<CompareResult | null>(null);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const completedScans = useMemo(
    () =>
      (scans as Scan[])
        .filter((s) => s.status === 'completed')
        .sort((a, b) => new Date(b.completed_at!).getTime() - new Date(a.completed_at!).getTime()),
    [scans],
  );

  async function handleCompare() {
    if (!scanIdA || !scanIdB) return;
    setComparing(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.scans.compare({ scan_id_a: scanIdA, scan_id_b: scanIdB });
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Comparison failed');
    } finally {
      setComparing(false);
    }
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      </div>
    );
  }

  if (isScansError) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-severity-critical/10 mb-4">
          <AlertCircle className="h-6 w-6 text-severity-critical" />
        </div>
        <h2 className="text-sm font-semibold text-text-primary mb-1">Fehler beim Laden</h2>
        <p className="text-xs text-text-tertiary max-w-sm mb-4">
          {(scansError as Error | null)?.message || 'Unbekannter Fehler'}
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
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">Compare Scans</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Compare two scans to identify new, fixed, and unchanged findings
        </p>
      </div>

      {/* Scan Selectors */}
      <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5 space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Scan A */}
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1.5">
              Scan A (Baseline)
            </label>
            <select
              value={scanIdA}
              onChange={(e) => setScanIdA(e.target.value)}
              className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30"
            >
              <option value="">-- Select baseline scan --</option>
              {completedScans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.target} &mdash; {formatDate(scan.completed_at)}
                </option>
              ))}
            </select>
          </div>

          {/* Scan B */}
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1.5">
              Scan B (New)
            </label>
            <select
              value={scanIdB}
              onChange={(e) => setScanIdB(e.target.value)}
              className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30"
            >
              <option value="">-- Select new scan --</option>
              {completedScans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.target} &mdash; {formatDate(scan.completed_at)}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleCompare}
            disabled={!scanIdA || !scanIdB || scanIdA === scanIdB || comparing}
            className="flex items-center gap-2 rounded-md bg-accent px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {comparing ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <GitCompare size={14} />
            )}
            Vergleichen
          </button>
          {scanIdA && scanIdB && scanIdA === scanIdB && (
            <span className="text-xs text-severity-high">
              Please select two different scans
            </span>
          )}
        </div>

        {error && (
          <p className="text-xs text-severity-critical">{error}</p>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* New Findings */}
          <Section
            title="New Findings"
            subtitle="Only in Scan B (new)"
            icon={<Plus size={14} />}
            color="text-status-success"
            bgColor="bg-status-success/5"
            borderColor="border-status-success/20"
            items={result.new_findings}
            renderItem={(f) => <FindingRow key={f.title + f.severity} finding={f} />}
          />

          {/* Fixed Findings */}
          <Section
            title="Fixed Findings"
            subtitle="Only in Scan A (resolved)"
            icon={<Minus size={14} />}
            color="text-status-success"
            bgColor="bg-status-success/5"
            borderColor="border-status-success/20"
            items={result.fixed_findings}
            renderItem={(f) => <FindingRow key={f.title + f.severity} finding={f} strikethrough />}
          />

          {/* Unchanged */}
          <Section
            title="Unchanged Findings"
            subtitle="Present in both scans"
            icon={<Equal size={14} />}
            color="text-text-tertiary"
            bgColor="bg-bg-tertiary/30"
            borderColor="border-border-subtle"
            items={result.unchanged_findings}
            renderItem={(f) => <FindingRow key={f.title + f.severity} finding={f} muted />}
          />

          {/* Port Changes */}
          {(result.new_ports.length > 0 || result.closed_ports.length > 0) && (
            <div className="rounded-lg border border-border-subtle bg-bg-secondary overflow-hidden">
              <div className="px-5 py-3 border-b border-border-subtle">
                <h3 className="text-sm font-semibold text-text-primary">Port Changes</h3>
              </div>
              <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* New Ports */}
                <div>
                  <p className="text-xs font-medium text-status-success mb-2">
                    New Ports ({result.new_ports.length})
                  </p>
                  {result.new_ports.length === 0 ? (
                    <p className="text-xs text-text-tertiary">None</p>
                  ) : (
                    <div className="space-y-1">
                      {result.new_ports.map((p) => (
                        <p key={`${p.host}:${p.port}`} className="text-xs font-mono text-text-primary">
                          {p.host}:{p.port}/{p.protocol}
                          {p.service && (
                            <span className="text-text-tertiary ml-2">({p.service})</span>
                          )}
                        </p>
                      ))}
                    </div>
                  )}
                </div>

                {/* Closed Ports */}
                <div>
                  <p className="text-xs font-medium text-severity-high mb-2">
                    Closed Ports ({result.closed_ports.length})
                  </p>
                  {result.closed_ports.length === 0 ? (
                    <p className="text-xs text-text-tertiary">None</p>
                  ) : (
                    <div className="space-y-1">
                      {result.closed_ports.map((p) => (
                        <p key={`${p.host}:${p.port}`} className="text-xs font-mono text-text-tertiary line-through">
                          {p.host}:{p.port}/{p.protocol}
                          {p.service && (
                            <span className="ml-2">({p.service})</span>
                          )}
                        </p>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty state when no comparison made yet */}
      {!result && !comparing && (
        <div className="rounded-lg border border-border-subtle bg-bg-secondary px-5 py-12 text-center">
          <GitCompare size={28} className="mx-auto mb-3 text-text-tertiary" strokeWidth={1.5} />
          <p className="text-sm text-text-tertiary">Select two scans and click Vergleichen</p>
          <p className="text-xs text-text-tertiary mt-1">
            The comparison will show new, fixed, and unchanged findings
          </p>
        </div>
      )}
    </div>
  );
}

// ── Helper Components ───────────────────────────────────────────────

interface SectionProps<T> {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  borderColor: string;
  items: T[];
  renderItem: (item: T, index: number) => React.ReactNode;
}

function Section<T>({ title, subtitle, icon, color, bgColor, borderColor, items = [] as unknown as T[], renderItem }: SectionProps<T>) {
  return (
    <div className={`rounded-lg border ${borderColor} ${bgColor} overflow-hidden`}>
      <div className="px-5 py-3 border-b border-border-subtle flex items-center gap-2">
        <span className={color}>{icon}</span>
        <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
        <span className="text-xs text-text-tertiary">({items.length})</span>
        <span className="text-xs text-text-tertiary ml-1">&mdash; {subtitle}</span>
      </div>
      {items.length === 0 ? (
        <p className="px-5 py-4 text-xs text-text-tertiary">None</p>
      ) : (
        <div className="divide-y divide-border-subtle">{items.map(renderItem)}</div>
      )}
    </div>
  );
}

interface CompareFinding {
  title: string;
  severity: string;
  cvss_score?: number;
  target_host?: string;
  target_port?: number | null;
}

function FindingRow({
  finding,
  strikethrough,
  muted,
}: {
  finding: CompareFinding;
  strikethrough?: boolean;
  muted?: boolean;
}) {
  const severityColors: Record<string, string> = {
    critical: 'text-severity-critical',
    high: 'text-severity-high',
    medium: 'text-severity-medium',
    low: 'text-severity-low',
    info: 'text-severity-info',
  };

  return (
    <div className={`px-5 py-3 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4 ${muted ? 'opacity-60' : ''}`}>
      <span
        className={`text-[10px] font-semibold uppercase tracking-wider w-16 shrink-0 ${
          severityColors[finding.severity] ?? 'text-text-secondary'
        }`}
      >
        {finding.severity}
      </span>
      <span
        className={`text-xs text-text-primary flex-1 ${strikethrough ? 'line-through' : ''}`}
      >
        {finding.title}
      </span>
      {finding.cvss_score != null && (
        <span className="text-[10px] text-text-tertiary tabular-nums">
          CVSS {finding.cvss_score.toFixed(1)}
        </span>
      )}
      {finding.target_host && (
        <span className="text-[10px] font-mono text-text-tertiary">
          {finding.target_host}
          {finding.target_port != null ? `:${finding.target_port}` : ''}
        </span>
      )}
    </div>
  );
}
