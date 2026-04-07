// Seite zum Vergleichen zweier Scan-Ergebnisse

import { useState, useMemo } from 'react';
import { GitCompare, Loader2, Plus, Minus, Equal, AlertCircle } from 'lucide-react';
import { useScans } from '../hooks/useApi';
import { api } from '../services/api';
import { formatDate } from '../utils/format';
import type { Scan, CompareResult } from '../types/api';
import { CompareSection } from '../components/compare/CompareSection';
import { FindingRow } from '../components/compare/FindingRow';
import { PortChanges } from '../components/compare/PortChanges';

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
      {/* Seitenüberschrift */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">Compare Scans</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Compare two scans to identify new, fixed, and unchanged findings
        </p>
      </div>

      {/* Scan-Auswahl */}
      <ScanSelector
        completedScans={completedScans}
        scanIdA={scanIdA}
        scanIdB={scanIdB}
        onSelectA={setScanIdA}
        onSelectB={setScanIdB}
        onCompare={handleCompare}
        comparing={comparing}
        error={error}
      />

      {/* Ergebnisse */}
      {result && <CompareResults result={result} />}

      {/* Leerzustand wenn noch kein Vergleich durchgeführt */}
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

// ── Scan-Auswahl-Bereich ────────────────────────────────────────────

interface ScanSelectorProps {
  completedScans: Scan[];
  scanIdA: string;
  scanIdB: string;
  onSelectA: (id: string) => void;
  onSelectB: (id: string) => void;
  onCompare: () => void;
  comparing: boolean;
  error: string | null;
}

function ScanSelector({
  completedScans, scanIdA, scanIdB, onSelectA, onSelectB, onCompare, comparing, error,
}: ScanSelectorProps) {
  return (
    <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5 space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-text-secondary mb-1.5">
            Scan A (Baseline)
          </label>
          <select
            value={scanIdA}
            onChange={(e) => onSelectA(e.target.value)}
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
        <div>
          <label className="block text-xs font-medium text-text-secondary mb-1.5">
            Scan B (New)
          </label>
          <select
            value={scanIdB}
            onChange={(e) => onSelectB(e.target.value)}
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
          onClick={onCompare}
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
  );
}

// ── Vergleichsergebnisse ────────────────────────────────────────────

interface CompareResultsProps {
  result: CompareResult;
}

function CompareResults({ result }: CompareResultsProps) {
  return (
    <div className="space-y-4">
      <CompareSection
        title="New Findings"
        subtitle="Only in Scan B (new)"
        icon={<Plus size={14} />}
        color="text-status-success"
        bgColor="bg-status-success/5"
        borderColor="border-status-success/20"
        items={result.new_findings}
        renderItem={(f) => <FindingRow key={f.title + f.severity} finding={f} />}
      />

      <CompareSection
        title="Fixed Findings"
        subtitle="Only in Scan A (resolved)"
        icon={<Minus size={14} />}
        color="text-status-success"
        bgColor="bg-status-success/5"
        borderColor="border-status-success/20"
        items={result.fixed_findings}
        renderItem={(f) => <FindingRow key={f.title + f.severity} finding={f} strikethrough />}
      />

      <CompareSection
        title="Unchanged Findings"
        subtitle="Present in both scans"
        icon={<Equal size={14} />}
        color="text-text-tertiary"
        bgColor="bg-bg-tertiary/30"
        borderColor="border-border-subtle"
        items={result.unchanged_findings}
        renderItem={(f) => <FindingRow key={f.title + f.severity} finding={f} muted />}
      />

      <PortChanges newPorts={result.new_ports} closedPorts={result.closed_ports} />
    </div>
  );
}
