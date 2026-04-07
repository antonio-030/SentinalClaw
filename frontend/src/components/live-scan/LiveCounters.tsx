import { Monitor, Wifi, Bug, Clock } from 'lucide-react';

// ── Props-Interface für die Live-Zähler ────────────────────────────
interface LiveCountersProps {
  totalHosts: number;
  totalPorts: number;
  totalFindings: number;
  elapsed: string;
}

/**
 * Vier Zähler-Karten für den Live-Scan:
 * Hosts, offene Ports, Findings und Laufzeit.
 */
export function LiveCounters({ totalHosts, totalPorts, totalFindings, elapsed }: LiveCountersProps) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
        <Monitor size={16} className="mx-auto mb-1.5 text-text-tertiary" strokeWidth={1.8} />
        <p className="text-2xl font-semibold text-text-primary tabular-nums">{totalHosts}</p>
        <p className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">Hosts</p>
      </div>
      <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
        <Wifi size={16} className="mx-auto mb-1.5 text-text-tertiary" strokeWidth={1.8} />
        <p className="text-2xl font-semibold text-text-primary tabular-nums">{totalPorts}</p>
        <p className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">Offene Ports</p>
      </div>
      <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
        <Bug size={16} className="mx-auto mb-1.5 text-text-tertiary" strokeWidth={1.8} />
        <p className="text-2xl font-semibold text-text-primary tabular-nums">{totalFindings}</p>
        <p className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">Findings</p>
      </div>
      <div className="rounded-lg border border-border-subtle bg-bg-secondary p-4 text-center">
        <Clock size={16} className="mx-auto mb-1.5 text-text-tertiary" strokeWidth={1.8} />
        <p className="text-2xl font-semibold text-text-primary tabular-nums font-mono">
          {elapsed}
        </p>
        <p className="text-[10px] text-text-tertiary uppercase tracking-wider mt-1">Laufzeit</p>
      </div>
    </div>
  );
}
