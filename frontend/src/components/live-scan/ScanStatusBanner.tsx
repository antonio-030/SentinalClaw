import { Link } from 'react-router-dom';
import { CheckCircle2, OctagonX } from 'lucide-react';

// ── Props-Interface für das Status-Banner ──────────────────────────
interface ScanStatusBannerProps {
  status: string;
  scanId: string;
  elapsed: string;
  totalHosts: number;
  totalPorts: number;
  totalFindings: number;
}

/**
 * Zeigt ein kontextabhängiges Banner je nach Scan-Status:
 * - Laufend: Animierte Punkte + Laufzeit
 * - Abgeschlossen: Zusammenfassung mit Link zu den Details
 * - Fehlgeschlagen: Fehlermeldung
 */
export function ScanStatusBanner({
  status,
  scanId,
  elapsed,
  totalHosts,
  totalPorts,
  totalFindings,
}: ScanStatusBannerProps) {
  const isRunning = status === 'running' || status === 'pending';

  return (
    <>
      {isRunning && (
        <div className="rounded-lg border border-accent/30 bg-accent/5 p-3 flex items-center gap-3">
          <span className="flex gap-0.5 shrink-0">
            <span className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
            <span className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
            <span className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
          </span>
          <div>
            <p className="text-sm font-medium text-text-primary">Scan läuft — {elapsed}</p>
            <p className="text-xs text-text-secondary">Agent führt Phasen autonom aus. Die Seite aktualisiert sich alle 3 Sekunden.</p>
          </div>
        </div>
      )}

      {status === 'completed' && (
        <div className="rounded-lg border border-status-success/30 bg-status-success/5 p-3 flex items-center gap-3">
          <CheckCircle2 size={18} className="text-status-success shrink-0" />
          <div>
            <p className="text-sm font-medium text-text-primary">Scan abgeschlossen</p>
            <p className="text-xs text-text-secondary">{totalHosts} Hosts, {totalPorts} Ports, {totalFindings} Findings in {elapsed}</p>
          </div>
          <Link to={`/scans/${scanId}`} className="ml-auto text-xs text-accent hover:underline shrink-0">Details &rarr;</Link>
        </div>
      )}

      {status === 'failed' && (
        <div className="rounded-lg border border-status-error/30 bg-status-error/5 p-3 flex items-center gap-3">
          <OctagonX size={18} className="text-status-error shrink-0" />
          <div>
            <p className="text-sm font-medium text-text-primary">Scan fehlgeschlagen</p>
            <p className="text-xs text-text-secondary">Einige Phasen konnten nicht abgeschlossen werden.</p>
          </div>
        </div>
      )}
    </>
  );
}
