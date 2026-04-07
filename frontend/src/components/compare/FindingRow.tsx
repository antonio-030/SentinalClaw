// Einzelne Zeile für ein Finding im Scan-Vergleich

import type { CompareFinding } from '../../types/api';

/** Schweregrad-Farbzuordnung für die Anzeige */
const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-severity-critical',
  high: 'text-severity-high',
  medium: 'text-severity-medium',
  low: 'text-severity-low',
  info: 'text-severity-info',
};

interface FindingRowProps {
  finding: CompareFinding;
  strikethrough?: boolean;
  muted?: boolean;
}

/** Zeigt ein Finding mit Schweregrad, Titel, CVSS und Ziel-Adresse */
export function FindingRow({ finding, strikethrough, muted }: FindingRowProps) {
  return (
    <div className={`px-5 py-3 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4 ${muted ? 'opacity-60' : ''}`}>
      <span
        className={`text-[10px] font-semibold uppercase tracking-wider w-16 shrink-0 ${
          SEVERITY_COLORS[finding.severity] ?? 'text-text-secondary'
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
