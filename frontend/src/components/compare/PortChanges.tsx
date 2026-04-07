// Anzeige der Port-Änderungen zwischen zwei Scans

import type { ComparePort } from '../../types/api';

interface PortChangesProps {
  newPorts: ComparePort[];
  closedPorts: ComparePort[];
}

/** Zeigt neue und geschlossene Ports im Vergleich zweier Scans */
export function PortChanges({ newPorts, closedPorts }: PortChangesProps) {
  if (newPorts.length === 0 && closedPorts.length === 0) return null;

  return (
    <div className="rounded-lg border border-border-subtle bg-bg-secondary overflow-hidden">
      <div className="px-5 py-3 border-b border-border-subtle">
        <h3 className="text-sm font-semibold text-text-primary">Port Changes</h3>
      </div>
      <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Neue Ports */}
        <div>
          <p className="text-xs font-medium text-status-success mb-2">
            New Ports ({newPorts.length})
          </p>
          {newPorts.length === 0 ? (
            <p className="text-xs text-text-tertiary">None</p>
          ) : (
            <div className="space-y-1">
              {newPorts.map((p) => (
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

        {/* Geschlossene Ports */}
        <div>
          <p className="text-xs font-medium text-severity-high mb-2">
            Closed Ports ({closedPorts.length})
          </p>
          {closedPorts.length === 0 ? (
            <p className="text-xs text-text-tertiary">None</p>
          ) : (
            <div className="space-y-1">
              {closedPorts.map((p) => (
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
  );
}
