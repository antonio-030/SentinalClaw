import type { OpenPort } from '../../types/api';

// ── Props-Interface für die Ports-Tabelle ──────────────────────────
interface PortsTabProps {
  openPorts: OpenPort[];
}

/**
 * Tabelle der offenen Ports eines Scans.
 * Wird als Tab-Inhalt auf der Scan-Detailseite angezeigt.
 */
export function PortsTab({ openPorts }: PortsTabProps) {
  return (
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
            {openPorts.length === 0 && (
              <tr>
                <td colSpan={5} className="px-5 py-10 text-center text-xs text-text-tertiary">No open ports found</td>
              </tr>
            )}
            {openPorts.map((p: OpenPort, i: number) => (
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
  );
}
