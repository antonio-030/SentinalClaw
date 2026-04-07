import { useNavigate } from 'react-router-dom';
import { SeverityBadge } from '../shared/SeverityBadge';
import { CvssScore } from '../shared/CvssScore';
import type { Finding, Severity } from '../../types/api';

// ── Props-Interface für die Findings-Tabelle ───────────────────────
interface FindingsTabProps {
  findings: Finding[];
}

/**
 * Tabelle der Findings eines Scans.
 * Jede Zeile ist klickbar und navigiert zur Finding-Detailseite.
 */
export function FindingsTab({ findings }: FindingsTabProps) {
  const navigate = useNavigate();

  return (
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
  );
}
