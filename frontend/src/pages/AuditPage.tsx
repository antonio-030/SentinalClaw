import { ScrollText, AlertCircle } from 'lucide-react';
import { useAudit } from '../hooks/useApi';
import { formatDate } from '../utils/format';
import type { AuditEntry } from '../types/api';

function actionColor(action: string) {
  if (action.includes('kill') || action.includes('delete')) return 'text-severity-critical';
  if (action.includes('create') || action.includes('start')) return 'text-status-success';
  if (action.includes('cancel') || action.includes('stop')) return 'text-severity-high';
  return 'text-text-primary';
}

export function AuditPage() {
  const { data: entries = [], isLoading, isError, error, refetch } = useAudit();

  if (isLoading) return <div className="flex justify-center py-16"><div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" /></div>;

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-severity-critical/10 mb-4">
          <AlertCircle className="h-6 w-6 text-severity-critical" />
        </div>
        <h2 className="text-sm font-semibold text-text-primary mb-1">Fehler beim Laden</h2>
        <p className="text-xs text-text-tertiary max-w-sm mb-4">
          {(error as Error | null)?.message || 'Unbekannter Fehler'}
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
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">Audit Log</h1>
        <p className="mt-1 text-sm text-text-secondary">Complete record of all system actions and events</p>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border-subtle bg-bg-secondary overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-subtle text-left">
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Timestamp</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Action</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Triggered By</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Resource</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {entries.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-5 py-12 text-center">
                    <ScrollText size={28} className="mx-auto mb-3 text-text-tertiary" strokeWidth={1.5} />
                    <p className="text-sm text-text-tertiary">No audit entries</p>
                    <p className="text-xs text-text-tertiary mt-1">System events will appear here</p>
                  </td>
                </tr>
              )}
              {entries.map((entry: AuditEntry) => (
                <tr key={entry.id} className="hover:bg-bg-tertiary/30 transition-colors">
                  <td className="px-5 py-3.5 text-xs text-text-tertiary tabular-nums font-mono whitespace-nowrap">
                    {formatDate(entry.created_at)}
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`text-xs font-semibold tracking-wide ${actionColor(entry.action)}`}>
                      {entry.action}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-xs text-text-secondary">
                    {entry.triggered_by}
                  </td>
                  <td className="px-5 py-3.5 text-xs text-text-secondary font-mono">
                    {entry.resource_type
                      ? `${entry.resource_type}${entry.resource_id ? ` #${entry.resource_id.slice(0, 8)}` : ''}`
                      : '--'}
                  </td>
                  <td className="px-5 py-3.5 text-xs text-text-tertiary max-w-xs truncate">
                    {Object.keys(entry.details).length > 0
                      ? JSON.stringify(entry.details)
                      : '--'}
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
