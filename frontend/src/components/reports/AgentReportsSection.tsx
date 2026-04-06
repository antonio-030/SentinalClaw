// ── Agent-Reports Abschnitt für die Reports-Seite ──────────────────
//
// Zeigt vom Agent automatisch gespeicherte Reports (OSINT, Vulnerability, etc.)
// mit Typ-Badge, Target und Datum. Klick öffnet den Report als Markdown.

import { useState } from 'react';
import { Bot, ChevronDown, ChevronUp, Loader2 } from 'lucide-react';
import { useAgentReports } from '../../hooks/useApi';
import { api } from '../../services/api';
import { formatDate } from '../../utils/format';
import { MarkdownRenderer } from '../chat/MarkdownRenderer';
import type { AgentReport, AgentReportDetail } from '../../types/api';

// Farben für die Report-Typ-Badges
const REPORT_TYPE_STYLES: Record<string, string> = {
  osint: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  vulnerability: 'bg-red-500/15 text-red-400 border-red-500/30',
  compliance: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  executive: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
};

// Labels für die Report-Typen
const REPORT_TYPE_LABELS: Record<string, string> = {
  osint: 'OSINT',
  vulnerability: 'Vulnerability',
  compliance: 'Compliance',
  executive: 'Executive',
};

function ReportTypeBadge({ type }: { type: string }) {
  const style = REPORT_TYPE_STYLES[type] ?? 'bg-gray-500/15 text-gray-400 border-gray-500/30';
  const label = REPORT_TYPE_LABELS[type] ?? type;
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${style}`}>
      {label}
    </span>
  );
}

export function AgentReportsSection() {
  const { data: reports = [], isLoading } = useAgentReports();
  const [openReportId, setOpenReportId] = useState<string | null>(null);
  const [reportDetail, setReportDetail] = useState<AgentReportDetail | null>(null);
  const [loadingId, setLoadingId] = useState<string | null>(null);

  async function handleToggleReport(reportId: string) {
    // Zuklappen wenn bereits offen
    if (openReportId === reportId) {
      setOpenReportId(null);
      setReportDetail(null);
      return;
    }

    setLoadingId(reportId);
    try {
      const detail = await api.agentReports.get(reportId);
      setReportDetail(detail);
      setOpenReportId(reportId);
    } catch (err) {
      setReportDetail({
        id: reportId, title: 'Fehler', report_type: 'unknown',
        content: `Fehler: ${err instanceof Error ? err.message : 'Report konnte nicht geladen werden'}`,
        target: '', created_at: '',
      });
      setOpenReportId(reportId);
    } finally {
      setLoadingId(null);
    }
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-8">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Überschrift */}
      <div className="flex items-center gap-2">
        <Bot size={18} className="text-accent" strokeWidth={1.5} />
        <h2 className="text-lg font-semibold text-text-primary">Agent-Reports</h2>
        <span className="text-xs text-text-tertiary">({(reports as AgentReport[]).length})</span>
      </div>

      {(reports as AgentReport[]).length === 0 && (
        <div className="rounded-lg border border-border-subtle bg-bg-secondary px-5 py-8 text-center">
          <Bot size={24} className="mx-auto mb-2 text-text-tertiary" strokeWidth={1.5} />
          <p className="text-sm text-text-tertiary">Keine Agent-Reports vorhanden</p>
          <p className="text-xs text-text-tertiary mt-1">
            Reports werden automatisch gespeichert wenn der Agent strukturierte Berichte erstellt
          </p>
        </div>
      )}

      {(reports as AgentReport[]).map((report) => {
        const isOpen = openReportId === report.id;
        return (
          <div key={report.id} className="rounded-lg border border-border-subtle bg-bg-secondary overflow-hidden">
            {/* Report-Zeile */}
            <button
              onClick={() => handleToggleReport(report.id)}
              disabled={loadingId === report.id}
              className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-bg-tertiary/50 transition-colors disabled:opacity-60"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="text-sm font-medium text-text-primary truncate">{report.title}</p>
                  <ReportTypeBadge type={report.report_type} />
                </div>
                <p className="text-xs text-text-tertiary mt-0.5">
                  {report.target && <span className="font-mono">{report.target} &middot; </span>}
                  {formatDate(report.created_at)}
                </p>
              </div>
              {loadingId === report.id ? (
                <Loader2 size={14} className="animate-spin text-text-tertiary shrink-0" />
              ) : isOpen ? (
                <ChevronUp size={14} className="text-text-tertiary shrink-0" />
              ) : (
                <ChevronDown size={14} className="text-text-tertiary shrink-0" />
              )}
            </button>

            {/* Report-Inhalt */}
            {isOpen && reportDetail && reportDetail.id === report.id && (
              <div className="border-t border-border-subtle bg-bg-primary">
                <div className="px-5 py-3 flex items-center justify-between border-b border-border-subtle">
                  <span className="text-xs font-medium text-text-secondary uppercase tracking-wider">
                    {REPORT_TYPE_LABELS[report.report_type] ?? report.report_type} Report
                  </span>
                  <button
                    onClick={() => { setOpenReportId(null); setReportDetail(null); }}
                    className="text-xs text-text-tertiary hover:text-text-secondary transition-colors"
                  >
                    Schließen
                  </button>
                </div>
                <div className="px-5 py-4 max-h-[60vh] overflow-y-auto">
                  <MarkdownRenderer content={reportDetail.content} />
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
