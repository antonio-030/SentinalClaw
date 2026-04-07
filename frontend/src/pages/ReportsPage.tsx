import { useState, useMemo } from 'react';
import { FileText, ChevronDown, ChevronUp, Loader2, FileDown, Trash2, AlertCircle } from 'lucide-react';
import { useScans } from '../hooks/useApi';
import { api } from '../services/api';
import { showToast } from '../components/shared/NotificationToast';
import { formatDate } from '../utils/format';
import { MarkdownRenderer } from '../components/chat/MarkdownRenderer';
import { AgentReportsSection } from '../components/reports/AgentReportsSection';
import type { Scan } from '../types/api';

type ReportType = 'executive' | 'technical' | 'compliance';

interface ReportState {
  scanId: string;
  type: ReportType;
  content: string;
}

export function ReportsPage() {
  const { data: scans = [], isLoading, isError, error, refetch } = useScans();
  const [openReport, setOpenReport] = useState<ReportState | null>(null);
  const [loadingReport, setLoadingReport] = useState<string | null>(null);
  const [loadingPdf, setLoadingPdf] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const completedScans = useMemo(
    () =>
      (scans as Scan[])
        .filter((s) => s.status === 'completed')
        .sort((a, b) => new Date(b.completed_at!).getTime() - new Date(a.completed_at!).getTime()),
    [scans],
  );

  async function handleReport(scanId: string, type: ReportType) {
    const key = `${scanId}-${type}`;
    if (openReport?.scanId === scanId && openReport?.type === type) {
      setOpenReport(null);
      return;
    }
    setLoadingReport(key);
    try {
      const content = await api.scans.report(scanId, type);
      setOpenReport({ scanId, type, content });
    } catch (err) {
      setOpenReport({
        scanId, type,
        content: `Fehler: ${err instanceof Error ? err.message : 'Report konnte nicht geladen werden'}`,
      });
    } finally {
      setLoadingReport(null);
    }
  }

  async function handleDeleteScan(scanId: string, target: string) {
    if (!confirm(`Scan "${target}" und alle zugehörigen Reports wirklich löschen?`)) return;
    setDeletingId(scanId);
    try {
      await api.scans.delete(scanId);
      if (openReport?.scanId === scanId) setOpenReport(null);
      refetch();
      showToast('success', 'Scan gelöscht', target);
    } catch (err) {
      showToast('error', 'Löschen fehlgeschlagen',
        err instanceof Error ? err.message : 'Unbekannter Fehler');
    } finally {
      setDeletingId(null);
    }
  }

  async function handlePdfDownload(scanId: string, type: ReportType) {
    const key = `${scanId}-${type}-pdf`;
    setLoadingPdf(key);
    try {
      const blob = await api.scans.reportPdf(scanId, type);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentinelclaw-${type}-${scanId.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`PDF-Fehler: ${err instanceof Error ? err.message : 'Unbekannt'}`);
    } finally {
      setLoadingPdf(null);
    }
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      </div>
    );
  }

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
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">Reports</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Reports generieren, anzeigen und als PDF herunterladen
        </p>
      </div>

      <div className="space-y-3">
        {completedScans.length === 0 && (
          <div className="rounded-lg border border-border-subtle bg-bg-secondary px-5 py-12 text-center">
            <FileText size={28} className="mx-auto mb-3 text-text-tertiary" strokeWidth={1.5} />
            <p className="text-sm text-text-tertiary">Keine abgeschlossenen Scans vorhanden</p>
            <p className="text-xs text-text-tertiary mt-1">Starte einen Scan, um Reports zu generieren</p>
          </div>
        )}

        {/* Überschrift für Scan-Reports (nur wenn es auch Agent-Reports gibt) */}
        <div className="flex items-center gap-2">
          <FileText size={18} className="text-accent" strokeWidth={1.5} />
          <h2 className="text-lg font-semibold text-text-primary">Scan-Reports</h2>
        </div>

        {completedScans.map((scan) => {
          const isOpen = openReport?.scanId === scan.id;
          return (
            <div key={scan.id} className="rounded-lg border border-border-subtle bg-bg-secondary overflow-hidden">
              {/* Scan-Zeile */}
              <div className="flex flex-col sm:flex-row sm:items-center gap-3 px-5 py-4">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-mono text-text-primary truncate">{scan.target}</p>
                  <p className="text-xs text-text-tertiary mt-0.5">
                    {formatDate(scan.completed_at)} &middot; {scan.tokens_used.toLocaleString()} Tokens
                  </p>
                </div>

                {/* Report-Buttons + PDF + Löschen */}
                <div className="flex flex-col sm:flex-row gap-2 items-start sm:items-center">
                  {(['executive', 'technical', 'compliance'] as ReportType[]).map((type) => {
                    const key = `${scan.id}-${type}`;
                    const pdfKey = `${key}-pdf`;
                    const isActive = openReport?.scanId === scan.id && openReport?.type === type;
                    const labels: Record<ReportType, string> = {
                      executive: 'Executive',
                      technical: 'Technisch',
                      compliance: 'Compliance',
                    };
                    return (
                      <div key={type} className="flex gap-1">
                        {/* Anzeigen-Button */}
                        <button
                          onClick={() => handleReport(scan.id, type)}
                          disabled={loadingReport === key}
                          className={`flex items-center justify-center gap-1.5 rounded-l-md px-3 py-1.5 text-xs font-medium transition-colors ${
                            isActive
                              ? 'bg-accent text-white'
                              : 'border border-border-default text-text-secondary hover:text-text-primary hover:bg-bg-tertiary'
                          } disabled:opacity-40 disabled:cursor-not-allowed`}
                        >
                          {loadingReport === key ? (
                            <Loader2 size={12} className="animate-spin" />
                          ) : isActive ? (
                            <ChevronUp size={12} />
                          ) : (
                            <ChevronDown size={12} />
                          )}
                          {labels[type]}
                        </button>
                        {/* PDF-Download-Button */}
                        <button
                          onClick={() => handlePdfDownload(scan.id, type)}
                          disabled={loadingPdf === pdfKey}
                          title={`${labels[type]}-Report als PDF herunterladen`}
                          className="flex items-center justify-center rounded-r-md border border-l-0 border-border-default px-2 py-1.5 text-text-tertiary hover:text-accent hover:bg-accent/10 transition-colors disabled:opacity-40"
                        >
                          {loadingPdf === pdfKey ? (
                            <Loader2 size={12} className="animate-spin" />
                          ) : (
                            <FileDown size={12} />
                          )}
                        </button>
                      </div>
                    );
                  })}
                  {/* Löschen-Button */}
                  <button
                    onClick={() => handleDeleteScan(scan.id, scan.target)}
                    disabled={deletingId === scan.id}
                    title="Scan und Reports löschen"
                    className="flex items-center justify-center rounded-md border border-border-default px-2 py-1.5 text-text-tertiary hover:text-severity-critical hover:border-severity-critical/30 transition-colors disabled:opacity-40"
                    aria-label={`Scan ${scan.target} löschen`}
                  >
                    {deletingId === scan.id
                      ? <Loader2 size={12} className="animate-spin" />
                      : <Trash2 size={12} />}
                  </button>
                </div>
              </div>

              {/* Report-Inhalt */}
              {isOpen && openReport && (
                <div className="border-t border-border-subtle bg-bg-primary">
                  <div className="px-5 py-3 flex items-center justify-between border-b border-border-subtle">
                    <span className="text-xs font-medium text-text-secondary uppercase tracking-wider">
                      {openReport.type} Report
                    </span>
                    <button
                      onClick={() => setOpenReport(null)}
                      className="text-xs text-text-tertiary hover:text-text-secondary transition-colors"
                    >
                      Schließen
                    </button>
                  </div>
                  <div className="px-5 py-4 max-h-[60vh] overflow-y-auto">
                    <MarkdownRenderer content={openReport.content} />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Agent-Reports — automatisch gespeicherte Reports vom Chat-Agent */}
      <AgentReportsSection />
    </div>
  );
}
