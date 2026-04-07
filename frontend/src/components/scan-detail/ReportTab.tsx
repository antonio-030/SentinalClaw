// ── Props-Interface für den Report-Tab ─────────────────────────────
interface ReportTabProps {
  reportHtml: string | null;
}

/**
 * Anzeige des generierten Reports.
 * Zeigt entweder den HTML-Report oder einen Platzhalter-Hinweis.
 */
export function ReportTab({ reportHtml }: ReportTabProps) {
  return (
    <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
      {reportHtml ? (
        <pre className="text-sm text-text-secondary whitespace-pre-wrap font-mono p-4 bg-bg-primary rounded-lg border border-border-subtle overflow-x-auto">
          {reportHtml}
        </pre>
      ) : (
        <p className="text-xs text-text-tertiary">Click &quot;Report generieren&quot; to generate a technical report.</p>
      )}
    </div>
  );
}
