// ── Generischer Wrapper für React-Query-States ──────────────────────
// Kapselt Loading-, Error-, Empty- und Erfolgs-Zustände zentral,
// damit jede Seite konsistentes Fehler-Handling bekommt.

import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { AlertCircle, Inbox } from 'lucide-react';
import { LoadingSpinner } from './LoadingSpinner';

interface QueryWrapperProps<T> {
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  data: T | undefined;
  refetch: () => void;
  /** Icon für den leeren Zustand */
  emptyIcon?: LucideIcon;
  /** Überschrift für den leeren Zustand */
  emptyTitle?: string;
  /** Beschreibungstext für den leeren Zustand */
  emptyDescription?: string;
  /** Prüfung ob Daten als "leer" gelten — Standard: Array.length === 0 */
  isEmpty?: (data: T) => boolean;
  /** Render-Funktion die aufgerufen wird wenn Daten vorhanden sind */
  children: (data: T) => ReactNode;
}

/**
 * Zeigt je nach Query-Status:
 * - Ladeindikator (isLoading)
 * - Fehler-UI mit Retry-Button (isError)
 * - Leerer Zustand (data leer)
 * - children(data) wenn Daten vorhanden
 */
export function QueryWrapper<T>({
  isLoading,
  isError,
  error,
  data,
  refetch,
  emptyIcon: EmptyIcon = Inbox,
  emptyTitle = 'Keine Daten vorhanden',
  emptyDescription,
  isEmpty,
  children,
}: QueryWrapperProps<T>) {
  // Ladezustand
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  // Fehlerzustand mit Retry-Möglichkeit
  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-severity-critical/10 mb-4">
          <AlertCircle className="h-6 w-6 text-severity-critical" />
        </div>
        <h2 className="text-sm font-semibold text-text-primary mb-1">
          Fehler beim Laden
        </h2>
        <p className="text-xs text-text-tertiary max-w-sm mb-4">
          {error?.message || 'Ein unbekannter Fehler ist aufgetreten'}
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

  // Leerer Zustand — prüfe ob Daten leer sind
  const dataIsEmpty = data === undefined
    || data === null
    || (isEmpty ? isEmpty(data) : Array.isArray(data) && data.length === 0);

  if (dataIsEmpty && data !== undefined) {
    return (
      <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-bg-tertiary mb-4">
          <EmptyIcon size={24} className="text-text-tertiary" />
        </div>
        <h3 className="text-sm font-medium text-text-primary mb-1">{emptyTitle}</h3>
        {emptyDescription && (
          <p className="text-xs text-text-tertiary max-w-sm">{emptyDescription}</p>
        )}
      </div>
    );
  }

  // Daten vorhanden — Render-Funktion aufrufen
  if (data !== undefined) {
    return <>{children(data)}</>;
  }

  return null;
}
