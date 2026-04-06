// ── Detailpanel für ausgewählte Sicherheitsschicht ──────────────────

import type { ReactNode } from 'react';

export interface LayerData {
  name: string;
  description: string;
  icon: ReactNode;
  active: boolean;
  color: string;
  details: string[];
}

interface LayerDetailPanelProps {
  layer: LayerData | null;
}

export function LayerDetailPanel({ layer }: LayerDetailPanelProps) {
  if (!layer) {
    return (
      <div className="rounded-xl border border-border-subtle bg-bg-secondary/60 backdrop-blur-sm p-6 flex flex-col items-center justify-center min-h-[320px]">
        <div className="w-10 h-10 rounded-full border border-border-default flex items-center justify-center mb-3">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <circle cx="8" cy="8" r="6" stroke="#5A6478" strokeWidth="1.5" strokeDasharray="3 3" />
            <circle cx="8" cy="8" r="2" fill="#5A6478" />
          </svg>
        </div>
        <p className="text-xs text-text-tertiary text-center">
          Ring anklicken um<br />Schicht-Details anzuzeigen
        </p>
      </div>
    );
  }

  return (
    <div
      className="rounded-xl border border-border-subtle bg-bg-secondary/60 backdrop-blur-sm overflow-hidden"
      style={{ animation: 'detail-fade-in 0.3s ease-out' }}
    >
      {/* Farbiger Oberkanten-Streifen */}
      <div className="h-1" style={{ background: layer.color }} />

      <div className="p-5">
        {/* Header */}
        <div className="flex items-start gap-3 mb-4">
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: `${layer.color}15`, color: layer.color }}
          >
            {layer.icon}
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-text-primary leading-tight">
              {layer.name}
            </h3>
            <span
              className="inline-flex items-center gap-1 mt-1 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full"
              style={{
                background: layer.active ? '#22C55E18' : '#EF444418',
                color: layer.active ? '#22C55E' : '#EF4444',
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{
                  background: layer.active ? '#22C55E' : '#EF4444',
                  boxShadow: `0 0 6px ${layer.active ? '#22C55E' : '#EF4444'}`,
                }}
              />
              {layer.active ? 'AKTIV' : 'INAKTIV'}
            </span>
          </div>
        </div>

        {/* Beschreibung */}
        <p className="text-xs text-text-secondary leading-relaxed mb-4">
          {layer.description}
        </p>

        {/* Sub-Features */}
        <div className="space-y-1.5">
          <p className="text-[10px] font-medium text-text-tertiary uppercase tracking-wider mb-2">
            Komponenten
          </p>
          {layer.details.map((detail, i) => (
            <div
              key={detail}
              className="flex items-center gap-2.5 py-1.5 px-2.5 rounded-md bg-bg-primary/60 border border-border-subtle/50"
              style={{ animation: `detail-fade-in 0.3s ease-out ${0.05 * (i + 1)}s both` }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{
                  background: layer.active ? '#22C55E' : '#EF4444',
                  boxShadow: layer.active ? '0 0 4px #22C55E60' : 'none',
                }}
              />
              <span className="text-[11px] font-mono text-text-primary">{detail}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
