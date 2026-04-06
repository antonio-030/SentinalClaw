// ── Live-Activity-Feed — Terminal-Style Log-Stream ──────────────────

import { useEffect, useRef } from 'react';

// ── Typen ───────────────────────────────────────────────────────────

export interface AgentStep {
  type: 'thinking' | 'tool_start' | 'tool_result' | 'log';
  tool?: string;
  command?: string;
  message?: string;
  success?: boolean;
  output_preview?: string;
  duration_ms?: number;
  iteration?: number;
  total_tools?: number;
}

interface AgentActivityFeedProps {
  steps: AgentStep[];
  elapsedSeconds: number;
}

// ── Log-Zeile im Terminal-Style ─────────────────────────────────────

function LogLine({ step, index }: { step: AgentStep; index: number }) {
  const time = new Date().toLocaleTimeString('de-DE', {
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });

  if (step.type === 'tool_start') {
    return (
      <div className="flex gap-2 animate-fade-in font-mono text-[11px] leading-relaxed">
        <span className="text-text-tertiary shrink-0">{time}</span>
        <span className="text-accent">{'>'}</span>
        <span className="text-accent truncate">
          {step.command ?? step.tool ?? 'tool'}
        </span>
      </div>
    );
  }

  if (step.type === 'tool_result') {
    const color = step.success !== false ? 'text-status-success' : 'text-severity-critical';
    const icon = step.success !== false ? '✓' : '✗';
    return (
      <div className="flex gap-2 animate-fade-in font-mono text-[11px] leading-relaxed">
        <span className="text-text-tertiary shrink-0">{time}</span>
        <span className={color}>{icon}</span>
        <span className={`${color} truncate`}>
          {step.output_preview ?? (step.success !== false ? 'OK' : 'Fehler')}
        </span>
      </div>
    );
  }

  if (step.type === 'thinking') {
    return (
      <div className="flex gap-2 animate-fade-in font-mono text-[11px] leading-relaxed">
        <span className="text-text-tertiary shrink-0">{time}</span>
        <span className="text-severity-medium animate-pulse">●</span>
        <span className="text-text-secondary">
          {step.message ?? 'Agent denkt nach...'}
        </span>
      </div>
    );
  }

  // log — allgemeine Log-Zeile
  return (
    <div className="flex gap-2 animate-fade-in font-mono text-[11px] leading-relaxed">
      <span className="text-text-tertiary shrink-0">{time}</span>
      <span className="text-text-tertiary">│</span>
      <span className="text-text-tertiary truncate">
        {step.message ?? ''}
      </span>
    </div>
  );
}

// ── Hauptkomponente ─────────────────────────────────────────────────

export function AgentActivityFeed({ steps, elapsedSeconds }: AgentActivityFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-Scroll bei neuen Steps
  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [steps.length]);

  // Nur die letzten 50 Zeilen zeigen
  const visibleSteps = steps.slice(-50);

  return (
    <div className="flex justify-start">
      <div className="bg-bg-primary border border-border-subtle rounded-lg w-full overflow-hidden">
        {/* Header */}
        <div className="flex items-center gap-2 px-3 py-2 bg-bg-secondary border-b border-border-subtle">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-accent" />
          </span>
          <span className="text-[11px] font-semibold text-accent">
            Agent arbeitet
          </span>
          <span className="text-[10px] text-text-tertiary tabular-nums font-mono ml-auto">
            {elapsedSeconds}s
          </span>
        </div>

        {/* Terminal-Log */}
        <div className="px-3 py-2 max-h-52 overflow-y-auto space-y-0.5 bg-[#0a0c10]">
          {visibleSteps.length === 0 && (
            <div className="font-mono text-[11px] text-text-tertiary animate-pulse">
              Verbinde mit Sandbox-Logs...
            </div>
          )}
          {visibleSteps.map((step, i) => (
            <LogLine key={`${step.type}-${i}`} step={step} index={i} />
          ))}
          <div ref={scrollRef} />
        </div>
      </div>
    </div>
  );
}
