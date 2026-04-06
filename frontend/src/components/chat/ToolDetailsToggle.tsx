// ── Aufklappbare Tool-Details + Sandbox-Logs unter Agent-Nachrichten ─

import { useState, useMemo } from 'react';
import {
  ChevronRight, ChevronDown, Terminal, CheckCircle, XCircle, ScrollText,
} from 'lucide-react';

interface ToolDetail {
  tool: string;
  command?: string;
  success?: boolean;
  duration_ms?: number;
  output_preview?: string;
}

interface LogEntry {
  type: string;
  message: string;
}

interface ParsedMetadata {
  tools?: ToolDetail[];
  logs?: LogEntry[];
  total_duration_ms?: number;
}

interface ToolDetailsToggleProps {
  metadata: string;
}

function parseMetadata(raw: string): ParsedMetadata | null {
  try {
    const parsed = JSON.parse(raw) as ParsedMetadata;
    const hasTools = parsed.tools && parsed.tools.length > 0;
    const hasLogs = parsed.logs && parsed.logs.length > 0;
    if (!hasTools && !hasLogs) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function ToolDetailsToggle({ metadata }: ToolDetailsToggleProps) {
  const [expanded, setExpanded] = useState(false);
  const [showLogs, setShowLogs] = useState(false);

  const parsed = useMemo(() => parseMetadata(metadata), [metadata]);
  if (!parsed) return null;

  const toolCount = parsed.tools?.length ?? 0;
  const logCount = parsed.logs?.length ?? 0;
  const totalDuration = parsed.total_duration_ms
    ? `${(parsed.total_duration_ms / 1000).toFixed(1)}s`
    : null;

  const label = toolCount > 0
    ? `${toolCount} ${toolCount === 1 ? 'Tool' : 'Tools'}${totalDuration ? ` · ${totalDuration}` : ''}`
    : `${logCount} Log-Einträge`;

  return (
    <div className="mt-1.5">
      {/* Toggle-Button */}
      <button
        onClick={() => setExpanded(prev => !prev)}
        className="flex items-center gap-1 text-[10px] text-text-tertiary hover:text-text-secondary transition-colors"
      >
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <Terminal size={10} />
        <span>{label}</span>
      </button>

      {expanded && (
        <div className="mt-1.5">
          {/* Tab-Leiste wenn beides vorhanden */}
          {toolCount > 0 && logCount > 0 && (
            <div className="flex gap-2 mb-1.5">
              <button
                onClick={() => setShowLogs(false)}
                className={`text-[10px] px-2 py-0.5 rounded transition-colors ${
                  !showLogs ? 'bg-accent/15 text-accent' : 'text-text-tertiary hover:text-text-secondary'
                }`}
              >
                Tools
              </button>
              <button
                onClick={() => setShowLogs(true)}
                className={`text-[10px] px-2 py-0.5 rounded transition-colors ${
                  showLogs ? 'bg-accent/15 text-accent' : 'text-text-tertiary hover:text-text-secondary'
                }`}
              >
                <span className="inline-flex items-center gap-1">
                  <ScrollText size={9} /> Sandbox-Logs
                </span>
              </button>
            </div>
          )}

          {/* Tool-Details */}
          {!showLogs && parsed.tools && parsed.tools.length > 0 && (
            <div className="space-y-1 border-l border-border-subtle ml-1.5 pl-2.5">
              {parsed.tools.map((tool, i) => (
                <div key={`t-${i}`} className="flex items-start gap-1.5">
                  {tool.success !== false ? (
                    <CheckCircle size={11} className="text-status-success shrink-0 mt-0.5" />
                  ) : (
                    <XCircle size={11} className="text-severity-critical shrink-0 mt-0.5" />
                  )}
                  <span className="text-[10px] font-mono text-text-secondary truncate">
                    {tool.tool}{tool.command ? ` ${tool.command}` : ''}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Sandbox-Logs */}
          {(showLogs || (toolCount === 0 && logCount > 0)) && parsed.logs && (
            <div className="rounded bg-[#0a0c10] px-2.5 py-2 max-h-60 overflow-y-auto overflow-x-auto">
              {parsed.logs.map((log, i) => {
                const color = log.type === 'tool_start' ? 'text-accent'
                  : log.type === 'tool_result' ? 'text-status-success'
                  : log.type === 'thinking' ? 'text-text-secondary'
                  : 'text-text-tertiary';
                const icon = log.type === 'tool_start' ? '>'
                  : log.type === 'tool_result' ? '✓'
                  : log.type === 'thinking' ? '●'
                  : '│';
                return (
                  <div key={`l-${i}`} className={`font-mono text-[10px] leading-relaxed ${color} whitespace-nowrap`}>
                    <span className="text-text-tertiary mr-1">{icon}</span>
                    {log.message}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
