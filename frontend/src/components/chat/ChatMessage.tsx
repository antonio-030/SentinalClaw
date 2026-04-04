// ── Einzelne Chat-Nachricht mit rollenbasiertem Styling ─────────────
//
// User-Nachrichten: rechts, Akzentfarbe
// Agent-Nachrichten: links, sekundaerer Hintergrund
// System-Nachrichten: zentriert, klein, grau

import { Link } from 'react-router-dom';
import type { ChatMessage as ChatMessageType } from '../../types/api';

interface ChatMessageProps {
  message: ChatMessageType;
}

export function ChatMessage({ message }: ChatMessageProps) {
  const { role, content, message_type, scan_id } = message;

  // System-Nachrichten: zentriert, kompakt
  if (role === 'system') {
    return (
      <div className="flex justify-center my-2">
        <div className="max-w-[85%] px-3 py-1.5 rounded-lg bg-bg-tertiary/50 text-[11px] text-text-tertiary text-center">
          {content}
          {message_type === 'scan_started' && scan_id && (
            <Link
              to={`/scans/${scan_id}/live`}
              className="ml-1 text-accent hover:underline font-medium"
            >
              Live ansehen
            </Link>
          )}
        </div>
      </div>
    );
  }

  // User vs. Agent Styling
  const isUser = role === 'user';

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-2.5`}>
      <div
        className={`max-w-[85%] rounded-xl px-3.5 py-2.5 text-[13px] leading-relaxed whitespace-pre-wrap break-words ${
          isUser
            ? 'bg-accent/10 text-text-primary rounded-br-sm'
            : 'bg-bg-secondary text-text-primary rounded-bl-sm border border-border-subtle'
        }`}
      >
        {/* Agent-Label */}
        {!isUser && (
          <p className="text-[10px] font-semibold text-accent mb-1 uppercase tracking-wide">
            Agent
          </p>
        )}
        {content}
      </div>
    </div>
  );
}
