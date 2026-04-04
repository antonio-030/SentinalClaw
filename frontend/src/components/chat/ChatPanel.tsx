// ── Agent Chat Panel — Vereinfachte robuste Version ─────────────────

import { useState, useEffect, useRef } from 'react';
import { Bot, X, Send } from 'lucide-react';
import { api } from '../../services/api';
import type { ChatMessage as ChatMsg } from '../../types/api';

interface ChatPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

interface LocalMessage {
  id: string;
  role: 'user' | 'agent' | 'system';
  content: string;
  timestamp: string;
}

export function ChatPanel({ isOpen, onClose }: ChatPanelProps) {
  const [messages, setMessages] = useState<LocalMessage[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-Scroll bei neuen Nachrichten
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length]);

  // Nachricht senden — direkt mit fetch, kein React Query
  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    const text = input.trim();
    if (!text || sending) return;

    // User-Nachricht sofort anzeigen
    const userMsg: LocalMessage = {
      id: Date.now().toString(),
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }),
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setSending(true);

    try {
      const data = await api.chat.send(text);

      const agentMsg: LocalMessage = {
        id: (Date.now() + 1).toString(),
        role: 'agent',
        content: data.response,
        timestamp: new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages(prev => [...prev, agentMsg]);

      if (data.scan_started) {
        const sysMsg: LocalMessage = {
          id: (Date.now() + 2).toString(),
          role: 'system',
          content: `Scan gestartet! ID: ${data.scan_id}`,
          timestamp: new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }),
        };
        setMessages(prev => [...prev, sysMsg]);
      }
    } catch (err) {
      const errMsg: LocalMessage = {
        id: (Date.now() + 1).toString(),
        role: 'system',
        content: `Fehler: ${err instanceof Error ? err.message : 'Verbindung fehlgeschlagen'}`,
        timestamp: new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages(prev => [...prev, errMsg]);
    } finally {
      // IMMER entsperren, egal ob Erfolg oder Fehler
      setSending(false);
    }
  }

  if (!isOpen) return null;

  return (
    <>
      {/* Mobile Overlay */}
      <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={onClose} />

      {/* Panel */}
      <aside className="fixed right-0 top-0 bottom-0 z-50 w-full sm:w-[380px] lg:static lg:z-auto lg:w-[380px] lg:shrink-0 flex flex-col bg-bg-primary border-l border-border-subtle">
        {/* Header */}
        <div className="shrink-0 h-14 flex items-center justify-between px-4 border-b border-border-subtle bg-bg-secondary">
          <div className="flex items-center gap-2">
            <Bot size={18} className="text-accent" />
            <span className="text-sm font-semibold text-text-primary">Agent Chat</span>
          </div>
          <button onClick={onClose} className="p-2 rounded-md text-text-secondary hover:text-text-primary hover:bg-bg-tertiary" aria-label="Schließen">
            <X size={18} />
          </button>
        </div>

        {/* Nachrichten */}
        <div className="flex-1 overflow-y-auto px-3 py-3 space-y-3">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center px-4">
              <Bot size={32} className="text-accent mb-3" />
              <p className="text-sm text-text-primary mb-1">SentinelClaw Agent</p>
              <p className="text-xs text-text-tertiary">Tippe eine Nachricht oder "Scanne scanme.nmap.org"</p>
            </div>
          )}

          {messages.map(msg => (
            <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[85%] rounded-xl px-3 py-2 ${
                msg.role === 'user'
                  ? 'bg-accent/15 text-text-primary rounded-br-sm'
                  : msg.role === 'system'
                  ? 'bg-bg-tertiary text-text-tertiary text-center w-full rounded-lg'
                  : 'bg-bg-secondary border border-border-subtle text-text-primary rounded-bl-sm'
              }`}>
                {msg.role === 'agent' && (
                  <p className="text-[10px] font-semibold text-accent mb-1">Agent</p>
                )}
                <p className="text-[13px] whitespace-pre-wrap break-words">{msg.content}</p>
                <p className="text-[10px] text-text-tertiary mt-1">{msg.timestamp}</p>
              </div>
            </div>
          ))}

          {sending && (
            <div className="flex justify-start">
              <div className="bg-bg-secondary border border-border-subtle rounded-xl rounded-bl-sm px-3 py-2">
                <p className="text-[10px] font-semibold text-accent mb-1">Agent</p>
                <div className="flex items-center gap-1">
                  <span className="text-xs text-text-tertiary">denkt</span>
                  <span className="flex gap-0.5">
                    <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                  </span>
                </div>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* Eingabe — als Form damit Submit garantiert funktioniert */}
        <form onSubmit={handleSend} className="flex items-center gap-2 p-3 border-t border-border-subtle bg-bg-secondary">
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            disabled={sending}
            placeholder="Nachricht..."
            autoComplete="off"
            className="flex-1 rounded-lg border border-border-subtle bg-bg-primary px-3 py-3 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-accent/50 disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={sending || !input.trim()}
            className="shrink-0 flex items-center justify-center h-12 w-12 rounded-lg bg-accent text-white active:bg-accent/70 disabled:opacity-30 touch-manipulation"
            aria-label="Senden"
          >
            <Send size={20} />
          </button>
        </form>
      </aside>
    </>
  );
}
