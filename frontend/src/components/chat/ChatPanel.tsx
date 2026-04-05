// ── Agent Chat Panel — mit persistentem Verlauf ─────────────────────

import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bot, X, Send } from 'lucide-react';
import Markdown from 'react-markdown';
import { api } from '../../services/api';

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

// Nachrichten in localStorage persistieren
const STORAGE_KEY = 'sc_chat_messages';

function loadMessages(): LocalMessage[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveMessages(msgs: LocalMessage[]) {
  // Maximal 100 Nachrichten behalten
  const trimmed = msgs.slice(-100);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
}

export function ChatPanel({ isOpen, onClose }: ChatPanelProps) {
  const navigate = useNavigate();
  const [messages, setMessages] = useState<LocalMessage[]>(loadMessages);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [thinkingSeconds, setThinkingSeconds] = useState(0);
  const bottomRef = useRef<HTMLDivElement>(null);

  // Timer für "denkt seit X Sekunden"
  useEffect(() => {
    if (!sending) { setThinkingSeconds(0); return; }
    const interval = setInterval(() => setThinkingSeconds(s => s + 1), 1000);
    return () => clearInterval(interval);
  }, [sending]);

  // Bei jeder Änderung: in localStorage speichern
  useEffect(() => {
    saveMessages(messages);
  }, [messages]);

  // Auto-Scroll bei neuen Nachrichten
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length]);

  // Server-History beim ersten Öffnen laden (einmalig)
  useEffect(() => {
    if (!isOpen) return;
    if (messages.length > 0) return; // Nur laden wenn leer

    api.chat.history().then(serverMsgs => {
      if (serverMsgs && serverMsgs.length > 0) {
        const converted: LocalMessage[] = serverMsgs.map(m => ({
          id: m.id,
          role: m.role as 'user' | 'agent' | 'system',
          content: m.content,
          timestamp: new Date(m.created_at).toLocaleTimeString('de-DE', {
            hour: '2-digit', minute: '2-digit',
          }),
        }));
        setMessages(converted);
      }
    }).catch(() => {
      // Server nicht erreichbar — kein Problem, lokaler Verlauf bleibt
    });
  }, [isOpen]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    const text = input.trim();
    if (!text || sending) return;

    const now = new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });

    const userMsg: LocalMessage = {
      id: Date.now().toString(),
      role: 'user',
      content: text,
      timestamp: now,
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

      if (data.scan_started && data.scan_id) {
        const sysMsg: LocalMessage = {
          id: (Date.now() + 2).toString(),
          role: 'system',
          content: `__SCAN_LINK__${data.scan_id}`,
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
      setSending(false);
    }
  }

  function clearHistory() {
    setMessages([]);
    localStorage.removeItem(STORAGE_KEY);
  }

  if (!isOpen) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={onClose} />

      <aside className="fixed right-0 top-0 bottom-0 z-50 w-full sm:w-[380px] lg:static lg:z-auto lg:w-[380px] lg:shrink-0 flex flex-col bg-bg-primary border-l border-border-subtle">
        {/* Header */}
        <div className="shrink-0 h-14 flex items-center justify-between px-4 border-b border-border-subtle bg-bg-secondary">
          <div className="flex items-center gap-2">
            <Bot size={18} className="text-accent" />
            <span className="text-sm font-semibold text-text-primary">Agent Chat</span>
            {messages.length > 0 && (
              <span className="text-[10px] text-text-tertiary">({messages.length})</span>
            )}
          </div>
          <div className="flex items-center gap-1">
            {messages.length > 0 && (
              <button
                onClick={clearHistory}
                className="px-2 py-1 rounded text-[10px] text-text-tertiary hover:text-text-secondary hover:bg-bg-tertiary"
              >
                Leeren
              </button>
            )}
            <button onClick={onClose} className="p-2 rounded-md text-text-secondary hover:text-text-primary hover:bg-bg-tertiary" aria-label="Schließen">
              <X size={18} />
            </button>
          </div>
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

          {messages.map(msg => {
            if (msg.content.startsWith('__SCAN_LINK__')) {
              const scanId = msg.content.replace('__SCAN_LINK__', '');
              return (
                <div key={msg.id} className="w-full">
                  <button
                    onClick={() => { navigate(`/scans/${scanId}/live`); onClose(); }}
                    className="w-full rounded-lg border border-status-success/30 bg-status-success/10 p-3 text-left hover:bg-status-success/15 active:bg-status-success/20 transition-colors touch-manipulation"
                  >
                    <p className="text-xs font-semibold text-status-success mb-1">✅ Scan gestartet</p>
                    <p className="text-[11px] text-text-secondary">Tippe hier für Live-Fortschritt →</p>
                    <p className="text-[10px] font-mono text-text-tertiary mt-1">{scanId.slice(0, 8)}...</p>
                  </button>
                </div>
              );
            }

            return (
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
                  {msg.role === 'agent' ? (
                    <div className="text-[13px] break-words prose prose-invert prose-sm max-w-none
                      prose-p:my-1 prose-li:my-0.5 prose-ul:my-1 prose-ol:my-1
                      prose-strong:text-text-primary prose-strong:font-semibold
                      prose-code:text-accent prose-code:bg-accent/10 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-[12px]
                      prose-headings:text-text-primary prose-headings:text-sm prose-headings:mt-2 prose-headings:mb-1
                      prose-a:text-accent prose-a:no-underline hover:prose-a:underline
                    ">
                      <Markdown>{msg.content}</Markdown>
                    </div>
                  ) : (
                    <p className="text-[13px] whitespace-pre-wrap break-words">{msg.content}</p>
                  )}
                  <p className="text-[10px] text-text-tertiary mt-1">{msg.timestamp}</p>
                </div>
              </div>
            );
          })}

          {sending && (
            <div className="flex justify-start">
              <div className="bg-bg-secondary border border-accent/20 rounded-xl rounded-bl-sm px-3 py-2 max-w-[85%]">
                <p className="text-[10px] font-semibold text-accent mb-1">Agent</p>
                <div className="flex items-center gap-2">
                  <span className="flex gap-0.5">
                    <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                  </span>
                  <span className="text-xs text-text-secondary">
                    {thinkingSeconds < 5 ? 'Verarbeite Anfrage...' :
                     thinkingSeconds < 15 ? 'Analysiere Daten...' :
                     thinkingSeconds < 30 ? 'Claude generiert Antwort...' :
                     thinkingSeconds < 60 ? 'Komplexe Analyse — bitte warten...' :
                     `Dauert etwas länger (${thinkingSeconds}s)...`}
                  </span>
                  <span className="text-[10px] text-text-tertiary tabular-nums font-mono">{thinkingSeconds}s</span>
                </div>
                {thinkingSeconds > 15 && (
                  <button
                    onClick={() => setSending(false)}
                    className="mt-2 text-[10px] text-severity-critical hover:underline"
                  >
                    Abbrechen
                  </button>
                )}
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* Eingabe */}
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
