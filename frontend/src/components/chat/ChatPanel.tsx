// ── Agent Chat Panel — Hauptkomponente des Chat-Systems ─────────────
//
// Desktop: rechtes Seitenpanel (380px breit)
// Mobile: Fullscreen Slide-Over, getoggled per Chat-Bubble-Button
//
// Features:
// - Nachrichtenliste mit Auto-Scroll
// - Scan-Selector Dropdown
// - "Agent denkt..." Indikator
// - Polling-basiert (kein WebSocket)

import { useState, useEffect, useRef, useCallback } from 'react';
import { Bot, Minus, X, ChevronDown } from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../../services/api';
import type { ChatMessage as ChatMessageType } from '../../types/api';
import { ChatMessage } from './ChatMessage';
import { ChatInput } from './ChatInput';

// ── Query Keys ──────────────────────────────────────────────────────

const chatKeys = {
  history: (scanId?: string) => ['chat', 'history', scanId] as const,
};

// ── Props ───────────────────────────────────────────────────────────

interface ChatPanelProps {
  /** Panel sichtbar? (Mobile-Toggle) */
  isOpen: boolean;
  /** Panel schliessen (Mobile) */
  onClose: () => void;
}

export function ChatPanel({ isOpen, onClose }: ChatPanelProps) {
  const queryClient = useQueryClient();

  // Lokaler State
  const [selectedScanId, setSelectedScanId] = useState<string | undefined>(undefined);
  const [localMessages, setLocalMessages] = useState<ChatMessageType[]>([]);
  const [isThinking, setIsThinking] = useState(false);
  const [scanDropdownOpen, setScanDropdownOpen] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);

  // ── Daten laden ─────────────────────────────────────────────────

  // Chat-Verlauf laden
  const { data: history } = useQuery({
    queryKey: chatKeys.history(selectedScanId),
    queryFn: () => api.chat.history(selectedScanId),
    refetchInterval: 5_000,
    enabled: isOpen,
  });

  // Scan-Liste fuer Dropdown
  const { data: scans } = useQuery({
    queryKey: ['scans'],
    queryFn: api.scans.list,
    staleTime: 10_000,
  });

  // Chat-Nachricht senden
  const sendMutation = useMutation({
    mutationFn: ({ message, scanId }: { message: string; scanId?: string }) =>
      api.chat.send(message, scanId),
    onSuccess: (data) => {
      // Agent-Antwort als lokale Nachricht hinzufuegen
      const agentMsg: ChatMessageType = {
        id: crypto.randomUUID(),
        role: 'agent',
        content: data.response,
        message_type: 'text',
        created_at: new Date().toISOString(),
        scan_id: data.scan_id || selectedScanId,
      };

      setLocalMessages((prev) => [...prev, agentMsg]);
      setIsThinking(false);

      // Wenn ein Scan gestartet wurde, Scan-ID setzen
      if (data.scan_started && data.scan_id) {
        setSelectedScanId(data.scan_id);
        // Scans-Liste invalidieren
        queryClient.invalidateQueries({ queryKey: ['scans'] });
      }

      // Chat-Verlauf invalidieren
      queryClient.invalidateQueries({ queryKey: chatKeys.history(selectedScanId) });
    },
    onError: () => {
      const errorMsg: ChatMessageType = {
        id: crypto.randomUUID(),
        role: 'system',
        content: 'Fehler beim Senden der Nachricht. Bitte versuche es erneut.',
        message_type: 'text',
        created_at: new Date().toISOString(),
      };
      setLocalMessages((prev) => [...prev, errorMsg]);
      setIsThinking(false);
    },
  });

  // ── Nachricht senden ──────────────────────────────────────────────

  const handleSend = useCallback(
    (message: string) => {
      // User-Nachricht sofort lokal anzeigen (optimistic)
      const userMsg: ChatMessageType = {
        id: crypto.randomUUID(),
        role: 'user',
        content: message,
        message_type: 'text',
        created_at: new Date().toISOString(),
        scan_id: selectedScanId,
      };

      setLocalMessages((prev) => [...prev, userMsg]);
      setIsThinking(true);

      sendMutation.mutate({ message, scanId: selectedScanId });
    },
    [selectedScanId, sendMutation],
  );

  // ── Nachrichten zusammenfuehren (Server + lokal) ──────────────────

  const allMessages = (() => {
    const serverMsgs = history ?? [];
    const serverIds = new Set(serverMsgs.map((m) => m.id));
    // Lokale Nachrichten die noch nicht vom Server kommen
    const uniqueLocal = localMessages.filter((m) => !serverIds.has(m.id));
    return [...serverMsgs, ...uniqueLocal];
  })();

  // Lokale Nachrichten bereinigen wenn Server-Daten sich aendern
  useEffect(() => {
    if (history && history.length > 0) {
      const serverIds = new Set(history.map((m) => m.id));
      setLocalMessages((prev) => prev.filter((m) => !serverIds.has(m.id)));
    }
  }, [history]);

  // ── Auto-Scroll ───────────────────────────────────────────────────

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [allMessages.length, isThinking]);

  // ── Scan wechseln -> lokale Nachrichten zuruecksetzen ─────────────

  const handleScanChange = (scanId: string | undefined) => {
    setSelectedScanId(scanId);
    setLocalMessages([]);
    setScanDropdownOpen(false);
  };

  // ── Dropdown schliessen bei Klick ausserhalb ──────────────────────

  useEffect(() => {
    if (!scanDropdownOpen) return;
    const handler = () => setScanDropdownOpen(false);
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, [scanDropdownOpen]);

  // ── Render ────────────────────────────────────────────────────────

  // Panel-Container-Klassen (Desktop vs. Mobile)
  const panelClasses = isOpen
    ? 'translate-x-0 opacity-100'
    : 'translate-x-full opacity-0 pointer-events-none';

  return (
    <>
      {/* Mobile Overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Chat-Panel */}
      <aside
        className={`
          fixed right-0 top-0 bottom-0 z-50 w-full sm:w-[380px]
          lg:static lg:z-auto lg:w-[380px] lg:shrink-0
          flex flex-col bg-bg-primary border-l border-border-subtle
          transform transition-all duration-200 ease-out
          ${panelClasses}
          lg:translate-x-0 lg:opacity-100 lg:pointer-events-auto
          ${!isOpen ? 'lg:hidden' : ''}
        `}
      >
        {/* ── Header ──────────────────────────────────────────────── */}
        <div className="shrink-0 h-14 flex items-center justify-between px-3 border-b border-border-subtle bg-bg-secondary">
          <div className="flex items-center gap-2">
            <div className="flex items-center justify-center w-7 h-7 rounded-lg bg-accent/10 text-accent">
              <Bot size={16} strokeWidth={2} />
            </div>
            <span className="text-sm font-semibold text-text-primary">Agent Chat</span>
          </div>

          <div className="flex items-center gap-1">
            {/* Scan-Selector */}
            <div className="relative">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setScanDropdownOpen(!scanDropdownOpen);
                }}
                className="flex items-center gap-1 px-2 py-1 rounded-md text-[11px] text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors"
              >
                <span className="max-w-[100px] truncate">
                  {selectedScanId
                    ? scans?.find((s) => s.id === selectedScanId)?.target ?? 'Scan'
                    : 'Alle'}
                </span>
                <ChevronDown size={12} />
              </button>

              {scanDropdownOpen && (
                <div className="absolute right-0 top-full mt-1 w-56 max-h-64 overflow-y-auto rounded-lg border border-border-subtle bg-bg-secondary shadow-xl z-50">
                  <button
                    onClick={() => handleScanChange(undefined)}
                    className={`w-full text-left px-3 py-2 text-[12px] hover:bg-bg-tertiary transition-colors ${
                      !selectedScanId ? 'text-accent font-medium' : 'text-text-secondary'
                    }`}
                  >
                    Alle Nachrichten
                  </button>
                  {scans?.map((scan) => (
                    <button
                      key={scan.id}
                      onClick={() => handleScanChange(scan.id)}
                      className={`w-full text-left px-3 py-2 text-[12px] hover:bg-bg-tertiary transition-colors border-t border-border-subtle ${
                        selectedScanId === scan.id ? 'text-accent font-medium' : 'text-text-secondary'
                      }`}
                    >
                      <span className="block truncate">{scan.target}</span>
                      <span className="text-[10px] text-text-tertiary">{scan.status}</span>
                    </button>
                  ))}
                  {(!scans || scans.length === 0) && (
                    <p className="px-3 py-2 text-[11px] text-text-tertiary">
                      Keine Scans vorhanden
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Schliessen-Button */}
            <button
              onClick={onClose}
              className="p-1.5 rounded-md text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors"
              aria-label="Chat minimieren"
            >
              <span className="hidden lg:block"><Minus size={16} /></span>
              <span className="lg:hidden"><X size={16} /></span>
            </button>
          </div>
        </div>

        {/* ── Nachrichtenliste ────────────────────────────────────── */}
        <div
          ref={messagesContainerRef}
          className="flex-1 overflow-y-auto px-3 py-3 space-y-0.5"
        >
          {allMessages.length === 0 && !isThinking && (
            <div className="flex flex-col items-center justify-center h-full text-center px-4">
              <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-accent/10 text-accent mb-3">
                <Bot size={24} strokeWidth={1.5} />
              </div>
              <p className="text-sm font-medium text-text-primary mb-1">
                SentinelClaw Agent
              </p>
              <p className="text-[12px] text-text-tertiary leading-relaxed max-w-[260px]">
                Starte einen Scan, analysiere Ergebnisse oder stelle eine Frage.
                Probiere: "Scanne 10.10.10.1"
              </p>
            </div>
          )}

          {allMessages.map((msg) => (
            <ChatMessage key={msg.id} message={msg} />
          ))}

          {/* "Agent denkt..." Indikator */}
          {isThinking && (
            <div className="flex justify-start mb-2.5">
              <div className="bg-bg-secondary rounded-xl rounded-bl-sm border border-border-subtle px-3.5 py-2.5">
                <p className="text-[10px] font-semibold text-accent mb-1 uppercase tracking-wide">
                  Agent
                </p>
                <div className="flex items-center gap-1.5">
                  <span className="text-[12px] text-text-tertiary">Agent denkt</span>
                  <span className="flex gap-0.5">
                    <span className="w-1 h-1 bg-accent/60 rounded-full animate-bounce [animation-delay:0ms]" />
                    <span className="w-1 h-1 bg-accent/60 rounded-full animate-bounce [animation-delay:150ms]" />
                    <span className="w-1 h-1 bg-accent/60 rounded-full animate-bounce [animation-delay:300ms]" />
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Scroll-Anker */}
          <div ref={messagesEndRef} />
        </div>

        {/* ── Eingabefeld ─────────────────────────────────────────── */}
        <ChatInput onSend={handleSend} disabled={isThinking} />
      </aside>
    </>
  );
}
