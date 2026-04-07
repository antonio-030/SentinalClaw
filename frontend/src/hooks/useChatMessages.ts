// ── Chat-Nachrichten-Management mit Persistenz und Polling ──────────
//
// Kapselt die gesamte Nachrichten-Logik: localStorage-Persistenz,
// Server-History-Laden, Polling für Agent-Antworten und das Senden.

import { useState, useEffect, useRef } from 'react';
import { useWebSocket } from './useWebSocket';
import { api } from '../services/api';
import type { AgentStep } from '../components/chat/AgentActivityFeed';

// ── Typen ───────────────────────────────────────────────────────────

export interface LocalMessage {
  id: string;
  role: 'user' | 'agent' | 'system';
  content: string;
  timestamp: string;
  metadata?: string;
}

// ── Persistenz ──────────────────────────────────────────────────────

const STORAGE_KEY = 'sc_chat_messages';
const MAX_PERSISTED_MESSAGES = 100;

function loadMessages(): LocalMessage[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveMessages(msgs: LocalMessage[]) {
  const trimmed = msgs.slice(-MAX_PERSISTED_MESSAGES);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
}

// ── Zeitstempel-Helper ──────────────────────────────────────────────

function nowTimestamp(): string {
  return new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
}

// ── Hook ────────────────────────────────────────────────────────────

export function useChatMessages(isOpen: boolean) {
  const [messages, setMessages] = useState<LocalMessage[]>(loadMessages);
  const [sending, setSending] = useState(false);
  const [thinkingSeconds, setThinkingSeconds] = useState(0);
  const [agentSteps, setAgentSteps] = useState<AgentStep[]>([]);
  const agentStepsRef = useRef<AgentStep[]>([]);
  const wsResponseRef = useRef<string | null>(null);
  const { connected: wsConnected, on: wsOn } = useWebSocket();

  // WebSocket: Agent-Antworten empfangen
  useEffect(() => {
    wsOn('agent_response', (data) => {
      const content = data.content as string;
      if (content && sending) wsResponseRef.current = content;
    });
  }, [wsOn, sending]);

  // WebSocket: Live-Schritte des Agents empfangen
  useEffect(() => {
    wsOn('agent_step', (data) => {
      const step = data as unknown as AgentStep;
      setAgentSteps(prev => {
        const updated = [...prev, step];
        agentStepsRef.current = updated;  // Ref synchron halten
        return updated;
      });
    });
  }, [wsOn]);

  // Timer für Denk-Dauer
  useEffect(() => {
    if (!sending) { setThinkingSeconds(0); return; }
    const interval = setInterval(() => setThinkingSeconds(s => s + 1), 1000);
    return () => clearInterval(interval);
  }, [sending]);

  // Persistenz bei Änderungen
  useEffect(() => { saveMessages(messages); }, [messages]);

  // Server-History beim ersten Öffnen laden
  useEffect(() => {
    if (!isOpen || messages.length > 0) return;
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
      // Server nicht erreichbar — lokaler Verlauf bleibt bestehen
    });
  }, [isOpen]);

  // Alle Agent-Steps als Metadata für die Nachricht aufbereiten
  function buildToolMetadata(): string | undefined {
    // Ref nutzen statt State — State hat in der Closure den alten Wert
    const steps = agentStepsRef.current;
    if (steps.length === 0) return undefined;
    const toolResults = steps.filter(s => s.type === 'tool_result');
    const totalDuration = toolResults.reduce((sum, s) => sum + (s.duration_ms ?? 0), 0);
    const tools = toolResults.map(s => ({
      tool: s.tool ?? 'unknown',
      command: s.command,
      success: s.success,
      duration_ms: s.duration_ms,
      output_preview: s.output_preview,
    }));
    // Alle Log-Zeilen als Verlauf speichern (dedupliziert)
    const seen = new Set<string>();
    const logs = steps
      .map(s => ({
        type: s.type,
        message: s.message ?? s.command ?? s.output_preview ?? '',
      }))
      .filter(l => {
        const key = `${l.type}:${l.message}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    return JSON.stringify({ tools, logs, total_duration_ms: totalDuration });
  }

  // Polling als Fallback wenn WebSocket keine Antwort liefert
  async function pollForAgentResponse(userMessageTime: number): Promise<string | null> {
    wsResponseRef.current = null;
    const maxPolls = 240; // 20 Minuten bei 5s Intervall
    for (let i = 0; i < maxPolls; i++) {
      if (wsResponseRef.current) {
        const response = wsResponseRef.current;
        wsResponseRef.current = null;
        return response;
      }
      await new Promise(r => setTimeout(r, wsConnected ? 1000 : 5000));
      try {
        const history = await api.chat.history();
        if (history && history.length > 0) {
          const last = history[history.length - 1];
          if (last.role === 'agent' && new Date(last.created_at).getTime() > userMessageTime) {
            return last.content;
          }
        }
      } catch {
        // Polling-Fehler ignorieren — nächster Versuch folgt
      }
    }
    return null;
  }

  // Nachricht senden und auf Antwort warten
  async function handleSend(text: string) {
    if (!text || sending) return;

    const userMsg: LocalMessage = {
      id: Date.now().toString(),
      role: 'user',
      content: text,
      timestamp: nowTimestamp(),
    };
    setMessages(prev => [...prev, userMsg]);
    setAgentSteps([]);  // Alte Logs leeren bei neuer Nachricht
    agentStepsRef.current = [];
    setSending(true);

    try {
      const data = await api.chat.send(text);

      if (data.response === '__AGENT_THINKING__') {
        const agentResponse = await pollForAgentResponse(Date.now() - 2000);
        if (agentResponse) {
          addAgentMessage(agentResponse);
        } else {
          addSystemMessage('Agent hat nicht rechtzeitig geantwortet. Prüfe den Chat-Verlauf später.');
        }
      } else {
        addAgentMessage(data.response);
        if (data.scan_started && data.scan_id) {
          addSystemMessage(`__SCAN_LINK__${data.scan_id}`);
        }
      }
    } catch (err) {
      const errorText = err instanceof Error ? err.message : 'Verbindung fehlgeschlagen';
      addSystemMessage(`Fehler: ${errorText}`);
    } finally {
      setSending(false);
      // Steps bleiben sichtbar bis zur nächsten Nachricht
    }
  }

  function addAgentMessage(content: string) {
    const msg: LocalMessage = {
      id: (Date.now() + 1).toString(),
      role: 'agent',
      content,
      timestamp: nowTimestamp(),
      metadata: buildToolMetadata(),
    };
    setMessages(prev => [...prev, msg]);
  }

  function addSystemMessage(content: string) {
    const msg: LocalMessage = {
      id: (Date.now() + 2).toString(),
      role: 'system',
      content,
      timestamp: nowTimestamp(),
    };
    setMessages(prev => [...prev, msg]);
  }

  function clearHistory() {
    setMessages([]);
    localStorage.removeItem(STORAGE_KEY);
    const csrfMatch = document.cookie.match(/(?:^|;\s*)sc_csrf=([^;]*)/);
    const csrfToken = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
    fetch('/api/v1/chat/history', {
      method: 'DELETE',
      headers: { 'X-CSRF-Token': csrfToken },
      credentials: 'include',
    }).catch(() => {});
  }

  return {
    messages,
    sending,
    thinkingSeconds,
    agentSteps,
    handleSend,
    clearHistory,
  };
}
