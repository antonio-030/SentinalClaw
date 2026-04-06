// ── WebSocket-Hook für Echtzeit-Updates ─────────────────────────────

import { useEffect, useRef, useCallback, useState } from 'react';

type WsEvent = 'agent_response' | 'approval_required' | 'approval_decided'
  | 'scan_progress' | 'kill_activated' | 'pong';

interface WsMessage {
  event: WsEvent;
  data: Record<string, unknown>;
  timestamp: string;
}

type EventHandler = (data: Record<string, unknown>) => void;

interface UseWebSocketReturn {
  connected: boolean;
  sendMessage: (text: string) => void;
  on: (event: WsEvent, handler: EventHandler) => void;
  off: (event: WsEvent) => void;
}

const RECONNECT_DELAY_MS = 3000;
const HEARTBEAT_INTERVAL_MS = 30000;

export function useWebSocket(): UseWebSocketReturn {
  const wsRef = useRef<WebSocket | null>(null);
  const handlersRef = useRef<Map<WsEvent, EventHandler>>(new Map());
  const heartbeatRef = useRef<ReturnType<typeof setInterval>>();
  const [connected, setConnected] = useState(false);

  const connect = useCallback(() => {
    const token = localStorage.getItem('sc_token');
    if (!token) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const url = `${protocol}//${host}/ws/chat?token=${encodeURIComponent(token)}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      // Heartbeat starten
      heartbeatRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send('ping');
      }, HEARTBEAT_INTERVAL_MS);
    };

    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        const handler = handlersRef.current.get(msg.event);
        if (handler) handler(msg.data);
      } catch {
        // Ungültiges JSON ignorieren
      }
    };

    ws.onclose = () => {
      setConnected(false);
      if (heartbeatRef.current) clearInterval(heartbeatRef.current);
      // Auto-Reconnect nach Verzögerung
      setTimeout(connect, RECONNECT_DELAY_MS);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (heartbeatRef.current) clearInterval(heartbeatRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const sendMessage = useCallback((text: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(text);
    }
  }, []);

  const on = useCallback((event: WsEvent, handler: EventHandler) => {
    handlersRef.current.set(event, handler);
  }, []);

  const off = useCallback((event: WsEvent) => {
    handlersRef.current.delete(event);
  }, []);

  return { connected, sendMessage, on, off };
}
