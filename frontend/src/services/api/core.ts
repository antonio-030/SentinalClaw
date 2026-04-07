// ── SentinelClaw API — Kern-Utilities ───────────────────────────────
//
// Enthält die Basis-Infrastruktur für alle API-Aufrufe:
// CSRF-Token-Handling, generischer Fetch-Wrapper, Timeout-Logik.

const BASE = ''; // Vite proxy leitet /api und /health an localhost:3001 weiter

// ── CSRF-Token aus Cookie lesen ──────────────────────────────────────

function getCsrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)sc_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : '';
}

// ── Generic fetch wrapper ────────────────────────────────────────────

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string>),
  };

  // CSRF-Token bei zustandsändernden Requests als Header mitsenden
  if (STATE_CHANGING_METHODS.has(method)) {
    headers['X-CSRF-Token'] = getCsrfToken();
  }

  // Timeout: 20 Min für Chat (komplexe Scans/OSINT brauchen Zeit), 30s für Rest
  const timeoutMs = url.includes('/chat') ? 1_200_000 : 30_000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(`${BASE}${url}`, {
      ...init,
      headers,
      credentials: 'include',
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new Error('Zeitüberschreitung — die Anfrage hat zu lange gedauert. Versuche es erneut.');
    }
    // Netzwerkfehler: Backend nicht erreichbar, CORS-Problem, etc.
    throw new Error(
      'Server nicht erreichbar. Prüfe ob das Backend auf Port 3001 läuft.'
    );
  }
  clearTimeout(timeoutId);

  if (res.status === 401 && !url.includes('/auth/login')) {
    // Session abgelaufen — ausloggen
    try {
      const { useAuthStore } = await import('../../stores/authStore');
      useAuthStore.getState().logout();
    } catch {
      // Store nicht verfügbar — Seite zeigt Login beim nächsten Render
    }
    throw new Error('Session abgelaufen');
  }

  if (!res.ok) {
    const body = await res.text().catch(() => 'Unknown error');
    throw new Error(`API Error ${res.status}: ${body}`);
  }

  // 204 No Content (DELETE-Responses, etc.)
  if (res.status === 204) {
    return undefined as T;
  }

  return res.json();
}

export { BASE, fetchJson };
