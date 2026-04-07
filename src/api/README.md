# API — REST-Backend

> FastAPI-basierte REST-API mit JWT-Auth, WebSocket und rollenbasierter Zugriffskontrolle.

## Was macht dieses Modul?

Die API exponiert alle SentinelClaw-Funktionen als REST-Endpoints für die Web-UI.
Sie verwaltet Authentifizierung (JWT + MFA), Autorisierung (RBAC), Scan-Steuerung,
Finding-Verwaltung, DSGVO-Funktionen und Echtzeit-Kommunikation über WebSocket.

## Dateien

| Datei | Funktion |
|---|---|
| `server.py` | App-Setup, Health, Status, Kill, Audit, Profile |
| `auth_routes.py` | Login, Registrierung, Token-Refresh |
| `mfa_routes.py` | Multi-Faktor-Authentifizierung |
| `scan_routes.py` | CRUD für Scans (Start, List, Get, Delete, Cancel) |
| `scan_detail_routes.py` | Export, Compare, Report, Hosts, Ports, Phasen |
| `finding_routes.py` | Finding-Verwaltung und -Abfragen |
| `chat_routes.py` | Chat-Agent-Endpunkte |
| `agent_report_routes.py` | CRUD für Agent-Reports |
| `approval_routes.py` | Genehmigungsworkflow für Eskalationsstufen 3/4 |
| `settings_routes.py` | Systemweite Einstellungen über die Web-UI |
| `gdpr_routes.py` | DSGVO: Datenexport, Löschung, Consent |
| `websocket_manager.py` | WebSocket-Verbindungsverwaltung |
| `security_headers.py` | CSP, HSTS, X-Frame-Options Middleware |
| `rate_limiter.py` | Request-Rate-Limiting |

## Starten

```bash
python -m uvicorn src.api.server:app --host 0.0.0.0 --port 3001
```

## Umgebungsvariablen

| Variable | Beschreibung |
|---|---|
| `SENTINEL_JWT_SECRET` | JWT-Signierungsschlüssel |
| `SENTINEL_DB_PATH` | Pfad zur SQLite-Datenbank |
| `SENTINEL_CORS_ORIGINS` | Erlaubte CORS-Origins |
| `SENTINEL_API_PORT` | API-Port (Standard: 3001) |

## Dependencies

- `fastapi`, `uvicorn` (Web-Framework)
- `pydantic` (Request/Response-Validierung)
- `python-jose` (JWT-Tokens)
- `bcrypt` (Passwort-Hashing)
