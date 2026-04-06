# SentinelClaw

> KI-gestützte Security Assessment Platform — angetrieben von NVIDIA NemoClaw, OpenClaw und Claude

Self-hosted Penetrationstest-Plattform mit autonomen Agenten, Kernel-Level-Sandbox-Isolation und einer 8-Schichten-Sicherheitsarchitektur. Läuft lokal mit Python 3.12+, React, Docker und SQLite.

---

## Wie SentinelClaw mit NemoClaw und OpenClaw arbeitet

SentinelClaw nutzt **NVIDIA NemoClaw** als Agent-Runtime. NemoClaw bündelt drei Kernkomponenten:

```
┌─────────────────────────────────────────────────────────────┐
│  NemoClaw (NVIDIA Agent-Runtime)                            │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  OpenClaw — Agent-Runtime + Multi-Agent-Orchestrierung│  │
│  │  Der "sentinelclaw" Agent wird hier ausgeführt.       │  │
│  │  Claude als LLM-Backend, Bash(*) als Tool.            │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  OpenShell — Kernel-Level Sandbox-Isolation            │  │
│  │  Landlock LSM + Seccomp BPF + Network Namespaces      │  │
│  │  SSH-Proxy für isolierte Agent-Ausführung              │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Der Scan-Flow im Detail

Wenn ein Scan gestartet wird (Web-UI oder CLI), passiert folgendes:

```
Benutzer startet Scan (Web-UI / CLI)
    │
    ▼
┌────────────────────────────────────────────────────────────┐
│  SentinelClaw API  (FastAPI, POST /api/v1/scans)          │
│  → Erstellt Scan-Job in der Datenbank                     │
│  → Startet Background-Task                                │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  Orchestrator-Agent (FA-01)                                │
│  → Erstellt Scan-Plan (mindestens 2 Phasen)               │
│  → Koordiniert die Phasen-Ausführung                      │
│  → Sammelt Ergebnisse, erstellt Executive Summary          │
└────────────────────┬───────────────────────────────────────┘
                     │
          ┌──────────┼──────────┬──────────────┐
          ▼          ▼          ▼              ▼
    ┌──────────┐┌──────────┐┌──────────┐┌──────────┐
    │ Phase 1  ││ Phase 2  ││ Phase 3  ││ Phase 4  │
    │ Host     ││ Port-    ││ Vuln-    ││ Analyse  │
    │ Discovery││ Scan     ││ Scan     ││ & Report │
    └────┬─────┘└────┬─────┘└────┬─────┘└────┬─────┘
         │           │           │            │
         └─────┬─────┘           │            │
               │                 │            │
               ▼                 ▼            ▼
┌────────────────────────────────────────────────────────────┐
│  NemoClaw Runtime  (nemoclaw_runtime.py)                   │
│                                                            │
│  Für JEDE Phase:                                           │
│  1. Baut SSH-Kommando:                                     │
│     ssh -o ProxyCommand="openshell ssh-proxy               │
│         --gateway-name nemoclaw                             │
│         --name my-assistant"                                │
│         sandbox@openshell-my-assistant                      │
│                                                            │
│  2. Führt OpenClaw Agent in der Sandbox aus:               │
│     openclaw run                                           │
│         --agent sentinelclaw                                │
│         --system-prompt-file /sandbox/AGENT.md              │
│         --tools bash                                        │
│         --output text                                       │
│         -p "[Analysiere diese nmap-Ergebnisse...]"          │
│                                                            │
│  3. Claude (OpenClaw) analysiert den Prompt:                │
│     → Entscheidet autonom welche Bash-Befehle nötig sind   │
│     → Führt nmap/nuclei/curl über Bash-Tool aus            │
│     → Parst die Ergebnisse                                 │
│     → Gibt strukturierte Analyse zurück                    │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  OpenShell Sandbox  (Kernel-Level-Isolation)               │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Landlock LSM      → Dateisystem-Zugriff beschränkt  │  │
│  │  Seccomp BPF       → Syscall-Filter aktiv            │  │
│  │  Network Namespaces → Nur Whitelist-Ziele erreichbar │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  Darin läuft:                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Docker Sandbox-Container                             │  │
│  │  cap_drop: ALL | nur NET_RAW für nmap                │  │
│  │  read_only: true | non-root User (scanner)            │  │
│  │  PID-Limit: 256 | Memory: 2GB | CPU: 2.0             │  │
│  │                                                       │  │
│  │  Tools: nmap 7.80, nuclei 3.3.7, curl, dig, whois    │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### Der Chat-Agent (separater Pfad)

Der Agent-Chat in der Web-UI nutzt denselben NemoClaw-Stack, aber mit einem Tool-Loop:

```
Chat-UI → POST /api/v1/chat → Chat-Agent (ask_agent)
    │
    ▼
NemoClaw Runtime → SSH → OpenShell → openclaw run --agent sentinelclaw
    │
    ├─ Agent antwortet mit Tool-Markern (```tool bash nmap -sV ...)
    │   → execute_scan_command() → docker exec → Sandbox
    │   → Ergebnis zurück an Agent
    │
    ├─ Agent analysiert Ergebnis, ruft ggf. weitere Tools auf
    │   (Loop: maximal 15 Iterationen)
    │
    └─ Agent gibt finale Antwort (Markdown) → WebSocket → UI
```

---

## Features

### Scan-Pipeline
- **Orchestrator-Agent** — Plant und koordiniert mehrphasige Scans (Host Discovery → Port-Scan → Vuln-Assessment → Analyse)
- **4-Phasen-Scan** — Jede Phase ist ein eigenständiger OpenClaw-Agent-Aufruf mit eigener DB-Persistenz
- **Agent-Chat** — Interaktiver Chat mit dem Security-Agent, autonome Tool-Aufrufe in der Sandbox
- **7 Scan-Profile** — Quick, Standard, Full, Web, Datenbank, Infrastruktur, Stealth (+ eigene Profile erstellen)

### Sicherheitsarchitektur (8 Schichten)

```
┌─────────────────────────────────────────────────────────────┐
│ 8. Auth & RBAC       JWT, bcrypt, 5 Rollen, MFA (TOTP)     │
│ 7. Audit-Logging     Append-Only, kein DELETE, unveränderbar│
│ 6. Kill Switch       4 Pfade: App, Container, Netzwerk, OS │
│ 5. Netzwerk-Isolation  sentinel-internal, sentinel-scanning │
│ 4. Docker Sandbox    cap_drop ALL, read-only, non-root      │
│ 3. Input-Validierung Shell-Metazeichen, PII-Masking         │
│ 2. Scope-Validator   7 Checks vor jedem Tool-Aufruf         │
│ 1. NemoClaw Runtime  OpenClaw + OpenShell + Landlock/seccomp│
└─────────────────────────────────────────────────────────────┘
```

### Web-UI (17 Seiten)
- Dashboard mit animierter Security-Shield-Visualisierung
- Live-Scan-Fortschritt mit Phasen-Tracking
- Reports (Executive, Technisch, Compliance) als Markdown + PDF-Download
- PDF-Reports mit Autorisierungsnachweis (§202a, §303b StGB)
- Editierbare Einstellungen (Tool-Timeouts, Agent-Limits, Sandbox, LLM)
- Profil-Management (Builtin + Custom)
- Whitelist-Verwaltung mit Bestätigungstypen
- Agent-Chat mit Syntax-Highlighting und WebSocket
- Approval-System für Eskalationsstufe 3+ (Exploitation)
- Monitoring, Audit-Log, Findings, Export (CSV/JSONL/SARIF)

### LLM-Provider
- **Claude** (Anthropic) — Standard-Provider via OpenClaw/CLI oder API
- **Azure OpenAI** — DSGVO-konform, Daten bleiben in der EU
- **Ollama** — Self-Hosted, maximale Datensouveränität

---

## Voraussetzungen

| Komponente | Version | Hinweis |
|---|---|---|
| Python | 3.12+ | Mit `venv`-Unterstützung |
| Node.js | 20+ | Für das Frontend |
| Docker Desktop | 20.10+ | Muss laufen bevor Scans gestartet werden |
| NemoClaw / OpenShell | Aktuell | OpenClaw + OpenShell installiert |
| Git | 2.30+ | Für Repository-Klonen |

---

## Schnellstart

```bash
# 1. Repository klonen
git clone https://github.com/antonio-030/SentinatlCraw.git
cd SentinatlCraw

# 2. Backend einrichten
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 3. Frontend einrichten
cd frontend && npm install && cd ..

# 4. Umgebungsvariablen konfigurieren
cp .env.example .env
# .env anpassen: SENTINEL_ALLOWED_TARGETS, SENTINEL_JWT_SECRET setzen

# 5. Sandbox-Container bauen und starten
docker compose build sandbox
docker compose up -d sandbox

# 6. Backend starten (Port 3001)
python -m uvicorn src.api.server:app --host 0.0.0.0 --port 3001

# 7. Frontend starten (Port 5173) — in neuem Terminal
cd frontend && npm run dev
```

Öffne `http://localhost:5173` — Login: `admin@sentinelclaw.local` / `admin`

### Scan über CLI

```bash
python -m src.cli orchestrate --target scanme.nmap.org --ports 22,80,443 --yes
```

---

## Projektstruktur

```
src/
├── api/                              # FastAPI REST-API (11 Route-Dateien)
│   ├── server.py                     # App-Setup, Health, Kill, WebSocket
│   ├── scan_routes.py                # Scan CRUD + Background-Executor
│   ├── scan_detail_routes.py         # Export, Compare, Report, PDF
│   ├── chat_routes.py                # Agent-Chat + WebSocket-Push
│   ├── auth_routes.py                # Login, Register, RBAC
│   ├── mfa_routes.py                 # MFA Setup/Verify/Login
│   ├── settings_routes.py            # Einstellungen + Profile CRUD
│   ├── approval_routes.py            # Eskalations-Genehmigungen
│   ├── whitelist_routes.py           # Autorisierte Scan-Ziele
│   ├── kill_verification_routes.py   # Kill-Verifikation (5 Checks)
│   ├── websocket_manager.py          # WS-Verbindungsmanager
│   └── agent_tool_routes.py          # Tool-Installation in Sandbox
│
├── agents/
│   ├── nemoclaw_runtime.py           # NemoClaw Runtime (SSH → OpenShell → OpenClaw)
│   ├── chat_agent.py                 # Chat-Agent mit Tool-Loop
│   ├── llm_provider.py               # Provider-Factory (Claude/Azure/Ollama)
│   ├── azure_provider.py             # Azure OpenAI Provider
│   ├── ollama_provider.py            # Ollama Provider
│   ├── scan_executor.py              # docker exec Wrapper
│   └── recon/                        # Recon-Agent Prompts + Parser
│
├── orchestrator/
│   ├── agent.py                      # Orchestrator-Agent (FA-01)
│   ├── multi_phase.py                # 4-Phasen-Koordination
│   └── phases/                       # Host Discovery, Port-Scan, Vuln, SSL, Analyse
│
├── shared/
│   ├── kill_switch.py                # Kill-Switch (4 Pfade)
│   ├── network_kill.py               # Netzwerk-Kill (iptables)
│   ├── os_kill.py                    # OS-Level Process-Kill
│   ├── scope_validator.py            # 7 Scope-Checks
│   ├── sanitizer.py                  # PII-Masking, Input-Sanitizing
│   ├── database.py                   # SQLite (14 Tabellen)
│   ├── auth.py                       # JWT + RBAC + MFA
│   ├── mfa.py                        # TOTP-Funktionen
│   ├── report_generator.py           # Markdown-Reports
│   ├── pdf_generator.py              # PDF-Reports mit Autorisierung
│   └── settings_service.py           # Gecachter Settings-Layer
│
├── sandbox/
│   └── executor.py                   # Docker-Sandbox-Executor
│
└── watchdog/
    ├── service.py                    # Watchdog-Prozess
    └── scope_checks.py              # Scope-Violation-Erkennung

frontend/src/
├── pages/                            # 17 Seiten
├── components/
│   ├── chat/                         # ChatPanel, MarkdownRenderer, ApprovalCard
│   ├── dashboard/                    # SecurityShield (animiert), SeverityChart
│   ├── layout/                       # Sidebar, TopBar, AppLayout
│   └── shared/                       # StatusBadge, MfaCodeInput, etc.
├── hooks/                            # useApi, useWebSocket
└── services/                         # API-Client
```

---

## Konfiguration

Alle Einstellungen über Umgebungsvariablen (`SENTINEL_`-Präfix) oder die Web-UI (Einstellungen-Seite).

| Variable | Default | Beschreibung |
|---|---|---|
| `SENTINEL_LLM_PROVIDER` | `claude-abo` | Provider: `claude-abo`, `claude`, `azure`, `ollama` |
| `SENTINEL_ALLOWED_TARGETS` | *(leer)* | Komma-separierte Scan-Ziele |
| `SENTINEL_JWT_SECRET` | *(dev-default)* | JWT-Signatur-Secret (in Produktion setzen!) |
| `SENTINEL_SANDBOX_TIMEOUT` | `300` | Max. Tool-Laufzeit in Sekunden |
| `SENTINEL_LLM_MAX_TOKENS_PER_SCAN` | `50000` | Token-Budget pro Scan |
| `SENTINEL_LOG_LEVEL` | `INFO` | DEBUG, INFO, WARNING, ERROR |

Vollständige Liste: siehe `.env.example`

---

## Sicherheit

### Kill-Switch (4 unabhängige Pfade)

| Pfad | Methode | Latenz |
|---|---|---|
| 1. Application | Atomares Flag, alle Scans gestoppt | <1s |
| 2. Container | Docker SIGKILL + Netzwerk-Disconnect | <3s |
| 3. Netzwerk | iptables DROP auf Scan-Netzwerk | <1s |
| 4. OS-Level | `kill -9` auf Scanner-Prozesse | <5s |

Auslösbar über: Web-UI (roter Kill-Button), API (`POST /api/v1/kill`), CLI, Chat (`/kill`).

Wiederherstellung über: Monitoring-Seite → "System wiederherstellen" Button.

### Scope-Validator (7 Checks)

Jeder Tool-Aufruf wird gegen 7 Regeln geprüft. Bei Verstoß → sofortige Blockierung:

1. Target in Whitelist?
2. Target nicht in Blacklist?
3. Target nicht in verbotenen IP-Ranges?
4. Port im erlaubten Bereich?
5. Zeitfenster eingehalten?
6. Eskalationsstufe erlaubt?
7. Tool in Allowlist?

---

## Tests

```bash
# Unit-Tests
python -m pytest tests/unit/ -v

# E2E-Tests (Scan, Kill-Switch, Scope)
python -m pytest tests/e2e/ -v

# Frontend TypeScript-Check
cd frontend && npx tsc --noEmit
```

---

## CI/CD

GitHub Actions Pipeline (`.github/workflows/ci.yml`):
- **Lint** — Ruff + Black
- **Test Backend** — pytest Unit-Tests
- **Test Frontend** — TypeScript Build-Check
- **Security** — pip-audit + npm audit

---

## Lizenz

Proprietary — Alle Rechte vorbehalten.

---

## Autor

**Jaciel Antonio Acea Ruiz**
