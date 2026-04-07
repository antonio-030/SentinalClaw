#!/usr/bin/env bash
# ============================================================
# SentinelClaw — Erstinstallation
# ============================================================
# Startet NemoClaw, baut Container, richtet Backend + Frontend ein.
# Aufruf: ./scripts/setup.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "=========================================="
echo "  SentinelClaw — Erstinstallation"
echo "=========================================="
echo ""

# --- Voraussetzungen prüfen ---
command -v docker >/dev/null 2>&1 || error "Docker nicht gefunden. Installiere Docker Desktop."
command -v python3 >/dev/null 2>&1 || error "Python3 nicht gefunden."
command -v node >/dev/null 2>&1 || error "Node.js nicht gefunden."
docker info >/dev/null 2>&1 || error "Docker-Daemon läuft nicht. Starte Docker Desktop."
info "Voraussetzungen geprüft"

# --- .env erstellen falls nicht vorhanden ---
if [ ! -f .env ]; then
    cp .env.example .env
    info ".env aus .env.example erstellt"
    warn "Bitte .env anpassen: SENTINEL_ALLOWED_TARGETS und SENTINEL_JWT_SECRET setzen"
else
    info ".env existiert bereits"
fi

# --- NemoClaw Gateway starten ---
if command -v openshell >/dev/null 2>&1; then
    # Prüfe ob Gateway bereits läuft
    if openshell status 2>&1 | grep -q "Connected"; then
        info "NemoClaw Gateway läuft bereits"
    else
        info "Starte NemoClaw Gateway (dauert ~60 Sekunden)..."
        openshell gateway start 2>&1 | tail -3
        info "NemoClaw Gateway gestartet"
    fi
else
    warn "openshell CLI nicht gefunden — NemoClaw wird nicht gestartet"
    warn "System nutzt Fallback-Provider (Claude API / Ollama)"
    warn "Installiere openshell: https://docs.nvidia.com/nemoclaw/latest/"
fi

# --- Docker-Container bauen und starten ---
info "Baue und starte Docker-Container..."
docker compose up -d --build 2>&1 | tail -5
info "Container gestartet"

# --- Warte auf Healthchecks ---
info "Warte auf Healthchecks (30 Sekunden)..."
sleep 30

echo ""
echo "--- Container-Status ---"
docker ps --format "table {{.Names}}\t{{.Status}}" --filter "label=sentinelclaw"
echo ""

# --- Python-Umgebung einrichten ---
if [ ! -d .venv ]; then
    info "Erstelle Python-Umgebung..."
    python3 -m venv .venv
fi
info "Installiere Python-Dependencies..."
.venv/bin/pip install -e ".[dev]" --quiet 2>&1 | tail -1
info "Backend bereit"

# --- Frontend einrichten ---
if [ ! -d frontend/node_modules ]; then
    info "Installiere Frontend-Dependencies..."
    cd frontend && npm install --silent 2>&1 | tail -1 && cd ..
fi
info "Frontend bereit"

echo ""
echo "=========================================="
echo "  Installation abgeschlossen!"
echo "=========================================="
echo ""
echo "  Backend starten:  .venv/bin/uvicorn src.api.server:app --host 0.0.0.0 --port 3001"
echo "  Frontend starten: cd frontend && npm run dev"
echo ""
echo "  Web-UI:   http://localhost:5173"
echo "  Login:    admin@sentinelclaw.local / admin"
echo ""
echo "  Optional:"
echo "    Monitoring: docker compose --profile monitoring up -d"
echo "    PostgreSQL: docker compose --profile postgresql up -d"
echo ""
