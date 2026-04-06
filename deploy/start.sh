#!/usr/bin/env bash
# SentinelClaw — Produktions-Startup-Script
# Prüft Voraussetzungen, erstellt SSL-Zertifikate und startet alle Services.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.prod.yml"
ENV_FILE="${SCRIPT_DIR}/.env.prod"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.prod.example"
CERT_DIR="${SCRIPT_DIR}/certs"
KEY_DIR="${SCRIPT_DIR}/private"

# Farbige Ausgabe für bessere Lesbarkeit
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== SentinelClaw — Deployment ==="

# 1. Prüfe ob Docker läuft
if ! docker info > /dev/null 2>&1; then
  echo -e "${RED}[FEHLER] Docker läuft nicht. Bitte Docker starten.${NC}"
  exit 1
fi
echo -e "${GREEN}[OK] Docker läuft${NC}"

# 2. Prüfe ob .env.prod existiert — sonst Vorlage kopieren
if [ ! -f "${ENV_FILE}" ]; then
  if [ -f "${ENV_EXAMPLE}" ]; then
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    echo -e "${YELLOW}[HINWEIS] ${ENV_FILE} wurde aus Vorlage erstellt.${NC}"
    echo -e "${RED}[AKTION] Bitte ${ENV_FILE} konfigurieren und erneut starten.${NC}"
    exit 1
  else
    echo -e "${RED}[FEHLER] Weder ${ENV_FILE} noch ${ENV_EXAMPLE} gefunden.${NC}"
    exit 1
  fi
fi
echo -e "${GREEN}[OK] Konfiguration gefunden${NC}"

# Umgebungsvariablen aus .env.prod laden (ohne export in Shell)
set -a
# shellcheck source=/dev/null
source "${ENV_FILE}"
set +a

# 3. Prüfe ob JWT-Secret gesetzt ist
if [ -z "${SENTINEL_JWT_SECRET:-}" ] || [ "${SENTINEL_JWT_SECRET}" = "DEIN_JWT_SECRET_HIER" ]; then
  echo -e "${RED}[FEHLER] SENTINEL_JWT_SECRET ist nicht gesetzt oder enthält den Platzhalter.${NC}"
  echo "  Generieren: python3 -c \"import secrets; print(secrets.token_urlsafe(64))\""
  exit 1
fi
echo -e "${GREEN}[OK] JWT-Secret konfiguriert${NC}"

# 4. Prüfe ob LLM-API-Key gesetzt ist
if [ -z "${NEMOCLAW_LLM_API_KEY:-}" ]; then
  PROVIDER="${NEMOCLAW_LLM_PROVIDER:-claude}"
  if [ "${PROVIDER}" != "ollama" ]; then
    echo -e "${YELLOW}[WARNUNG] NEMOCLAW_LLM_API_KEY ist nicht gesetzt (Provider: ${PROVIDER}).${NC}"
    echo "  Der Agent kann ohne API-Key keine LLM-Anfragen senden."
  fi
fi

# 5. Prüfe SSL-Zertifikate — erstelle Self-Signed wenn nicht vorhanden
if [ ! -f "${CERT_DIR}/sentinelclaw.crt" ] || [ ! -f "${KEY_DIR}/sentinelclaw.key" ]; then
  echo -e "${YELLOW}[SSL] Keine Zertifikate gefunden — erstelle Self-Signed...${NC}"
  mkdir -p "${CERT_DIR}" "${KEY_DIR}"
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${KEY_DIR}/sentinelclaw.key" \
    -out "${CERT_DIR}/sentinelclaw.crt" \
    -subj "/CN=sentinelclaw.local" \
    2>/dev/null
  echo -e "${GREEN}[OK] Self-Signed-Zertifikat erstellt (365 Tage gültig)${NC}"
else
  echo -e "${GREEN}[OK] SSL-Zertifikate vorhanden${NC}"
fi

# 6. Services starten
echo ""
echo "Starte Services..."
docker compose -f "${COMPOSE_FILE}" up -d --build

# 7. Warte auf Service-Start
echo "Warte 15 Sekunden auf Service-Start..."
sleep 15

# 8. Health-Check
echo ""
if curl -sf http://localhost:3001/health > /dev/null 2>&1; then
  echo -e "${GREEN}[OK] API-Health-Check bestanden${NC}"
else
  echo -e "${YELLOW}[WARNUNG] Health-Check fehlgeschlagen — Services starten möglicherweise noch.${NC}"
  echo "  Prüfe mit: docker compose -f ${COMPOSE_FILE} logs -f api"
fi

# 9. Zusammenfassung
PROVIDER="${NEMOCLAW_LLM_PROVIDER:-claude}"
echo ""
echo "=========================================="
echo " SentinelClaw — Deployment-Zusammenfassung"
echo "=========================================="
echo "  URL:          https://localhost"
echo "  API:          http://localhost:3001"
echo "  Login:        admin@sentinelclaw.local / admin"
echo "  LLM-Provider: ${PROVIDER}"
echo "  Debug-Modus:  ${SENTINEL_DEBUG:-false}"
echo ""
echo "  Passwort nach dem ersten Login ändern!"
echo "=========================================="
