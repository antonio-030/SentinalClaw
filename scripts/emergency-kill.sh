#!/usr/bin/env bash
# Emergency-Kill Script für SentinelClaw
#
# Notfall-Skript für SSH-Zugriff ohne laufende Anwendung.
# Stoppt alle Container, trennt Netzwerke, beendet Scanner-Prozesse.
# Schreibt ein Protokoll nach /var/log/sentinelclaw/emergency-kill.log
#
# Verwendung: sudo bash scripts/emergency-kill.sh

set -euo pipefail

LOG_DIR="/var/log/sentinelclaw"
LOG_FILE="${LOG_DIR}/emergency-kill.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Log-Verzeichnis erstellen falls nötig
mkdir -p "${LOG_DIR}"

log() {
    local message="[${TIMESTAMP}] $1"
    echo "${message}" | tee -a "${LOG_FILE}"
}

log "=== SentinelClaw Emergency Kill gestartet ==="
log "Ausgeführt von: $(whoami)@$(hostname)"

# Schritt 1: Netzwerke trennen
log "Schritt 1: Docker-Netzwerke trennen..."
for network in sentinel-scanning sentinel-internal; do
    if docker network inspect "${network}" >/dev/null 2>&1; then
        docker network disconnect -f "${network}" sentinelclaw-sandbox 2>/dev/null && \
            log "  Netzwerk '${network}' getrennt" || \
            log "  Netzwerk '${network}': Container nicht verbunden"
    else
        log "  Netzwerk '${network}' existiert nicht"
    fi
done

# Schritt 2: Alle SentinelClaw-Container stoppen und entfernen
log "Schritt 2: Container stoppen..."
CONTAINERS=$(docker ps -a --filter "name=sentinelclaw-" --format "{{.Names}}" 2>/dev/null || true)
if [ -n "${CONTAINERS}" ]; then
    echo "${CONTAINERS}" | while read -r container; do
        docker rm -f "${container}" 2>/dev/null && \
            log "  Container '${container}' entfernt" || \
            log "  Container '${container}' konnte nicht entfernt werden"
    done
else
    log "  Keine SentinelClaw-Container gefunden"
fi

# Schritt 3: Scanner-Prozesse beenden
log "Schritt 3: Scanner-Prozesse beenden..."
KILLED=0
for proc in nmap nuclei curl nikto sslscan; do
    if pkill -9 "${proc}" 2>/dev/null; then
        log "  Prozess '${proc}' beendet"
        KILLED=$((KILLED + 1))
    fi
done
log "  ${KILLED} Prozess-Gruppen beendet"

# Schritt 4: Zusammenfassung
log "=== Emergency Kill abgeschlossen ==="
log "Log geschrieben nach: ${LOG_FILE}"
