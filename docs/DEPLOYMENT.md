# SentinelClaw — Deployment-Anleitung

- **Autor**: Jaciel Antonio Acea Ruiz
- **Datum**: 2026-04-06
- **Status**: Aktiv

---

## 1. Voraussetzungen

| Anforderung | Minimum |
|---|---|
| Server-OS | Linux (Ubuntu 22.04+, Debian 12+) oder macOS |
| Docker | Version 24+ mit Docker Compose v2 |
| RAM | 4 GB (empfohlen: 8 GB) |
| Festplatte | 10 GB frei (Images + Daten) |
| SSL-Zertifikat | Self-Signed oder Let's Encrypt |
| Netzwerk | Port 80, 443 offen |

---

## 2. Schnellstart

```bash
# Repository klonen
git clone https://github.com/antonio-030/SentinelClaw.git
cd SentinelClaw

# Produktions-Konfiguration erstellen
cp .env.example deploy/.env.prod
```

**`deploy/.env.prod` bearbeiten** — mindestens diese Werte setzen:

```bash
# PFLICHT: Sicheres JWT-Secret generieren (mind. 32 Zeichen)
SENTINEL_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")

# PFLICHT: Erlaubte Scan-Ziele definieren
SENTINEL_ALLOWED_TARGETS=10.10.10.0/24

# Produktion: Debug ausschalten (deaktiviert /docs und /redoc)
SENTINEL_DEBUG=false

# LLM-Provider: NemoClaw (Standard)
SENTINEL_LLM_PROVIDER=nemoclaw
```

**NemoClaw LLM-Provider konfigurieren** — in `deploy/docker-compose.prod.yml` oder als Environment-Variable:

```bash
# LLM-Provider im NemoClaw-Gateway setzen:
NEMOCLAW_LLM_PROVIDER=claude       # claude, azure oder ollama
NEMOCLAW_LLM_API_KEY=sk-ant-xxx    # API-Key für den gewählten Provider
```

Der NemoClaw-Gateway routet die LLM-Anfragen über den OpenShell
Privacy-Router an den konfigurierten Provider.

### SSL-Zertifikat erstellen (Self-Signed fuer Tests)

```bash
mkdir -p deploy/certs deploy/private

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout deploy/private/sentinelclaw.key \
  -out deploy/certs/sentinelclaw.crt \
  -subj "/CN=sentinel.firma.de"
```

### Starten

```bash
cd deploy
docker compose -f docker-compose.prod.yml up -d
```

Die Anwendung ist jetzt erreichbar unter: `https://<server-ip>`

---

## 3. Erster Login

| Feld | Wert |
|---|---|
| E-Mail | `admin@sentinelclaw.local` |
| Passwort | `admin` |

**Wichtig**: Das Standard-Passwort nach dem ersten Login sofort ändern.
Das System erstellt den Admin-Account automatisch beim ersten Start.

---

## 4. SSL mit Let's Encrypt

Fuer Produktionsumgebungen mit eigenem Domainnamen:

```bash
# Certbot installieren (Ubuntu)
sudo apt install certbot

# Zertifikat anfordern (Port 80 muss offen sein)
sudo certbot certonly --standalone -d sentinel.firma.de

# Zertifikate in deploy/ verlinken
cp /etc/letsencrypt/live/sentinel.firma.de/fullchain.pem deploy/certs/sentinelclaw.crt
cp /etc/letsencrypt/live/sentinel.firma.de/privkey.pem deploy/private/sentinelclaw.key

# Neustart damit Nginx die neuen Zertifikate lädt
docker compose -f docker-compose.prod.yml restart frontend
```

**Automatische Erneuerung** (Crontab):

```bash
0 3 * * 1 certbot renew --quiet && docker compose -f /pfad/zu/deploy/docker-compose.prod.yml restart frontend
```

---

## 5. Backup

Die SQLite-Datenbank enthält alle Scan-Ergebnisse, Benutzer und Konfigurationen.

```bash
# Manuelles Backup
mkdir -p backups
cp data/sentinelclaw.db "backups/sentinelclaw_$(date +%Y%m%d_%H%M%S).db"
```

**Automatisches tägliches Backup** (Crontab):

```bash
0 2 * * * cp /pfad/zu/data/sentinelclaw.db "/pfad/zu/backups/sentinelclaw_$(date +\%Y\%m\%d).db"
```

**Wiederherstellen**:

```bash
docker compose -f docker-compose.prod.yml down
cp backups/sentinelclaw_20260406.db data/sentinelclaw.db
docker compose -f docker-compose.prod.yml up -d
```

---

## 6. Updates

```bash
cd /pfad/zu/SentinelClaw

# Neuesten Code holen
git pull

# Images neu bauen und starten
cd deploy
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```

**Empfehlung**: Vor jedem Update ein Backup der Datenbank erstellen (siehe Abschnitt 5).

---

## 7. Monitoring

### Health-Endpoint

```bash
curl -k https://localhost/health
```

Antwort im Produktionsmodus:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "mode": "production",
  "checks": {
    "database": true,
    "docker": true,
    "sandbox": true,
    "jwt_secure": true
  }
}
```

### Logs

```bash
# Alle Services
docker compose -f docker-compose.prod.yml logs -f

# Nur API
docker compose -f docker-compose.prod.yml logs -f api

# Nur Watchdog
docker compose -f docker-compose.prod.yml logs -f watchdog
```

### Container-Status

```bash
docker compose -f docker-compose.prod.yml ps
```

---

## 8. Troubleshooting

### API startet nicht im Produktionsmodus

**Symptom**: `RuntimeError: Server kann nicht im Produktionsmodus starten`

**Ursache**: Produktions-Anforderungen nicht erfuellt (z.B. JWT-Secret fehlt).

**Lösung**: Logs prüfen und `deploy/.env.prod` korrigieren:

```bash
docker compose -f docker-compose.prod.yml logs api
```

### Sandbox-Container nicht gefunden

**Symptom**: Health-Endpoint zeigt `sandbox_running: false`

**Lösung**:

```bash
docker compose -f docker-compose.prod.yml up -d sandbox
```

### Frontend zeigt "502 Bad Gateway"

**Symptom**: Nginx kann die API nicht erreichen.

**Lösung**: Prüfen ob der API-Container läuft und gesund ist:

```bash
docker compose -f docker-compose.prod.yml ps api
docker compose -f docker-compose.prod.yml logs api
```

### SSL-Zertifikat abgelaufen

**Symptom**: Browser zeigt SSL-Warnung.

**Lösung**: Neues Zertifikat erstellen (siehe Abschnitt 4) und Frontend neustarten.

### Datenbank gesperrt (SQLite)

**Symptom**: `database is locked` Fehler in den Logs.

**Lösung**: Sicherstellen dass nur eine API-Instanz läuft. SQLite unterstützt keine parallelen Schreibzugriffe.

```bash
docker compose -f docker-compose.prod.yml restart api
```
