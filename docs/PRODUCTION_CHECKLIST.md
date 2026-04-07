# SentinelClaw — Production Checklist

> **Autor:** Jaciel Antonio Acea Ruiz
> **Stand:** 2026-04-07
> **Status:** Aktiv
> **Zweck:** Vollständige Prüfliste vor jedem Produktiv-Deployment

---

## 1. Pre-Deployment

- [ ] `SENTINEL_JWT_SECRET` gesetzt (mindestens 32 Zeichen, kryptographisch zufällig)
- [ ] `SENTINEL_DEBUG=false` in der Produktivumgebung
- [ ] PostgreSQL-Datenbank konfiguriert und erreichbar (kein SQLite in Production)
- [ ] Datenbankmigrationen ausgeführt und verifiziert
- [ ] SSL-Zertifikate gültig und installiert (Let's Encrypt oder eigene CA)
- [ ] Backups getestet — mindestens ein vollständiger Restore-Durchlauf
- [ ] Alle `.env.example`-Variablen in der Produktivumgebung gesetzt
- [ ] CI-Pipeline grün (Lint, Tests, Security-Audit, SAST, Docker-Scan)

## 2. Netzwerk

- [ ] TLS 1.3 für alle externen Verbindungen erzwungen
- [ ] TLS zwischen internen Services (API ↔ Datenbank, API ↔ MCP-Server)
- [ ] Firewall-Regeln: nur benötigte Ports offen (443, ggf. 8080 intern)
- [ ] Docker-Netzwerk-Isolation verifiziert (eigenes Bridge-Network)
- [ ] CORS auf erlaubte Origins eingeschränkt (keine Wildcards)
- [ ] Rate-Limiting auf Reverse-Proxy-Ebene aktiv (nginx/Caddy)
- [ ] Kein direkter Zugriff auf Datenbank von außen möglich

## 3. Authentifizierung

- [ ] MFA für alle Admin-Konten aktiviert (TOTP via pyotp)
- [ ] Standard-Admin-Passwort geändert (`must_change_password` erzwungen)
- [ ] Rate-Limiting für Login-Endpunkt aktiv (max. 5 Versuche / Minute)
- [ ] JWT-Token-Rotation konfiguriert (Access: 15 Min., Refresh: 7 Tage)
- [ ] Session-Invalidierung bei Passwortänderung funktionsfähig
- [ ] Brute-Force-Schutz: Account-Lockout nach fehlgeschlagenen Versuchen

## 4. Monitoring

- [ ] Prometheus erreichbar und scrapet alle Endpunkte
- [ ] Grafana-Dashboard geladen (System-Metriken, API-Latenz, Scan-Statistiken)
- [ ] Alert-Rules konfiguriert (CPU > 80%, Disk > 90%, API-Fehlerrate > 5%)
- [ ] Log-Rotation aktiv (max. 100 MB pro Logdatei, 7 Tage Aufbewahrung)
- [ ] Health-Check-Endpunkte für alle Services erreichbar
- [ ] Uptime-Monitoring eingerichtet (externer Ping auf `/health`)

## 5. DSGVO

- [ ] Aufbewahrungsfristen für Scan-Daten gesetzt und automatisch durchgesetzt
- [ ] AVV (Auftragsverarbeitungsvertrag) für LLM-Provider unterzeichnet
- [ ] Datenexport getestet (DSGVO Art. 20 — Recht auf Datenübertragbarkeit)
- [ ] Datenlöschung getestet (DSGVO Art. 17 — Recht auf Löschung)
- [ ] Verarbeitungsverzeichnis (Art. 30) dokumentiert
- [ ] Datenschutzerklärung aktuell und erreichbar
- [ ] Keine personenbezogenen Daten in Logs (PII-Maskierung verifiziert)

## 6. Sandbox

- [ ] Docker-Härtung verifiziert: `cap_drop: ALL` für alle Container
- [ ] Nur benötigte Capabilities hinzugefügt (`NET_RAW` für nmap)
- [ ] Container laufen als non-root User (`USER` Directive gesetzt)
- [ ] Read-only Filesystem wo möglich (`read_only: true`)
- [ ] Resource-Limits gesetzt (CPU, Memory, PIDs) für alle Container
- [ ] Netzwerk-Whitelist aktiv — Container erreichen nur freigegebene Ziele
- [ ] Timeouts für alle Tool-Ausführungen konfiguriert
- [ ] Kein privilegierter Modus (`privileged: false`)

## 7. Backup & Recovery

- [ ] Automatisches Datenbank-Backup aktiv (mindestens täglich)
- [ ] Backup-Verschlüsselung aktiviert (AES-256)
- [ ] Restore vollständig getestet (Datenbank + Konfiguration)
- [ ] RPO dokumentiert (Recovery Point Objective — max. akzeptabler Datenverlust)
- [ ] RTO dokumentiert (Recovery Time Objective — max. akzeptable Ausfallzeit)
- [ ] Backup-Speicherort getrennt vom Produktivsystem
- [ ] Backup-Integrität wird regelmäßig geprüft (Checksummen)
