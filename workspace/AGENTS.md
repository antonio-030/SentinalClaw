# Multi-Agent-Konfiguration

## Verfügbare Agenten
- **sentinelclaw**: Haupt-Security-Agent (OSINT, Scanning, Analyse)
- **orchestrator**: Koordiniert Multi-Phase-Scans

## Koordinationsregeln
- Nur ein Agent pro Scan-Ziel gleichzeitig
- Ergebnisse werden in der zentralen DB gespeichert
- Kill-Switch stoppt ALLE Agenten sofort
