# SentinelClaw API — FastAPI Backend
# Non-root User, Health-Check, Docker-Socket für Sandbox-Steuerung

FROM python:3.12-slim

WORKDIR /app

# System-Dependencies (curl für Healthcheck, ssh für OpenShell-Zugriff)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl openssh-client && rm -rf /var/lib/apt/lists/*

# Python-Dependencies (Layer-Caching optimiert)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || pip install --no-cache-dir -e .

# App-Code kopieren
COPY src/ src/
COPY workspace/ workspace/

# Daten-Verzeichnis erstellen
RUN mkdir -p data

# Non-root User
RUN useradd -m sentinelclaw && \
    chown -R sentinelclaw:sentinelclaw /app

EXPOSE 3001

HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -sf http://localhost:3001/health || exit 1

CMD ["python", "-m", "uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "3001"]
