# SentinelClaw Agent-Container
# OpenClaw Agent-Runtime in NemoClaw/OpenShell-Isolation.
# LLM-Provider wird über den NemoClaw-Gateway konfiguriert.

FROM python:3.12-slim

# Sicherheit: Non-root User
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

# NemoClaw/OpenClaw installieren
RUN pip install --no-cache-dir nemoclaw openclaw

# Docker CLI für docker exec auf den Sandbox-Container
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io curl jq && rm -rf /var/lib/apt/lists/*

# Arbeitsverzeichnis
WORKDIR /workspace

# Non-root User nutzen
USER sentinel

# Healthcheck: OpenClaw ist installiert
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD openclaw --version || exit 1

# Kein Entrypoint — Container wird per docker exec angesprochen
CMD ["sleep", "infinity"]
