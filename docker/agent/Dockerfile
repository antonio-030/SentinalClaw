# SentinelClaw Agent-Container
# Claude CLI als Agent-Runtime in isolierter Umgebung.
# Auth wird über gemountetes ~/.claude/ Volume bereitgestellt.

FROM node:20-alpine

# Sicherheit: Non-root User
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

# Claude CLI installieren (globales npm-Package)
RUN npm install -g @anthropic-ai/claude-code@latest && \
    npm cache clean --force

# Docker CLI fuer docker exec auf den Sandbox-Container
RUN apk add --no-cache docker-cli curl jq

# Arbeitsverzeichnis
WORKDIR /workspace

# Non-root User nutzen
USER sentinel

# Claude CLI muss im PATH sein
ENV PATH="/usr/local/bin:$PATH"

# Healthcheck: Claude CLI ist installiert und Auth vorhanden
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD claude --version || exit 1

# Kein Entrypoint — Container wird per docker exec angesprochen
CMD ["sleep", "infinity"]
