# SentinelClaw Frontend — Multi-Stage Build
# Stage 1: Vite-Build | Stage 2: Nginx Static-Serving

FROM node:20-alpine AS build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

FROM nginx:1.27-alpine
LABEL maintainer="sentinelclaw" \
      description="SentinelClaw Frontend — React Web-UI" \
      sentinelclaw="true"

COPY --from=build /app/dist /usr/share/nginx/html
COPY docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget --spider --quiet http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
