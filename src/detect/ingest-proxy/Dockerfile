# src/detect/ingest-proxy/Dockerfile
# Write-only ingest proxy for the detection audit sink.
# Item 13, ADR-007 D3, SPEC-07 section 3 condition (b).
#
# Single-stage build: no external npm deps, no native binaries, no build tools needed.
# node:22-alpine is already minimal. Pinned by digest. Re-pin on upgrade.
# node:22-alpine digest pinned 2026-06-14.
# To re-pin: docker pull node:22-alpine && docker inspect node:22-alpine | jq '.[].RepoDigests'
FROM node:22-alpine@sha256:9385cd9f3001dfc3431e8ead12c43e9e1f87cc1b9b5c6cfd0f73865d405b27c4

# Non-root user (least privilege).
RUN addgroup -g 10001 ingest && adduser -u 10001 -G ingest -s /bin/false -D ingest

WORKDIR /app
COPY server.js package.json ./
RUN chown -R ingest:ingest /app

USER 10001:10001
EXPOSE 3001

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["node", "server.js"]
