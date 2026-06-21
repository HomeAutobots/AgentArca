#!/usr/bin/env bash
# src/detect/immudb-setup.sh
#
# Item 13: External tamper-resistant sink setup (immudb).
# ADR-007 D3, SPEC-07 section 3 + section 10-E.
#
# immudb is a cryptographically verifiable, append-only database.
# It is deployed as a Docker Compose sidecar (see docker-compose.detect.yml).
# The container writes to its ingest endpoint; no read-back or delete is permitted
# from inside the dev container.
#
# The FOUR non-negotiable R-b annotation conditions (SPEC-07 section 3):
#   (a) Collector on the HOST SIDE of the ADR-002 boundary (host.docker.internal or
#       Docker bridge address), NOT an arbitrary external host.
#   (b) Write-only / append-only from the container. No read-back, no list, no delete.
#   (c) Separation of duties: whoever changes the system cannot alter the sink contents.
#   (d) Any off-host forwarding hop is to a destination the agent cannot reach and
#       cannot read from; that hop is on the egress allowlist.
#
# Architecture in this deployment:
#   - immudb runs as a Docker Compose service on the same Docker network.
#   - The custom ingest proxy (ingest-proxy service) wraps immudb's REST API and
#     ONLY allows POST to /ingest. GET, DELETE, PUT, and PATCH are rejected (405).
#   - The dev container (devcontainer service) can POST to the ingest proxy at
#     http://ingest-proxy:3001/ingest (write-only).
#   - The dev container CANNOT read immudb directly (different port, not exposed
#     to the devcontainer's network path).
#   - The immudb admin interface (port 8080) and gRPC API (port 3322) are NOT
#     reachable from the devcontainer's network path.
#   - This satisfies conditions (a), (b), (c) per SPEC-07 section 3.
#
# Condition (d): there is NO off-host forwarding hop in this deployment. Logs stay
# host-side in immudb. If you add remote forwarding to a SIEM, that hop must be to
# a destination the agent cannot reach and must be on the egress allowlist.
#
# Usage:
#   ./immudb-setup.sh setup   - Initialize immudb and create the audit collection.
#   ./immudb-setup.sh verify  - Run the write-only proof (OI-13-E / AC-13-N02).
#   ./immudb-setup.sh status  - Check if sink is healthy.
#   ./immudb-setup.sh teardown - Stop the sink containers.
#
# Environment:
#   INGEST_URL  - The ingest endpoint (default: http://localhost:3001/ingest)
#   IMMUDB_PORT - immudb gRPC port (default: 3322)
#   IMMUDB_HTTP_PORT - immudb HTTP port (default: 8080)
#
# See also: docker-compose.detect.yml (sink Compose service definitions).

set -euo pipefail

INGEST_URL="${INGEST_URL:-http://localhost:3001/ingest}"
IMMUDB_PORT="${IMMUDB_PORT:-3322}"
IMMUDB_HTTP_PORT="${IMMUDB_HTTP_PORT:-8080}"
COMPOSE_FILE="$(dirname "$0")/docker-compose.detect.yml"

usage() {
  echo "Usage: $0 {setup|verify|status|teardown}" >&2
  exit 1
}

cmd_setup() {
  echo "[immudb-setup] Starting sink services via Compose..." >&2
  docker compose -f "$COMPOSE_FILE" up -d immudb ingest-proxy otel-collector
  echo "[immudb-setup] Waiting for immudb to be ready (up to 30s)..." >&2
  local i=0
  while [ $i -lt 30 ]; do
    if curl -sf "http://localhost:${IMMUDB_HTTP_PORT}/readyz" >/dev/null 2>&1; then
      echo "[immudb-setup] immudb is ready." >&2
      break
    fi
    sleep 1
    i=$((i + 1))
  done
  if [ $i -ge 30 ]; then
    echo "[immudb-setup] ERROR: immudb did not become ready within 30s." >&2
    exit 1
  fi
  echo "[immudb-setup] Waiting for ingest-proxy to be ready (up to 15s)..." >&2
  i=0
  while [ $i -lt 15 ]; do
    if curl -sf "http://localhost:3001/health" >/dev/null 2>&1; then
      echo "[immudb-setup] ingest-proxy is ready." >&2
      break
    fi
    sleep 1
    i=$((i + 1))
  done
  if [ $i -ge 15 ]; then
    echo "[immudb-setup] ERROR: ingest-proxy did not become ready within 15s." >&2
    exit 1
  fi
  echo "[immudb-setup] Sink setup complete." >&2
  echo "[immudb-setup] HOOK_LOG_SINK and MCP_DETECTION_SINK should be set to: ${INGEST_URL}" >&2
}

cmd_verify() {
  # OI-13-E / AC-13-N02: write-only proof.
  # POST must succeed; GET and DELETE must be rejected.
  # This is the LOAD-BEARING proof (security-reviewer gate).
  echo "[immudb-setup] === WRITE-ONLY SINK PROOF (OI-13-E / AC-13-N02) ===" >&2

  # 1. POST (write) - must succeed
  echo "[immudb-setup] 1. Testing POST (write) to ${INGEST_URL}..." >&2
  POST_RESULT=$(curl -sf -w "\n%{http_code}" -X POST "${INGEST_URL}" \
    -H "Content-Type: application/json" \
    -d '{"source":"sink-verify-test","timestamp":"2026-06-14T00:00:00Z","message":"write-only-proof-test","level":"INFO"}' \
    2>&1) || true
  POST_HTTP_CODE=$(echo "$POST_RESULT" | tail -1)
  POST_BODY=$(echo "$POST_RESULT" | head -1)
  echo "[immudb-setup] POST result: HTTP ${POST_HTTP_CODE} / body: ${POST_BODY}" >&2
  if echo "$POST_HTTP_CODE" | grep -qE '^(200|201|204)$'; then
    echo "[immudb-setup] POST: PASS (${POST_HTTP_CODE}) - write succeeded." >&2
  else
    echo "[immudb-setup] POST: FAIL (${POST_HTTP_CODE}) - write SHOULD succeed." >&2
    exit 1
  fi

  # 2. GET (read) - must be rejected
  echo "[immudb-setup] 2. Testing GET (read) to ${INGEST_URL}..." >&2
  GET_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${INGEST_URL}" 2>&1) || true
  echo "[immudb-setup] GET result: HTTP ${GET_HTTP_CODE}" >&2
  if echo "$GET_HTTP_CODE" | grep -qE '^(403|404|405|000)$'; then
    echo "[immudb-setup] GET: PASS (${GET_HTTP_CODE}) - read rejected as required." >&2
  else
    echo "[immudb-setup] GET: FAIL (${GET_HTTP_CODE}) - read MUST be rejected (403/404/405/000)." >&2
    exit 1
  fi

  # 3. DELETE - must be rejected
  echo "[immudb-setup] 3. Testing DELETE to ${INGEST_URL}..." >&2
  DEL_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${INGEST_URL}" 2>&1) || true
  echo "[immudb-setup] DELETE result: HTTP ${DEL_HTTP_CODE}" >&2
  if echo "$DEL_HTTP_CODE" | grep -qE '^(403|404|405|000)$'; then
    echo "[immudb-setup] DELETE: PASS (${DEL_HTTP_CODE}) - delete rejected as required." >&2
  else
    echo "[immudb-setup] DELETE: FAIL (${DEL_HTTP_CODE}) - delete MUST be rejected." >&2
    exit 1
  fi

  echo "[immudb-setup] === WRITE-ONLY PROOF: ALL THREE CHECKS PASSED ===" >&2
  echo "[immudb-setup] POST: HTTP ${POST_HTTP_CODE} (succeeded)" >&2
  echo "[immudb-setup] GET:  HTTP ${GET_HTTP_CODE} (rejected)" >&2
  echo "[immudb-setup] DELETE: HTTP ${DEL_HTTP_CODE} (rejected)" >&2
  echo "[immudb-setup] Sink satisfies SPEC-07 section 3 condition (b): write-only." >&2
}

cmd_status() {
  echo "[immudb-setup] Checking sink status..." >&2
  if curl -sf "http://localhost:${IMMUDB_HTTP_PORT}/readyz" >/dev/null 2>&1; then
    echo "[immudb-setup] immudb: HEALTHY" >&2
  else
    echo "[immudb-setup] immudb: UNREACHABLE (port ${IMMUDB_HTTP_PORT})" >&2
  fi
  if curl -sf "http://localhost:3001/health" >/dev/null 2>&1; then
    echo "[immudb-setup] ingest-proxy: HEALTHY" >&2
  else
    echo "[immudb-setup] ingest-proxy: UNREACHABLE (port 3001)" >&2
  fi
}

cmd_teardown() {
  echo "[immudb-setup] Tearing down sink services..." >&2
  docker compose -f "$COMPOSE_FILE" down --remove-orphans || true
  echo "[immudb-setup] Teardown complete." >&2
}

case "${1:-}" in
  setup)    cmd_setup ;;
  verify)   cmd_verify ;;
  status)   cmd_status ;;
  teardown) cmd_teardown ;;
  *)        usage ;;
esac
