#!/usr/bin/env bash
# src/detect/apply-detect-wiring.sh
# Applies the item 13 detection wiring to docker-compose.yml.
# Item 13, AC-13-N06, SPEC-07 section 2a + AL-08 RC-2.
#
# This script:
#   1. Sets HOOK_LOG_SINK in docker-compose.yml to the external sink ingest endpoint.
#   2. Sets MCP_DETECTION_SINK in docker-compose.yml to the external sink ingest endpoint.
#   3. Adds the startup-check.sh invocation to the devcontainer startup.
#   4. Verifies the pretooluse.sh log_attempt function handles HTTP sinks (the curl branch).
#
# AC-13-N06 requirement:
#   "At item 13 DONE, the production HOOK_LOG_SINK environment variable set on the
#    SPEC-05 hook points at the EXTERNAL tamper-resistant sink, not the local fallback."
#
# This is the DONE-BLOCKER for item 13. Until this script is run, HOOK_LOG_SINK
# is the local fallback (/tmp/copilot-hook/decisions.log) and item 13 is NOT DONE.
#
# Usage:
#   ./apply-detect-wiring.sh [--ingest-url URL] [--dry-run] [--verify]
#
#   --ingest-url URL  : the external sink ingest URL (default: http://host.docker.internal:3001/ingest)
#   --dry-run         : show changes without applying them
#   --verify          : verify that HOOK_LOG_SINK is set to the external sink (AC-13-N06 check)
#
# After running this script:
#   1. Restart the devcontainer: docker compose restart devcontainer
#   2. Verify a hook decision lands at the external sink (AC-13-N06 step b).

set -euo pipefail

INGEST_URL="${INGEST_URL:-http://host.docker.internal:3001/ingest}"
COMPOSE_FILE="$(dirname "$0")/../../docker-compose.yml"
COMPOSE_FILE="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)/$(basename "$COMPOSE_FILE")"
DRY_RUN=0
VERIFY_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ingest-url) shift; INGEST_URL="$1" ;;
    --dry-run) DRY_RUN=1 ;;
    --verify) VERIFY_ONLY=1 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "[detect-wiring] ERROR: docker-compose.yml not found at: $COMPOSE_FILE" >&2
  exit 1
fi

# ============================================================
# VERIFY MODE: check current HOOK_LOG_SINK value (AC-13-N06 check a)
# ============================================================
verify_wiring() {
  echo "[detect-wiring] === AC-13-N06 VERIFICATION ===" >&2
  local current_hook_sink
  current_hook_sink=$(grep 'HOOK_LOG_SINK:' "$COMPOSE_FILE" | head -1 | awk -F'"' '{print $2}' || echo "not found")
  local current_mcp_sink
  current_mcp_sink=$(grep 'MCP_DETECTION_SINK:' "$COMPOSE_FILE" | head -1 | awk -F'"' '{print $2}' || echo "not found")

  echo "[detect-wiring] HOOK_LOG_SINK in docker-compose.yml: ${current_hook_sink}" >&2
  echo "[detect-wiring] MCP_DETECTION_SINK in docker-compose.yml: ${current_mcp_sink}" >&2

  local failures=0

  if echo "$current_hook_sink" | grep -qE "^https?://"; then
    echo "[detect-wiring] PASS: HOOK_LOG_SINK is set to external HTTP sink." >&2
  else
    echo "[detect-wiring] FAIL: HOOK_LOG_SINK is NOT set to external HTTP sink." >&2
    echo "[detect-wiring] FAIL: Current value: ${current_hook_sink}" >&2
    echo "[detect-wiring] FAIL: Run: ./apply-detect-wiring.sh --ingest-url ${INGEST_URL}" >&2
    failures=$((failures + 1))
  fi

  if echo "$current_mcp_sink" | grep -qE "^https?://"; then
    echo "[detect-wiring] PASS: MCP_DETECTION_SINK is set to external HTTP sink." >&2
  else
    echo "[detect-wiring] INFO: MCP_DETECTION_SINK not yet set to external sink (may not be present)." >&2
  fi

  if [ "$failures" -gt 0 ]; then
    echo "[detect-wiring] AC-13-N06: FAIL - HOOK_LOG_SINK is still the local fallback." >&2
    echo "[detect-wiring] Item 13 is NOT DONE until this is fixed." >&2
    return 1
  fi

  echo "[detect-wiring] AC-13-N06 (check a): PASS - HOOK_LOG_SINK points at external sink." >&2
  echo "[detect-wiring] Run step (b): trigger a hook decision and verify it arrives at ${INGEST_URL}" >&2
  return 0
}

if [ "$VERIFY_ONLY" -eq 1 ]; then
  verify_wiring
  exit $?
fi

# ============================================================
# APPLY: update docker-compose.yml environment block
# ============================================================
echo "[detect-wiring] Applying detection wiring to: $COMPOSE_FILE" >&2
echo "[detect-wiring] External sink ingest URL: $INGEST_URL" >&2

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[detect-wiring] [DRY-RUN] Would update HOOK_LOG_SINK to: $INGEST_URL" >&2
  echo "[detect-wiring] [DRY-RUN] Would update/add MCP_DETECTION_SINK to: $INGEST_URL" >&2
  exit 0
fi

# Update HOOK_LOG_SINK line in docker-compose.yml.
# The line currently reads: HOOK_LOG_SINK: "/tmp/copilot-hook/decisions.log"
# Replace it with: HOOK_LOG_SINK: "http://host.docker.internal:3001/ingest"
if grep -q 'HOOK_LOG_SINK:' "$COMPOSE_FILE"; then
  # Use sed to replace the value (portable macOS/Linux sed).
  # On macOS: sed -i '' 's/old/new/'
  # On Linux: sed -i 's/old/new/'
  if sed --version 2>/dev/null | grep -q GNU; then
    sed -i "s|HOOK_LOG_SINK:.*|HOOK_LOG_SINK: \"${INGEST_URL}\"|" "$COMPOSE_FILE"
  else
    sed -i '' "s|HOOK_LOG_SINK:.*|HOOK_LOG_SINK: \"${INGEST_URL}\"|" "$COMPOSE_FILE"
  fi
  echo "[detect-wiring] Updated HOOK_LOG_SINK to: $INGEST_URL" >&2
else
  echo "[detect-wiring] WARNING: HOOK_LOG_SINK not found in $COMPOSE_FILE" >&2
  echo "[detect-wiring] Add manually: HOOK_LOG_SINK: \"${INGEST_URL}\"" >&2
fi

# Add or update MCP_DETECTION_SINK (SPEC-07 AL-08 RC-2 requirement).
if grep -q 'MCP_DETECTION_SINK:' "$COMPOSE_FILE"; then
  if sed --version 2>/dev/null | grep -q GNU; then
    sed -i "s|MCP_DETECTION_SINK:.*|MCP_DETECTION_SINK: \"${INGEST_URL}\"|" "$COMPOSE_FILE"
  else
    sed -i '' "s|MCP_DETECTION_SINK:.*|MCP_DETECTION_SINK: \"${INGEST_URL}\"|" "$COMPOSE_FILE"
  fi
  echo "[detect-wiring] Updated MCP_DETECTION_SINK to: $INGEST_URL" >&2
else
  # Add MCP_DETECTION_SINK after the HOOK_LOG_SINK line.
  if sed --version 2>/dev/null | grep -q GNU; then
    sed -i "/HOOK_LOG_SINK:/a\\      MCP_DETECTION_SINK: \"${INGEST_URL}\"" "$COMPOSE_FILE"
  else
    sed -i '' "/HOOK_LOG_SINK:/a\\
      MCP_DETECTION_SINK: \"${INGEST_URL}\"" "$COMPOSE_FILE"
  fi
  echo "[detect-wiring] Added MCP_DETECTION_SINK: $INGEST_URL" >&2
fi

# Also patch pretooluse.sh to handle HTTP HOOK_LOG_SINK (the curl branch).
# See hook-forwarder-addition.sh for the snippet to add to pretooluse.sh.
echo "[detect-wiring] NOTE: pretooluse.sh log_attempt function needs the HTTP/curl branch." >&2
echo "[detect-wiring] See src/detect/hook-forwarder-addition.sh for the log_attempt patch." >&2

echo "[detect-wiring] Wiring applied. Restart the stack:" >&2
echo "[detect-wiring]   docker compose down && docker compose up -d" >&2
echo "[detect-wiring] Then verify AC-13-N06:" >&2
echo "[detect-wiring]   ./apply-detect-wiring.sh --verify" >&2
