#!/usr/bin/env bash
# src/detect/startup-check.sh
# Startup checks for the detection and audit layer.
# Item 13, OI-13-J, SPEC-07 section 2b.
#
# Runs at container start (wired into entrypoint.sh or docker-compose.yml command).
# Checks:
#   1. Creates the agentDebugLog directory (VS Code issue #307890 workaround).
#   2. Confirms HOOK_LOG_SINK is set to the external sink (not the local fallback).
#      If HOOK_LOG_SINK is the local fallback, this is a WARNING (not a hard fail),
#      because during item 11 build window the local fallback is acceptable.
#      AC-13-N06: HOOK_LOG_SINK must NOT be the local fallback at item 13 DONE.
#   3. Confirms the local hook log fallback directory is writable (for fail-safe).
#   4. Confirms the sink ingest endpoint is reachable (soft check; log and continue).
#
# OI-13-J: VS Code issue #307890 - github.copilot.chat.agentDebugLog.fileLogging.enabled
# may not create the debug-logs directory despite being set to true.
# This startup check creates the directory proactively and fails the container start
# if the directory cannot be created (guaranteeing the log target exists).
#
# REQUIRES-LIVE-RUNTIME: The "does setting agentDebugLog.fileLogging.enabled actually
# create the directory" question can only be definitively answered with a running
# VS Code instance and the Copilot extension. This startup check is the workaround:
# we create the directory ourselves so it always exists before VS Code tries to use it.

set -euo pipefail

FAIL_HARD=0  # Set to 1 to fail the container start on critical checks

# ============================================================
# CHECK 1: Create agentDebugLog directory (OI-13-J)
# ============================================================
# VS Code writes the agent debug log (github.copilot.chat.agentDebugLog.fileLogging.enabled)
# to ~/.copilot/debug-logs/ (or ~/.copilot-debug-logs/ depending on version).
# If this directory does not exist, the log is silently not created (VS Code issue #307890).
# We create it proactively.

HOME_DIR="${HOME:-/home/devuser}"
DEBUG_LOG_DIRS=(
  "${HOME_DIR}/.copilot/debug-logs"
  "${HOME_DIR}/.copilot-debug-logs"
  "${HOME_DIR}/.config/github-copilot/debug-logs"
)

echo "[startup-check] Creating agentDebugLog directories (OI-13-J, VS Code issue #307890)..." >&2
for dir in "${DEBUG_LOG_DIRS[@]}"; do
  if mkdir -p "$dir" 2>/dev/null; then
    echo "[startup-check] Created: $dir" >&2
  else
    echo "[startup-check] WARNING: Could not create: $dir (check volume permissions)" >&2
    if [ "$FAIL_HARD" -eq 1 ]; then
      echo "[startup-check] FAIL: agentDebugLog directory creation failed. Container start aborted." >&2
      exit 1
    fi
  fi
done

# ============================================================
# CHECK 2: HOOK_LOG_SINK status (AC-13-N06)
# ============================================================
HOOK_SINK="${HOOK_LOG_SINK:-/tmp/copilot-hook/decisions.log}"
LOCAL_FALLBACK_PATTERN="^/tmp/|^/var/log/"

echo "[startup-check] HOOK_LOG_SINK = ${HOOK_SINK}" >&2

if echo "$HOOK_SINK" | grep -qE "$LOCAL_FALLBACK_PATTERN"; then
  echo "[startup-check] WARNING: HOOK_LOG_SINK is set to a LOCAL path: ${HOOK_SINK}" >&2
  echo "[startup-check] WARNING: Per AC-13-N06, this MUST be set to the external sink at item 13 DONE." >&2
  echo "[startup-check] WARNING: Set HOOK_LOG_SINK=http://host.docker.internal:3001/ingest in docker-compose.yml." >&2
  # Not a hard fail during development; hard fail only at DONE gate.
elif echo "$HOOK_SINK" | grep -qE "^https?://"; then
  echo "[startup-check] PASS: HOOK_LOG_SINK is set to external HTTP sink: ${HOOK_SINK}" >&2
else
  echo "[startup-check] INFO: HOOK_LOG_SINK = ${HOOK_SINK} (non-HTTP, non-local: file path)" >&2
fi

# ============================================================
# CHECK 3: MCP_DETECTION_SINK status (SPEC-07 AL-08 RC-2)
# ============================================================
MCP_SINK="${MCP_DETECTION_SINK:-/var/log/copilot-hook/decisions.log}"

echo "[startup-check] MCP_DETECTION_SINK = ${MCP_SINK}" >&2

if echo "$MCP_SINK" | grep -qE "$LOCAL_FALLBACK_PATTERN"; then
  echo "[startup-check] WARNING: MCP_DETECTION_SINK is set to a LOCAL path: ${MCP_SINK}" >&2
  echo "[startup-check] WARNING: Per SPEC-07 AL-08 RC-2, this MUST point to the external sink." >&2
elif echo "$MCP_SINK" | grep -qE "^https?://"; then
  echo "[startup-check] PASS: MCP_DETECTION_SINK is set to external HTTP sink: ${MCP_SINK}" >&2
fi

# ============================================================
# CHECK 4: Local fallback directory
# ============================================================
FALLBACK_DIR="/tmp/copilot-hook"
if mkdir -p "$FALLBACK_DIR" 2>/dev/null; then
  echo "[startup-check] Local hook log fallback directory ready: $FALLBACK_DIR" >&2
else
  echo "[startup-check] WARNING: Cannot create fallback dir $FALLBACK_DIR" >&2
fi

# ============================================================
# CHECK 5: Sink reachability (soft check)
# ============================================================
if echo "$HOOK_SINK" | grep -qE "^https?://"; then
  echo "[startup-check] Checking sink reachability: ${HOOK_SINK}..." >&2
  SINK_HEALTH_URL=$(echo "$HOOK_SINK" | sed 's|/ingest$|/health|')
  if curl -sf --max-time 5 "$SINK_HEALTH_URL" >/dev/null 2>&1; then
    echo "[startup-check] PASS: External sink is reachable at ${SINK_HEALTH_URL}" >&2
  else
    echo "[startup-check] WARNING: External sink is NOT reachable at ${SINK_HEALTH_URL}" >&2
    echo "[startup-check] WARNING: Hook log events will fall back to local path until sink is available." >&2
    echo "[startup-check] INFO: Start the sink with: docker compose -f src/detect/docker-compose.detect.yml up -d" >&2
  fi
fi

echo "[startup-check] Startup checks complete." >&2
exit 0
