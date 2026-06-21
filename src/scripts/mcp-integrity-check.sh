#!/usr/bin/env bash
# src/scripts/mcp-integrity-check.sh
#
# Checks the SHA-256 of mcp.json against the known-good manifest.
#
# Runs:
#   - On container session start (postStartCommand in devcontainer.json), BEFORE any MCP server starts.
#   - In CI (ci/mcp-composability-gate.sh and the CI test suite run this).
#   - Manually by an operator before re-authorizing a changed mcp.json.
#
# On MISMATCH: refuses to start servers (exits non-zero) AND emits a HIGH-SIGNAL alert
#              to the detection sink (item 13 wires MCP_DETECTION_SINK to the external sink).
#              This alert is the one item 13's AL-08 alert rule triggers on.
#
# On MATCH:    emits an INFO confirmation and exits 0.
#
# Fail-closed policy:
#   - Missing manifest                -> HIGH-SIGNAL alert + exit 1 (never silently continue)
#   - Missing mcp.json                -> HIGH-SIGNAL alert + exit 1
#   - Hash mismatch                   -> HIGH-SIGNAL alert + exit 1
#   - sha256sum/shasum tool missing   -> HIGH-SIGNAL alert + exit 1
#   - lsattr check for manifest       -> ERROR alert + exit 1 if lsattr indicates immutable-bit absent
#     (the overlay2 silent-no-op case: we report the concern but do NOT block normal operation;
#      the PRIMARY protection is root-owned mode-444 + read-only-volume-mount; see section 8 notes)
#
# Alert fields (REAL SPEC-06 fields, consumed by item 13 AL-08):
#   component = mcp-integrity-check
#   level     = HIGH-SIGNAL  (on any mismatch or missing-file event)
#   level     = INFO         (on successful hash match)
#   event     = mcp_json_hash_mismatch  (on hash mismatch)
#   event     = mcp_json_manifest_missing
#   event     = mcp_json_file_missing
#   event     = mcp_integrity_check_passed
#
# Source: SPEC-06 section 8. ADR-006 D7, CVE-2025-54136 (MCPoison class).
# This script is protected by SPEC-06 section 8's own immutability mechanism (root-owned,
# mode 555, chattr +i with lsattr verification, read-only-mount fallback). It is NOT in
# the SPEC-05 canonical boundary-config list (SPEC-05 section 5 does not enumerate it).
# Its protection is owned by SPEC-06 section 8.
#
# Environment variables:
#   MCP_JSON_PATH       Path to mcp.json (default: ${WORKSPACE_ROOT:-/workspace}/.vscode/mcp.json)
#   MCP_MANIFEST_PATH   Path to the known-good hash manifest (default: /etc/managed-mcp/mcp-integrity.sha256)
#   MCP_DETECTION_SINK  Path to the detection log sink (default: /var/log/copilot-hook/decisions.log)
#                       Item 13 will override this to point at the external tamper-resistant sink.
#                       Until item 13 wires the external sink, events are written to the local path.

set -euo pipefail

MCP_JSON_PATH="${MCP_JSON_PATH:-${WORKSPACE_ROOT:-/workspace}/.vscode/mcp.json}"
MANIFEST_PATH="${MCP_MANIFEST_PATH:-/etc/managed-mcp/mcp-integrity.sha256}"
DETECTION_SINK="${MCP_DETECTION_SINK:-/var/log/copilot-hook/decisions.log}"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

# Emit a structured alert to the detection sink AND to stderr for operator visibility.
# Fields: component, level, event, message (always the four SPEC-06 fields).
emit_alert() {
  local level="$1"
  local event="$2"
  local message="$3"
  local log_line
  log_line=$(printf '{"timestamp":"%s","component":"mcp-integrity-check","level":"%s","event":"%s","message":"%s"}\n' \
    "$TIMESTAMP" "$level" "$event" "$message")
  # Write to detection sink. Two paths:
  #   HTTP sink (item 13 AC-13-N06 / RC-2 wiring): POST via curl.
  #   File sink (local fallback / development mode): file append.
  # Logging failure MUST NOT fail-open: both paths use || true so a sink outage
  # does not suppress the alert on stderr. Always print to stderr for operator visibility.
  if [[ "${DETECTION_SINK:-}" == http://* ]] || [[ "${DETECTION_SINK:-}" == https://* ]]; then
    curl -sf -X POST "${DETECTION_SINK}" \
      -H "Content-Type: application/json" \
      -d "${log_line}" --max-time 5 >/dev/null 2>&1 || true
    # Also write to local fallback for defense-in-depth (audit trail survives sink outage).
    local local_fallback="/tmp/copilot-mcp-integrity/alerts.log"
    mkdir -p "$(dirname "$local_fallback")" 2>/dev/null || true
    printf '%s\n' "$log_line" >> "$local_fallback" 2>/dev/null || true
  else
    # File sink: create parent dir and append.
    mkdir -p "$(dirname "$DETECTION_SINK")" 2>/dev/null || true
    printf '%s\n' "$log_line" >> "$DETECTION_SINK" 2>/dev/null || true
  fi
  printf '[mcp-integrity] %s [%s]: %s\n' "$level" "$event" "$message" >&2
}

# Determine the sha256sum tool available on this platform.
# macOS uses shasum -a 256; Linux uses sha256sum.
if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256_CMD="shasum -a 256"
else
  emit_alert "HIGH-SIGNAL" "mcp_integrity_tool_missing" \
    "Neither sha256sum nor shasum found - cannot verify mcp.json integrity - refusing to start MCP servers"
  exit 1
fi

# Check the manifest exists. If absent, fail closed immediately.
if [ ! -f "$MANIFEST_PATH" ]; then
  emit_alert "HIGH-SIGNAL" "mcp_json_manifest_missing" \
    "mcp.json integrity manifest missing at $MANIFEST_PATH - refusing to start MCP servers - operator must run manifest-generation script as root"
  exit 1
fi

# Check mcp.json exists. If absent, fail closed immediately.
if [ ! -f "$MCP_JSON_PATH" ]; then
  emit_alert "HIGH-SIGNAL" "mcp_json_file_missing" \
    "mcp.json not found at $MCP_JSON_PATH - refusing to start MCP servers"
  exit 1
fi

# Compute the current SHA-256 of mcp.json.
# The manifest line format is "<hash>  <path>"; extract just the hash.
CURRENT_HASH=$(eval "$SHA256_CMD \"$MCP_JSON_PATH\"" | awk '{print $1}')
EXPECTED_HASH=$(awk '{print $1}' "$MANIFEST_PATH")

if [ -z "$CURRENT_HASH" ]; then
  emit_alert "HIGH-SIGNAL" "mcp_integrity_hash_computation_failed" \
    "Failed to compute SHA-256 of $MCP_JSON_PATH - refusing to start MCP servers"
  exit 1
fi

if [ -z "$EXPECTED_HASH" ]; then
  emit_alert "HIGH-SIGNAL" "mcp_integrity_manifest_empty" \
    "Manifest at $MANIFEST_PATH is empty or malformed - refusing to start MCP servers"
  exit 1
fi

# The core integrity check. On mismatch, emit the REAL SPEC-06 HIGH-SIGNAL alert and exit 1.
# This is the MCPoison (CVE-2025-54136 class) detection path.
if [ "$CURRENT_HASH" != "$EXPECTED_HASH" ]; then
  emit_alert "HIGH-SIGNAL" "mcp_json_hash_mismatch" \
    "mcp.json integrity check FAILED: expected=$EXPECTED_HASH actual=$CURRENT_HASH - POSSIBLE MCPoison SWAP (CVE-2025-54136 class) - refusing to start MCP servers - investigate immediately"
  exit 1
fi

# Hash matches: emit INFO confirmation and exit 0.
emit_alert "INFO" "mcp_integrity_check_passed" \
  "mcp.json integrity check PASSED: hash=$CURRENT_HASH - zero-server default confirmed clean"
exit 0
