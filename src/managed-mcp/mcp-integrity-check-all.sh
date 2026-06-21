#!/usr/bin/env bash
# /usr/local/bin/mcp-integrity-check-all.sh (deployed to image at this path)
# Checks SHA-256 of all three agents' MCP config files against the known-good manifest.
# Extension of SPEC-06 section 8 to cover three agents (SPEC-24 section 6).
# Source: SPEC-24 section 6, ADR-008 D5, ADR-006 D7.
#
# REQUIRES BASH 4+ (uses declare -A associative arrays).
# The container runs Ubuntu 22.04 (bash 5.x). This script MUST run inside the container
# or in a CI Linux environment. It will NOT run correctly on macOS with the system
# Bash 3.2 at /bin/bash. On macOS, invoke via the container:
#   docker compose --profile <agent> exec devcontainer-<agent> mcp-integrity-check-all.sh
# or install bash >= 4 (e.g. via Homebrew) and invoke: /usr/local/bin/bash mcp-integrity-check-all.sh
#
# RUNS: on container session start (postStartCommand), in CI.
# ON MISMATCH: exits non-zero + emits HIGH-SIGNAL alert to detection sink.
#
# IMMUTABILITY: this script is root-owned, mode 444, chattr+i (same protection as
# the SPEC-06 original single-agent script). The Dockerfile bakes it in at mode 444.
#
# USAGE:
#   # Check all three agents (CI mode; no AGENT env var):
#   mcp-integrity-check-all.sh
#
#   # Check only the active agent (runtime mode; AGENT env var from compose profile):
#   AGENT=claude mcp-integrity-check-all.sh
#
# ENV VARS:
#   AGENT - active agent profile (copilot|claude|codex); unset = check all three (CI)
#   WORKSPACE_ROOT - workspace volume path (default: /workspace)
#   CLAUDE_CONFIG_DIR - Claude user config dir (default: /home/devuser/.claude)
#   CODEX_HOME - Codex user config dir (default: /home/devuser/.codex)
#   HOOK_LOG_SINK - detection sink URL or path (default: /var/log/copilot-hook/mcp-integrity.log)
#
# MCP config locations per agent:
#   copilot: {WORKSPACE_ROOT}/.vscode/mcp.json         (key: "servers", zero = {})
#   claude:  {WORKSPACE_ROOT}/.mcp.json                 (key: "mcpServers", zero = {})
#   codex:   {CODEX_HOME}/config.toml                   (key: [mcp_servers.*], zero = absent)

set -euo pipefail

# BASH VERSION GUARD: this script requires bash 4+ (uses declare -A associative arrays).
# It is designed to run INSIDE the Linux container (bash 5.x) or a CI Linux environment.
# On macOS with the system bash 3.2, exit with a clear diagnostic instead of a cryptic
# "declare: -A: invalid option" or arithmetic-subscript error.
# To run on macOS: either invoke via the container, or install bash>=4 via Homebrew and
# call /usr/local/bin/bash mcp-integrity-check-all.sh directly.
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "[mcp-integrity-all] ERROR: bash 4+ is required (found bash ${BASH_VERSION})." >&2
  echo "[mcp-integrity-all] This script uses associative arrays (declare -A) and must run" >&2
  echo "[mcp-integrity-all] inside the dev container (bash 5) or a Linux CI environment." >&2
  echo "[mcp-integrity-all] On macOS: docker compose --profile <agent> exec devcontainer-<agent> mcp-integrity-check-all.sh" >&2
  exit 1
fi

MANIFEST_PATH="/etc/managed-mcp/mcp-integrity-all.sha256"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-/workspace}"
CLAUDE_CONFIG_DIR="${CLAUDE_CONFIG_DIR:-/home/devuser/.claude}"
CODEX_HOME="${CODEX_HOME:-/home/devuser/.codex}"
AGENT="${AGENT:-}"
DETECTION_SINK="${HOOK_LOG_SINK:-/var/log/copilot-hook/mcp-integrity.log}"

declare -A MCP_FILES
MCP_FILES["copilot"]="${WORKSPACE_ROOT}/.vscode/mcp.json"
MCP_FILES["claude"]="${WORKSPACE_ROOT}/.mcp.json"
MCP_FILES["codex"]="${CODEX_HOME}/config.toml"

FAILED=0

if [ ! -f "$MANIFEST_PATH" ]; then
    echo "[mcp-integrity-all] FATAL: manifest not found: ${MANIFEST_PATH}" >&2
    echo "[mcp-integrity-all] Generate via: src/managed-mcp/generate-mcp-integrity-manifest.sh" >&2
    exit 1
fi

# Determine which agents to check.
if [ -n "$AGENT" ]; then
    AGENTS_TO_CHECK=("$AGENT")
else
    AGENTS_TO_CHECK=("copilot" "claude" "codex")
fi

for AGENT_KEY in "${AGENTS_TO_CHECK[@]}"; do
    CONFIG_FILE="${MCP_FILES[$AGENT_KEY]:-}"
    if [ -z "$CONFIG_FILE" ]; then
        echo "[mcp-integrity-all] WARN: unknown AGENT=${AGENT_KEY}; skipping." >&2
        continue
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[mcp-integrity-all] WARN: MCP config not found: ${CONFIG_FILE} (agent=${AGENT_KEY})" >&2
        echo "[mcp-integrity-all] WARN: Skipping integrity check for ${AGENT_KEY} (file absent)." >&2
        continue
    fi

    # Look up the expected SHA for this agent from the manifest.
    # Manifest line format: <sha256>  <agent>/<filename>
    EXPECTED_SHA=$(grep " ${AGENT_KEY}/" "$MANIFEST_PATH" 2>/dev/null | awk '{print $1}' | head -1)
    if [ -z "$EXPECTED_SHA" ]; then
        echo "[mcp-integrity-all] FATAL: no manifest entry for agent=${AGENT_KEY}" >&2
        echo "[mcp-integrity-all] Regenerate manifest: src/managed-mcp/generate-mcp-integrity-manifest.sh" >&2
        FAILED=1
        continue
    fi

    ACTUAL_SHA=$(sha256sum "$CONFIG_FILE" | awk '{print $1}')
    if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
        echo "[mcp-integrity-all] FATAL: MCP config MISMATCH for agent=${AGENT_KEY}" >&2
        echo "  File:     ${CONFIG_FILE}" >&2
        echo "  Expected: ${EXPECTED_SHA}" >&2
        echo "  Actual:   ${ACTUAL_SHA}" >&2
        echo "[mcp-integrity-all] Possible MCPoison (CVE-2025-54136) or unauthorized edit." >&2
        # HIGH-SIGNAL alert to detection sink.
        TIMESTAMP=$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)
        ALERT_LINE=$(printf '{"timestamp":"%s","event":"mcp-integrity-mismatch","agent":"%s","file":"%s","expected":"%s","actual":"%s"}\n' \
            "$TIMESTAMP" "$AGENT_KEY" "$CONFIG_FILE" "$EXPECTED_SHA" "$ACTUAL_SHA")
        if [[ "${DETECTION_SINK:-}" == http://* ]] || [[ "${DETECTION_SINK:-}" == https://* ]]; then
            curl -sf -X POST "${DETECTION_SINK}" \
                -H "Content-Type: application/json" \
                -d "${ALERT_LINE}" \
                --max-time 5 >/dev/null 2>&1 || true
        fi
        mkdir -p "$(dirname "$DETECTION_SINK")" 2>/dev/null || true
        printf '%s\n' "$ALERT_LINE" >> "$DETECTION_SINK" 2>/dev/null || true
        FAILED=1
    else
        echo "[mcp-integrity-all] OK: ${AGENT_KEY} MCP config verified: ${ACTUAL_SHA}"
    fi
done

if [ "$FAILED" -eq 1 ]; then
    echo "[mcp-integrity-all] FATAL: MCP config integrity check failed." >&2
    echo "[mcp-integrity-all] STOP: do not start any MCP servers until the mismatch is investigated." >&2
    exit 1
fi
echo "[mcp-integrity-all] All checked MCP configs verified against manifest."
