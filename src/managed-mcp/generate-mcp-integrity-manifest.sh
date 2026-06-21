#!/usr/bin/env bash
# src/managed-mcp/generate-mcp-integrity-manifest.sh
# Generates the multi-agent MCP integrity manifest.
# Run this after any change to any agent's MCP config file.
# The manifest is baked into the image at /etc/managed-mcp/mcp-integrity-all.sha256.
# Source: SPEC-24 section 6, ADR-008 D5.
#
# USAGE (run from repo root):
#   bash src/managed-mcp/generate-mcp-integrity-manifest.sh
#
# OUTPUT: src/managed-mcp/mcp-integrity-all.sha256
#
# Format: one entry per line: <sha256>  <agent>/<filename>
# Example:
#   abc123...  copilot/.vscode/mcp.json
#   def456...  claude/.mcp.json
#   ghi789...  codex/config.toml
#
# ORDERING NOTE (SPEC-22 section 6 RC-22-2):
#   This script MUST be run AFTER SPEC-22 finalizes the assembled config.toml.
#   A stale manifest (generated before the final config.toml) will fail the CI gate.

set -euo pipefail

MANIFEST_OUT="src/managed-mcp/mcp-integrity-all.sha256"
REPO_ROOT="${REPO_ROOT:-.}"

# MCP config paths per agent (no associative arrays for bash 3 compatibility)
COPILOT_FILE="${REPO_ROOT}/src/.vscode/mcp.json"
CLAUDE_FILE="${REPO_ROOT}/.mcp.json"
CODEX_FILE="${REPO_ROOT}/src/managed-config/codex/config.toml"

{
    echo "# mcp-integrity-all.sha256"
    echo "# Generated: $(date -Iseconds)"
    echo "# Format: <sha256>  <agent>/<filename>"
    echo "# SPEC-24 section 6, ADR-008 D5"
    echo "# Regenerate: bash src/managed-mcp/generate-mcp-integrity-manifest.sh"
} > "$MANIFEST_OUT"

for PAIR in "copilot:${COPILOT_FILE}" "claude:${CLAUDE_FILE}" "codex:${CODEX_FILE}"; do
    AGENT_KEY="${PAIR%%:*}"
    FILE="${PAIR#*:}"
    if [ ! -f "$FILE" ]; then
        echo "[generate-manifest] WARN: MCP config not found for ${AGENT_KEY}: ${FILE}" >&2
        echo "[generate-manifest] WARN: Skipping ${AGENT_KEY}; ensure file exists before baking into image." >&2
        continue
    fi
    SHA=$(sha256sum "$FILE" 2>/dev/null || shasum -a 256 "$FILE" | awk '{print $1}')
    SHA=$(echo "$SHA" | awk '{print $1}')
    BASENAME=$(basename "$FILE")
    printf '%s  %s/%s\n' "$SHA" "$AGENT_KEY" "$BASENAME" >> "$MANIFEST_OUT"
    echo "[generate-manifest] OK: ${AGENT_KEY}/${BASENAME} -> ${SHA}"
done

echo "[generate-manifest] Manifest written to: ${MANIFEST_OUT}"
echo "[generate-manifest] Contents:"
cat "$MANIFEST_OUT"
