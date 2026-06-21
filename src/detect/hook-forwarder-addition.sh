#!/usr/bin/env bash
# src/detect/hook-forwarder-addition.sh
#
# Item 13: Hook log forwarder addition.
# ADR-007 D2a, SPEC-07 section 2a + section 10-D.
#
# THIS IS NOT A STANDALONE HOOK SCRIPT. It documents the ONLY change
# item 13 makes to the SPEC-05 pretooluse.sh hook: wiring HOOK_LOG_SINK
# to the external sink (via the docker-compose.yml environment block).
#
# SPEC-07 section 2a says: "Item 13 sets HOOK_LOG_SINK to the external
# sink ingest endpoint. This is the ONLY change item 13 makes to the hook."
#
# The hook enforcement logic, fail-closed semantics, stdout invariants,
# and the log_attempt function all remain owned by SPEC-05 (item 11).
# Item 13 DOES NOT redefine the hook.
#
# OI-13-B (snake_case reconciliation, consumed from OI-11-B-confirmed-fields):
#   The confirmed session_id field authority is the item-11 artifact at
#   src/.github/hooks/permissiondecision-shape-finding.md (RC-4).
#   Per that artifact:
#     VS Code primary: session_id (snake_case)
#     CLI primary: sessionId (camelCase)
#     Parser: .session_id // .sessionId (defensive dual-casing)
#     Log line emitted key: sessionId (historical compatibility with SPEC-07 format)
#   Item 13 consumes this authority; it does NOT independently re-derive the casing.
#
# OI-13-C (hook type):
#   The verified mechanism is command-type (the hook descriptor at
#   .github/hooks/pretooluse.json uses "type":"command").
#   The http-type hook was NOT found in official docs as of 2026-06-14.
#   The command-type forwarder (the shell script that POSTs via curl) is used.
#   Source: code.visualstudio.com/docs/agent-customization/hooks (2026-06-14).
#
# ENRICHED LOG LINE FORMAT (SPEC-07 section 2a):
#   The item-11 pretooluse.sh log_attempt function emits a JSON line to HOOK_LOG_SINK.
#   The SPEC-07 enriched format for the external sink is:
#   {
#     "source": "pretooluse_hook",
#     "timestamp": "<ISO8601-UTC>",
#     "sessionId": "<id from stdin, .session_id // .sessionId>",
#     "hook_event_name": "<PreToolUse|PostToolUse>",
#     "tool_name": "<tool name>",
#     "tool_use_id": "<id>",
#     "parsed_command": "<normalized command or path>",
#     "decision": "<allow|ask|deny>",
#     "reason": "<reason string from the hook>"
#   }
#
#   NOTE: The log line key is "sessionId" (camelCase) per item-11's log_attempt
#   function (historical compatibility). The VALUE is populated from whichever
#   input field was non-empty (.session_id // .sessionId). See OI-11-B-confirmed-fields.
#
# HOW TO WIRE (AC-13-N06):
#   In docker-compose.yml under the devcontainer service environment block,
#   change:
#     HOOK_LOG_SINK: "/tmp/copilot-hook/decisions.log"
#   to:
#     HOOK_LOG_SINK: "http://host.docker.internal:3001/ingest"
#   AND add:
#     MCP_DETECTION_SINK: "http://host.docker.internal:3001/ingest"
#
#   This is the ONE wiring change item 13 makes. After this change:
#   - The pretooluse.sh log_attempt function POSTs to the external sink.
#   - The mcp-integrity-check.sh emit_alert function POSTs to the external sink.
#   - The local fallback path (/tmp/copilot-hook/decisions.log) is still written
#     if the POST fails (fail-closed: logging failure does NOT fail the decision).
#   - AC-13-N06 is satisfied: HOOK_LOG_SINK is NOT the local fallback path.
#
# CURL FORWARDER SNIPPET:
#   The pretooluse.sh log_attempt function currently does:
#     printf '%s\n' "$log_line" >> "$LOG_SINK" 2>/dev/null || true
#   When HOOK_LOG_SINK is an HTTP URL (http://...), this append fails silently.
#   Item 13 adds a URL-detection branch to log_attempt that uses curl instead.
#   This is the ONLY code change to pretooluse.sh that item 13 makes.
#
#   The modified log_attempt should look like:
#
#   log_attempt() {
#     local log_line="$1"
#     local log_sink="${HOOK_LOG_SINK:-/tmp/copilot-hook/decisions.log}"
#     if [[ "$log_sink" == http://* ]] || [[ "$log_sink" == https://* ]]; then
#       # External HTTP sink (item 13). POST the log line to the ingest endpoint.
#       # Fail silently on network error (logging failure MUST NOT fail the decision).
#       # Timeout: 5s (fast fail; do not delay hook decision for a slow sink).
#       curl -sf -X POST "$log_sink" \
#         -H "Content-Type: application/json" \
#         -d "$log_line" \
#         --max-time 5 \
#         >/dev/null 2>&1 || true
#       # Also write to the local fallback (defense-in-depth for forensics).
#       local local_fallback="/tmp/copilot-hook/decisions.log"
#       mkdir -p "$(dirname "$local_fallback")" 2>/dev/null || true
#       printf '%s\n' "$log_line" >> "$local_fallback" 2>/dev/null || true
#     else
#       # Local file sink (item 11 default / fallback).
#       mkdir -p "$(dirname "$log_sink")" 2>/dev/null || true
#       printf '%s\n' "$log_line" >> "$log_sink" 2>/dev/null || true
#     fi
#   }
#
# This snippet is the forward-mechanism for command-type hooks (OI-13-C).
# The http-type hook (if it existed) would allow VS Code to POST directly without
# a shell script; since only command-type is verified, the curl approach is used.
#
# MCP_DETECTION_SINK REPOINT (SPEC-07 AL-08 RC-2):
#   In docker-compose.yml under devcontainer environment:
#     MCP_DETECTION_SINK: "http://host.docker.internal:3001/ingest"
#   This repoints the mcp-integrity-check.sh emit_alert to the external sink.
#   Without this, the highest-priority MCP alert writes to the in-container
#   fallback path (SPEC-07 section 5 AL-08 RC-2 requirement).
#
# DO NOT edit pretooluse.sh enforcement logic here. Route enforcement changes to
# SPEC-05 / item 11. This file is DOCUMENTATION of the item 13 wiring only.

echo "This file documents the item-13 wiring; it is not a runnable script." >&2
echo "See the HOW TO WIRE section above for the docker-compose.yml change." >&2
echo "See src/detect/apply-detect-wiring.sh for the automated wiring script." >&2
exit 0
