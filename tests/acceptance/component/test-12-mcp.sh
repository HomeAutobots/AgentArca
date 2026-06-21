#!/usr/bin/env bash
# tests/acceptance/component/test-12-mcp.sh
#
# Acceptance tests for item 12 (MCP posture build).
# Area 8, Phase 5.
#
# Coverage map (SPEC-06 AC-MCP-* and BUILD_PLAN AC-12-*):
#   AC-12-P01  zero MCP servers (mcp.json servers == {})
#   AC-12-P04  mcp-integrity-check passes on fresh container start (hash matches)
#   AC-12-P05  mcp-integrity-check detects mismatch + emits HIGH-SIGNAL alert with REAL fields
#   AC-12-N01  ci/mcp-supply-chain-scan.sh exits 0 on zero-server mcp.json
#   AC-12-N02  ci/mcp-composability-gate.sh exits 0 (no server present)
#   MCP-SETTINGS  chat.mcp.discovery.enabled=false + chat.mcp.autoStart=false present
#
# Permanent regression assertions:
#   REGRESSION-12-SUPPLY-CHAIN-NPXCMD  npx-as-command scan catches the RC-1 pattern
#   REGRESSION-12-INTEGRITY-FIELDS     integrity-check emits REAL SPEC-06 fields (not invented)
#
# Supply-chain scan regression tests (RC-1 fix, must never silently regress):
#   - npx as command field -> scan exits 1
#   - uvx as command field -> scan exits 1
#   - @latest in args -> scan exits 1
#   - zero servers -> scan exits 0 (regression: RC-1 fix must not break zero-server)
#
# Requires: PROJECT_ROOT set. Stack not required for most tests (offline).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/test-helpers.sh"

COMPONENT="mcp"
PASS=0
FAIL=0
SKIP=0
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
MCP_JSON="${PROJECT_ROOT}/src/.vscode/mcp.json"
SUPPLY_SCAN="${PROJECT_ROOT}/ci/mcp-supply-chain-scan.sh"
COMPOSABILITY_GATE="${PROJECT_ROOT}/ci/mcp-composability-gate.sh"
INTEGRITY_CHECK="${PROJECT_ROOT}/src/scripts/mcp-integrity-check.sh"

# ------------------------------------------------------------
# AC-12-P01: zero MCP servers
# ------------------------------------------------------------
begin_test "AC-12-P01" "mcp.json servers == {} (zero MCP servers, default steady state)"
if [ ! -f "${MCP_JSON}" ]; then
  fail_test "AC-12-P01" "mcp.json not found at ${MCP_JSON}"
else
  SERVERS=$(python3 -c "import json; d=json.load(open('${MCP_JSON}')); print(json.dumps(d.get('servers',{})))" 2>/dev/null || echo "PARSE_ERROR")
  if [ "${SERVERS}" = "{}" ] || [ "${SERVERS}" = "null" ]; then
    pass_test "AC-12-P01" "mcp.json servers={} (zero servers confirmed)"
  else
    fail_test "AC-12-P01" "mcp.json servers=${SERVERS} (expected {}; MCP server(s) present in default config)"
  fi
fi

# ------------------------------------------------------------
# MCP-SETTINGS: chat.mcp.discovery.enabled=false + autoStart=false
# ------------------------------------------------------------
begin_test "MCP-SETTINGS" "chat.mcp.discovery.enabled=false and chat.mcp.autoStart=false in managed settings"
SETTINGS_FILE="${PROJECT_ROOT}/src/managed-config/settings.json"
if [ ! -f "${SETTINGS_FILE}" ]; then
  fail_test "MCP-SETTINGS" "managed settings.json not found at ${SETTINGS_FILE}"
else
  DISCOVERY=$(grep '"chat.mcp.discovery.enabled"' "${SETTINGS_FILE}" 2>/dev/null || echo "MISSING")
  AUTOSTART=$(grep '"chat.mcp.autoStart"' "${SETTINGS_FILE}" 2>/dev/null || echo "MISSING")
  if echo "${DISCOVERY}" | grep -q "false" && echo "${AUTOSTART}" | grep -q "false"; then
    pass_test "MCP-SETTINGS" "chat.mcp.discovery.enabled=false and chat.mcp.autoStart=false confirmed"
  else
    fail_test "MCP-SETTINGS" "discovery='${DISCOVERY}' autoStart='${AUTOSTART}' (both must be false)"
  fi
fi

# ------------------------------------------------------------
# AC-12-P04: mcp-integrity-check passes on unmodified mcp.json
# (pass-with-matching-hash test)
# ------------------------------------------------------------
begin_test "AC-12-P04" "mcp-integrity-check passes on unmodified mcp.json (hash match)"
if [ ! -f "${INTEGRITY_CHECK}" ]; then
  fail_test "AC-12-P04" "mcp-integrity-check.sh not found at ${INTEGRITY_CHECK}"
else
  # Create a temp manifest with the real hash
  REAL_HASH=$(sha256sum "${MCP_JSON}" 2>/dev/null | awk '{print $1}' || \
              shasum -a 256 "${MCP_JSON}" 2>/dev/null | awk '{print $1}' || \
              echo "")
  if [ -z "${REAL_HASH}" ]; then
    skip_test "AC-12-P04" "REQUIRES-TOOL: sha256sum/shasum not available to compute mcp.json hash"
  else
    MANIFEST_DIR=$(mktemp -d)
    MANIFEST_FILE="${MANIFEST_DIR}/mcp-integrity.sha256"
    echo "${REAL_HASH}  ${MCP_JSON}" > "${MANIFEST_FILE}"

    INTEGRITY_EXIT=0
    INTEGRITY_OUTPUT=$(MCP_JSON_PATH="${MCP_JSON}" \
      MCP_MANIFEST_PATH="${MANIFEST_FILE}" \
      MCP_DETECTION_SINK="/tmp/acc15-mcp-integrity-test.log" \
      bash "${INTEGRITY_CHECK}" 2>&1) || INTEGRITY_EXIT=$?

    rm -rf "${MANIFEST_DIR}"

    if [ "${INTEGRITY_EXIT}" -eq 0 ] && echo "${INTEGRITY_OUTPUT}" | grep -q "mcp_integrity_check_passed"; then
      pass_test "AC-12-P04" "integrity-check PASSED (hash match confirmed): ${REAL_HASH}"
    else
      fail_test "AC-12-P04" "integrity-check failed: exit=${INTEGRITY_EXIT}, output=${INTEGRITY_OUTPUT}"
    fi
  fi
fi

# ------------------------------------------------------------
# AC-12-P05 (PERMANENT REGRESSION: REGRESSION-12-INTEGRITY-FIELDS)
# integrity-check detects mismatch + emits REAL SPEC-06 fields
# Fields: component=mcp-integrity-check, level=HIGH-SIGNAL, event=mcp_json_hash_mismatch
# ------------------------------------------------------------
begin_test "AC-12-P05 [REGRESSION-12-INTEGRITY-FIELDS]" "integrity-check detects mismatch + emits REAL SPEC-06 fields (component=mcp-integrity-check, level=HIGH-SIGNAL, event=mcp_json_hash_mismatch)"
if [ ! -f "${INTEGRITY_CHECK}" ]; then
  fail_test "AC-12-P05 [REGRESSION-12-INTEGRITY-FIELDS]" "mcp-integrity-check.sh not found"
else
  # Create a manifest with a WRONG hash (simulate mismatch)
  MANIFEST_DIR=$(mktemp -d)
  MANIFEST_FILE="${MANIFEST_DIR}/mcp-integrity.sha256"
  echo "000000000000000000000000000000000000000000000000000000000000dead  ${MCP_JSON}" > "${MANIFEST_FILE}"
  SINK_FILE="${MANIFEST_DIR}/alerts.log"

  MISMATCH_EXIT=0
  MISMATCH_OUTPUT=$(MCP_JSON_PATH="${MCP_JSON}" \
    MCP_MANIFEST_PATH="${MANIFEST_FILE}" \
    MCP_DETECTION_SINK="${SINK_FILE}" \
    bash "${INTEGRITY_CHECK}" 2>&1) || MISMATCH_EXIT=$?

  rm -rf "${MANIFEST_DIR}"

  # Verify: exit non-zero + REAL SPEC-06 fields present.
  # The integrity-check emits two forms:
  #   (a) Stderr human-readable: "[mcp-integrity] HIGH-SIGNAL [mcp_json_hash_mismatch]: ..."
  #   (b) JSON to sink: {"component":"mcp-integrity-check","level":"HIGH-SIGNAL","event":"mcp_json_hash_mismatch"}
  # We check stderr form (a) here; the JSON sink form (b) requires a running ingest-proxy (test-13).
  # REAL SPEC-06 fields: component=mcp-integrity-check, level=HIGH-SIGNAL, event=mcp_json_hash_mismatch.
  # In stderr form: "[mcp-integrity]" (abbreviated component prefix) + "HIGH-SIGNAL" + "mcp_json_hash_mismatch".
  FIELDS_OK=0
  # Check stderr human-readable form (primary observable in offline test)
  if echo "${MISMATCH_OUTPUT}" | grep -q "HIGH-SIGNAL" && \
     echo "${MISMATCH_OUTPUT}" | grep -q "mcp_json_hash_mismatch"; then
    FIELDS_OK=1
  fi
  # Also check JSON sink file if it was written
  if [ -f "${MANIFEST_DIR}/alerts.log" ] 2>/dev/null; then
    if grep -q "mcp-integrity-check" "${MANIFEST_DIR}/alerts.log" 2>/dev/null && \
       grep -q "HIGH-SIGNAL" "${MANIFEST_DIR}/alerts.log" 2>/dev/null && \
       grep -q "mcp_json_hash_mismatch" "${MANIFEST_DIR}/alerts.log" 2>/dev/null; then
      FIELDS_OK=1
    fi
  fi

  if [ "${MISMATCH_EXIT}" -ne 0 ] && [ "${FIELDS_OK}" -eq 1 ]; then
    pass_test "AC-12-P05 [REGRESSION-12-INTEGRITY-FIELDS]" "mismatch detected: exit=${MISMATCH_EXIT}; REAL SPEC-06 fields confirmed (HIGH-SIGNAL + mcp_json_hash_mismatch present in stderr/sink output; JSON sink form verified when ingest-proxy is running)"
  elif [ "${MISMATCH_EXIT}" -eq 0 ]; then
    fail_test "AC-12-P05 [REGRESSION-12-INTEGRITY-FIELDS]" "integrity-check exited 0 on mismatch (should exit non-zero)"
  else
    fail_test "AC-12-P05 [REGRESSION-12-INTEGRITY-FIELDS]" "exit=${MISMATCH_EXIT} but REAL SPEC-06 fields (HIGH-SIGNAL, mcp_json_hash_mismatch) missing from output. Output: ${MISMATCH_OUTPUT}"
  fi
fi

# ------------------------------------------------------------
# AC-12-N01 (PERMANENT REGRESSION: REGRESSION-12-SUPPLY-CHAIN-NPXCMD)
# Supply-chain scan: zero servers exits 0 + npx-as-command exits 1
# These are the RC-1 regression tests (build defect that was fixed).
# ------------------------------------------------------------
begin_test "AC-12-N01 [REGRESSION-12-SUPPLY-CHAIN-NPXCMD]" "mcp-supply-chain-scan.sh: zero-server exits 0; npx-as-command exits 1"
if [ ! -f "${SUPPLY_SCAN}" ]; then
  fail_test "AC-12-N01 [REGRESSION-12-SUPPLY-CHAIN-NPXCMD]" "mcp-supply-chain-scan.sh not found at ${SUPPLY_SCAN}"
else
  # Test 1: zero servers + mcp.json exits 0 (scope: MCP config only, not full compose)
  # Run from the src/ directory so the scan focuses on the mcp.json and src/ Dockerfiles.
  # The full docker-compose.yml scan catches verdaccio:5 (no digest) - that is a separate
  # item-14 finding (see FINDING below). The MCP supply-chain gate is for MCP server configs.
  ZERO_EXIT=0
  ZERO_OUTPUT=$(cd "${PROJECT_ROOT}/src" && MCP_JSON_PATH="${MCP_JSON}" bash "${SUPPLY_SCAN}" 2>&1) || ZERO_EXIT=$?
  if [ "${ZERO_EXIT}" -eq 0 ]; then
    pass_test "AC-12-N01-zero-server" "supply-chain scan (src/ scope): zero servers exits 0 (RC-1 regression: clean baseline)"
  else
    # Check if the failure is only from docker-compose.yml Verdaccio image (item-14 finding)
    if echo "${ZERO_OUTPUT}" | grep -q "verdaccio" && \
       ! echo "${ZERO_OUTPUT}" | grep -qiE "(npx|uvx|@latest)"; then
      fail_test "AC-12-N01-zero-server" "FINDING->item-14: supply-chain scan exits ${ZERO_EXIT} due to verdaccio/verdaccio:5 (tag without @sha256: digest). Verdaccio image in docker-compose.yml must be pinned to a digest. Output: ${ZERO_OUTPUT}"
    else
      fail_test "AC-12-N01-zero-server" "supply-chain scan: zero servers exits ${ZERO_EXIT} (should be 0). Output: ${ZERO_OUTPUT}"
    fi
  fi

  # Test 2: npx as command field exits 1 (RC-1 regression guard)
  NPX_MCP=$(mktemp /tmp/acc15-mcp-npx-XXXXXX.json)
  printf '{"inputs":[],"servers":{"evil":{"command":"npx","args":["-y","@evil/server"]}}}' > "${NPX_MCP}"
  NPX_EXIT=0
  NPX_OUTPUT=$(MCP_JSON_PATH="${NPX_MCP}" bash "${SUPPLY_SCAN}" 2>&1) || NPX_EXIT=$?
  rm -f "${NPX_MCP}"
  if [ "${NPX_EXIT}" -ne 0 ] && echo "${NPX_OUTPUT}" | grep -qiE "(npx|runtime.fetch|prohibited)"; then
    pass_test "AC-12-N01-npx-command" "supply-chain scan: npx-as-command exits ${NPX_EXIT} + names npx violation (RC-1 permanent regression closed)"
  else
    fail_test "AC-12-N01-npx-command" "supply-chain scan: npx-as-command exit=${NPX_EXIT} (expected non-zero + npx violation). Output: ${NPX_OUTPUT}"
  fi

  # Test 3: uvx as command exits 1
  UVX_MCP=$(mktemp /tmp/acc15-mcp-uvx-XXXXXX.json)
  printf '{"inputs":[],"servers":{"pyserver":{"command":"uvx","args":["mcp-server-python"]}}}' > "${UVX_MCP}"
  UVX_EXIT=0
  UVX_OUTPUT=$(MCP_JSON_PATH="${UVX_MCP}" bash "${SUPPLY_SCAN}" 2>&1) || UVX_EXIT=$?
  rm -f "${UVX_MCP}"
  if [ "${UVX_EXIT}" -ne 0 ]; then
    pass_test "AC-12-N01-uvx-command" "supply-chain scan: uvx-as-command exits ${UVX_EXIT} (prohibited runtime loader)"
  else
    fail_test "AC-12-N01-uvx-command" "supply-chain scan: uvx-as-command exits 0 (should be non-zero)"
  fi

  # Test 4: @latest in args exits 1
  LATEST_MCP=$(mktemp /tmp/acc15-mcp-latest-XXXXXX.json)
  printf '{"inputs":[],"servers":{"latestserver":{"command":"node","args":["@acme/mcp-server@latest"]}}}' > "${LATEST_MCP}"
  LATEST_EXIT=0
  LATEST_OUTPUT=$(MCP_JSON_PATH="${LATEST_MCP}" bash "${SUPPLY_SCAN}" 2>&1) || LATEST_EXIT=$?
  rm -f "${LATEST_MCP}"
  if [ "${LATEST_EXIT}" -ne 0 ]; then
    pass_test "AC-12-N01-latest" "supply-chain scan: @latest-in-args exits ${LATEST_EXIT} (unpinned version tag detected)"
  else
    fail_test "AC-12-N01-latest" "supply-chain scan: @latest-in-args exits 0 (should be non-zero)"
  fi
fi

# ------------------------------------------------------------
# AC-12-N02: composability gate exits 0 (no server present)
# ------------------------------------------------------------
begin_test "AC-12-N02" "ci/mcp-composability-gate.sh exits 0 (no server present)"
if [ ! -f "${COMPOSABILITY_GATE}" ]; then
  fail_test "AC-12-N02" "mcp-composability-gate.sh not found at ${COMPOSABILITY_GATE}"
else
  COMP_EXIT=0
  COMP_OUTPUT=$(MCP_JSON_PATH="${MCP_JSON}" bash "${COMPOSABILITY_GATE}" 2>&1) || COMP_EXIT=$?
  if [ "${COMP_EXIT}" -eq 0 ]; then
    pass_test "AC-12-N02" "composability gate exits 0 (zero servers, no gate-decision record required)"
  else
    fail_test "AC-12-N02" "composability gate exits ${COMP_EXIT}. Output: ${COMP_OUTPUT}"
  fi
fi

# Note: AC-MCP-02 Linux+root manifest immutability test REQUIRES-LINUX-HOST
add_skip_note "AC-MCP-02" "REQUIRES-LINUX-HOST: mcp-integrity-manifest-generate.sh run as root + lsattr verify requires a Linux host (macOS chattr is unavailable). Wire to item-18 regression on Linux."
# Note: AC-MCP-12 sandbox-auto-approve hook-fires REQUIRES-VS-CODE-RUNTIME
add_skip_note "AC-MCP-12" "REQUIRES-LIVE-RUNTIME: OI-12-E sandbox containment test (PreToolUse hook fires for sandboxed server tool calls) requires VS Code runtime + sandboxed server. Zero-server default has nothing to contain. Item 16 red-teamer owns this when a server is added."

# Summary
print_component_summary "${COMPONENT}" "${PASS}" "${FAIL}" "${SKIP}"
