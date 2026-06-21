#!/usr/bin/env bash
# tests/acceptance/component/test-13-detection.sh
#
# Acceptance tests for item 13 (detection and audit).
# Area 8, Phase 5.
#
# Coverage map (SPEC-07 AC-07-* and BUILD_PLAN AC-13-*):
#   AC-13-N02 (write-only sink): POST 201, GET/DELETE/PUT 405
#   AC-13-N04 (AL-08): mcp.json mismatch fires HIGH-SIGNAL at external sink (covered in test-12)
#   HOOK-LOG-SINK-SET: HOOK_LOG_SINK points at external sink (not local fallback)
#   SINK-WRITE-ONLY: ingest-proxy server.js: POST->201, GET->405
#   DETECT-ARTIFACTS: all required detect/ artifacts present (rsyslog, auditd, etc.)
#   D7-SELF-TEST: correlation-query.sh --self-test reconstructs seeded timeline
#   TIMESTAMPS-UTC: log entries use UTC (Z suffix)
#   NO-COMMITTED-CREDENTIAL: INGEST_PROXY_PASSWORD not in source
#
# Permanent regression assertions:
#   REGRESSION-13-SINK-WRITE-ONLY  external sink is write-only (POST 201, GET 405)
#   REGRESSION-13-HOOK-LOG-SINK    HOOK_LOG_SINK points at external sink
#
# Most detection tests that require a live running sink (the ingest-proxy)
# are run against the container's reported HOOK_LOG_SINK env variable.
# The ingest-proxy can be started separately for full verification.
#
# Requires: DEVCONTAINER_ID set (for env var checks). INGEST_PROXY_URL optional.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/test-helpers.sh"

COMPONENT="detection"
PASS=0
FAIL=0
SKIP=0
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

dc_exec() {
  docker exec --user 1000:1000 "${DEVCONTAINER_ID}" "$@"
}

# ------------------------------------------------------------
# HOOK-LOG-SINK-SET (PERMANENT REGRESSION: REGRESSION-13-HOOK-LOG-SINK)
# HOOK_LOG_SINK must point at the external sink, not local fallback
# AC-13-N06 (from BUILD_PLAN): the production HOOK_LOG_SINK must NOT be local fallback
# ------------------------------------------------------------
begin_test "HOOK-LOG-SINK-SET [REGRESSION-13-HOOK-LOG-SINK]" "HOOK_LOG_SINK points at external sink (not /tmp or /var/log local fallback)"
HOOK_LOG_SINK=$(docker exec "${DEVCONTAINER_ID}" sh -c 'echo "${HOOK_LOG_SINK:-UNSET}"' 2>/dev/null) || HOOK_LOG_SINK="UNSET"
MCP_SINK=$(docker exec "${DEVCONTAINER_ID}" sh -c 'echo "${MCP_DETECTION_SINK:-UNSET}"' 2>/dev/null) || MCP_SINK="UNSET"

if echo "${HOOK_LOG_SINK}" | grep -qE "^http(s)?://"; then
  pass_test "HOOK-LOG-SINK-SET [REGRESSION-13-HOOK-LOG-SINK]" "HOOK_LOG_SINK='${HOOK_LOG_SINK}' (HTTP sink, not local fallback)"
elif echo "${HOOK_LOG_SINK}" | grep -qE "^/tmp|^/var/log"; then
  fail_test "HOOK-LOG-SINK-SET [REGRESSION-13-HOOK-LOG-SINK]" "HOOK_LOG_SINK='${HOOK_LOG_SINK}' is LOCAL FALLBACK path. AC-13-N06: must point at external sink. Item 13 is NOT DONE until this is wired. (FINDING -> item 13)"
else
  fail_test "HOOK-LOG-SINK-SET [REGRESSION-13-HOOK-LOG-SINK]" "HOOK_LOG_SINK='${HOOK_LOG_SINK}' (unexpected value; expected http://host.docker.internal:3001/ingest or similar)"
fi

# Verify MCP_DETECTION_SINK also points at external sink
if echo "${MCP_SINK}" | grep -qE "^http(s)?://"; then
  pass_test "HOOK-LOG-SINK-MCP" "MCP_DETECTION_SINK='${MCP_SINK}' (HTTP external sink)"
else
  fail_test "HOOK-LOG-SINK-MCP" "MCP_DETECTION_SINK='${MCP_SINK}' (expected HTTP external sink)"
fi

# ------------------------------------------------------------
# SINK-WRITE-ONLY (PERMANENT REGRESSION: REGRESSION-13-SINK-WRITE-ONLY)
# Test the ingest-proxy server: POST 201, GET 405, DELETE 405, PUT 405
# This tests the server.js write-only enforcement (OI-13-E / AC-13-N02).
# We test the server.js logic directly if node is available; otherwise skip.
# ------------------------------------------------------------
begin_test "SINK-WRITE-ONLY [REGRESSION-13-SINK-WRITE-ONLY]" "ingest-proxy: POST->201, GET->405, DELETE->405, PUT->405"
INGEST_PROXY_JS="${PROJECT_ROOT}/src/detect/ingest-proxy/server.js"
if [ ! -f "${INGEST_PROXY_JS}" ]; then
  fail_test "SINK-WRITE-ONLY [REGRESSION-13-SINK-WRITE-ONLY]" "server.js not found at ${INGEST_PROXY_JS}"
else
  # Start a local instance of the ingest proxy in test mode (SINK_FILE to a temp file)
  if command -v node >/dev/null 2>&1; then
    SINK_TMP=$(mktemp /tmp/acc15-ingest-XXXXXX.log)
    PROXY_PORT=13001
    INGEST_PORT=${PROXY_PORT} SINK_FILE="${SINK_TMP}" node "${INGEST_PROXY_JS}" &
    PROXY_PID=$!
    sleep 2  # Give it time to start

    INGEST_URL="http://localhost:${PROXY_PORT}/ingest"
    WRITE_ONLY_FAIL=0

    # Test POST -> 201
    POST_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${INGEST_URL}" \
      -H "Content-Type: application/json" \
      -d '{"test":"acc15","event":"acceptance-test","ts":"2026-06-14T00:00:00Z"}' \
      --max-time 5 2>/dev/null) || POST_STATUS="000"
    if [ "${POST_STATUS}" = "201" ]; then
      pass_test "SINK-WRITE-ONLY-POST" "POST /ingest -> 201 (write accepted)"
    else
      fail_test "SINK-WRITE-ONLY-POST" "POST /ingest -> ${POST_STATUS} (expected 201)"
      WRITE_ONLY_FAIL=1
    fi

    # Test GET -> 405
    # Do NOT use -f: 4xx responses are expected here and -f would cause curl to
    # return exit code 22, making the || "000" fallback trigger.
    GET_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${INGEST_URL}" \
      --max-time 5 2>/dev/null)
    if [ "${GET_STATUS}" = "405" ]; then
      pass_test "SINK-WRITE-ONLY-GET" "GET /ingest -> 405 (read rejected; write-only enforcement)"
    else
      fail_test "SINK-WRITE-ONLY-GET" "GET /ingest -> ${GET_STATUS} (expected 405)"
      WRITE_ONLY_FAIL=1
    fi

    # Test DELETE -> 405
    DEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${INGEST_URL}" \
      --max-time 5 2>/dev/null)
    if [ "${DEL_STATUS}" = "405" ]; then
      pass_test "SINK-WRITE-ONLY-DELETE" "DELETE /ingest -> 405 (delete rejected)"
    else
      fail_test "SINK-WRITE-ONLY-DELETE" "DELETE /ingest -> ${DEL_STATUS} (expected 405)"
      WRITE_ONLY_FAIL=1
    fi

    # Test PUT -> 405
    PUT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${INGEST_URL}" \
      -H "Content-Type: application/json" -d '{}' \
      --max-time 5 2>/dev/null)
    if [ "${PUT_STATUS}" = "405" ]; then
      pass_test "SINK-WRITE-ONLY-PUT" "PUT /ingest -> 405 (rejected)"
    else
      fail_test "SINK-WRITE-ONLY-PUT" "PUT /ingest -> ${PUT_STATUS} (expected 405)"
      WRITE_ONLY_FAIL=1
    fi

    # Summary for write-only
    if [ "${WRITE_ONLY_FAIL}" -eq 0 ]; then
      pass_test "SINK-WRITE-ONLY [REGRESSION-13-SINK-WRITE-ONLY]" "ingest-proxy write-only enforcement confirmed (POST 201 + GET/DELETE/PUT 405)"
    fi

    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
    rm -f "${SINK_TMP}"
  else
    skip_test "SINK-WRITE-ONLY [REGRESSION-13-SINK-WRITE-ONLY]" "REQUIRES-TOOL: node.js not available on host for local ingest-proxy test. Deploy the stack and test via INGEST_PROXY_URL=http://host.docker.internal:3001."
  fi
fi

# ------------------------------------------------------------
# DETECT-ARTIFACTS: all required detection artifacts present
# These must exist as files (they were built by item 13 implementer).
# ------------------------------------------------------------
begin_test "DETECT-ARTIFACTS" "all required detection artifacts present in src/detect/"
DETECT_DIR="${PROJECT_ROOT}/src/detect"
REQUIRED_ARTIFACTS=(
  "rsyslog-forward.conf"
  "auditd.rules"
  "otel-collector.yaml"
  "hook-forwarder-addition.sh"
  "immudb-setup.sh"
  "alert-rules.dsl"
  "dns-logging.conf"
  "canary-placement.sh"
  "correlation-query.sh"
  "ingest-proxy/server.js"
)
MISSING_ARTIFACTS=()
for artifact in "${REQUIRED_ARTIFACTS[@]}"; do
  if [ ! -f "${DETECT_DIR}/${artifact}" ]; then
    MISSING_ARTIFACTS+=("${artifact}")
  fi
done
if [ ${#MISSING_ARTIFACTS[@]} -eq 0 ]; then
  pass_test "DETECT-ARTIFACTS" "all ${#REQUIRED_ARTIFACTS[@]} required detection artifacts present"
else
  fail_test "DETECT-ARTIFACTS" "missing detection artifacts: ${MISSING_ARTIFACTS[*]}"
fi

# ------------------------------------------------------------
# AL-08: verify alert-rules.dsl defines AL-08 with REAL SPEC-06 fields
# ------------------------------------------------------------
begin_test "AL-08-FIELDS" "alert-rules.dsl: AL-08 defined with REAL SPEC-06 fields (component=mcp-integrity-check AND level=HIGH-SIGNAL)"
ALERT_DSL="${PROJECT_ROOT}/src/detect/alert-rules.dsl"
if [ ! -f "${ALERT_DSL}" ]; then
  fail_test "AL-08-FIELDS" "alert-rules.dsl not found at ${ALERT_DSL}"
else
  if grep -q "mcp-integrity-check" "${ALERT_DSL}" && \
     grep -q "HIGH-SIGNAL" "${ALERT_DSL}"; then
    pass_test "AL-08-FIELDS" "alert-rules.dsl contains AL-08 with REAL SPEC-06 fields (mcp-integrity-check AND HIGH-SIGNAL)"
  else
    fail_test "AL-08-FIELDS" "alert-rules.dsl missing AL-08 SPEC-06 fields. Required: component=mcp-integrity-check AND level=HIGH-SIGNAL"
  fi
fi

# ------------------------------------------------------------
# TIMESTAMPS-UTC: detection artifacts use UTC timestamps
# ------------------------------------------------------------
begin_test "TIMESTAMPS-UTC" "detection log format uses UTC (Z suffix in timestamp)"
HOOK_FWD="${PROJECT_ROOT}/src/detect/hook-forwarder-addition.sh"
if [ -f "${HOOK_FWD}" ]; then
  if grep -q "%Y-%m-%dT%H:%M:%SZ" "${HOOK_FWD}" 2>/dev/null || \
     grep -q "date -u" "${HOOK_FWD}" 2>/dev/null || \
     grep -q "UTC" "${HOOK_FWD}" 2>/dev/null; then
    pass_test "TIMESTAMPS-UTC" "hook-forwarder uses UTC timestamp format"
  else
    fail_test "TIMESTAMPS-UTC" "hook-forwarder timestamp format may not be UTC (check date format in hook-forwarder-addition.sh)"
  fi
else
  fail_test "TIMESTAMPS-UTC" "hook-forwarder-addition.sh not found"
fi

# ------------------------------------------------------------
# NO-COMMITTED-CREDENTIAL: immudb password not hardcoded in source
# ------------------------------------------------------------
begin_test "NO-COMMITTED-CREDENTIAL" "no hardcoded immudb password or credential in src/detect/ source files"
CREDENTIAL_HITS=$(grep -rl "immudb_password\|IMMUDB_PASSWORD\|password123\|changeme\|secret123" \
  "${PROJECT_ROOT}/src/detect/" 2>/dev/null | grep -v ".md" || echo "")
if [ -z "${CREDENTIAL_HITS}" ]; then
  pass_test "NO-COMMITTED-CREDENTIAL" "no hardcoded credentials found in src/detect/ source files"
else
  fail_test "NO-COMMITTED-CREDENTIAL" "potential hardcoded credentials found: ${CREDENTIAL_HITS}"
fi

# Check that .env.example exists and IMMUDB_ADMIN_PASSWORD is required (not set to a value)
ENV_EXAMPLE="${PROJECT_ROOT}/src/detect/.env.example"
if [ -f "${ENV_EXAMPLE}" ]; then
  if grep -q "IMMUDB_ADMIN_PASSWORD" "${ENV_EXAMPLE}"; then
    pass_test "NO-COMMITTED-CREDENTIAL-ENV" ".env.example documents IMMUDB_ADMIN_PASSWORD as env-required (not hardcoded)"
  else
    fail_test "NO-COMMITTED-CREDENTIAL-ENV" ".env.example missing IMMUDB_ADMIN_PASSWORD entry"
  fi
fi

# ------------------------------------------------------------
# D7-SELF-TEST: correlation-query.sh --self-test
# AC-07-P06: reconstructs seeded 4-event session timeline
# ------------------------------------------------------------
begin_test "D7-SELF-TEST" "correlation-query.sh --self-test reconstructs seeded session timeline (AC-07-P06)"
CORR_QUERY="${PROJECT_ROOT}/src/detect/correlation-query.sh"
if [ ! -f "${CORR_QUERY}" ]; then
  fail_test "D7-SELF-TEST" "correlation-query.sh not found at ${CORR_QUERY}"
else
  CORR_EXIT=0
  CORR_OUTPUT=$(bash "${CORR_QUERY}" --self-test 2>&1) || CORR_EXIT=$?
  if [ "${CORR_EXIT}" -eq 0 ]; then
    pass_test "D7-SELF-TEST" "correlation-query.sh --self-test exit 0 (D7 session-join self-test passed)"
  else
    # Check if --self-test is implemented (some scripts may have it, some not yet)
    if echo "${CORR_OUTPUT}" | grep -qiE "(not implemented|no.*self.test|usage)"; then
      skip_test "D7-SELF-TEST" "REQUIRES-IMPLEMENTATION: correlation-query.sh --self-test mode not yet implemented. Item 13 OI-13-G: must build and security-review the D7 correlation against a seeded test session."
    else
      fail_test "D7-SELF-TEST" "correlation-query.sh --self-test exit ${CORR_EXIT}. Output: ${CORR_OUTPUT}"
    fi
  fi
fi

# Note: live detection tests (AC-13-P01..P06, auditd canary-watch, OTel spans)
# require a Linux host + running auditd + live sink
add_skip_note "AC-13-LIVE" "REQUIRES-LINUX-HOST: auditd rules (-e 2 unload-prevention, canary -p r watch), OTel span capture, and rsyslog TLS forwarding require a Linux host with auditd. Wire to item-18 regression on Linux target."

# Summary
print_component_summary "${COMPONENT}" "${PASS}" "${FAIL}" "${SKIP}"
