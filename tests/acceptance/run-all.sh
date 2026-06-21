#!/usr/bin/env bash
# tests/acceptance/run-all.sh
#
# Item-15 acceptance suite top-level runner.
# Brings up the stack with project name acc15 + compose override, runs all tests,
# reports PASS/FAIL/SKIP per test and a summary, tears down the stack.
#
# Usage:
#   cd <project-root>
#   bash tests/acceptance/run-all.sh [--no-build] [--no-teardown] [--skip-stack]
#
# Options:
#   --no-build      Skip 'docker compose build' (use cached images)
#   --no-teardown   Do not tear down the stack after tests (for debugging)
#   --skip-stack    Do not bring up the stack (assume it is already running)
#   --component X   Run only component X (gateway, container-base, credentials,
#                   approval, mcp, detection, caches, golden-path)
#
# Environment:
#   PROJECT_ROOT    (auto-detected from this script's location)
#   ACC15_TIMEOUT   Seconds to wait for the stack to become healthy (default: 180)
#
# Parallel-run coordination with item-16 red-teamer:
#   This runner uses project name 'acc15' and compose override
#   tests/acceptance/compose.test-override.yml which:
#     - Removes hardcoded container_name entries (prevents naming collision)
#     - Uses copilot-net=172.31.0.0/24 and cache-net=172.30.0.0/24 (item-15's ranges)
#     - Lowers mem_limit to 2g to leave room for the concurrent red-teamer stack
#   Item-16 uses project name 'red16' with 172.28.x and 172.29.x subnets.
#
# TEARDOWN:
#   Always runs 'docker compose -p acc15 down -v' at the end (unless --no-teardown).
#   This removes all acc15-prefixed containers, networks, and volumes.
#   Named volumes are prefixed by the project name (acc15_agent-workspace, etc.)
#   and are removed by 'down -v' - they do NOT collide with production volumes.
#
# Regression discipline (item 18):
#   This script is the regression harness. Re-run on every VS Code, Copilot,
#   MCP, base-image, or Docker update. The test IDs and permanent regression
#   assertions (REGRESSION-*) are the tripwires.
#
# Exit code:
#   0 = all tests passed (FAIL count = 0)
#   1 = one or more tests FAILED
#   2 = runner setup error (stack failed to come up, etc.)

set -uo pipefail

# ============================================================
# SETUP
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
OVERRIDE_FILE="${SCRIPT_DIR}/compose.test-override.yml"
PROJECT="acc15"
LOG_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_FILE="${LOG_DIR}/run-${TIMESTAMP}.log"
SUMMARY_FILE="${LOG_DIR}/summary-${TIMESTAMP}.txt"
NO_BUILD=0
NO_TEARDOWN=0
SKIP_STACK=0
ONLY_COMPONENT=""
TIMEOUT="${ACC15_TIMEOUT:-180}"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)    NO_BUILD=1 ;;
    --no-teardown) NO_TEARDOWN=1 ;;
    --skip-stack)  SKIP_STACK=1 ;;
    --component)   ONLY_COMPONENT="$2"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "${LOG_DIR}"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
STACK_BROUGHT_UP=0

# ============================================================
# LOGGING
# ============================================================

log() {
  local line="[runner] $*"
  echo "${line}"
  echo "${line}" >> "${LOG_FILE}"
}

log_section() {
  local line="=== $* ==="
  echo ""
  echo "${line}"
  echo "${line}" >> "${LOG_FILE}"
}

# ============================================================
# TEARDOWN (trap on exit)
# ============================================================

teardown() {
  local exit_code=$?
  if [ "${STACK_BROUGHT_UP}" -eq 1 ] && [ "${NO_TEARDOWN}" -eq 0 ]; then
    log "Tearing down acc15 stack..."
    docker compose -p "${PROJECT}" \
      -f "${COMPOSE_FILE}" \
      -f "${OVERRIDE_FILE}" \
      --profile copilot \
      down -v 2>&1 | tee -a "${LOG_FILE}" || true
    # Remove the pre-created external networks (created before 'up')
    docker network rm acc15_copilot-net acc15_cache-net 2>/dev/null || true
    log "Teardown complete. No acc15 containers/volumes/networks remain."
  elif [ "${NO_TEARDOWN}" -eq 1 ]; then
    log "WARNING: --no-teardown set. acc15 stack still running. Tear down manually:"
    log "  docker compose -p acc15 -f docker-compose.yml -f tests/acceptance/compose.test-override.yml --profile copilot down -v"
    log "  docker network rm acc15_copilot-net acc15_cache-net"
  fi

  # Final summary
  echo ""
  echo "========================================================"
  echo "ACCEPTANCE SUITE FINAL SUMMARY (item 15)"
  echo "Run: ${TIMESTAMP}"
  echo "Log: ${LOG_FILE}"
  echo "========================================================"
  echo "PASS:  ${TOTAL_PASS}"
  echo "FAIL:  ${TOTAL_FAIL}"
  echo "SKIP:  ${TOTAL_SKIP}"
  echo "TOTAL: $((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))"
  echo ""
  if [ "${TOTAL_FAIL}" -gt 0 ]; then
    echo "RESULT: FAILED (${TOTAL_FAIL} test(s) failed)"
    echo "See ${LOG_FILE} for details."
    echo ""
    echo "FINDINGS (routes back to build items):"
    grep "\[FAIL\]" "${LOG_FILE}" 2>/dev/null | head -20 || true
  else
    echo "RESULT: PASSED (${TOTAL_PASS} passed, ${TOTAL_SKIP} skipped)"
  fi
  echo "========================================================"

  # Write summary file
  {
    echo "TIMESTAMP: ${TIMESTAMP}"
    echo "PASS: ${TOTAL_PASS}"
    echo "FAIL: ${TOTAL_FAIL}"
    echo "SKIP: ${TOTAL_SKIP}"
    echo "RESULT: $([ "${TOTAL_FAIL}" -eq 0 ] && echo PASSED || echo FAILED)"
  } > "${SUMMARY_FILE}"

  exit "${exit_code}"
}
trap teardown EXIT

# ============================================================
# STACK STARTUP
# ============================================================

cd "${PROJECT_ROOT}"

if [ "${SKIP_STACK}" -eq 0 ]; then
  log_section "STARTING acc15 STACK"
  log "Project root: ${PROJECT_ROOT}"
  log "Compose file: ${COMPOSE_FILE}"
  log "Override:     ${OVERRIDE_FILE}"
  log "Project name: ${PROJECT}"

  if [ "${NO_BUILD}" -eq 0 ]; then
    log "Building images (--no-build to skip)..."
    docker compose -p "${PROJECT}" \
      -f "${COMPOSE_FILE}" \
      -f "${OVERRIDE_FILE}" \
      --profile copilot \
      build 2>&1 | tee -a "${LOG_FILE}"
  fi

  # Pre-create external networks with specific subnets (avoids compose IPAM merge bug).
  # The override marks these as external:true; compose attaches to them instead of creating.
  log "Pre-creating external networks with non-conflicting subnets (10.15.0.0/24, 10.15.1.0/24)..."
  docker network create --driver bridge --subnet 10.15.0.0/24 acc15_copilot-net 2>/dev/null || \
    log "(acc15_copilot-net already exists - continuing)"
  docker network create --driver bridge --subnet 10.15.1.0/24 acc15_cache-net 2>/dev/null || \
    log "(acc15_cache-net already exists - continuing)"

  log "Starting stack..."
  docker compose -p "${PROJECT}" \
    -f "${COMPOSE_FILE}" \
    -f "${OVERRIDE_FILE}" \
    --profile copilot \
    up -d 2>&1 | tee -a "${LOG_FILE}"
  STACK_BROUGHT_UP=1

  # FIX (2026-06-20): Health poll uses 'docker compose ps gateway-copilot --format {{.Health}}'
  # instead of the prior Python JSON scan over 'ps --format json'.
  # Root cause of the original timeout: the prior 'up -d' lacked --profile copilot, so
  # gateway-copilot never started, the JSON output contained no "gateway" container, the
  # Python snippet returned empty on every iteration, and the poll timed out at 180s.
  # Additionally the Python snippet looked at 'Health' in the compose-ps JSON, which
  # is correct but only works when the service is actually running. The simpler Go-template
  # approach (same as rt25-run-profiles.sh line 156) reads health from the running container
  # directly. An empty result (container not yet started) is treated as "starting" and
  # the loop continues.
  log "Waiting for gateway to become healthy (timeout: ${TIMEOUT}s)..."
  WAITED=0
  while true; do
    GW_HEALTH=$(docker compose -p "${PROJECT}" \
      -f "${COMPOSE_FILE}" \
      -f "${OVERRIDE_FILE}" \
      --profile copilot \
      ps gateway-copilot --format '{{.Health}}' 2>/dev/null | tr -d '\r' || echo "")
    # Treat empty (container not yet listed) as "starting".
    GW_HEALTH="${GW_HEALTH:-starting}"

    if [ "${GW_HEALTH}" = "healthy" ]; then
      log "Gateway is healthy."
      break
    fi

    if [ "${WAITED}" -ge "${TIMEOUT}" ]; then
      log "ERROR: Gateway did not become healthy within ${TIMEOUT}s. Last status: ${GW_HEALTH}"
      docker compose -p "${PROJECT}" \
        -f "${COMPOSE_FILE}" \
        -f "${OVERRIDE_FILE}" \
        --profile copilot \
        logs --tail=50 2>&1 | tee -a "${LOG_FILE}" || true
      exit 2
    fi

    sleep 5
    WAITED=$((WAITED + 5))
    log "Waiting... ${WAITED}s / ${TIMEOUT}s (gateway health: ${GW_HEALTH})"
  done

  # Additional wait for caches to initialize
  log "Waiting 10s for caches (Verdaccio/devpi) to initialize..."
  sleep 10
fi

# ============================================================
# DISCOVER CONTAINER IDs
# ============================================================

log_section "DISCOVERING CONTAINER IDs (project: ${PROJECT})"

DEVCONTAINER_ID=$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" \
  --filter "label=com.docker.compose.service=devcontainer" \
  --format "{{.ID}}" 2>/dev/null | head -1)

# FIX-F2 (2026-06-20): gateway service renamed to gateway-copilot (per-profile gateways).
# acc15 uses the copilot profile, so the gateway service label is gateway-copilot.
GATEWAY_ID=$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" \
  --filter "label=com.docker.compose.service=gateway-copilot" \
  --format "{{.ID}}" 2>/dev/null | head -1)

VERDACCIO_ID=$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" \
  --filter "label=com.docker.compose.service=verdaccio" \
  --format "{{.ID}}" 2>/dev/null | head -1)

DEVPI_ID=$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" \
  --filter "label=com.docker.compose.service=devpi" \
  --format "{{.ID}}" 2>/dev/null | head -1)

log "DEVCONTAINER_ID: ${DEVCONTAINER_ID:-NOT_FOUND}"
log "GATEWAY_ID:      ${GATEWAY_ID:-NOT_FOUND}"
log "VERDACCIO_ID:    ${VERDACCIO_ID:-NOT_FOUND}"
log "DEVPI_ID:        ${DEVPI_ID:-NOT_FOUND}"

if [ -z "${DEVCONTAINER_ID}" ]; then
  log "ERROR: devcontainer not running. Cannot proceed."
  exit 2
fi
if [ -z "${GATEWAY_ID}" ]; then
  log "ERROR: gateway not running. Cannot proceed."
  exit 2
fi

export DEVCONTAINER_ID GATEWAY_ID VERDACCIO_ID DEVPI_ID PROJECT PROJECT_ROOT

# ============================================================
# COMPONENT TEST RUNNER HELPER
# ============================================================

run_component() {
  local name="$1"
  local script="$2"

  if [ -n "${ONLY_COMPONENT}" ] && [ "${ONLY_COMPONENT}" != "${name}" ]; then
    return 0
  fi

  log_section "COMPONENT: ${name}"

  # Run the test script in a subshell; capture output; extract counts
  COMP_PASS=0
  COMP_FAIL=0
  COMP_SKIP=0

  # Run the component test and tee to log
  # The script sets PASS/FAIL/SKIP internally; we parse the [PASS]/[FAIL]/[SKIP] lines
  COMP_OUTPUT=$(bash "${script}" 2>&1) || true
  echo "${COMP_OUTPUT}" | tee -a "${LOG_FILE}"

  # grep -c can return "0\n0" on macOS when the input contains multiple lines
  # and none match - use tr to strip newlines before arithmetic.
  COMP_PASS=$(echo "${COMP_OUTPUT}" | grep -c "^\[PASS\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
  COMP_FAIL=$(echo "${COMP_OUTPUT}" | grep -c "^\[FAIL\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
  COMP_SKIP=$(echo "${COMP_OUTPUT}" | grep -c "^\[SKIP\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
  # Guard: ensure values are numeric
  COMP_PASS=$((COMP_PASS + 0))
  COMP_FAIL=$((COMP_FAIL + 0))
  COMP_SKIP=$((COMP_SKIP + 0))

  # Accumulate totals
  TOTAL_PASS=$((TOTAL_PASS + COMP_PASS))
  TOTAL_FAIL=$((TOTAL_FAIL + COMP_FAIL))
  TOTAL_SKIP=$((TOTAL_SKIP + COMP_SKIP))

  log "[${name}] PASS=${COMP_PASS} FAIL=${COMP_FAIL} SKIP=${COMP_SKIP}"
}

# ============================================================
# RUN COMPONENT TESTS
# ============================================================

COMP_DIR="${SCRIPT_DIR}/component"

log_section "RUNNING ACCEPTANCE SUITE (item 15, project acc15)"
log "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Docker version: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
log "Project: ${PROJECT}"

# Component order: boundary first (same order as build phases)
run_component "gateway"         "${COMP_DIR}/test-08-gateway.sh"
run_component "container-base"  "${COMP_DIR}/test-09-container-base.sh"
run_component "credentials"     "${COMP_DIR}/test-10-credentials.sh"
run_component "approval"        "${COMP_DIR}/test-11-approval.sh"
run_component "mcp"             "${COMP_DIR}/test-12-mcp.sh"
run_component "detection"       "${COMP_DIR}/test-13-detection.sh"
run_component "caches"          "${COMP_DIR}/test-14-caches.sh"
run_component "golden-path"     "${COMP_DIR}/test-golden-path.sh"

# ============================================================
# PERMANENT REGRESSION ASSERTION SUMMARY
# (The tripwires for item 18 regression discipline)
# ============================================================

log_section "PERMANENT REGRESSION ASSERTIONS (item 18 tripwires)"
REGRESSION_TESTS=(
  "REGRESSION-08-EPERM"
  "REGRESSION-08-N07"
  "REGRESSION-08-FAILCLOSED"
  "REGRESSION-11-SELFTEST"
  "REGRESSION-11-DUAL-OUT"
  "AC-12-N01-npx-command"
  "REGRESSION-12-INTEGRITY-FIELDS"
  "REGRESSION-13-SINK-WRITE-ONLY"
  "REGRESSION-13-HOOK-LOG-SINK"
  "REGRESSION-14-EXTERNAL-4873-DROP"
  "REGRESSION-14-EXTERNAL-3141-DROP"
)

REGRESSION_PASS=0
REGRESSION_FAIL=0
echo ""
echo "Regression assertion results (from log):"
for rt in "${REGRESSION_TESTS[@]}"; do
  if grep -q "\[PASS\].*${rt}" "${LOG_FILE}" 2>/dev/null; then
    echo "  [PASS] ${rt}"
    REGRESSION_PASS=$((REGRESSION_PASS + 1))
  elif grep -q "\[FAIL\].*${rt}" "${LOG_FILE}" 2>/dev/null; then
    echo "  [FAIL] ${rt}  <-- REGRESSION DETECTED"
    REGRESSION_FAIL=$((REGRESSION_FAIL + 1))
  elif grep -q "\[SKIP\].*${rt}" "${LOG_FILE}" 2>/dev/null; then
    echo "  [SKIP] ${rt}"
  else
    echo "  [???]  ${rt} (not found in log)"
  fi
done
echo ""
echo "Regression assertions: PASS=${REGRESSION_PASS} FAIL=${REGRESSION_FAIL}"
if [ "${REGRESSION_FAIL}" -gt 0 ]; then
  echo "WARNING: ${REGRESSION_FAIL} permanent regression assertion(s) FAILED."
fi

# The EXIT trap (teardown) handles the final summary and exit code.
# If TOTAL_FAIL > 0, exit code 1 is set there. But we need to set it here for the trap.
[ "${TOTAL_FAIL}" -eq 0 ] || exit 1
exit 0
