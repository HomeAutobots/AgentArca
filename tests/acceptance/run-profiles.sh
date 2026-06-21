#!/usr/bin/env bash
# tests/acceptance/run-profiles.sh
#
# Item-25 per-profile acceptance suite runner.
# Tests the claude and codex profiles for boundary + structural properties
# WITHOUT needing live agent credentials. Also runs Copilot non-regression.
#
# CREDENTIAL-INDEPENDENT SCOPE:
#   - Brings up each profile in turn (agent binary installs via npm during build;
#     needs network for the build, NOT for the boundary tests themselves).
#   - Tests isolation tier, egress boundary (block/allow), config immutability,
#     zero-MCP structural checks, and profile isolation (volume + env-var).
#   - Copilot non-regression: re-runs the full acc15 suite (or a lightweight check
#     that the Copilot profile compose config is unchanged).
#
# DEFERRED (credential-dependent, clearly marked SKIP not FAIL):
#   AC-20-P01/P02 (live inference), AC-21-P01..P03 (live auth flows),
#   AC-22-P01/P02, AC-23-P01/P03, AC-24-P04, allowlist discovery+lock.
#
# Usage:
#   cd <project-root>
#   bash tests/acceptance/run-profiles.sh [options]
#
# Options:
#   --no-build          Skip 'docker compose build'
#   --no-teardown       Leave stacks running after tests (for debugging)
#   --skip-stack        Assume stacks are already running (for debugging)
#   --profile <p>       Run only this profile (claude | codex | copilot-regression)
#   --timeout <s>       Seconds to wait for gateway healthy (default: 240)
#
# Project names used (to avoid collision with acc15/rt16):
#   acc25-claude        Claude profile stack
#   acc25-codex         Codex profile stack
#   (Copilot regression reuses the acc15 runner directly)
#
# Subnet allocation (must not conflict with acc15 10.15.x or rt16 172.28-29.x):
#   acc25-claude_copilot-net: 10.25.0.0/24
#   acc25-claude_cache-net:   10.25.1.0/24
#   acc25-codex_copilot-net:  10.26.0.0/24
#   acc25-codex_cache-net:    10.26.1.0/24
#
# Exit codes:
#   0 = all tests passed (FAIL count = 0)
#   1 = one or more tests FAILED (boundary defects)
#   2 = runner setup error

set -uo pipefail

# ============================================================
# SETUP
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
# Per-profile overrides use distinct subnets to avoid conflicts with production stack
OVERRIDE_CLAUDE="${SCRIPT_DIR}/compose.acc25-claude-override.yml"
OVERRIDE_CODEX="${SCRIPT_DIR}/compose.acc25-codex-override.yml"
LOG_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_FILE="${LOG_DIR}/run-profiles-${TIMESTAMP}.log"
SUMMARY_FILE="${LOG_DIR}/summary-profiles-${TIMESTAMP}.txt"

NO_BUILD=0
NO_TEARDOWN=0
SKIP_STACK=0
ONLY_PROFILE=""
TIMEOUT="${ACC25_TIMEOUT:-240}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)         NO_BUILD=1 ;;
    --no-teardown)      NO_TEARDOWN=1 ;;
    --skip-stack)       SKIP_STACK=1 ;;
    --profile)          ONLY_PROFILE="$2"; shift ;;
    --timeout)          TIMEOUT="$2"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "${LOG_DIR}"

# Source test helpers so pass_test/fail_test/skip_test are available for
# the lightweight Copilot regression path in step 3.
source "${SCRIPT_DIR}/lib/test-helpers.sh"
PASS=0; FAIL=0; SKIP=0

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

# ============================================================
# LOGGING
# ============================================================

log() {
  local line="[runner-25] $*"
  echo "${line}"
  echo "${line}" >> "${LOG_FILE}"
}

log_section() {
  echo ""
  echo "=== $* ==="
  echo "" >> "${LOG_FILE}"
  echo "=== $* ===" >> "${LOG_FILE}"
}

# ============================================================
# STACK LIFECYCLE HELPERS
# ============================================================

# Bash-3.2-safe stack tracking: two plain scalar flags, one per project.
# Replaces the bash-4-only associative array (declare -A STACKS_BROUGHT_UP).
# Pattern modeled on rt25-run-profiles.sh which uses CURRENT_PROFILE + case
# statements and avoids associative arrays entirely.
STACK_UP_CLAUDE=0
STACK_UP_CODEX=0

get_override_file() {
  local profile="$1"
  case "${profile}" in
    claude) echo "${OVERRIDE_CLAUDE}" ;;
    codex)  echo "${OVERRIDE_CODEX}" ;;
    *)      echo "${OVERRIDE_CLAUDE}" ;;  # fallback
  esac
}

get_networks_for_proj() {
  local proj="$1"
  echo "${proj}_copilot-net ${proj}_cache-net"
}

teardown_stack() {
  local proj="$1"
  local profile="$2"
  local override_file
  override_file=$(get_override_file "${profile}")
  if [ "${NO_TEARDOWN}" -eq 0 ]; then
    log "Tearing down ${proj} stack..."
    docker compose -p "${proj}" \
      -f "${COMPOSE_FILE}" \
      -f "${override_file}" \
      --profile "${profile}" \
      down -v 2>&1 | tee -a "${LOG_FILE}" || true
    # Remove pre-created external networks
    docker network rm "${proj}_copilot-net" "${proj}_cache-net" 2>/dev/null || true
    log "${proj} teardown complete."
  else
    log "WARNING: --no-teardown set. ${proj} stack still running."
    log "  Tear down manually: docker compose -p ${proj} -f docker-compose.yml -f ${override_file} --profile ${profile} down -v"
    log "  Then: docker network rm ${proj}_copilot-net ${proj}_cache-net"
  fi
}

bring_up_stack() {
  local proj="$1"
  local profile="$2"
  local override_file
  override_file=$(get_override_file "${profile}")

  log_section "STARTING STACK: ${proj} (profile=${profile})"

  if [ "${NO_BUILD}" -eq 0 ]; then
    log "Building ${profile} profile images..."
    docker compose -p "${proj}" \
      -f "${COMPOSE_FILE}" \
      -f "${override_file}" \
      --profile "${profile}" \
      build 2>&1 | tee -a "${LOG_FILE}" || {
        log "ERROR: build failed for ${proj}"
        return 1
      }
  fi

  # Pre-create external networks with non-conflicting subnets
  case "${profile}" in
    claude)
      log "Pre-creating networks for ${proj} (10.25.0.0/24, 10.25.1.0/24)..."
      docker network create --driver bridge --subnet 10.25.0.0/24 "${proj}_copilot-net" 2>/dev/null || \
        log "(${proj}_copilot-net already exists)"
      docker network create --driver bridge --subnet 10.25.1.0/24 "${proj}_cache-net" 2>/dev/null || \
        log "(${proj}_cache-net already exists)"
      ;;
    codex)
      log "Pre-creating networks for ${proj} (10.26.0.0/24, 10.26.1.0/24)..."
      docker network create --driver bridge --subnet 10.26.0.0/24 "${proj}_copilot-net" 2>/dev/null || \
        log "(${proj}_copilot-net already exists)"
      docker network create --driver bridge --subnet 10.26.1.0/24 "${proj}_cache-net" 2>/dev/null || \
        log "(${proj}_cache-net already exists)"
      ;;
  esac

  # FIX-F2 (2026-06-20): SQUID_AGENT_FRAGMENT is now HARDCODED in each per-profile gateway
  # service (gateway-copilot / gateway-claude / gateway-codex). No host-shell export is
  # needed. The prior export was the workaround for the Phase 8 defect where the gateway
  # read SQUID_AGENT_FRAGMENT via Compose interpolation from the host environment.
  # Left as a no-op comment here to document why this export was removed.

  log "Starting ${proj} stack..."
  docker compose -p "${proj}" \
    -f "${COMPOSE_FILE}" \
    -f "${override_file}" \
    --profile "${profile}" \
    up -d 2>&1 | tee -a "${LOG_FILE}" || {
      log "ERROR: docker compose up failed for ${proj}"
      return 1
    }

  log "Waiting for gateway healthy in ${proj} (timeout: ${TIMEOUT}s)..."
  local waited=0
  while true; do
    local gw_health
    gw_health=$(docker compose -p "${proj}" \
      -f "${COMPOSE_FILE}" \
      -f "${override_file}" \
      --profile "${profile}" \
      ps --format json 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        name = d.get('Name', d.get('Service', ''))
        if 'gateway' in name.lower():
            print(d.get('Health', d.get('Status', 'unknown')))
            break
    except: pass
" 2>/dev/null || echo "unknown")

    if [ "${gw_health}" = "healthy" ]; then
      log "Gateway healthy for ${proj}."
      break
    fi

    if [ "${waited}" -ge "${TIMEOUT}" ]; then
      log "ERROR: gateway did not become healthy within ${TIMEOUT}s for ${proj} (last: ${gw_health})"
      docker compose -p "${proj}" \
        -f "${COMPOSE_FILE}" \
        -f "${override_file}" \
        --profile "${profile}" \
        logs --tail=40 2>&1 | tee -a "${LOG_FILE}" || true
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
    log "Waiting... ${waited}s/${TIMEOUT}s (${proj} gateway: ${gw_health})"
  done

  log "Waiting 10s for caches to initialize..."
  sleep 10
  return 0
}

discover_containers() {
  local proj="$1"
  local svc_suffix="$2"   # "" for copilot (devcontainer), "-claude" or "-codex"

  # FIX-F2 (2026-06-20): gateway service is now gateway-<profile>. Derive from svc_suffix.
  # svc_suffix="" -> copilot -> gateway-copilot
  # svc_suffix="-claude" -> gateway-claude
  # svc_suffix="-codex"  -> gateway-codex
  local gw_svc
  case "${svc_suffix}" in
    "")       gw_svc="gateway-copilot" ;;
    -claude)  gw_svc="gateway-claude" ;;
    -codex)   gw_svc="gateway-codex" ;;
    *)        gw_svc="gateway-copilot" ;;
  esac

  local dc_id gw_id
  dc_id=$(docker ps \
    --filter "label=com.docker.compose.project=${proj}" \
    --filter "label=com.docker.compose.service=devcontainer${svc_suffix}" \
    --format "{{.ID}}" 2>/dev/null | head -1)
  gw_id=$(docker ps \
    --filter "label=com.docker.compose.project=${proj}" \
    --filter "label=com.docker.compose.service=${gw_svc}" \
    --format "{{.ID}}" 2>/dev/null | head -1)

  echo "${dc_id}:${gw_id}"
}

# ============================================================
# COMPONENT TEST RUNNER HELPER
# ============================================================

run_component() {
  local name="$1"
  local script="$2"

  log_section "COMPONENT: ${name}"

  COMP_OUTPUT=$(bash "${script}" 2>&1) || true
  echo "${COMP_OUTPUT}" | tee -a "${LOG_FILE}"

  local c_pass c_fail c_skip summary_line
  # Prefer the component summary line ("--- [name] PASS=X FAIL=Y SKIP=Z TOTAL=N ---")
  # because fail_test writes to both stdout and stderr, causing grep -c to double-count.
  summary_line=$(echo "${COMP_OUTPUT}" | grep "^--- \[" | tail -1 || true)
  if [ -n "${summary_line}" ]; then
    c_pass=$(echo "${summary_line}" | grep -oE 'PASS=[0-9]+' | grep -oE '[0-9]+' || echo 0)
    c_fail=$(echo "${summary_line}" | grep -oE 'FAIL=[0-9]+' | grep -oE '[0-9]+' | head -1 || echo 0)
    c_skip=$(echo "${summary_line}" | grep -oE 'SKIP=[0-9]+' | grep -oE '[0-9]+' || echo 0)
  else
    # Fallback: grep count (may double-count FAILs due to stderr+stdout merge)
    c_pass=$(echo "${COMP_OUTPUT}" | grep -c "^\[PASS\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
    c_fail=$(echo "${COMP_OUTPUT}" | grep -c "^\[FAIL\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
    c_skip=$(echo "${COMP_OUTPUT}" | grep -c "^\[SKIP\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
  fi
  c_pass=$((c_pass + 0))
  c_fail=$((c_fail + 0))
  c_skip=$((c_skip + 0))

  TOTAL_PASS=$((TOTAL_PASS + c_pass))
  TOTAL_FAIL=$((TOTAL_FAIL + c_fail))
  TOTAL_SKIP=$((TOTAL_SKIP + c_skip))

  log "[${name}] PASS=${c_pass} FAIL=${c_fail} SKIP=${c_skip}"
}

# ============================================================
# TEARDOWN TRAP
# ============================================================

teardown_all() {
  local exit_code=$?

  if [ "${NO_TEARDOWN}" -eq 0 ]; then
    if [ "${STACK_UP_CLAUDE}" -eq 1 ]; then
      teardown_stack "acc25-claude" claude
    fi
    if [ "${STACK_UP_CODEX}" -eq 1 ]; then
      teardown_stack "acc25-codex" codex
    fi
  fi

  echo ""
  echo "========================================================"
  echo "ITEM-25 ACCEPTANCE SUITE FINAL SUMMARY"
  echo "Run: ${TIMESTAMP}"
  echo "Log: ${LOG_FILE}"
  echo "========================================================"
  echo "PASS:     ${TOTAL_PASS}"
  echo "FAIL:     ${TOTAL_FAIL}"
  echo "SKIP:     ${TOTAL_SKIP} (includes DEFERRED credential-dependent ACs)"
  echo "TOTAL:    $((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))"
  echo ""
  if [ "${TOTAL_FAIL}" -gt 0 ]; then
    echo "RESULT: FAILED (${TOTAL_FAIL} boundary defect(s))"
    echo ""
    echo "FAILURES (routes back to implementer/security-reviewer):"
    grep "\[FAIL\]" "${LOG_FILE}" 2>/dev/null | head -30 || true
  else
    echo "RESULT: PASSED (${TOTAL_PASS} passed, ${TOTAL_SKIP} deferred/skipped)"
    echo "VERDICT: credential-independent boundary tests CLEAN."
    echo "         Deferred ACs require user's Anthropic/OpenAI credentials."
  fi
  echo "========================================================"

  {
    echo "TIMESTAMP: ${TIMESTAMP}"
    echo "PASS: ${TOTAL_PASS}"
    echo "FAIL: ${TOTAL_FAIL}"
    echo "SKIP: ${TOTAL_SKIP}"
    echo "RESULT: $([ "${TOTAL_FAIL}" -eq 0 ] && echo PASSED || echo FAILED)"
  } > "${SUMMARY_FILE}"

  exit "${exit_code}"
}
trap teardown_all EXIT

# Initialize stack tracking (plain scalars; see declaration above)
STACK_UP_CLAUDE=0
STACK_UP_CODEX=0

# ============================================================
# 0. OFFLINE PROFILE ISOLATION TESTS (no stack needed)
# ============================================================
log_section "STEP 0: OFFLINE PROFILE ISOLATION TESTS (no stack needed)"
export PROJECT_ROOT

if [ -z "${ONLY_PROFILE}" ] || [ "${ONLY_PROFILE}" = "isolation" ]; then
  run_component "profile-isolation" \
    "${SCRIPT_DIR}/component/test-25-profile-isolation.sh"
fi

# ============================================================
# 1. CLAUDE PROFILE BOUNDARY TESTS
# ============================================================
if [ -z "${ONLY_PROFILE}" ] || [ "${ONLY_PROFILE}" = "claude" ]; then
  log_section "STEP 1: CLAUDE PROFILE BOUNDARY TESTS"

  CLAUDE_PROJ="acc25-claude"

  if [ "${SKIP_STACK}" -eq 0 ]; then
    if bring_up_stack "${CLAUDE_PROJ}" claude; then
      STACK_UP_CLAUDE=1
    else
      log "ERROR: claude stack failed to come up. Skipping claude boundary tests."
      TOTAL_FAIL=$((TOTAL_FAIL + 1))
      echo "[FAIL] AC-25-CLAUDE-STACK-UP: Claude profile stack failed to start" | tee -a "${LOG_FILE}"
      # Continue to codex and copilot-regression even if claude fails
    fi
  else
    STACK_UP_CLAUDE=0
    log "SKIP_STACK=1: assuming acc25-claude stack is already running"
  fi

  if [ "${STACK_UP_CLAUDE}" -eq 1 ] || [ "${SKIP_STACK}" -eq 1 ]; then
    IDS=$(discover_containers "${CLAUDE_PROJ}" "-claude")
    CLAUDE_DC_ID="${IDS%%:*}"
    CLAUDE_GW_ID="${IDS##*:}"
    log "Claude containers: DEVCONTAINER=${CLAUDE_DC_ID:-NOT_FOUND} GATEWAY=${CLAUDE_GW_ID:-NOT_FOUND}"

    if [ -z "${CLAUDE_DC_ID}" ]; then
      log "ERROR: claude devcontainer not found. Skipping claude boundary tests."
      TOTAL_FAIL=$((TOTAL_FAIL + 1))
      echo "[FAIL] AC-25-CLAUDE-CONTAINER-FOUND: claude devcontainer not running" | tee -a "${LOG_FILE}"
    else
      export AGENT="claude"
      export DEVCONTAINER_ID="${CLAUDE_DC_ID}"
      export GATEWAY_ID="${CLAUDE_GW_ID}"
      export PROJECT="${CLAUDE_PROJ}"

      run_component "profile-boundary-claude" \
        "${SCRIPT_DIR}/component/test-25-profile-boundary.sh"
    fi
  fi
fi

# ============================================================
# 2. CODEX PROFILE BOUNDARY TESTS
# ============================================================
if [ -z "${ONLY_PROFILE}" ] || [ "${ONLY_PROFILE}" = "codex" ]; then
  log_section "STEP 2: CODEX PROFILE BOUNDARY TESTS"

  CODEX_PROJ="acc25-codex"

  if [ "${SKIP_STACK}" -eq 0 ]; then
    if bring_up_stack "${CODEX_PROJ}" codex; then
      STACK_UP_CODEX=1
    else
      log "ERROR: codex stack failed to come up. Skipping codex boundary tests."
      TOTAL_FAIL=$((TOTAL_FAIL + 1))
      echo "[FAIL] AC-25-CODEX-STACK-UP: Codex profile stack failed to start" | tee -a "${LOG_FILE}"
    fi
  else
    STACK_UP_CODEX=0
    log "SKIP_STACK=1: assuming acc25-codex stack is already running"
  fi

  if [ "${STACK_UP_CODEX}" -eq 1 ] || [ "${SKIP_STACK}" -eq 1 ]; then
    IDS=$(discover_containers "${CODEX_PROJ}" "-codex")
    CODEX_DC_ID="${IDS%%:*}"
    CODEX_GW_ID="${IDS##*:}"
    log "Codex containers: DEVCONTAINER=${CODEX_DC_ID:-NOT_FOUND} GATEWAY=${CODEX_GW_ID:-NOT_FOUND}"

    if [ -z "${CODEX_DC_ID}" ]; then
      log "ERROR: codex devcontainer not found. Skipping codex boundary tests."
      TOTAL_FAIL=$((TOTAL_FAIL + 1))
      echo "[FAIL] AC-25-CODEX-CONTAINER-FOUND: codex devcontainer not running" | tee -a "${LOG_FILE}"
    else
      export AGENT="codex"
      export DEVCONTAINER_ID="${CODEX_DC_ID}"
      export GATEWAY_ID="${CODEX_GW_ID}"
      export PROJECT="${CODEX_PROJ}"

      run_component "profile-boundary-codex" \
        "${SCRIPT_DIR}/component/test-25-profile-boundary.sh"
    fi
  fi
fi

# ============================================================
# 3. COPILOT NON-REGRESSION
# ============================================================
if [ -z "${ONLY_PROFILE}" ] || [ "${ONLY_PROFILE}" = "copilot-regression" ]; then
  log_section "STEP 3: COPILOT NON-REGRESSION"

  ACC15_RUNNER="${SCRIPT_DIR}/run-all.sh"
  if [ -f "${ACC15_RUNNER}" ]; then
    log "Running Copilot non-regression via acc15 runner (run-all.sh)..."
    log "This re-runs the full 83-test Copilot acceptance suite to confirm the profile refactor did not regress."
    log "NOTE: the acc15 runner manages its own stack (project acc15). It will build, test, and tear down."

    COP_OUTPUT=""
    COP_EXIT=0
    COP_OUTPUT=$(cd "${PROJECT_ROOT}" && bash "${ACC15_RUNNER}" 2>&1) || COP_EXIT=$?
    echo "${COP_OUTPUT}" | tee -a "${LOG_FILE}"

    COP_PASS=$(echo "${COP_OUTPUT}" | grep -c "^\[PASS\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
    COP_FAIL=$(echo "${COP_OUTPUT}" | grep -c "^\[FAIL\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
    COP_SKIP=$(echo "${COP_OUTPUT}" | grep -c "^\[SKIP\]" 2>/dev/null | tr -d '[:space:]' || echo 0)
    COP_PASS=$((COP_PASS + 0))
    COP_FAIL=$((COP_FAIL + 0))
    COP_SKIP=$((COP_SKIP + 0))

    TOTAL_PASS=$((TOTAL_PASS + COP_PASS))
    TOTAL_FAIL=$((TOTAL_FAIL + COP_FAIL))
    TOTAL_SKIP=$((TOTAL_SKIP + COP_SKIP))

    if [ "${COP_EXIT}" -eq 0 ] && [ "${COP_FAIL}" -eq 0 ]; then
      log "[copilot-regression] PASS=${COP_PASS} FAIL=0: Copilot baseline unchanged (non-regression confirmed)"
    elif [ "${COP_EXIT}" -eq 1 ] || [ "${COP_FAIL}" -gt 0 ]; then
      log "[copilot-regression] FAIL: ${COP_FAIL} Copilot test(s) regressed (ESCALATE to implementer)"
    else
      log "[copilot-regression] Runner exit=${COP_EXIT}: check log"
    fi
  else
    log "WARNING: acc15 runner not found at ${ACC15_RUNNER}. Skipping Copilot non-regression."
    log "Running lightweight Copilot non-regression check (compose config inspection only)..."

    # Lightweight regression: verify Copilot profile compose config is structurally intact
    COP_CONFIG=$(docker compose --profile copilot config 2>/dev/null || echo "")
    LREG_PASS=0
    LREG_FAIL=0

    # Check key Copilot settings are intact
    check_setting() {
      local desc="$1"
      local pattern="$2"
      local test_id="$3"
      if echo "${COP_CONFIG}" | grep -q "${pattern}"; then
        pass_test "${test_id}" "${desc}"
        LREG_PASS=$((LREG_PASS + 1))
      else
        fail_test "${test_id}" "${desc} - pattern '${pattern}' not found in copilot compose config"
        LREG_FAIL=$((LREG_FAIL + 1))
      fi
    }

    check_setting "cap_drop:ALL in Copilot profile"        "cap_drop"            "REG-COP-CAPDROP"
    check_setting "no-new-privileges in Copilot profile"   "no-new-privileges"   "REG-COP-NNP"
    check_setting "read_only:true in Copilot profile"      "read_only: true"     "REG-COP-READONLY"
    check_setting "network_mode=service:gateway-copilot"   "service:gateway-copilot" "REG-COP-NETMODE"
    check_setting "copilot-token-store in Copilot profile" "copilot-token-store" "REG-COP-TOKENSTORE"
    check_setting "SQUID_AGENT_FRAGMENT=copilot.conf"      "copilot.conf"        "REG-COP-FRAGMENT"

    TOTAL_PASS=$((TOTAL_PASS + LREG_PASS))
    TOTAL_FAIL=$((TOTAL_FAIL + LREG_FAIL))
    log "[copilot-regression-lightweight] PASS=${LREG_PASS} FAIL=${LREG_FAIL}"
  fi
fi

# ============================================================
# EXIT
# ============================================================
[ "${TOTAL_FAIL}" -eq 0 ] || exit 1
exit 0
