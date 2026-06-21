#!/usr/bin/env bash
# tests/acceptance/lib/test-helpers.sh
#
# Shared test helper functions for the item-15 acceptance suite.
# Sourced by each component test script.
#
# State is tracked via global counters PASS/FAIL/SKIP which each component
# test script owns and initializes. The run-all.sh runner accumulates totals.
#
# Output format:
#   [PASS] test-id: description
#   [FAIL] test-id: description - reason
#   [SKIP] test-id: REQUIRES-... reason
#
# Sink: stdout for PASS/SKIP, stderr for FAIL (run-all.sh separates them).
# All output also goes to the combined log (run-all.sh redirects with tee).

# Color codes (disabled in non-interactive/CI)
if [ -t 1 ] && [ "${CI:-}" != "true" ]; then
  COLOR_GREEN="\033[0;32m"
  COLOR_RED="\033[0;31m"
  COLOR_YELLOW="\033[0;33m"
  COLOR_RESET="\033[0m"
else
  COLOR_GREEN=""
  COLOR_RED=""
  COLOR_YELLOW=""
  COLOR_RESET=""
fi

# Output a begin marker (optional, for verbose debugging).
begin_test() {
  local test_id="$1"
  local description="$2"
  : # No-op; the pass/fail/skip functions emit the real output
}

# Record a passing test.
# Increments PASS counter and emits a PASS line.
pass_test() {
  local test_id="$1"
  local reason="$2"
  PASS=$((PASS + 1))
  printf "${COLOR_GREEN}[PASS]${COLOR_RESET} %s: %s\n" "${test_id}" "${reason}"
}

# Record a failing test.
# Increments FAIL counter and emits a FAIL line to BOTH stdout and stderr.
fail_test() {
  local test_id="$1"
  local reason="$2"
  FAIL=$((FAIL + 1))
  printf "${COLOR_RED}[FAIL]${COLOR_RESET} %s: %s\n" "${test_id}" "${reason}"
  printf "[FAIL] %s: %s\n" "${test_id}" "${reason}" >&2
}

# Record a skipped test with a documented reason.
# Increments SKIP counter. Reasons must start with REQUIRES-* or DOCUMENTED-*.
skip_test() {
  local test_id="$1"
  local reason="$2"
  SKIP=$((SKIP + 1))
  printf "${COLOR_YELLOW}[SKIP]${COLOR_RESET} %s: %s\n" "${test_id}" "${reason}"
}

# Add a skip note without incrementing the skip counter.
# Used for documenting known gaps alongside a passing/failing test.
add_skip_note() {
  local test_id="$1"
  local reason="$2"
  SKIP=$((SKIP + 1))
  printf "${COLOR_YELLOW}[SKIP]${COLOR_RESET} %s: %s\n" "${test_id}" "${reason}"
}

# Print per-component summary (called at end of each component test file).
print_component_summary() {
  local component="$1"
  local p="$2"
  local f="$3"
  local s="$4"
  local total=$((p + f + s))
  echo ""
  echo "--- [${component}] PASS=${p} FAIL=${f} SKIP=${s} TOTAL=${total} ---"
  echo ""
  # Export per-component results for the runner to accumulate
  # (runner sources each test file and reads PASS/FAIL/SKIP after)
}

# Validate that required env vars are set.
require_env() {
  local var="$1"
  local desc="$2"
  if [ -z "${!var:-}" ]; then
    echo "[ERROR] Required environment variable '${var}' is not set (${desc})" >&2
    exit 1
  fi
}
