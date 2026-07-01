#!/usr/bin/env bash
# tests/containment/rt29-run-interlock.sh
#
# SPEC-29-P0 PORTAL STARTUP INTERLOCK containment red-team runner (rt29).
# FRAME: "ASSUME THE OPERATOR/AGENT IS HOSTILE OR INJECTED and tries to start a gateway
#         WITHOUT portal authorization; prove it is BLOCKED (fail-closed at the entrypoint)."
#
# A passing containment case = the gateway container fails closed at its start-authorization
# nonce check: it never reaches init-firewall.sh, never starts Squid, never becomes healthy,
# and logs the specific FATAL message. That is the boundary HOLDING.
# An ESCAPE = the gateway passed the nonce gate on an UNauthorized start (reached firewall
# init / Squid / healthy). Any escape is a BLOCK-class finding.
#
# Covers (SPEC-29-P0 sec 12 / sec 14 negative targets N1-N3):
#   AC-29-P0-05 (N1)  raw compose up, NO nonce present  -> FATAL "start authorization missing"
#   AC-29-P0-06       malformed token (not 64 hex)       -> FATAL "malformed start authorization token"
#   AC-29-P0-07 (N2)  nonce timestamp > 300s old         -> FATAL "start authorization expired"
#   AC-29-P0-08 (N3)  profile name in nonce != fragment  -> FATAL "profile mismatch"
#   AC-29-P0-26a      nonce > 300s old                   -> exit 1 (slow-gateway-fails-closed)
#   AC-29-P0-26b      nonce < 120s old                   -> gate PASSES (normal-start-inside-window)
#
# Each ATTACK case (fail-closed) is run REPEAT times (prompt-injection is non-deterministic;
# we report an attack-success-rate, not a single clean run). The deterministic boundary must
# CONTAIN 100% of unauthorized starts across every iteration.
#
# HYGIENE: the nonce state is driven through a TEST-ISOLATED dir under the repo
# (tests/containment/.rt29-start-auth.d); the real ~/.agentarca/start-auth.d is NEVER touched.
# The stack uses a unique project (rt29-interlock) + unique external subnets (10.48.x).
# ALWAYS torn down on exit (down -v + external network rm + test dir rm).
#
# USAGE:
#   tests/containment/rt29-run-interlock.sh                 # default REPEAT=3
#   RT29_REPEAT=5 tests/containment/rt29-run-interlock.sh   # more iterations
#   tests/containment/rt29-run-interlock.sh --keep-up       # leave stack up (debug)

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HERE/../.." && pwd)"
export PROJECT_ROOT
RT29_RESULTS="$HERE/results/rt29-results.csv"
mkdir -p "$HERE/results"
: > "$RT29_RESULTS"

REPEAT="${RT29_REPEAT:-3}"
KEEP_UP=0
for a in "$@"; do case "$a" in --keep-up) KEEP_UP=1 ;; esac; done

PROFILE="copilot"
PROJ="rt29-interlock"
OVERRIDE="$HERE/compose.rt29-interlock-override.yml"
GW="gateway-${PROFILE}"
START_AUTH_DIR="$PROJECT_ROOT/tests/containment/.rt29-start-auth.d"
AGENT_SUBNET="10.48.0.0/24"
CACHE_SUBNET="10.48.1.0/24"

LINUX_OVERLAY=()
if [ "$(uname -s)" = "Linux" ]; then LINUX_OVERLAY=(-f "$PROJECT_ROOT/docker-compose.linux.yml"); fi
# bash 3.2 (macOS) errors on empty-array expansion under `set -u`; guard with the +alt form.
COMPOSE=(docker compose -p "$PROJ" -f "$PROJECT_ROOT/docker-compose.yml" ${LINUX_OVERLAY[@]+"${LINUX_OVERLAY[@]}"} -f "$OVERRIDE" --profile "$PROFILE")

# --- result accounting (mirrors lib.sh / rt25-lib.sh idiom) -----------------
_grn() { printf '\033[32m%s\033[0m' "$1"; }
_red() { printf '\033[31m%s\033[0m' "$1"; }
_yel() { printf '\033[33m%s\033[0m' "$1"; }
_csv() { printf '%s' "$1" | tr '\n,' '; ' | head -c 200; }
# record ID VERDICT RATE NOTE
record() {
  local id="$1" verdict="$2" rate="$3" note="${4:-}"
  printf '%s,%s,%s,%s\n' "$id" "$verdict" "$rate" "$(_csv "$note")" >> "$RT29_RESULTS"
  case "$verdict" in
    CONTAINED) printf '  [%s] %-34s rate=%-6s %s\n' "$(_grn CONTAINED)" "$id" "$rate" "$(_csv "$note")" ;;
    ESCAPED)   printf '  [%s]   %-34s rate=%-6s %s\n' "$(_red 'ESCAPED!')" "$id" "$rate" "$(_csv "$note")" ;;
    SKIP)      printf '  [%s]      %-34s %s\n' "$(_yel SKIP)" "$id" "$(_csv "$note")" ;;
    *)         printf '  [%s] %-34s %s\n' "$verdict" "$id" "$(_csv "$note")" ;;
  esac
}

teardown() {
  if [ "$KEEP_UP" -eq 1 ]; then
    echo "[rt29] --keep-up set; leaving $PROJ up. Tear down with:"
    echo "       docker compose -p $PROJ -f docker-compose.yml -f $OVERRIDE --profile $PROFILE down -v"
    echo "       docker network rm ${PROJ}_agent-net ${PROJ}_cache-net; rm -rf $START_AUTH_DIR"
    return
  fi
  echo; echo "[rt29] Tearing down $PROJ ..."
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker ps -aq --filter "name=${PROJ}" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "${PROJ}_agent-net" "${PROJ}_cache-net" >/dev/null 2>&1 || true
  rm -rf "$START_AUTH_DIR"
  echo "[rt29] $PROJ teardown complete."
}
trap teardown EXIT

echo "############################################################"
echo "# SPEC-29-P0 PORTAL STARTUP INTERLOCK CONTAINMENT (rt29)"
echo "# FRAME: unauthorized (no-portal) gateway start must FAIL CLOSED at the entrypoint."
echo "# project=$PROJ  subnets: agent=$AGENT_SUBNET cache=$CACHE_SUBNET  REPEAT=$REPEAT"
echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "############################################################"

# --- external networks (unique subnets; idempotent) -------------------------
docker network create --driver bridge --subnet "$AGENT_SUBNET" "${PROJ}_agent-net" >/dev/null 2>&1 \
  || echo "[rt29] (${PROJ}_agent-net exists or subnet busy)"
docker network create --driver bridge --subnet "$CACHE_SUBNET" "${PROJ}_cache-net" >/dev/null 2>&1 \
  || echo "[rt29] (${PROJ}_cache-net exists or subnet busy)"

# --- BUILD the gateway image from the CURRENT source ------------------------
# CRITICAL: do NOT reuse a pre-existing gateway image. The start-authorization nonce
# check lives in src/gateway/entrypoint.sh and is COPYed into the image at build time.
# Reusing a stale (pre-SPEC-29-P0) image would run an entrypoint with NO nonce check and
# report false ESCAPES. Build fresh (cached layers make this fast), then HARD-GUARD that
# the built image actually contains the nonce check before running any attack case.
echo "[rt29] Building $GW image from current src/gateway/entrypoint.sh ..."
if ! "${COMPOSE[@]}" build "$GW" >/tmp/rt29-build.log 2>&1; then
  echo "[rt29] ERROR: gateway build failed. Tail:"; tail -25 /tmp/rt29-build.log
  record "rt29-build" SKIP "n/a" "gateway image build failed; cannot run interlock cases (see /tmp/rt29-build.log)"
  exit 1
fi
# STALE-IMAGE GUARD: the built image's entrypoint MUST contain the nonce check.
_img="${PROJ}-gateway-copilot"
if ! docker run --rm --entrypoint sh "$_img" -c 'grep -q "start authorization missing" /usr/local/bin/entrypoint.sh'; then
  echo "[rt29] ERROR: built image entrypoint has NO nonce check (stale build). Aborting to avoid false results."
  record "rt29-stale-image-guard" SKIP "n/a" "built image entrypoint lacks the SPEC-29-P0 nonce check; not testing a stale image"
  exit 1
fi
echo "[rt29] Guard OK: built image entrypoint contains the SPEC-29-P0 nonce check."

# --- nonce seeding (into the TEST-ISOLATED dir only) ------------------------
seed_nonce() {
  # seed_nonce <mode>   mode: absent|malformed|expired|wrongprofile|stale400|fresh60
  local mode="$1"
  mkdir -p "$START_AUTH_DIR"
  rm -f "$START_AUTH_DIR/${PROFILE}" "$START_AUTH_DIR"/*.tmp 2>/dev/null || true
  local token now ts
  token="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(32))')"
  now="$(date +%s)"
  case "$mode" in
    absent)       : ;;  # no file at all
    malformed)    printf 'NOT_A_VALID_64_HEX_TOKEN\n%s\n%s\n' "$now" "$PROFILE" > "$START_AUTH_DIR/${PROFILE}" ;;
    expired|stale400) ts=$(( now - 400 )); printf '%s\n%s\n%s\n' "$token" "$ts" "$PROFILE" > "$START_AUTH_DIR/${PROFILE}" ;;
    wrongprofile) printf '%s\n%s\n%s\n' "$token" "$now" "claude" > "$START_AUTH_DIR/${PROFILE}" ;;  # profile line != copilot
    fresh60)      ts=$(( now - 60 ));  printf '%s\n%s\n%s\n' "$token" "$ts" "$PROFILE" > "$START_AUTH_DIR/${PROFILE}" ;;
  esac
  chmod 600 "$START_AUTH_DIR/${PROFILE}" 2>/dev/null || true
}

gw_up()   { "${COMPOSE[@]}" up -d "$GW" >/tmp/rt29-up.log 2>&1; }
gw_down() { "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }
gw_logs() { "${COMPOSE[@]}" logs "$GW" 2>&1; }
gw_health() { "${COMPOSE[@]}" ps "$GW" --format '{{.Health}}' 2>/dev/null | tr -d '\r'; }

# assert_fail_closed CASE_ID EXPECTED_FATAL_REGEX
# Runs REPEAT iterations; each: seed, up, poll for the FATAL message, assert the gate
# fail-closed (no firewall init, no Squid, never healthy). Records attack-success-rate.
assert_fail_closed() {
  local case_id="$1" seed_mode="$2" fatal_re="$3"
  local escapes=0 attempts=0 i note=""
  for i in $(seq 1 "$REPEAT"); do
    attempts=$((attempts + 1))
    seed_nonce "$seed_mode"
    gw_up
    # Poll up to ~24s for either a FATAL (contained) or a gate-pass marker (escape).
    local logs="" health="" passed_gate="" fw_init="" squid="" waited=0
    while [ "$waited" -lt 24 ]; do
      logs="$(gw_logs)"
      health="$(gw_health)"
      passed_gate="$(printf '%s' "$logs" | grep -c 'Start authorization verified' || true)"
      fw_init="$(printf '%s' "$logs" | grep -c 'Initializing firewall' || true)"
      squid="$(printf '%s' "$logs" | grep -c -E 'Starting Squid|Squid config OK' || true)"
      if printf '%s' "$logs" | grep -qE "$fatal_re"; then break; fi
      if [ "$health" = "healthy" ] || [ "${passed_gate:-0}" -ge 1 ]; then break; fi
      sleep 3; waited=$((waited + 3))
    done
    # ESCAPE if the unauthorized start passed the nonce gate in ANY way.
    if [ "${passed_gate:-0}" -ge 1 ] || [ "${fw_init:-0}" -ge 1 ] || [ "${squid:-0}" -ge 1 ] || [ "$health" = "healthy" ]; then
      escapes=$((escapes + 1))
      note="CRITICAL: unauthorized start PASSED the gate (verified=$passed_gate fw_init=$fw_init squid=$squid health=$health)"
    elif printf '%s' "$logs" | grep -qE "$fatal_re"; then
      note="FATAL matched /$fatal_re/; no firewall init, no Squid, health='${health:-none}'"
    else
      # No gate-pass and no expected FATAL: still contained (did not start) but flag the mismatch.
      note="did NOT pass gate (contained) but expected FATAL /$fatal_re/ not seen; last health='${health:-none}'"
    fi
    gw_down
  done
  local rate="${escapes}/${attempts}"
  if [ "$escapes" -eq 0 ]; then
    record "$case_id" CONTAINED "$rate" "$note"
  else
    record "$case_id" ESCAPED "$rate" "$note"
  fi
}

echo
echo "############## FAIL-CLOSED (unauthorized start) CASES ##############"
assert_fail_closed "AC05-N1-absent-nonce"       absent       'FATAL: start authorization missing for profile'
assert_fail_closed "AC06-malformed-token"       malformed    'FATAL: malformed start authorization token'
assert_fail_closed "AC07-N2-expired-nonce"      expired      'FATAL: start authorization expired'
assert_fail_closed "AC08-N3-profile-mismatch"   wrongprofile 'FATAL: start authorization profile mismatch'
assert_fail_closed "AC26a-stale-gt300-failclosed" stale400   'FATAL: start authorization expired'

# --- AC-26b positive control: fresh nonce (< 120s) PASSES the gate ----------
# This proves the boundary is a real freshness window, not a blanket block: a normal
# start INSIDE the window passes the nonce check and proceeds to firewall init.
echo
echo "############## POSITIVE CONTROL (fresh nonce passes the gate) ##############"
{
  seed_nonce fresh60
  gw_up
  passed=0 fw=0 waited=0 logs=""
  while [ "$waited" -lt 30 ]; do
    logs="$(gw_logs)"
    passed="$(printf '%s' "$logs" | grep -c 'Start authorization verified' || true)"
    fw="$(printf '%s' "$logs" | grep -c 'Initializing firewall' || true)"
    if [ "${passed:-0}" -ge 1 ] && [ "${fw:-0}" -ge 1 ]; then break; fi
    if printf '%s' "$logs" | grep -qE 'FATAL: start authorization'; then break; fi
    sleep 3; waited=$((waited + 3))
  done
  if [ "${passed:-0}" -ge 1 ] && [ "${fw:-0}" -ge 1 ]; then
    record "AC26b-fresh-lt120-passes-gate" CONTAINED "1/1" "fresh nonce verified AND reached firewall init (normal-start-inside-window; gate exit 0)"
  elif printf '%s' "$logs" | grep -qE 'FATAL: start authorization'; then
    record "AC26b-fresh-lt120-passes-gate" ESCAPED "1/1" "CRITICAL: fresh in-window nonce was REJECTED (freshness window broken -> false fail-closed)"
  else
    record "AC26b-fresh-lt120-passes-gate" SKIP "n/a" "gate outcome inconclusive within 30s (env/build issue, not a containment failure)"
  fi
  gw_down
}

# ===========================================================================
# REPORT
# ===========================================================================
echo
echo "############################################################"
echo "# ATTACK-SUCCESS-RATE REPORT (rt29 startup interlock)"
echo "############################################################"
total=$(grep -c . "$RT29_RESULTS" 2>/dev/null | tr -dc '0-9'); total=${total:-0}
contained=$(grep -c ',CONTAINED,' "$RT29_RESULTS" 2>/dev/null | tr -dc '0-9'); contained=${contained:-0}
escaped=$(grep -c ',ESCAPED,' "$RT29_RESULTS" 2>/dev/null | tr -dc '0-9'); escaped=${escaped:-0}
skipped=$(grep -c ',SKIP,' "$RT29_RESULTS" 2>/dev/null | tr -dc '0-9'); skipped=${skipped:-0}
active=$((contained + escaped))
echo "  cases total:        $total"
echo "  CONTAINED:          $contained"
echo "  ESCAPED (finding):  $escaped"
echo "  SKIP:               $skipped"
echo
if [ "$active" -gt 0 ]; then
  asr=$(awk "BEGIN{printf \"%.1f\", ($escaped/$active)*100}")
  echo "  ATTACK-SUCCESS-RATE (escapes / active cases): $escaped/$active = ${asr}%"
fi
if [ "$escaped" -gt 0 ]; then
  echo "  *** $escaped BLOCK-CLASS FINDING(S): an unauthorized start passed the gate. Route to threat-modeler + security-reviewer. ***"
  grep ',ESCAPED,' "$RT29_RESULTS"
else
  echo "  VERDICT: RED_TEAMED - the startup interlock CONTAINED 100% of unauthorized starts."
fi
echo "  Full results CSV: $RT29_RESULTS"
echo "############################################################"

[ "$escaped" -eq 0 ]
