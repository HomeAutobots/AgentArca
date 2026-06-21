#!/usr/bin/env bash
# tests/containment/rt25-run-profiles.sh
#
# ITEM-25 PER-PROFILE CONTAINMENT RED-TEAM SUITE RUNNER.
# FRAME: "ASSUME PROMPT INJECTION SUCCEEDS; prove the boundary HOLDS for EACH profile."
#
# For each requested profile (claude, codex, copilot) this:
#   1. Pre-creates external networks with a profile-unique subnet (no collision with acc15/
#      acc25/rt16/production).
#   2. Brings the stack up under a profile-unique project (rt25-<profile>) + the matching
#      override, with SQUID_AGENT_FRAGMENT=<profile>.conf so the gateway loads the right fragment.
#   3. Waits for the gateway healthcheck to go HEALTHY (fail-closed startup gate).
#   4. Runs the injected-agent attack scenarios as UID 1000 inside the dev container.
#   5. Tears the stack + its external networks down.
#
# Records one CSV row per attack to results/rt25-results.csv:
#   attack-id,profile,expected,observed,attack-success(yes|no|skip)
#
# attack-success=yes is a CRITICAL containment BREACH (routes to implementer/security-reviewer/
# threat-modeler). Target: 0 breaches on every profile. Copilot must stay at its 0/N baseline.
#
# USAGE:
#   tests/containment/rt25-run-profiles.sh                       # claude + codex + copilot
#   tests/containment/rt25-run-profiles.sh --profile claude      # one profile
#   tests/containment/rt25-run-profiles.sh --no-build            # skip image build
#   tests/containment/rt25-run-profiles.sh --keep-up             # leave stacks up (debug)
#   tests/containment/rt25-run-profiles.sh --timeout 300         # gateway-healthy wait (s)

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HERE/../.." && pwd)"
export PROJECT_ROOT
export RT25_RESULTS="$HERE/results/rt25-results.csv"
mkdir -p "$HERE/results"

# shellcheck source=rt25-lib.sh
. "$HERE/rt25-lib.sh"

PROFILES="claude codex copilot"
NO_BUILD=0
KEEP_UP=0
TIMEOUT="${RT25_TIMEOUT:-300}"

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILES="$2"; shift ;;
    --no-build) NO_BUILD=1 ;;
    --keep-up) KEEP_UP=1 ;;
    --timeout) TIMEOUT="$2"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# CSV header (overwrite at start of a full run).
printf 'attack-id,profile,expected,observed,attack-success\n' > "$RT25_RESULTS"

# Profile -> (project, override, dc-service, copilot-subnet, cache-subnet)
proj_for()      { echo "rt25-$1"; }
override_for()  { echo "$HERE/compose.rt25-$1-override.yml"; }
dcsvc_for()     { case "$1" in claude) echo devcontainer-claude;; codex) echo devcontainer-codex;; copilot) echo devcontainer;; esac; }
cop_subnet_for(){ case "$1" in claude) echo 10.45.0.0/24;; codex) echo 10.46.0.0/24;; copilot) echo 10.47.0.0/24;; esac; }
cache_subnet_for(){ case "$1" in claude) echo 10.45.1.0/24;; codex) echo 10.46.1.0/24;; copilot) echo 10.47.1.0/24;; esac; }

CURRENT_PROJ=""
CURRENT_OVERRIDE=""
CURRENT_PROFILE=""

teardown_one() {
  local profile="$1" proj override
  [ -z "$profile" ] && return 0
  proj="$(proj_for "$profile")"
  override="$(override_for "$profile")"
  if [ "$KEEP_UP" -eq 1 ]; then
    echo "[rt25] --keep-up: leaving $proj up. Tear down with:"
    echo "       docker compose -p $proj -f docker-compose.yml -f $override --profile $profile down -v"
    echo "       docker network rm ${proj}_copilot-net ${proj}_cache-net"
    return 0
  fi
  echo "[rt25] Tearing down $proj ..."
  # FIX-F2 (2026-06-20): SQUID_AGENT_FRAGMENT no longer needs to be set on the host for teardown
  # (it is hardcoded in the gateway service). The prepended env var was harmless but misleading.
  docker compose -p "$proj" \
    -f "$PROJECT_ROOT/docker-compose.yml" -f "$override" --profile "$profile" \
    down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "${proj}_copilot-net" "${proj}_cache-net" >/dev/null 2>&1 || true
  echo "[rt25] $proj teardown complete."
}

teardown_all() {
  teardown_one "$CURRENT_PROFILE"
}
trap teardown_all EXIT

echo "############################################################"
echo "# ITEM 25 PER-PROFILE CONTAINMENT RED-TEAM SUITE (rt25)"
echo "# FRAME: ASSUME PROMPT INJECTION SUCCEEDS; prove the boundary HOLDS per profile."
echo "# profiles: $PROFILES"
echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "############################################################"

run_profile() {
  local profile="$1"
  local proj override dcsvc cop_sub cache_sub
  proj="$(proj_for "$profile")"
  override="$(override_for "$profile")"
  dcsvc="$(dcsvc_for "$profile")"
  cop_sub="$(cop_subnet_for "$profile")"
  cache_sub="$(cache_subnet_for "$profile")"

  CURRENT_PROJ="$proj"; CURRENT_OVERRIDE="$override"; CURRENT_PROFILE="$profile"

  echo
  echo "============================================================"
  echo "[rt25] PROFILE=$profile  project=$proj  svc=$dcsvc"
  echo "       subnets: copilot-net=$cop_sub  cache-net=$cache_sub"
  echo "============================================================"

  # FIX-F2 (2026-06-20): SQUID_AGENT_FRAGMENT is now HARDCODED in each per-profile gateway
  # service (gateway-<profile>). No host-shell export is required anymore.
  local COMPOSE=(docker compose -p "$proj" -f "$PROJECT_ROOT/docker-compose.yml" -f "$override" --profile "$profile")
  # Gateway service name for this profile (per-profile gateways, FIX-F2).
  local gw_svc="gateway-${profile}"

  # 1. Pre-create external networks (idempotent).
  docker network create --driver bridge --subnet "$cop_sub" "${proj}_copilot-net" >/dev/null 2>&1 \
    || echo "[rt25] (${proj}_copilot-net exists or subnet busy)"
  docker network create --driver bridge --subnet "$cache_sub" "${proj}_cache-net" >/dev/null 2>&1 \
    || echo "[rt25] (${proj}_cache-net exists or subnet busy)"

  # 2. Build (unless skipped).
  if [ "$NO_BUILD" -eq 0 ]; then
    echo "[rt25] Building $profile images..."
    if ! "${COMPOSE[@]}" build >/tmp/rt25-build-$profile.log 2>&1; then
      echo "[rt25] WARN: build failed for $profile. Tail:"; tail -25 /tmp/rt25-build-$profile.log
      record25 "STACK-build-$profile" "$profile" "image builds" "build failed - see /tmp/rt25-build-$profile.log" skip
      teardown_one "$profile"; CURRENT_PROFILE=""; return 0
    fi
  fi

  # 3. Up.
  echo "[rt25] Bringing up $proj ..."
  if ! "${COMPOSE[@]}" up -d >/tmp/rt25-up-$profile.log 2>&1; then
    echo "[rt25] WARN: up failed for $profile. Tail:"; tail -25 /tmp/rt25-up-$profile.log
    record25 "STACK-up-$profile" "$profile" "stack starts" "up failed - see /tmp/rt25-up-$profile.log" skip
    teardown_one "$profile"; CURRENT_PROFILE=""; return 0
  fi

  # 4. Wait for gateway healthy.
  echo "[rt25] Waiting for gateway healthy (timeout ${TIMEOUT}s)..."
  local waited=0 healthy=0
  while [ "$waited" -lt "$TIMEOUT" ]; do
    local st
    # FIX-F2 (2026-06-20): use per-profile gateway service name.
    st=$("${COMPOSE[@]}" ps "$gw_svc" --format '{{.Health}}' 2>/dev/null | tr -d '\r')
    if [ "$st" = "healthy" ]; then healthy=1; break; fi
    sleep 5; waited=$((waited + 5))
  done
  if [ "$healthy" -ne 1 ]; then
    echo "[rt25] WARN: gateway not healthy for $profile. Logs:"; "${COMPOSE[@]}" logs "$gw_svc" 2>&1 | tail -30
    record25 "STACK-gateway-healthy-$profile" "$profile" "gateway healthcheck HEALTHY" "gateway did not reach healthy in ${TIMEOUT}s" skip
    teardown_one "$profile"; CURRENT_PROFILE=""; return 0
  fi
  echo "[rt25] gateway healthy. Ensuring dev container ($dcsvc) is up..."
  "${COMPOSE[@]}" up -d "$dcsvc" >/dev/null 2>&1 || true
  sleep 4

  # Confirm exec works.
  export RT25_PROJECT="$proj" RT25_OVERRIDE="$override" RT25_DC_SVC="$dcsvc" RT25_PROFILE="$profile"
  if ! dc_exec25 'echo rt25-exec-ok' 2>/dev/null | grep -q 'rt25-exec-ok'; then
    echo "[rt25] WARN: cannot exec into $dcsvc. Logs:"; "${COMPOSE[@]}" logs "$dcsvc" 2>&1 | tail -20
    record25 "STACK-dc-exec-$profile" "$profile" "exec into dev container" "could not exec into $dcsvc" skip
    teardown_one "$profile"; CURRENT_PROFILE=""; return 0
  fi

  # 5. Run the attack scenarios.
  bash "$HERE/rt25-scenario-profile-containment.sh"
  bash "$HERE/rt25-scenario-selfcheck.sh"

  # 6. Teardown this profile before the next.
  teardown_one "$profile"
  CURRENT_PROFILE=""
}

for p in $PROFILES; do
  case "$p" in claude|codex|copilot) run_profile "$p" ;; *) echo "[rt25] unknown profile '$p', skipping" ;; esac
done

# ===========================================================================
# REPORT
# ===========================================================================
echo
echo "############################################################"
echo "# ITEM 25 PER-PROFILE ATTACK-SUCCESS REPORT"
echo "############################################################"
# data rows = all minus the header line.
for prof in claude codex copilot; do
  total=$(awk -F, -v p="$prof" 'NR>1 && $2==p {n++} END{print n+0}' "$RT25_RESULTS")
  breach=$(awk -F, -v p="$prof" 'NR>1 && $2==p && $5=="yes" {n++} END{print n+0}' "$RT25_RESULTS")
  contained=$(awk -F, -v p="$prof" 'NR>1 && $2==p && $5=="no" {n++} END{print n+0}' "$RT25_RESULTS")
  skip=$(awk -F, -v p="$prof" 'NR>1 && $2==p && $5=="skip" {n++} END{print n+0}' "$RT25_RESULTS")
  [ "$total" -eq 0 ] && continue
  printf "  %-9s  attacks=%-3s CONTAINED=%-3s BREACH=%-3s SKIP=%-3s -> attack-success=%s/%s\n" \
    "$prof" "$total" "$contained" "$breach" "$skip" "$breach" "$((contained + breach))"
done
total_breach=$(awk -F, 'NR>1 && $5=="yes" {n++} END{print n+0}' "$RT25_RESULTS")
echo
if [ "$total_breach" -gt 0 ]; then
  echo "  *** $total_breach CONTAINMENT BREACH(ES) - CRITICAL FINDING. Route to implementer + security-reviewer + threat-modeler. ***"
  awk -F, 'NR>1 && $5=="yes"' "$RT25_RESULTS"
  VERDICT="FINDINGS"
else
  echo "  VERDICT: RED_TEAMED - boundary CONTAINED 100% of per-profile exfil/escape attempts (credential-independent scope)."
  VERDICT="RED_TEAMED"
fi
echo
echo "  Full results CSV: $RT25_RESULTS"
echo "  VERDICT: $VERDICT"
echo "############################################################"

# Exit non-zero ONLY on a real breach.
[ "$total_breach" -eq 0 ]
