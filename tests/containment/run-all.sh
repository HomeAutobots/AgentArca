#!/usr/bin/env bash
# tests/containment/run-all.sh
#
# ITEM 16 CONTAINMENT RED-TEAM SUITE RUNNER.
# FRAME: "ASSUME PROMPT INJECTION SUCCEEDS; prove the boundary HOLDS."
#
# Brings up the hardened stack under a UNIQUE compose project (rt16) + remapped subnets
# (172.29/172.28) via tests/containment/compose.test-override.yml, runs every containment
# scenario, reports CONTAINED/ESCAPED + the attack-success-rate, and tears the stack down.
#
# The boundary must CONTAIN 100% of exfil/escape attempts even when injection succeeds.
# ANY ESCAPED line is a CRITICAL finding (a real boundary failure) routed back to the
# relevant build item + architect/threat-modeler.
#
# USAGE:
#   tests/containment/run-all.sh              # full suite (offline + live stack)
#   tests/containment/run-all.sh --offline    # offline scenarios only (no Docker stack)
#   tests/containment/run-all.sh --keep-up    # do not tear down at the end (for debugging)
#
# PARALLEL-RUN SAFE: project=rt16, subnets 172.29/172.28, container_name removed. The
# item-15 acceptance suite (acc15, 172.31/172.30) can run concurrently without collision.
#
# CLEANUP: always `docker compose -p rt16 ... down -v` on exit (unless --keep-up).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HERE/../.." && pwd)"
export PROJECT_ROOT
export RT_RESULTS="$HERE/results/rt16-results.csv"
mkdir -p "$HERE/results"
: > "$RT_RESULTS"

# shellcheck source=lib.sh
. "$HERE/lib.sh"

OFFLINE_ONLY=0
KEEP_UP=0
for a in "$@"; do
  case "$a" in
    --offline) OFFLINE_ONLY=1 ;;
    --keep-up) KEEP_UP=1 ;;
  esac
done

# FIX (2026-06-20): --profile copilot added so gateway-copilot and devcontainer start.
# Without this flag only verdaccio and devpi started (they have no profiles: tag), gateway-copilot
# and devcontainer were never created, the health poll returned empty on every iteration,
# and all live scenarios were skipped after the 30*5s=150s wait.
# Native-Linux DNS overlay (docker-compose.linux.yml): layered automatically on Linux, inert on macOS.
LINUX_OVERLAY=()
if [ "$(uname -s)" = "Linux" ]; then LINUX_OVERLAY=(-f "$PROJECT_ROOT/docker-compose.linux.yml"); fi
COMPOSE=(docker compose -p rt16 -f "$PROJECT_ROOT/docker-compose.yml" "${LINUX_OVERLAY[@]}" -f "$HERE/compose.test-override.yml" --profile copilot)

teardown() {
  if [ "$KEEP_UP" -eq 1 ]; then
    echo "[run-all] --keep-up set; leaving rt16 stack up. Tear down with:"
    echo "          docker compose -p rt16 -f docker-compose.yml -f tests/containment/compose.test-override.yml down -v"
    return
  fi
  echo
  echo "[run-all] Tearing down rt16 stack..."
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  # belt-and-suspenders: remove any stray rt16 networks/containers/volumes.
  docker ps -aq --filter "name=rt16" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network ls -q --filter "name=rt16" | xargs -r docker network rm >/dev/null 2>&1 || true
  docker volume ls -q --filter "name=rt16" | xargs -r docker volume rm >/dev/null 2>&1 || true
  echo "[run-all] rt16 teardown complete."
}
trap teardown EXIT

echo "############################################################"
echo "# ITEM 16 CONTAINMENT RED-TEAM SUITE"
echo "# FRAME: ASSUME PROMPT INJECTION SUCCEEDS; prove the boundary HOLDS."
echo "# project=rt16  subnets: agent-net=172.29.0.0/24 cache-net=172.28.0.0/24"
echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "############################################################"

# ---------------------------------------------------------------------------
# Subnet-collision avoidance (parallel-run coordination with item-15 acc15).
# We use the PRODUCTION subnets (172.31/172.30) so the baked source-ACL stays valid.
# Docker refuses two networks on the same subnet, so if an item-15 stack currently holds
# 172.30/172.31 we wait for it to free them (two stacks cannot share a subnet at once).
# ---------------------------------------------------------------------------
subnet_in_use() {
  for n in $(docker network ls --format '{{.Name}}' 2>/dev/null); do
    # ignore our own rt16 networks
    case "$n" in rt16_*) continue ;; esac
    s=$(docker network inspect "$n" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null)
    if printf '%s' "$s" | grep -qE '172\.3[01]\.0\.0/24'; then return 0; fi
  done
  return 1
}
if [ "$OFFLINE_ONLY" -ne 1 ]; then
  waited=0
  while subnet_in_use; do
    if [ "$waited" -ge 180 ]; then
      echo "[run-all] WARN: 172.30/172.31 still held by another stack after 180s; proceeding anyway (bringup may fail)."
      break
    fi
    echo "[run-all] 172.30/172.31 in use by a concurrent stack (item-15?); waiting 10s (collision-avoidance)..."
    sleep 10; waited=$((waited + 10))
  done
fi

# ===========================================================================
# OFFLINE SCENARIOS (always run; no Docker stack required).
# ===========================================================================
echo
echo "############## OFFLINE CONTAINMENT SCENARIOS ##############"
bash "$HERE/scenario-approval-bypass.sh"
bash "$HERE/scenario-config-integrity.sh"
bash "$HERE/scenario-seccomp-static.sh"
bash "$HERE/scenario-documented.sh"

# ===========================================================================
# LIVE-STACK SCENARIOS (escape + exfil + immutability + push).
# ===========================================================================
if [ "$OFFLINE_ONLY" -eq 1 ]; then
  echo
  echo "[run-all] --offline set; skipping live-stack scenarios."
  record "LIVE-STACK-scenarios" SKIP "offline-mode" "live escape/exfil/immutability/push scenarios skipped (--offline)"
else
  echo
  echo "############## LIVE-STACK CONTAINMENT SCENARIOS ##############"
  echo "[run-all] Bringing up rt16 stack (build + healthcheck gate)..."
  if ! "${COMPOSE[@]}" up -d --build >/tmp/rt16-up.log 2>&1; then
    echo "[run-all] WARN: stack failed to come up. Tail of up log:"
    tail -25 /tmp/rt16-up.log
    record "LIVE-STACK-bringup" SKIP "stack-bringup-failed" "rt16 stack did not start; live scenarios skipped. See /tmp/rt16-up.log"
  else
    echo "[run-all] Waiting for gateway healthy (fail-closed startup gate)..."
    # FIX-F2 (2026-06-20): rt16 uses copilot profile; gateway service is now gateway-copilot.
    healthy=0
    for i in $(seq 1 30); do
      st=$("${COMPOSE[@]}" ps gateway-copilot --format '{{.Health}}' 2>/dev/null || echo "")
      if [ "$st" = "healthy" ]; then healthy=1; break; fi
      sleep 5
    done
    if [ "$healthy" -ne 1 ]; then
      echo "[run-all] WARN: gateway not healthy after wait. Gateway logs:"
      "${COMPOSE[@]}" logs gateway-copilot 2>&1 | tail -30
      record "LIVE-STACK-gateway-healthy" SKIP "gateway-unhealthy" "gateway did not reach healthy; live scenarios skipped"
    else
      echo "[run-all] gateway healthy. Confirming devcontainer is up..."
      # Ensure the devcontainer is running and we can exec into it.
      "${COMPOSE[@]}" up -d devcontainer >/dev/null 2>&1 || true
      sleep 4
      if dc_exec 'echo rt16-exec-ok' 2>/dev/null | grep -q 'rt16-exec-ok'; then
        echo "[run-all] devcontainer exec OK (UID $(dc_exec 'id -u' 2>/dev/null | tr -d '\r')). Running live scenarios..."
        # Copy the always-reject push proxy into the container's tmpfs and start it, so the
        # push scenario hits a REAL always-reject listener (the production posture). If this
        # fails the push scenario still contains via connection-refused (no listener).
        if "${COMPOSE[@]}" cp "$PROJECT_ROOT/src/scripts/push-proxy-reject.py" devcontainer:/tmp/push-proxy-reject.py >/dev/null 2>&1; then
          dc_exec 'pgrep -f push-proxy-reject >/dev/null 2>&1 || (nohup python3 /tmp/push-proxy-reject.py >/tmp/pushproxy.log 2>&1 & ) ; sleep 1; echo started' >/dev/null 2>&1 || true
        fi
        bash "$HERE/scenario-live-escape-exfil.sh"
        bash "$HERE/scenario-live-immutability-push.sh"
      else
        echo "[run-all] WARN: cannot exec into devcontainer. devcontainer logs:"
        "${COMPOSE[@]}" logs devcontainer 2>&1 | tail -20
        record "LIVE-STACK-devcontainer-exec" SKIP "devcontainer-exec-failed" "could not exec into devcontainer; live escape/exfil scenarios skipped"
      fi
    fi
  fi
fi

# ===========================================================================
# REPORT
# ===========================================================================
echo
echo "############################################################"
echo "# ATTACK-SUCCESS-RATE REPORT"
echo "############################################################"
# Use awk for robust counting (grep -c with || echo 0 can emit two lines).
total=$(grep -c . "$RT_RESULTS" 2>/dev/null); total=${total:-0}
contained=$(grep -c ',CONTAINED,' "$RT_RESULTS" 2>/dev/null); contained=${contained:-0}
escaped=$(grep -c ',ESCAPED,' "$RT_RESULTS" 2>/dev/null); escaped=${escaped:-0}
skipped=$(grep -c ',SKIP,' "$RT_RESULTS" 2>/dev/null); skipped=${skipped:-0}
# Force single-integer (strip any stray whitespace/newlines).
total=$(printf '%s' "$total" | tr -dc '0-9'); total=${total:-0}
contained=$(printf '%s' "$contained" | tr -dc '0-9'); contained=${contained:-0}
escaped=$(printf '%s' "$escaped" | tr -dc '0-9'); escaped=${escaped:-0}
skipped=$(printf '%s' "$skipped" | tr -dc '0-9'); skipped=${skipped:-0}
active=$((contained + escaped))

echo "  scenarios total:      $total"
echo "  CONTAINED:            $contained"
echo "  ESCAPED (CRITICAL):   $escaped"
echo "  SKIP (documented):    $skipped"
echo
if [ "$active" -gt 0 ]; then
  asr=$(awk "BEGIN{printf \"%.1f\", ($escaped/$active)*100}")
  echo "  ATTACK-SUCCESS-RATE (escapes / active deterministic scenarios): $escaped/$active = ${asr}%"
else
  echo "  ATTACK-SUCCESS-RATE: n/a (no active scenarios ran)"
fi
echo
if [ "$escaped" -gt 0 ]; then
  echo "  *** $escaped CRITICAL FINDING(S): boundary FAILED. Route to threat-modeler + the build item. ***"
  grep ',ESCAPED,' "$RT_RESULTS"
  VERDICT="FINDINGS"
else
  echo "  VERDICT: RED_TEAMED - boundary CONTAINED 100% of exfil/escape attempts."
  echo "           Documented residuals (SKIP) remain ACCEPTED-NOT-CLOSED: R-b, R-e, R-h, R-d, CamoLeak."
  VERDICT="RED_TEAMED"
fi
echo
echo "  Full results CSV: $RT_RESULTS"
echo "############################################################"

# Exit non-zero ONLY on a real escape (CRITICAL finding). SKIPs do not fail the suite.
[ "$escaped" -eq 0 ]
