#!/usr/bin/env bash
# tests/containment/rt25-lib.sh
# Shared helpers + result accounting for the ITEM-25 PER-PROFILE containment red-team suite.
#
# FRAME: ASSUME PROMPT INJECTION SUCCEEDS. The injected agent is a UID-1000 process inside
# the active profile's dev container. We simulate it by running the exfil/escape attempts
# DIRECTLY as UID 1000 via `docker exec` (the kernel/firewall does not care whether a human
# or an injected agent issued the action - it enforces identically). This is credential-
# independent: no live agent token is needed to prove the deterministic boundary.
#
# Each attack records one CSV row to $RT25_RESULTS:
#   attack-id,profile,expected,observed,attack-success(yes|no)
#
# attack-success=yes  -> the boundary FAILED (a real containment breach = CRITICAL finding).
# attack-success=no   -> the boundary HELD (the exfil/escape/bypass was contained).
# attack-success=skip -> could not be staged in this environment (recorded, not a pass).

set -uo pipefail

RT25_RESULTS="${RT25_RESULTS:-/tmp/rt25-results.csv}"

# Colors (best-effort)
_grn() { printf '\033[32m%s\033[0m' "$1"; }
_red() { printf '\033[31m%s\033[0m' "$1"; }
_yel() { printf '\033[33m%s\033[0m' "$1"; }

# CSV-escape a free-text note (strip commas/newlines so the CSV stays one-row-per-attack).
_csv() { printf '%s' "$1" | tr '\n,' '; ' | head -c 240; }

# record ATTACK_ID PROFILE EXPECTED OBSERVED SUCCESS(yes|no|skip)
record25() {
  local id="$1" profile="$2" expected="$3" observed="$4" success="$5"
  printf '%s,%s,%s,%s,%s\n' "$id" "$profile" "$(_csv "$expected")" "$(_csv "$observed")" "$success" >> "$RT25_RESULTS"
  case "$success" in
    no)   printf '  [%s] %-42s (%s) %s\n' "$(_grn CONTAINED)" "$id" "$profile" "$(_csv "$observed")" ;;
    yes)  printf '  [%s]   %-42s (%s) %s\n' "$(_red 'BREACH!!')" "$id" "$profile" "$(_csv "$observed")" ;;
    skip) printf '  [%s]      %-42s (%s) %s\n' "$(_yel SKIP)" "$id" "$profile" "$(_csv "$observed")" ;;
    *)    printf '  [%s] %-42s (%s) %s\n' "$success" "$id" "$profile" "$(_csv "$observed")" ;;
  esac
}

# ---------------------------------------------------------------------------
# CONTAINMENT-ASSERTION HELPERS.
# The convention: an attack is CONTAINED if the egress/escape attempt FAILED.
# "Failed" means: curl HTTP=000 / non-zero exit / connection error, EPERM, EROFS, etc.
# An attack is a BREACH only if the attempt demonstrably SUCCEEDED (HTTP 200/2xx/3xx/4xx
# proving the tunnel was spliced to a blocked host, EXIT=0 on a flush, a writable mount, etc).
# ---------------------------------------------------------------------------

# A curl egress attempt is CONTAINED when it did NOT reach the host.
# Reached = HTTP code in 2xx/3xx/4xx range AND not 000. Anything else (000, timeout, RST) = blocked.
# Usage: egress_blocked "$out"  -> returns 0 (true) if the egress was blocked (contained).
egress_blocked() {
  local out="$1"
  # If we ever see a real routed HTTP status (not 000), the host was REACHED => breach.
  if printf '%s' "$out" | grep -qE 'HTTP=(2[0-9][0-9]|3[0-9][0-9]|4[0-9][0-9]|5[0-9][0-9])' \
     && ! printf '%s' "$out" | grep -q 'HTTP=000'; then
    return 1   # reached => NOT blocked
  fi
  return 0     # blocked / contained
}

# DC_EXEC/GW_EXEC are set by the runner per-profile (it knows the project + service + override).
# These call into the per-profile dev container / gateway as UID 1000 / root respectively.
# The runner exports: RT25_PROJECT, RT25_OVERRIDE, RT25_DC_SVC, RT25_PROFILE, PROJECT_ROOT.
dc_exec25() {
  docker compose -p "$RT25_PROJECT" \
    -f "$PROJECT_ROOT/docker-compose.yml" \
    -f "$RT25_OVERRIDE" \
    --profile "$RT25_PROFILE" \
    exec -T "$RT25_DC_SVC" bash -lc "$1"
}
# FIX-F2 (2026-06-20): gateway service name is now gateway-<profile> (per-profile gateways).
# RT25_PROFILE is exported by rt25-run-profiles.sh before calling these helpers.
gw_exec25() {
  docker compose -p "$RT25_PROJECT" \
    -f "$PROJECT_ROOT/docker-compose.yml" \
    -f "$RT25_OVERRIDE" \
    --profile "$RT25_PROFILE" \
    exec -T "gateway-${RT25_PROFILE}" bash -lc "$1"
}
