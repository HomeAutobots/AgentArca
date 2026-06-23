#!/usr/bin/env bash
# tests/containment/rt25-scenario-local-overlay-mask.sh
#
# ITEM-25 DEVELOPER-LOCAL OVERLAY MASK attack (attack class 7). Run ONCE PER PROFILE by
# rt25-run-profiles.sh.
#
# FRAME: assume injection succeeded AND assume the host operator has (legitimately) widened
# their LOCAL egress allowlist via ./config/allowlist.local.d/overrides.conf (bind-mounted
# read-only at /etc/squid/local.d, hot-applied via SIGHUP; squid.conf does
# `include /etc/squid/local.d/*.conf`). That production overlay lets a developer ADD
# allowed_SNI hosts on top of the baked allowlist.
#
# The threat-modeler condition we prove here: a developer-local overlay must NOT be able to
# mask a boundary failure in the SHIPPED-boundary test suites. Every gateway test override
# mounts ./tests/acceptance/fixtures/empty-local.d (a committed comment-only placeholder)
# over /etc/squid/local.d, which (Compose dedupes bind mounts by target, override wins)
# SHADOWS the production ./config/allowlist.local.d mount. If that mask ever silently fell
# off, a developer's local widening would leak into the security/containment measurements and
# could hide a real open boundary => CONTAINMENT FAILURE.
#
# We attack the claim two independent ways:
#   (A) STRUCTURAL: inside the running test gateway, /etc/squid/local.d must contain ONLY the
#       committed placeholder (00-local.conf) and NO developer overrides.conf. A developer file
#       leaking through = the mask is off.
#   (B) FUNCTIONAL: a representative NON-BAKED host that a developer might plausibly add
#       locally (httpbin.org) must STILL be TERMINATED through the test proxy. If it is
#       reachable, a local overlay (or a mask regression) opened the boundary => BREACH.
#
# Both checks are meaningful on a clean checkout / in CI (where no overrides.conf exists): the
# placeholder is the only file, and httpbin.org is not baked, so it must terminate regardless.
#
# Requires (exported by the runner): RT25_PROFILE, RT25_PROJECT, RT25_OVERRIDE, RT25_DC_SVC,
# PROJECT_ROOT, RT25_RESULTS.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=rt25-lib.sh
. "$HERE/rt25-lib.sh"

P="$RT25_PROFILE"
echo
echo "=== [$P] DEVELOPER-LOCAL OVERLAY MASK attack (local widening must not mask the boundary) ==="

# ---------------------------------------------------------------------------
# (A) STRUCTURAL: /etc/squid/local.d inside the test gateway holds ONLY the committed
# placeholder. A real developer overrides.conf reaching the test gateway = the mask fell off.
# ---------------------------------------------------------------------------
{
  listing=$(gw_exec25 'ls -1 /etc/squid/local.d 2>&1; echo EXIT=$?' 2>&1)
  files=$(printf '%s' "$listing" | grep -vE '^EXIT=' | grep -E '\.conf$' | tr -d '\r' | sort | tr '\n' ' ' | sed 's/ *$//')
  has_placeholder=$(printf '%s' "$listing" | grep -c '00-local.conf')
  # Any *.conf other than the committed placeholder = a developer overlay leaked into the test
  # gateway (mask off). Only 00-local.conf is permitted.
  stray=$(printf '%s' "$listing" | grep -vE '^EXIT=' | grep -E '\.conf$' | grep -v '00-local.conf' | tr -d '\r' | tr '\n' ' ' | sed 's/ *$//')
  if [ "$has_placeholder" -ge 1 ] && [ -z "$stray" ]; then
    record25 "LOCAL-OVERLAY-mask-placeholder-only" "$P" "test gateway /etc/squid/local.d holds ONLY committed placeholder (no developer overrides.conf)" "files=[$files]" no
  else
    record25 "LOCAL-OVERLAY-mask-placeholder-only" "$P" "test gateway /etc/squid/local.d holds ONLY committed placeholder" "MASK OFF: stray=[$stray] files=[$files]" yes
  fi
}

# ---------------------------------------------------------------------------
# (A') STRUCTURAL: the placeholder is comment-only (adds zero allowed_SNI). Even the committed
# mask file must not itself widen egress. Assert no `allowed_SNI` directive is present in the
# loaded local.d.
# ---------------------------------------------------------------------------
{
  active=$(gw_exec25 'grep -RhE "^[[:space:]]*acl[[:space:]]+allowed_SNI" /etc/squid/local.d/ 2>/dev/null; echo EXIT=$?' 2>&1)
  added=$(printf '%s' "$active" | grep -cE 'allowed_SNI')
  if [ "$added" -eq 0 ]; then
    record25 "LOCAL-OVERLAY-placeholder-adds-no-host" "$P" "committed placeholder defines ZERO allowed_SNI (test boundary = baked allowlist only)" "no allowed_SNI in /etc/squid/local.d" no
  else
    record25 "LOCAL-OVERLAY-placeholder-adds-no-host" "$P" "committed placeholder defines ZERO allowed_SNI" "LOCAL HOST(S) PRESENT IN TEST GATEWAY: $(printf '%s' "$active" | grep -E 'allowed_SNI' | head -1)" yes
  fi
}

# ---------------------------------------------------------------------------
# (B) FUNCTIONAL: a representative non-baked host a developer might add locally (httpbin.org)
# must STILL be TERMINATED through the test proxy. This is the live proof that no local overlay
# (and no mask regression) widened the test boundary. Meaningful even on a clean checkout:
# httpbin.org is not in the baked allowlist, so it MUST terminate.
# ---------------------------------------------------------------------------
{
  host="httpbin.org"
  out=$(dc_exec25 "curl -s -x http://localhost:8080 --max-time 12 -o /dev/null -w 'HTTP=%{http_code}' https://$host/ 2>&1; echo \" EXIT=\$?\"" 2>&1)
  if egress_blocked "$out"; then
    record25 "LOCAL-OVERLAY-nonbaked-host-terminated" "$P" "representative local-overlay host ($host) STILL terminated (mask in effect; baked allowlist only)" "$out" no
  else
    record25 "LOCAL-OVERLAY-nonbaked-host-terminated" "$P" "representative local-overlay host ($host) terminated under test mask" "REACHED (local overlay widened the TEST boundary): $out" yes
  fi
}

echo "=== [$P] developer-local overlay mask attack complete ==="
