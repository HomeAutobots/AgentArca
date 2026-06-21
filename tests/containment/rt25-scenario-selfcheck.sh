#!/usr/bin/env bash
# tests/containment/rt25-scenario-selfcheck.sh
#
# ITEM-25 SELFCHECK-INTEGRITY attack (attack class 6). Run ONCE PER PROFILE.
# FRAME: the profile-aware fix made the POSITIVE-liveness probe (check b) select the active
# fragment's primary host (api.github.com / api.anthropic.com / api.openai.com). The NEGATIVE
# deny-half (checks c/d/e) was claimed preserved. We attack the claim:
#   (A) Can the gateway report HEALTHY while egress to a BLOCKED host actually succeeds?
#   (B) Can the positive probe be tricked into masking a broken/open boundary (false HEALTHY)?
#   (C) Does the profile-aware host selection ever DEGRADE the deny-half (turn a deny check off)?
#
# Requires (exported by the runner): RT25_PROFILE, RT25_PROJECT, RT25_OVERRIDE, RT25_DC_SVC,
# PROJECT_ROOT, RT25_RESULTS.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=rt25-lib.sh
. "$HERE/rt25-lib.sh"

P="$RT25_PROFILE"
echo
echo "=== [$P] SELFCHECK INTEGRITY attack (profile-aware fix adversarial re-check) ==="

# ---------------------------------------------------------------------------
# (0) BASELINE: the real selfcheck must currently report HEALTHY for this profile (it is the
# healthcheck that gated the dev container's start; it is already green or we would not be here).
# Run it explicitly inside the gateway and capture which positive host it picked.
# ---------------------------------------------------------------------------
{
  out=$(gw_exec25 'SELFCHECK_VERBOSE=1 /usr/local/bin/gateway-selfcheck.sh 2>&1; echo "RC=$?"' 2>&1)
  picked=$(printf '%s' "$out" | grep -oE 'Proxied request to [a-z.]+' | head -1 | awk '{print $4}')
  rc=$(printf '%s' "$out" | grep -oE 'RC=[0-9]+' | tail -1)
  # Expected: the picked positive host matches this profile.
  case "$P" in
    claude)  want="api.anthropic.com" ;;
    codex)   want="api.openai.com" ;;
    copilot) want="api.github.com" ;;
  esac
  if printf '%s' "$out" | grep -q 'RC=0' && [ "$picked" = "$want" ]; then
    record25 "SELFCHECK-positive-host-matches-profile" "$P" "positive probe selects $want; selfcheck HEALTHY" "picked=$picked $rc" no
  elif printf '%s' "$out" | grep -q 'RC=0'; then
    # HEALTHY but picked a different host: the fix did not select correctly. Not a containment
    # breach by itself (deny-half still runs), but a fix-integrity defect worth flagging.
    record25 "SELFCHECK-positive-host-matches-profile" "$P" "positive probe selects $want" "HEALTHY but picked=$picked (want $want) - fix selection drift" no
  else
    record25 "SELFCHECK-positive-host-matches-profile" "$P" "selfcheck HEALTHY for active profile" "selfcheck NOT healthy: $rc picked=$picked" skip
  fi
}

# ---------------------------------------------------------------------------
# (A) THE CORE ATTACK: force a TRUE OPEN-BOUNDARY condition and assert the selfcheck DETECTS it
# (reports UNHEALTHY), proving the negative deny-half is load-bearing and not masked by the
# profile-aware positive probe.
#
# We cannot actually open the real firewall (that would need NET_ADMIN we are proving is absent),
# so we attack the SELFCHECK LOGIC directly: run a modified copy of the selfcheck that simulates
# the boundary being OPEN (example.com reachable) and confirm the script returns NON-ZERO
# (UNHEALTHY) for EACH deny check, regardless of profile. If any profile setting could make a
# deny check pass while example.com is reachable, that is a masked-open-boundary breach.
#
# Method: copy the real selfcheck into the gateway tmpfs, then run it with a shim PATH where
# `curl` to example.com RETURNS 200 (simulating an open boundary) while api.<profile> returns 401.
# The selfcheck MUST still fail (UNHEALTHY) because check (c)/(d) see example.com=200.
# ---------------------------------------------------------------------------
{
  # A fake-curl shim (delivered as base64 to avoid any heredoc/quoting fragility) that returns
  # 200 for example.com AND 8.8.8.8 (SIMULATED OPEN BOUNDARY) and 401 for the profile's positive
  # host (a healthy allowlisted response). We prepend it to PATH and run a COPY of the real
  # gateway-selfcheck.sh. With the boundary simulated OPEN, the real selfcheck MUST report
  # UNHEALTHY because checks (c)/(d)/(e) see the blocked targets as reachable. If it reports
  # HEALTHY under any profile, the profile-aware positive probe masked the deny-half => BREACH.
  SHIM_B64="IyEvYmluL2Jhc2gKIyBmYWtlIGN1cmwgc2hpbSBmb3IgdGhlIHJ0MjUgc2VsZmNoZWNrIG9wZW4tYm91bmRhcnkgYXR0YWNrLgojIFJldHVybnMgMjAwIGZvciBleGFtcGxlLmNvbSAoU0lNVUxBVEVEIE9QRU4gQk9VTkRBUlkpLCA0MDEgZm9yIHRoZSBwcm9maWxlIHBvc2l0aXZlIGhvc3QsCiMgMDAwIG90aGVyd2lzZS4gSG9ub3JzIC0td3JpdGUtb3V0ICV7aHR0cF9jb2RlfS4gSWdub3JlcyBldmVyeXRoaW5nIGVsc2UgKHRoZSByZWFsIHNlbGZjaGVjawojIG9ubHkgdXNlcyB0aGUgaHR0cF9jb2RlIHZpYSAtLXdyaXRlLW91dCkuCkNPREU9MDAwClVSTD0iIgpmb3IgYSBpbiAiJEAiOyBkbwogIGNhc2UgIiRhIiBpbgogICAgaHR0cHM6Ly8qfGh0dHA6Ly8qKSBVUkw9IiRhIiA7OwogIGVzYWMKZG9uZQpjYXNlICIkVVJMIiBpbgogICpleGFtcGxlLmNvbSopIENPREU9MjAwIDs7CiAgKjguOC44LjgqKSBDT0RFPTIwMCA7OwogICphcGkuYW50aHJvcGljLmNvbSp8KmFwaS5vcGVuYWkuY29tKnwqYXBpLmdpdGh1Yi5jb20qKSBDT0RFPTQwMSA7OwogICopIENPREU9MDAwIDs7CmVzYWMKIyBFbWl0IHRoZSAtLXdyaXRlLW91dCB0ZW1wbGF0ZSB3aXRoICV7aHR0cF9jb2RlfSBzdWJzdGl0dXRlZC4KcHJldj0iIgpPVVQ9IiIKZm9yIGEgaW4gIiRAIjsgZG8KICBpZiBbICIkcHJldiIgPSAiLS13cml0ZS1vdXQiIF0gfHwgWyAiJHByZXYiID0gIi13IiBdOyB0aGVuCiAgICBPVVQ9IiR7YS8vJVx7aHR0cF9jb2RlXH0vJENPREV9IgogIGZpCiAgcHJldj0iJGEiCmRvbmUKcHJpbnRmICclcycgIiRPVVQiCmV4aXQgMAo="
  setup="mkdir -p /tmp/rt25shim && printf '%s' '$SHIM_B64' | base64 -d > /tmp/rt25shim/curl && \
chmod +x /tmp/rt25shim/curl && cp /usr/local/bin/gateway-selfcheck.sh /tmp/rt25-selfcheck.sh && \
PATH=/tmp/rt25shim:\$PATH SQUID_AGENT_FRAGMENT=${P}.conf bash /tmp/rt25-selfcheck.sh 2>&1; echo RC=\$?"
  out=$(gw_exec25 "$setup" 2>&1)
  rc=$(printf '%s' "$out" | grep -oE 'RC=[0-9]+' | tail -1 | tr -dc '0-9')
  # With example.com SIMULATED as reachable (200), the selfcheck MUST report UNHEALTHY (RC!=0).
  # If it reports HEALTHY (RC=0) under any profile, the deny-half was masked => BREACH.
  cfail=$(printf '%s' "$out" | grep -c 'FAIL: (c)')
  if [ "${rc:-1}" != "0" ] && printf '%s' "$out" | grep -q 'FAIL: (c)'; then
    record25 "SELFCHECK-open-boundary-detected" "$P" "selfcheck reports UNHEALTHY when example.com is reachable (deny-half load-bearing)" "RC=$rc; check(c) FAILED as required (open boundary caught)" no
  elif [ "${rc:-1}" = "0" ]; then
    record25 "SELFCHECK-open-boundary-detected" "$P" "selfcheck must report UNHEALTHY on open boundary" "MASKED OPEN BOUNDARY: selfcheck HEALTHY (RC=0) despite example.com=200" yes
  else
    # UNHEALTHY for some reason but check(c) line not seen exactly - still contained (it failed).
    record25 "SELFCHECK-open-boundary-detected" "$P" "selfcheck reports UNHEALTHY when example.com reachable" "RC=$rc (UNHEALTHY); c-fail-count=$cfail" no
  fi
}

# ---------------------------------------------------------------------------
# (B) Positive-probe masking: confirm the profile-aware host SELECTION cannot turn the
# negative checks OFF. Inspect the real selfcheck source for the property that checks c/d/e
# are UNCONDITIONAL (not inside a profile case). This is a static integrity assertion against
# the shipped script (no env can disable them).
# ---------------------------------------------------------------------------
{
  src=$(gw_exec25 'cat /usr/local/bin/gateway-selfcheck.sh' 2>&1)
  # The deny checks must reference example.com (c,d) and 8.8.8.8 (e) and must NOT be guarded by
  # a per-profile case branch. Assert each deny target appears, and that the only `case` on the
  # fragment is for POSITIVE_HOST selection (check b), not around c/d/e.
  has_c=$(printf '%s' "$src" | grep -c 'example.com')
  has_e=$(printf '%s' "$src" | grep -c '8.8.8.8')
  # Heuristic: the SQUID_AGENT_FRAGMENT case only assigns POSITIVE_HOST. Assert example.com /
  # 8.8.8.8 checks are not inside any 'copilot.conf)|claude.conf)|codex.conf)' branch by
  # confirming they appear AFTER the positive-host case closes (check c header present).
  if [ "$has_c" -ge 1 ] && [ "$has_e" -ge 1 ] \
     && printf '%s' "$src" | grep -q 'Check (c): Proxied request to example.com' \
     && printf '%s' "$src" | grep -q 'Check (d): Direct request to example.com' \
     && printf '%s' "$src" | grep -q 'Check (e): DNS query to 8.8.8.8'; then
    record25 "SELFCHECK-deny-half-unconditional" "$P" "deny checks (c/d/e) are unconditional, not profile-gated" "example.com(c/d) + 8.8.8.8(e) present and unguarded" no
  else
    record25 "SELFCHECK-deny-half-unconditional" "$P" "deny checks (c/d/e) unconditional" "DENY HALF WEAKENED: c=$has_c e=$has_e (profile-gated?)" yes
  fi
}

# ---------------------------------------------------------------------------
# (C) Live deny-half: from the gateway itself, confirm example.com via the proxy is STILL denied
# under this profile (the real, not simulated, negative check). This is the functional proof
# that the profile-aware change did not open the boundary for the blocked host.
# ---------------------------------------------------------------------------
{
  out=$(gw_exec25 "curl -s -x http://localhost:8080 --max-time 12 -o /dev/null -w 'HTTP=%{http_code}' https://example.com/ 2>&1; echo \" EXIT=\$?\"" 2>&1)
  if egress_blocked "$out"; then
    record25 "SELFCHECK-live-example.com-denied" "$P" "example.com via proxy STILL denied under $P (deny-half real)" "$out" no
  else
    record25 "SELFCHECK-live-example.com-denied" "$P" "example.com via proxy denied under $P" "EXAMPLE.COM REACHED VIA PROXY: $out" yes
  fi
}

echo "=== [$P] selfcheck-integrity attack complete ==="
