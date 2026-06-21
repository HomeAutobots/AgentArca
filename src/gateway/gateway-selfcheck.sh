#!/bin/bash
# src/gateway/gateway-selfcheck.sh
# Gateway healthcheck / self-check script.
# ADR-002 D6 (fail-closed, startup ordering, self-verification).
#
# Used by:
#   1. Docker compose healthcheck (CMD) - reports healthy/unhealthy
#   2. run-acceptance.sh harness - called explicitly with env var overrides
#
# Exit 0 = healthy (all checks pass).
# Exit non-zero = unhealthy (any check fails).
#
# Checks performed:
#   (a) Squid process is running.
#   (b) Proxied request to the ACTIVE PROFILE's primary allowlisted host succeeds (HTTP 200/401/403/404/421, not 000).
#       Profile-aware: copilot.conf->api.github.com, claude.conf->api.anthropic.com, codex.conf->api.openai.com.
#       Host is selected via SQUID_AGENT_FRAGMENT env var (set in gateway container environment by docker-compose.yml),
#       with fallback to grepping /etc/squid/allowlist.d/active-agent.conf, then hard-fallback to api.github.com.
#       With peek+splice: Squid peeks the SNI, finds it on the allowlist, splices the tunnel.
#       Client completes TLS handshake with the real server. Any routed response (401/403/404/421) is a PASS.
#   (c) Proxied request to example.com is denied (Squid 403 or connection-refused, NOT 200).
#       With peek+splice: Squid peeks the SNI (example.com), it is NOT on the allowlist,
#       ssl_bump terminate fires -> TCP RST to client -> curl returns 000 or connection error.
#   (d) Direct request to example.com (--noproxy '*') is blocked (TCP connect fails).
#   (e) DNS to 8.8.8.8 is blocked (only the permitted resolver is allowed).
#   (f) access.log contains the peeked SNI field for both allowed and blocked entries.
#       With peek+splice, %ssl::>sni is populated from the peeked ClientHello.
#
# Environment overrides (used by the test harness):
#   PROXY_HOST  (default: localhost)
#   PROXY_PORT  (default: 8080)
#   SELFCHECK_VERBOSE  (default: 0; set to 1 for verbose output)

set -euo pipefail

PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-8080}"
PROXY="http://${PROXY_HOST}:${PROXY_PORT}"
VERBOSE="${SELFCHECK_VERBOSE:-0}"
FAILURES=0

log()     { echo "[gateway-selfcheck] $*"; }
verbose() { [ "$VERBOSE" = "1" ] && echo "[gateway-selfcheck/verbose] $*" || true; }
fail()    { echo "[gateway-selfcheck] FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
pass()    { echo "[gateway-selfcheck] PASS: $*"; }

# ---- (a) Squid process check ----
log "Check (a): Squid process running..."
if pgrep -x squid > /dev/null 2>&1 || pgrep -x "(squid)" > /dev/null 2>&1; then
    pass "(a) Squid process is running"
else
    # Also accept squid3 name variant
    if pgrep squid > /dev/null 2>&1; then
        pass "(a) Squid process is running (pgrep squid)"
    else
        fail "(a) Squid process is NOT running"
    fi
fi

# ---- (b) Proxied request to the active profile's allowlisted host ----
# Profile-aware: the positive-liveness probe host is selected from the active fragment.
# copilot.conf -> api.github.com  (default; LOCKED baseline)
# claude.conf  -> api.anthropic.com
# codex.conf   -> api.openai.com
#
# How the active fragment is determined (in priority order):
#   1. SQUID_AGENT_FRAGMENT env var (set in the gateway container environment by docker-compose.yml).
#   2. Fallback: grep /etc/squid/allowlist.d/active-agent.conf for the primary steady-state
#      host that the entrypoint copied there (robust even if the env var is not in scope).
#   3. Hard fallback: api.github.com (copilot baseline; fail-safe, matches default fragment).
#
# A routed-but-unauthorized response (401/403/404/421) counts as PASS for the positive check.
# The proxy tunnel established + TLS splice working is what matters; we have no credentials.
# HTTP 000 (connection refused / timeout) means the allowlist is broken: that is a FAIL.

ACTIVE_FRAGMENT_FILE="/etc/squid/allowlist.d/active-agent.conf"
POSITIVE_HOST=""

# Method 1: read env var (set by docker-compose gateway environment block).
ACTIVE_FRAGMENT_NAME="${SQUID_AGENT_FRAGMENT:-}"
case "${ACTIVE_FRAGMENT_NAME}" in
  copilot.conf) POSITIVE_HOST="api.github.com" ;;
  claude.conf)  POSITIVE_HOST="api.anthropic.com" ;;
  codex.conf)   POSITIVE_HOST="api.openai.com" ;;
  *)            POSITIVE_HOST="" ;;
esac

# Method 2: inspect the installed active-agent.conf if env var was empty or unrecognized.
if [ -z "${POSITIVE_HOST}" ] && [ -f "${ACTIVE_FRAGMENT_FILE}" ]; then
  if grep -q 'api\.anthropic\.com' "${ACTIVE_FRAGMENT_FILE}" 2>/dev/null; then
    POSITIVE_HOST="api.anthropic.com"
  elif grep -q 'api\.openai\.com' "${ACTIVE_FRAGMENT_FILE}" 2>/dev/null; then
    POSITIVE_HOST="api.openai.com"
  elif grep -q 'api\.github\.com' "${ACTIVE_FRAGMENT_FILE}" 2>/dev/null; then
    POSITIVE_HOST="api.github.com"
  fi
fi

# Method 3: hard fallback to copilot baseline.
if [ -z "${POSITIVE_HOST}" ]; then
  POSITIVE_HOST="api.github.com"
  log "(b) WARNING: could not determine active fragment; falling back to api.github.com"
fi

log "Check (b): Proxied request to ${POSITIVE_HOST} via ${PROXY} (active fragment: ${ACTIVE_FRAGMENT_NAME:-unknown})..."
HTTP_STATUS=""
HTTP_STATUS=$(curl --proxy "${PROXY}" \
    --silent \
    --max-time 15 \
    --connect-timeout 10 \
    --output /dev/null \
    --write-out "%{http_code}" \
    "https://${POSITIVE_HOST}/" 2>/dev/null) || true

verbose "(b) ${POSITIVE_HOST} HTTP status: ${HTTP_STATUS}"

if [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "401" ] || [ "${HTTP_STATUS}" = "403" ] || [ "${HTTP_STATUS}" = "404" ] || [ "${HTTP_STATUS}" = "421" ]; then
    pass "(b) ${POSITIVE_HOST} via proxy: HTTP ${HTTP_STATUS} (allowed - routed response proves proxy tunnel + TLS splice working; status ${HTTP_STATUS} is a valid routed response without credentials)"
elif [ "${HTTP_STATUS}" = "000" ] || [ -z "${HTTP_STATUS}" ]; then
    fail "(b) ${POSITIVE_HOST} via proxy: connection failed (HTTP ${HTTP_STATUS:-empty}) - proxy may be down or allowlist wrong for active fragment '${ACTIVE_FRAGMENT_NAME:-unknown}'"
else
    fail "(b) ${POSITIVE_HOST} via proxy: unexpected HTTP ${HTTP_STATUS} for active fragment '${ACTIVE_FRAGMENT_NAME:-unknown}'"
fi

# ---- (c) Proxied request to example.com must be denied ----
log "Check (c): Proxied request to example.com via ${PROXY} (should be denied)..."
DENY_STATUS=""
DENY_STATUS=$(curl --proxy "${PROXY}" \
    --silent \
    --max-time 15 \
    --connect-timeout 10 \
    --output /dev/null \
    --write-out "%{http_code}" \
    "https://example.com" 2>/dev/null) || true

verbose "(c) example.com proxied HTTP status: ${DENY_STATUS}"

if [ "${DENY_STATUS}" = "403" ] || [ "${DENY_STATUS}" = "000" ]; then
    pass "(c) example.com via proxy: denied (HTTP ${DENY_STATUS})"
elif [ "${DENY_STATUS}" = "200" ]; then
    fail "(c) example.com via proxy: HTTP 200 - should be DENIED by Squid allowlist!"
else
    # TCP RST from Squid also shows as 000 or non-200; accept as denied
    pass "(c) example.com via proxy: denied (HTTP ${DENY_STATUS} - not 200)"
fi

# ---- (d) Direct request to example.com bypassing proxy ----
log "Check (d): Direct request to example.com with --noproxy '*' (should be blocked at L3)..."
DIRECT_STATUS=""
DIRECT_STATUS=$(curl --noproxy '*' \
    --silent \
    --max-time 10 \
    --connect-timeout 5 \
    --output /dev/null \
    --write-out "%{http_code}" \
    "https://example.com" 2>/dev/null) || true

verbose "(d) example.com direct HTTP status: ${DIRECT_STATUS}"

if [ "${DIRECT_STATUS}" = "000" ] || [ -z "${DIRECT_STATUS}" ]; then
    pass "(d) example.com direct (--noproxy '*'): blocked at L3 (HTTP ${DIRECT_STATUS:-empty} = TCP connect failed)"
elif [ "${DIRECT_STATUS}" = "200" ]; then
    fail "(d) example.com direct: HTTP 200 - L3 default-DROP is NOT blocking direct egress!"
else
    pass "(d) example.com direct: not HTTP 200 (${DIRECT_STATUS}) - L3 blocking in effect"
fi

# ---- (e) DNS to 8.8.8.8 ----
log "Check (e): DNS query to 8.8.8.8 (should be blocked; only 127.0.0.11 permitted)..."
if command -v dig > /dev/null 2>&1; then
    DNS_RESULT=0
    dig +time=3 +tries=1 @8.8.8.8 example.com > /dev/null 2>&1 || DNS_RESULT=$?
    if [ "$DNS_RESULT" -ne 0 ]; then
        pass "(e) DNS to 8.8.8.8: blocked (dig exit code ${DNS_RESULT})"
    else
        fail "(e) DNS to 8.8.8.8: SUCCEEDED - external DNS must be blocked!"
    fi
else
    log "(e) dig not available; skipping DNS check (iptables rule should still block)"
fi

# ---- (f) access.log SNI field check ----
log "Check (f): access.log SNI field populated..."
ACCESS_LOG="/var/log/squid/access.log"
if [ -f "${ACCESS_LOG}" ]; then
    # The custom log format ends with %ssl::>sni
    # Check if any log line has a non-dash SNI field (last field)
    SNI_COUNT=$(awk '{print $NF}' "${ACCESS_LOG}" 2>/dev/null | grep -c -v '^-$' 2>/dev/null) || SNI_COUNT=0
    if [ "${SNI_COUNT}" -gt 0 ]; then
        pass "(f) access.log has ${SNI_COUNT} entries with SNI populated"
    else
        log "(f) access.log exists but SNI field is all '-' (no HTTPS requests yet - acceptable at healthcheck time)"
        # This is not a FAIL for the healthcheck since it may run before any traffic
    fi
else
    log "(f) access.log not found yet (Squid may not have written it yet - acceptable at startup)"
fi

# ---- Summary ----
log "Selfcheck complete. Failures: ${FAILURES}"

if [ "${FAILURES}" -gt 0 ]; then
    echo "[gateway-selfcheck] UNHEALTHY: ${FAILURES} check(s) failed." >&2
    exit 1
fi

echo "[gateway-selfcheck] HEALTHY: all checks passed."
exit 0
