#!/bin/bash
# src/gateway/entrypoint.sh
# Gateway entrypoint: select the active agent fragment, initialize firewall, then start Squid.
# Runs as root (required for iptables with cap_add NET_ADMIN).
# ADR-002 D1, D2, D6. ADR-008 D2 (per-agent fragment selection, SPEC-20).
# ADR-009 D-A (per-profile gateway, hardcoded SQUID_AGENT_FRAGMENT).
#
# Design: Squid operates with SslPeekAndSplice (peek+splice, no CA cert).
# See squid.conf for the full mechanism description.
#
# Build-time discovery (2026-06-14): Skip 'squid -z' (cache directory init).
# squid -z initializes swap (disk cache) directories, which is a no-op when
# 'cache deny all' is set. Running -z when no cache_dir is configured causes
# it to exit non-zero. Start Squid directly.
#
# MULTI-AGENT FRAGMENT SELECTION (ADR-008 D2 / ADR-009 D-A, SPEC-20):
# Squid does NOT support env-var expansion in include directives (Squid 5.9 verified).
# The active fragment is selected by copying the agent-specific file to a fixed path
# that squid.conf's static include directive references:
#   /etc/squid/allowlist.d/active-agent.conf
#
# SQUID_AGENT_FRAGMENT is HARDCODED per gateway service in docker-compose.yml (ADR-009 D-A):
#   gateway-copilot -> SQUID_AGENT_FRAGMENT=copilot.conf (always)
#   gateway-claude  -> SQUID_AGENT_FRAGMENT=claude.conf  (always)
#   gateway-codex   -> SQUID_AGENT_FRAGMENT=codex.conf   (always)
#
# The hardcoding is what makes the fragment a structural property of the service, not an
# operator action. ADR-009 D-A documents the forcing defect: when the fragment was
# interpolated from a devcontainer env var, the variable did not cross the container
# boundary, so the shared gateway always loaded the default (copilot.conf).
#
# Defensive default: if SQUID_AGENT_FRAGMENT is somehow unset at runtime, copilot.conf
# is used. This is a fail-safe; production always has it hardcoded per service.
set -euo pipefail

echo "[gateway/entrypoint] Starting gateway sidecar (peek+splice SNI filtering)"

# ============================================================
# STEP 0: Fragment selection (ADR-008 D2 / SPEC-20)
# ============================================================

FRAGMENT_DIR="/etc/squid/allowlist.d"
ACTIVE_FRAGMENT="${FRAGMENT_DIR}/active-agent.conf"
AGENT_FRAGMENT="${SQUID_AGENT_FRAGMENT:-copilot.conf}"

# Validate the fragment name: only allow the three known values.
# Reject anything else to prevent path traversal or unexpected config injection.
case "$AGENT_FRAGMENT" in
  copilot.conf|claude.conf|codex.conf)
    ;;
  *)
    echo "[gateway/entrypoint] ERROR: Unknown SQUID_AGENT_FRAGMENT='${AGENT_FRAGMENT}'." >&2
    echo "[gateway/entrypoint] Must be one of: copilot.conf claude.conf codex.conf" >&2
    exit 1
    ;;
esac

FRAGMENT_SOURCE="${FRAGMENT_DIR}/${AGENT_FRAGMENT}"

if [ ! -f "$FRAGMENT_SOURCE" ]; then
  echo "[gateway/entrypoint] ERROR: Agent fragment not found: ${FRAGMENT_SOURCE}" >&2
  exit 1
fi

echo "[gateway/entrypoint] Selecting agent fragment: ${AGENT_FRAGMENT} -> ${ACTIVE_FRAGMENT}"
# Idempotent: remove any prior active-agent.conf first. It is chmod 444 below, and under
# cap_drop ALL there is no CAP_DAC_OVERRIDE, so a plain `cp` over an existing 444 file fails
# on container RESTART ("Permission denied"). Removing it (a dir-write, which root can do)
# keeps the copy restart-safe. Without this, any gateway restart bricks the container.
rm -f "${ACTIVE_FRAGMENT}" 2>/dev/null || true
cp "${FRAGMENT_SOURCE}" "${ACTIVE_FRAGMENT}"
chmod 444 "${ACTIVE_FRAGMENT}"
echo "[gateway/entrypoint] Fragment installed (mode 444, read-only)."

# Point Squid's resolver at GATEWAY_DNS_RESOLVER (default 192.168.65.7 = Docker Desktop;
# 127.0.0.11 on native Linux via docker-compose.linux.yml). squid.conf is baked into the
# image, so rewrite the dns_nameservers line at startup to match the L3 firewall resolver.
GATEWAY_DNS_RESOLVER="${GATEWAY_DNS_RESOLVER:-192.168.65.7}"
# Validate before interpolating into sed (and before init-firewall consumes it): the
# value must be a bare dotted-quad IPv4 address. Fail closed on anything else so a bad
# value can't corrupt squid.conf or be passed downstream to the L3 firewall rules.
# Reject any char outside [0-9.] first: bash ERE '$' matches before a trailing newline, so a
# value like $'192.168.65.7\n' would otherwise slip past the dotted-quad regex below.
if [[ "${GATEWAY_DNS_RESOLVER}" == *[!0-9.]* ]]; then
  echo "[gateway/entrypoint] ERROR: GATEWAY_DNS_RESOLVER='${GATEWAY_DNS_RESOLVER}' contains characters other than digits and dots." >&2
  exit 1
fi
if [[ ! "${GATEWAY_DNS_RESOLVER}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "[gateway/entrypoint] ERROR: GATEWAY_DNS_RESOLVER='${GATEWAY_DNS_RESOLVER}' is not a valid IPv4 address." >&2
  exit 1
fi
IFS='.' read -r _o1 _o2 _o3 _o4 <<< "${GATEWAY_DNS_RESOLVER}"
for _o in "$_o1" "$_o2" "$_o3" "$_o4"; do
  if [ "$_o" -gt 255 ]; then
    echo "[gateway/entrypoint] ERROR: GATEWAY_DNS_RESOLVER='${GATEWAY_DNS_RESOLVER}' has an octet out of range (>255)." >&2
    exit 1
  fi
done
if [ -w /etc/squid/squid.conf ]; then
  sed -i "s/^dns_nameservers .*/dns_nameservers ${GATEWAY_DNS_RESOLVER}/" /etc/squid/squid.conf
  echo "[gateway/entrypoint] Squid dns_nameservers set to ${GATEWAY_DNS_RESOLVER}."
fi

# ============================================================
# STEP 1: Start-authorization check (ADR-012 / SPEC-29-P0)
# ============================================================
# The portal or break-glass must have written a fresh nonce to /run/start-auth/<profile>
# before starting this container. Absence or staleness means unauthorized start: fail closed.
# Use AGENT_FRAGMENT (already validated against the three-value allowlist at entrypoint.sh:48-56)
# rather than SQUID_AGENT_FRAGMENT directly, so the nonce check reuses the same validated token.
_nonce_profile="${AGENT_FRAGMENT%.conf}"  # strip .conf suffix: "claude.conf" -> "claude"
_nonce_file="/run/start-auth/${_nonce_profile}"

if [[ ! -f "${_nonce_file}" ]]; then
  echo "[gateway/entrypoint] FATAL: start authorization missing for profile '${_nonce_profile}'." >&2
  echo "[gateway/entrypoint] Start this profile via the portal UI, 'agentarca up ${_nonce_profile}', or break-glass (src/scripts/break-glass-up.sh ${_nonce_profile})." >&2
  exit 1
fi

# Read the three-line nonce file
_nonce_token=$(sed -n '1p' "${_nonce_file}")
_nonce_ts=$(sed -n '2p' "${_nonce_file}")
_nonce_pname=$(sed -n '3p' "${_nonce_file}")

# Validate token: exactly 64 lowercase hex chars
if ! [[ "${_nonce_token}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "[gateway/entrypoint] FATAL: malformed start authorization token." >&2
  exit 1
fi

# Validate freshness: nonce must be <= 300 seconds old
_now=$(date +%s)
_age=$(( _now - _nonce_ts ))
if (( _age < 0 || _age > 300 )); then
  echo "[gateway/entrypoint] FATAL: start authorization expired (age=${_age}s, max=300s)." >&2
  echo "[gateway/entrypoint] Re-start via: portal UI, 'agentarca up ${_nonce_profile}', or break-glass (src/scripts/break-glass-up.sh ${_nonce_profile})." >&2
  exit 1
fi

# Validate profile name matches this gateway's fragment
if [[ "${_nonce_pname}" != "${_nonce_profile}" ]]; then
  echo "[gateway/entrypoint] FATAL: start authorization profile mismatch (got '${_nonce_pname}', expected '${_nonce_profile}')." >&2
  exit 1
fi

echo "[gateway/entrypoint] Start authorization verified for profile '${_nonce_profile}'."
# --- End startup authorization check ---

# ============================================================
# STEP 2: Initialize the firewall.
# ============================================================
echo "[gateway/entrypoint] Initializing firewall..."
/usr/local/bin/init-firewall.sh

echo "[gateway/entrypoint] Firewall initialized. Starting Squid..."

# ============================================================
# STEP 3: Verify config parses cleanly before launching.
# ============================================================
echo "[gateway/entrypoint] Verifying Squid config..."
squid -k parse -f /etc/squid/squid.conf 2>&1 || {
    echo "[gateway/entrypoint] ERROR: Squid config parse failed. Aborting." >&2
    exit 1
}
echo "[gateway/entrypoint] Squid config OK."

# ============================================================
# STEP 4: Start Squid in foreground.
# ============================================================
# -N: no daemon fork (keep in foreground for Docker container lifecycle).
exec squid -N -f /etc/squid/squid.conf
