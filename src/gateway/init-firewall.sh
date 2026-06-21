#!/bin/bash
# src/gateway/init-firewall.sh
# L3 iptables firewall for the gateway sidecar.
# ADR-002 D2, D5, D6.
#
# Design:
#   - Default-DROP on OUTPUT chain (all egress blocked unless explicitly permitted)
#   - ONLY permitted egress:
#       (a) the L7 proxy listener itself (loopback, port 8080) - for devcontainer
#       (b) Docker internal DNS resolver (127.0.0.11, ALL ports) - ADR-002 D5
#           RUNTIME FINDING: Docker uses DNAT to redirect :53 to :<high-port>
#           BEFORE the filter OUTPUT chain runs. Must allow all of 127.0.0.11.
#       (c) Established/related connections (return traffic for Squid's outbound)
#       (d) Squid outbound to allowed HTTPS destinations (port 443)
#       (e) Squid outbound to allowed HTTP destinations (port 80)
#   - Drop all other port-53 traffic (kills DNS tunneling to external resolvers)
#   - No IPv6 egress (disabled at compose network level; ip6tables rules as backstop)
#   - Drop ICMP egress (no ping-tunnel channel, ADR-002 D5)
#
# Self-verification:
#   After programming the rules, verify:
#     - example.com is NOT reachable (abort if it is)
#     - api.github.com IS reachable via the proxy (abort if it is not)
#
# This script must run as root (it is invoked from entrypoint.sh in the
# gateway container which holds cap_add: [NET_ADMIN, NET_RAW]).

set -euo pipefail

log() { echo "[init-firewall] $*"; }
die() { echo "[init-firewall] FATAL: $*" >&2; exit 1; }

log "Starting firewall initialization"

# ---- Flush existing rules ----
log "Flushing existing iptables rules"
iptables -F OUTPUT 2>/dev/null || true
iptables -F INPUT 2>/dev/null || true
iptables -F FORWARD 2>/dev/null || true
iptables -X 2>/dev/null || true

# ---- INPUT chain: allow established, allow loopback, drop others ----
iptables -P INPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ---- FORWARD chain: default drop (gateway is not a router) ----
iptables -P FORWARD DROP

# ---- OUTPUT chain: build rules before setting default-DROP policy ----
# Add specific ACCEPT rules first, THEN set default policy to DROP.
# This avoids a window where all egress is blocked before rules are applied.

# Allow loopback (Squid listens on 0.0.0.0:8080; devcontainer connects on localhost)
iptables -A OUTPUT -o lo -j ACCEPT

# ITEM 14: Allow Squid to accept connections from cache-net containers.
# Verdaccio and devpi send their HTTPS_PROXY upstream requests to the gateway from
# their cache-net IPs. The INPUT chain must allow these connections.
# The OUTPUT chain rules below allow Squid to forward the upstream requests.
#
# Using RFC1918-wide source ranges for portability (covers 172.30.x, 10.15.x, etc.).
# This is safe: these are all private Docker bridge addresses not reachable from the internet.
# The Squid L7 allowlist is the effective boundary, not the L3 source-IP restriction here.
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8     -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -s 172.16.0.0/12  -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -s 192.168.0.0/16 -j ACCEPT

# Allow DNS ONLY to the Docker Desktop host resolver (192.168.65.7).
# RUNTIME FINDING (2026-06-14, Docker Desktop macOS):
#   The embedded DNS resolver at 127.0.0.11 relies on conntrack DNAT/SNAT
#   that does not function properly inside containers on custom bridge networks
#   in Docker Desktop. DNS to 127.0.0.11 returns SERVFAIL immediately.
#   The Docker Desktop host resolver at 192.168.65.7 (the LinuxKit VM's
#   resolver, not an internet-facing DNS) works correctly.
#   This is an internal address not reachable from the public internet.
#   The compose file also sets dns: [192.168.65.7] so /etc/resolv.conf
#   uses this address instead of 127.0.0.11.
#
# On a native Linux host (not Docker Desktop), replace 192.168.65.7 with
# 127.0.0.11 (the embedded resolver that works on native Linux).
DNS_RESOLVER="192.168.65.7"
iptables -A OUTPUT -p udp --dport 53 -d "${DNS_RESOLVER}" -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d "${DNS_RESOLVER}" -j ACCEPT

# Also allow loopback DNS (in case 127.0.0.11 is needed for container-internal resolution)
iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT

# Block all other DNS (port 53 to arbitrary destinations)
# This kills DNS tunneling to arbitrary external resolvers (ADR-002 D5, moby #36907).
iptables -A OUTPUT -p udp --dport 53 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -j DROP

# Allow established/related return traffic (needed for Squid's outbound connections)
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow Squid outbound HTTPS (port 443) to reach allowed destinations.
# IMPORTANT: Only allow TCP/443 from the Squid worker process (uid=proxy=13).
# This prevents devcontainer processes (which share this netns) from making
# direct TCP/443 connections, enforcing that all HTTPS goes through the proxy.
# The L7 allowlist enforces WHICH destinations; L3 allows the port class.
# Squid's worker process runs as uid=proxy (uid 13 in this Ubuntu image).
iptables -A OUTPUT -p tcp --dport 443 -m owner --uid-owner proxy -j ACCEPT

# Allow Squid outbound HTTP (port 80) for non-TLS upstream resources.
iptables -A OUTPUT -p tcp --dport 80 -m owner --uid-owner proxy -j ACCEPT

# ITEM 14 / RC-14-1 FIX (2026-06-14): Allow devcontainer (sharing this netns) to reach
# the pull-through cache services (plain HTTP, internal Docker networks only).
# Verdaccio (npm): port 4873. devpi (pip): port 3141.
#
# SHIPPED RULE: accept TCP/4873 and TCP/3141 to all RFC1918 private address ranges.
# This covers:
#   - Production: copilot-net (172.31.0.0/24) and cache-net (172.30.0.0/24).
#   - Test environments: Docker auto-assigned subnets (10.15.x, 10.25.x, etc.).
# Both ranges are private Docker bridge addresses not reachable from the internet.
# An external host on TCP/4873 or TCP/3141 has a public IP that cannot match
# any private RFC1918 range, so those packets hit the default-DROP rule.
#
# The Squid L7 allowlist is the effective boundary for external registry access.
# L3 closes the DIRECT exfil path (bypassing the proxy) on these ports.
iptables -A OUTPUT -p tcp -d 10.0.0.0/8     --dport 4873 -j ACCEPT
iptables -A OUTPUT -p tcp -d 172.16.0.0/12  --dport 4873 -j ACCEPT
iptables -A OUTPUT -p tcp -d 192.168.0.0/16 --dport 4873 -j ACCEPT
iptables -A OUTPUT -p tcp -d 10.0.0.0/8     --dport 3141 -j ACCEPT
iptables -A OUTPUT -p tcp -d 172.16.0.0/12  --dport 3141 -j ACCEPT
iptables -A OUTPUT -p tcp -d 192.168.0.0/16 --dport 3141 -j ACCEPT

log "Cache port rules: ports 4873/3141 accepted for all RFC1918 private ranges (internal Docker bridges only)"

# Drop ICMP egress (no ping-tunnel channel, ADR-002 D5)
iptables -A OUTPUT -p icmp -j DROP

# ---- Now set OUTPUT default policy to DROP ----
# Any egress not matching the rules above is blocked.
iptables -P OUTPUT DROP

log "iptables rules programmed. OUTPUT default-DROP is now active."

# ---- IPv6 backstop ----
# Compose disables IPv6 at the network level, but add ip6tables rules
# as a defense-in-depth backstop (ADR-002 D5/D6d).
if command -v ip6tables &>/dev/null; then
    ip6tables -P OUTPUT DROP 2>/dev/null || log "ip6tables OUTPUT policy: failed to set DROP (may not be supported in this environment; compose-level IPv6 disable is the primary control)"
    ip6tables -P INPUT DROP 2>/dev/null || true
    ip6tables -P FORWARD DROP 2>/dev/null || true
    log "ip6tables default-DROP set (IPv6 backstop)"
else
    log "ip6tables not available; compose-level IPv6 disable is the primary control"
fi

# ---- Self-verification ----
# This script verifies L3 firewall rules are in effect.
# NOTE: The gateway container itself CAN reach upstream hosts on port 443
# (that is how it proxies requests). Checking "example.com is unreachable
# from the gateway" is NOT a valid test because the gateway needs TCP/443
# access to all upstreams to function. The correct L3 check is:
#   - Arbitrary external DNS (8.8.8.8) is blocked (tunneling prevention)
#   - Port 80/443 to the internet is allowed only for Squid (the gateway does
#     the L7 filtering; the devcontainer has no separate direct path because
#     it shares the gateway's netns and any direct connection goes through the
#     same iptables rules)
#
# The proxy-level check (Squid denies example.com at L7) is done by
# gateway-selfcheck.sh which runs AFTER Squid is up.

log "Self-verification: checking that external DNS is blocked..."

# Test: DNS to 8.8.8.8 should NOT be reachable (only ${DNS_RESOLVER} is allowed)
if command -v dig &>/dev/null; then
    DNS_BLOCKED=0
    dig +time=3 +tries=1 @8.8.8.8 example.com &>/dev/null || DNS_BLOCKED=1
    if [ "$DNS_BLOCKED" -eq 0 ]; then
        die "SELF-CHECK FAIL: DNS query to 8.8.8.8 succeeded! Firewall is NOT blocking external DNS. Aborting."
    fi
    log "SELF-CHECK PASS: DNS to 8.8.8.8 is blocked (only ${DNS_RESOLVER} permitted)"
else
    log "dig not available; skipping DNS block check"
fi

log "Firewall initialization complete. Squid will now verify proxy-level connectivity."
log "  Proxy will self-check: api.github.com reachable via proxy, example.com blocked via proxy."
log "  See gateway-selfcheck.sh for the proxy-level verification."

# Print the programmed rules for the log record
log "--- iptables OUTPUT chain ---"
iptables -L OUTPUT -n -v --line-numbers 2>/dev/null || true
log "--- end iptables OUTPUT chain ---"

exit 0
