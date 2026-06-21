# src/gateway/Dockerfile
# Gateway sidecar: Squid SslPeekAndSplice (peek+splice, no CA distributed) + iptables firewall.
# Base image pinned by digest (ubuntu:22.04 as of 2026-06-13).
# No secrets baked in. No unnecessary binaries beyond Squid + iptables.
# ADR-002 D1, D2, D3. CLAUDE.md invariant 5.
#
# Design: peek+splice SNI filtering (restored from BLOCK-1 resolution, 2026-06-14).
#
#   Squid operates as an explicit HTTP proxy:
#     http_port 8080 ssl-bump cert=... key=... generate-host-certificates=on
#   For each HTTPS CONNECT tunnel, Squid:
#     1. Peeks the TLS ClientHello to read the real SNI (ssl_bump peek step1, with at_step SslBump1)
#     2. Splices (tunnels without decrypting) if the peeked SNI is on the allowlist
#     3. Terminates (TCP RST) if the peeked SNI is NOT on the allowlist
#
#   NO DECRYPTION. NO CA DISTRIBUTED TO CLIENTS.
#   splice does not decrypt traffic. Clients see only the real server certificate.
#
# EMPIRICAL FINDINGS (RC-3, 2026-06-14, Squid 5.9):
#
#  Finding 1 - cert= is required:
#   Squid 5.9 requires a cert= parameter on the ssl-bump http_port line even
#   in splice-only mode. Without cert=, Squid starts the security_file_certgen
#   helper processes, which immediately crash (no cert context), causing Squid
#   to exit with code 1.
#
#  Finding 2 - generate-host-certificates=on is required:
#   With generate-host-certificates=off, the TLS peek context is null and every
#   peek attempt fails with OpenSSL error:0A0000C3 (null ssl ctx). Squid accepts
#   the CONNECT and sends 200 but cannot peek the ClientHello, causing ALL
#   connections to be treated as if no ssl_bump rule matched.
#   generate-host-certificates=on initializes the per-connection TLS handle.
#   No certs are generated in practice: cert generation (the MITM path) is only
#   triggered by ssl_bump bump actions, and our config uses only splice/terminate.
#   The ssl_db initialized below remains empty during operation.
#
#  Finding 3 - sslcrtd_program / ssl_db initialization is required:
#   Even with splice-only config, Squid starts security_file_certgen helpers.
#   Without a valid ssl_db, helpers crash immediately. Squid aborts with:
#   "FATAL: The sslcrtd_program helpers are crashing too rapidly, need help!"
#   The ssl_db is initialized at build time (below). No certs are stored in it.
#
#  Finding 4 - at_step SslBump1 is required for correct splice/terminate:
#   Without 'acl step1 at_step SslBump1', 'ssl_bump peek all' matches at every
#   step. At step 2, Squid re-evaluates rules and may re-peek instead of firing
#   the splice/terminate rule. Empirically: without at_step, example.com was
#   spliced (allowed) instead of terminated (blocked). With at_step:
#   - step 1: peek fires (reads ClientHello SNI)
#   - step 2: peek no longer matches (step1 ACL doesn't match SslBump2);
#             Squid evaluates splice (allowed_SNI) or terminate (all)
#
#   This cert is NOT a CA cert (basicConstraints CA:FALSE), is NOT distributed
#   to clients (no CA bundle update, no NODE_EXTRA_CA_CERTS), and is NOT used
#   to decrypt or MITM any connection. It exists solely to satisfy Squid 5.9's
#   internal TLS context initialization requirement for the ssl-bump port.
#   Spliced connections present only the real upstream server's certificate to
#   the client. Terminated connections receive a TCP RST (no cert presented).
#
# Build-time discoveries (verified 2026-06-14):
#
#  1. squid vs squid-openssl conflict:
#     On Ubuntu 22.04, 'squid' and 'squid-openssl' are mutually exclusive
#     (Conflicts: squid in squid-openssl package). Install squid-openssl only.
#     squid-openssl is required for ssl_bump / SslPeekAndSplice.
#
#  2. at_step SslBump1 is required (not 'peek all', not 'peek step1 all'):
#     In explicit proxy mode with SslPeekAndSplice, the correct canonical form is:
#       acl step1 at_step SslBump1
#       ssl_bump peek step1
#     Without at_step, terminate does not fire for non-allowlisted SNIs.
#
#  3. cache_dir null not supported in this Squid build:
#     Use 'cache deny all' without a cache_dir directive.

FROM ubuntu@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d

LABEL org.opencontainers.image.description="Hardened AgentArca dev container gateway sidecar (ADR-002, peek+splice SNI filtering)"
LABEL org.opencontainers.image.source="https://github.com/HomeAutobots/AgentArca"

# Install runtime dependencies:
#   squid-openssl: Squid with ssl-bump support (replaces squid, conflicts with squid pkg)
#                  Required for SslPeekAndSplice (ssl_bump peek+splice).
#   openssl: generate the build-time self-signed cert for the ssl-bump port context.
#            NOT a CA cert. NOT distributed to clients. Required by Squid 5.9 for the
#            ssl-bump port even with generate-host-certificates=off (see RC-3 above).
#   ca-certificates: Squid validates upstream TLS certs (verifies server certs when splicing)
#   curl: used in gateway-selfcheck.sh (AC-08-P02, AC-08-P03)
#   dnsutils: dig, used in gateway-selfcheck.sh and init-firewall.sh (AC-08-N03)
#   iptables: used in init-firewall.sh (L3 default-DROP, ADR-002 D2)
#   iproute2: ip command for diagnostic use
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        squid-openssl \
        openssl \
        ca-certificates \
        curl \
        iptables \
        dnsutils \
        iproute2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/squid /var/spool/squid /etc/squid/conf.d /etc/squid/ssl \
    && chown -R proxy:proxy /var/log/squid /var/spool/squid

# Generate a self-signed certificate for Squid's ssl-bump port TLS context.
#
# PURPOSE (RC-3): Squid 5.9 requires a cert= parameter on 'http_port ssl-bump'
# even when peek+splice+terminate is configured and generate-host-certificates=off.
# Without it, Squid crashes at startup (sslcrtd_program helper fails with no cert).
#
# WHAT THIS CERT IS:
#   - NOT a CA cert (basicConstraints CA:FALSE, no CA:TRUE)
#   - Generated at build time (not injected as a secret, reproducible)
#   - NOT distributed to clients (no devcontainer CA bundle, no NODE_EXTRA_CA_CERTS)
#   - NOT used to decrypt or MITM traffic (splice = transparent TCP tunnel)
#   - NOT a trust anchor for any client
#
# WHAT THIS CERT IS NOT:
#   - It is not the "MITM opt-in" full-bump CA from ADR-002 D3
#   - It does not enable content inspection
#   - Clients never see or trust this cert
#   - Spliced connections show only the real upstream server cert
#   - Terminated connections receive a TCP RST (no cert presented)
#
# It satisfies Squid's internal ssl-bump port TLS context initialization.
# This is a Squid 5.9 implementation requirement, not a design decision.
RUN openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/CN=squid-splice-port-context/O=DevContainerGateway/OU=EgressControl" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -keyout /etc/squid/ssl/squid-splice.key \
    -out /etc/squid/ssl/squid-splice.crt \
    && chmod 640 /etc/squid/ssl/squid-splice.key \
                 /etc/squid/ssl/squid-splice.crt \
    && chown root:proxy /etc/squid/ssl/squid-splice.key \
                        /etc/squid/ssl/squid-splice.crt

# Initialize the SSL certificate database for security_file_certgen.
#
# Why needed (additional RC-3 finding, 2026-06-14):
#   Even with generate-host-certificates=on (needed for the TLS peek context),
#   Squid starts security_file_certgen helper processes. These processes require
#   a database directory (specified via sslcrtd_program ... -s /var/lib/squid/ssl_db).
#   Without initialization, the helpers crash immediately and Squid aborts with:
#   "FATAL: The sslcrtd_program helpers are crashing too rapidly, need help!"
#
#   Initialization (security_file_certgen -c -s ... -M ...) creates the db structure.
#
# Security note: The ssl_db is a cache for dynamically generated per-host certs,
#   used only if bump (MITM) actions are taken. Since our ssl_bump config only does
#   peek -> splice (pass-through) or terminate (TCP RST), no certs are generated
#   and the db remains empty. Clients are never presented with generated certs.
#   The db is initialized here to satisfy Squid's startup requirements, not for
#   any MITM purpose.
RUN mkdir -p /var/lib/squid \
    && /usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB \
    && chown -R proxy:proxy /var/lib/squid

# Copy Squid configs (main config + modular fragments only).
# squid-allowlist.conf (the monolithic legacy file) is NOT copied here.
# It was removed from the production image (ADR-009 clean-base refactor):
#   - It is included by NOTHING in the production squid.conf (which loads
#     allowlist.d/base.conf + allowlist.d/active-agent.conf + conf.d/*.conf).
#   - It duplicated copilot.conf content and created a false "second source of truth".
#   - The discovery harness does not need it (discovery uses splice-all, no allowlist).
#   - The file is retained at src/gateway/discovery/squid-allowlist.conf for reference.
# The copilot allowlist has ONE live source: squid-allowlist.d/copilot.conf.
COPY squid.conf /etc/squid/squid.conf
# Multi-agent profile fragments (ADR-008 D2, SPEC-20).
# The entrypoint.sh selects the active fragment at container start.
RUN mkdir -p /etc/squid/allowlist.d
COPY squid-allowlist.d/base.conf /etc/squid/allowlist.d/base.conf
COPY squid-allowlist.d/copilot.conf /etc/squid/allowlist.d/copilot.conf
COPY squid-allowlist.d/claude.conf /etc/squid/allowlist.d/claude.conf
COPY squid-allowlist.d/codex.conf /etc/squid/allowlist.d/codex.conf

# Copy init, healthcheck, and entrypoint scripts
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
COPY gateway-selfcheck.sh /usr/local/bin/gateway-selfcheck.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 755 /usr/local/bin/init-firewall.sh \
              /usr/local/bin/gateway-selfcheck.sh \
              /usr/local/bin/entrypoint.sh \
    && chmod 644 /etc/squid/squid.conf \
    && chmod 444 /etc/squid/allowlist.d/base.conf \
                 /etc/squid/allowlist.d/copilot.conf \
                 /etc/squid/allowlist.d/claude.conf \
                 /etc/squid/allowlist.d/codex.conf

# Drop SUID/SGID binaries to reduce attack surface (ADR-004 D2).
RUN find / -xdev -perm /6000 -type f 2>/dev/null | xargs -r chmod a-s

# Gateway runs as root: required for iptables (cap_add NET_ADMIN in compose).
# The Squid worker process drops to 'proxy' user after startup.
USER root

# Squid HTTP proxy port (shared netns - only accessible from within the netns).
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
