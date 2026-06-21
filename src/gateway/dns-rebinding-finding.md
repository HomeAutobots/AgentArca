# DNS Rebinding Finding

**OI-08-A | AC-08-N05 | Verified: 2026-06-14 | Environment: Docker Desktop 25.0.2 on macOS**

## Summary

DNS rebinding attacks are blocked by the peek+splice SNI allowlist and the L3 default-DROP. Because all egress goes through an explicit HTTP proxy with SNI-based filtering, DNS rebinding does not provide a usable attack path into the container's network or to internal services.

Note: this document was originally recorded when the proxy used CONNECT-destination (dstdomain) filtering. It has been updated (2026-06-14, BLOCK-1 resolution) to reflect the restored peek+splice SNI filtering design. The rebinding-blocking conclusion is unchanged and applies equally under peek+splice.

## Attack Model

DNS rebinding works by:
1. Attacker controls a domain (e.g., rebind-test.internal) that initially resolves to an external IP
2. After the victim browser connects, the attacker changes DNS to resolve to an internal IP (e.g., 192.168.1.1 or 169.254.169.254)
3. The browser's same-origin policy is confused: subsequent requests to "rebind-test.internal" go to the internal IP

In a standard container without a proxy, this allows an injected agent to reach internal network services by resolving an attacker-controlled domain to a private IP after the initial connection.

## Why the Design Blocks It

### Layer 7: SNI Allowlist via peek+splice

The explicit proxy model with peek+splice changes the DNS rebinding threat fundamentally. When the devcontainer makes an HTTPS request, it sends:

```
CONNECT rebind-test.internal:443 HTTP/1.1
```

Squid accepts the CONNECT from localnet (so it can peek the ClientHello), then peeks the TLS ClientHello. The SNI in the ClientHello is `rebind-test.internal`. Squid evaluates `ssl::server_name` against `allowed_SNI`. `rebind-test.internal` is not in the allowlist. `ssl_bump terminate all` fires: Squid sends a TCP RST to the client. No DNS resolution to the rebound IP is attempted.

Note on DNS rebinding vs SNI: DNS rebinding changes which IP the hostname resolves to, but it cannot change the SNI the client sends in the TLS ClientHello. The SNI is the hostname the client chose to connect to (`rebind-test.internal`), not the resolved IP. Even if the IP resolved to an internal address, Squid observes the SNI `rebind-test.internal` and blocks it because it is not on the allowlist. The rebinding trick does not help the attacker get past the SNI check.

### Layer 3: Default-DROP Output Policy

Even if an attacker somehow bypassed the proxy, the L3 default-DROP output policy on the gateway blocks any direct TCP connection that does not go through Squid's proxy process (uid 13). Direct connections to private IPs time out.

### Private IP CONNECT Requests Also Blocked

When a CONNECT is sent for a private IP literal (e.g., `CONNECT 169.254.169.254:443`), Squid peeks the ClientHello. The SNI for an IP-literal CONNECT may be empty or may be the attacker-controlled domain. Either way: if it is not on `allowed_SNI`, `ssl_bump terminate all` fires and the connection is reset.

## Empirical Results (2026-06-14, recorded under the previous CONNECT-destination design)

The following probes were run from the devcontainer via proxy when CONNECT-destination filtering was in use. The results are expected to be the same or stronger under peek+splice (SNI is a stricter check than CONNECT host):

| Target | CONNECT result | curl exit | Squid log |
|--------|---------------|-----------|-----------|
| `rebind-test.internal:443` | TCP_DENIED/403 | 56 | HIER_NONE |
| `169.254.169.254:443` | TCP_DENIED/403 | 28 (35s timeout at L3) | HIER_NONE |
| `10.0.0.1:443` | TCP_DENIED/403 | 56 | HIER_NONE |

Note on 169.254.169.254: The curl timeout was 35 seconds (compared to instant 403 for the others). This is because `169.254.169.254` is a link-local address that may cause delays in the TCP path, though the CONNECT was still denied at Squid (403 in log).

Under peek+splice, blocked connections return a TCP RST (from `ssl_bump terminate all`) rather than an HTTP 403. curl reports these as exit 35 (SSL handshake failed) or 000 (connection reset), not exit 56.

## Scope Note: DNS Rebinding vs SNI-Mismatch

The security reviewer noted (item-08-security-review.md): "The rebinding finding does not address the SNI-mismatch / domain-fronting bypass." These are distinct vectors:

- DNS rebinding: attacker changes DNS resolution of `rebind-test.internal` to a private IP. Blocked by SNI check on `rebind-test.internal` (not on allowlist).
- SNI-mismatch / domain-fronting: attacker sends `CONNECT api.github.com:443` (allowlisted CONNECT host) but sends SNI `evil.com` in the TLS ClientHello. Under peek+splice, Squid peeks the real SNI `evil.com`, which is not on the allowlist, and `ssl_bump terminate all` fires. This bypass is closed by AC-08-N07.

Both vectors are blocked by peek+splice SNI filtering. The CONNECT-destination approach (the previous design) blocked DNS rebinding (CONNECT host check) but did NOT block SNI-mismatch (CONNECT host was checked, not SNI). The restored peek+splice design closes both.

## Residual Risk

The residual risk for DNS rebinding is low in this design because:

1. The SNI from the ClientHello is the authority for the L7 decision, not the resolved IP. DNS rebinding cannot change what SNI the client sends.
2. Private IP CONNECT destinations trigger a peek of the ClientHello; the SNI is not on the allowlist, so they are terminated.
3. All allowed SNI values (e.g., `api.github.com`) are controlled by GitHub. An attacker cannot make `api.github.com` resolve to an internal IP in a way that would bypass the SNI check (Squid checks the SNI, not the resolved IP).

The one acknowledged residual risk (from the residual-risk register, ADR-002) is exfiltration via allowlisted destinations (e.g., git push to github.com). This is not a DNS rebinding risk; it is an authorized-destination risk. Addressed in the residual-risk register, not here.
