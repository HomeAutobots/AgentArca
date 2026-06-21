# OI-10-C Finding: Copilot Token Proxy-Injection Feasibility Analysis

- Date: 2026-06-14
- Item: 10 (credential handling build)
- Status: FEASIBILITY ANALYSIS (not a full build). Committed posture unchanged.

## Question

Can Envoy's credential_injector filter (or similar proxy-level injection) substitute
the Copilot CLI's Bearer token into requests to *.githubcopilot.com, so the agent
holds a dummy token and the real token never enters the container?

## Two distinct token paths

The answer differs by Copilot deployment path:

### Path 1: Copilot CLI / headless (the ADR-003 D2 headless default)

The @github/copilot CLI sends HTTP requests to:
  - api.individual.githubcopilot.com (Copilot agent API)
  - telemetry.individual.githubcopilot.com (Copilot telemetry)

These requests carry an `Authorization: Bearer <token>` HTTP header. This IS
theoretically amenable to Envoy credential_injector header substitution:

Envoy filter type:
  type.googleapis.com/envoy.extensions.filters.http.credential_injector.v3.CredentialInjector

With an SDS-backed credential source and `header_value_prefix: "Bearer "`, Envoy
can strip the agent's Authorization header and substitute the real token from the
secret store. The gateway already terminates the TLS to *.individual.githubcopilot.com
in the SNI-peek-and-splice mode; to inject a header, the gateway would need to switch
that destination to the MITM/terminate path (decrypt-and-rewrite), which is the
ADR-002 D3 full-MITM opt-in (requires a custom CA in the container and breaks any
cert-pinned clients).

**Conclusion for CLI path:** Feasible in principle. The technical components exist.
BUT it is not committed because:

1. It requires switching *.individual.githubcopilot.com from SNI-splice to MITM-terminate,
   which is the ADR-002 D3 full-MITM opt-in that the default posture explicitly avoids.
   This creates a tension: the splice-no-decrypt design (ADR-002 D3 default) and
   the credential_injector require decryption of the same TLS stream. They cannot
   coexist for the same destination in the same gateway configuration.

2. It would require the gateway to hold the REAL Copilot token (as an SDS secret).
   The gateway sidecar would become a new high-value secret holder. If the gateway
   is compromised, the real token is at risk. This trades one attack surface for
   another.

3. The committed posture (ADR-003 D3/D4) is minimization + egress containment.
   That is already the correct posture. Adding proxy-injection complexity introduces
   a new attack surface without a corresponding reduction in R-c: the token is still
   present (in the gateway), still reachable from within the trust boundary (the gateway
   is inside the same compose stack), and egress is still the primary containment.

4. ADR-003 D4 explicitly states: "This pattern is NOT confirmed to work for the
   Copilot Chat token... Copilot-token proxy-injection is marked
   carried-pending-empirical-verification and is NOT a committed control."

### Path 2: Copilot Chat extension (VS Code fallback model)

The Copilot Chat extension (the VS Code FALLBACK model, NOT the headless default)
uses a different authentication mechanism: the GitHub Authentication extension is
a host-side "ui"-kind extension running in the LOCAL extension host. The OAuth token
lives in host VS Code SecretStorage (Electron `safeStorage`/OSCrypt) and is brokered
into the container over the VS Code Remote Development RPC protocol.

This is NOT an HTTP `Authorization: Bearer <token>` header carried in a TLS stream
that the gateway can see. It is an RPC call over the VS Code Dev Containers control
plane channel. The proxy-injection pattern does NOT apply to this path; the gateway
has no visibility into the VS Code RPC protocol.

**Conclusion for Chat extension path:** Proxy-injection is NOT applicable. The
token is brokered over VS Code RPC, not a standard HTTP header the proxy can intercept
and substitute. This was flagged as "not confirmed" in ADR-003 D4 and that assessment
is confirmed here.

## Summary assessment

| Path | Injection technically possible? | Conflicts with posture? | Committed? |
|------|--------------------------------|-------------------------|------------|
| CLI Bearer (*.individual.githubcopilot.com) | Yes (via MITM-terminate + credential_injector) | Yes (splice-no-decrypt vs MITM-terminate tension) | NO |
| Chat extension RPC (VS Code fallback) | No (RPC, not HTTP Authorization header) | N/A | NO |

## Committed posture (unchanged)

ADR-003 D3 and D4 remain the committed posture:
- Token minimization via fine-grained PAT (CLI path, VERIFIED)
- Egress containment (ADR-002 boundary) is the primary control
- R-c (readable Copilot token) is accepted and named
- Proxy-injection is NOT a committed control

This finding does NOT change R-c severity (MEDIUM/HIGH), class (bounded-but-present),
or never-solved-away status. The token is agent-readable; egress is the containment.

## Escalation status

No escalation required. The finding confirms that the committed posture
(minimization + egress) is already the correct and sufficient posture.
The proxy-injection path is technically possible for the CLI path but conflicts
with the splice-no-decrypt design and introduces its own attack surface. It is
not built.
