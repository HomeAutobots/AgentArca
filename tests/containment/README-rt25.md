# Item-25 per-profile containment red-team (rt25)

Frame: **assume prompt injection succeeds**. The injected agent is a UID-1000 process inside
the active profile's dev container. We simulate it by running the exfil/escape attempts
DIRECTLY as UID 1000 via `docker exec` (the kernel and firewall enforce identically whether a
human or an injected agent issued the action). This is credential-independent: no live agent
token is needed to prove the deterministic boundary. There is no live-agent gap here; the
injected-agent model runs the attacks directly.

## What it tests, per profile (claude, codex, copilot)

1. EGRESS EXFIL CONTAINMENT (R-b core): non-allowlisted host (example.com/attacker.com),
   SNI-mismatch / domain-fronting, direct-to-IP on 443/80/arbitrary port, DNS exfil (`@8.8.8.8`)
   + DoH hosts, proxy-bypass (no-proxy and alt-proxy), registry-direct source-ACL.
2. CROSS-AGENT ALLOWLIST NON-UNION: under each profile, every OTHER agent's backend host is
   BLOCKED (fragments are not unioned).
3. PROFILE MUTUAL EXCLUSION (R-m): no other profile's token/cache volume is mounted, no
   foreign credential env-var bleed, workspace is the one deliberate shared surface.
4. BOUNDARY-CONFIG IMMUTABILITY UNDER ATTACK: append/truncate/rm the profile's immutable
   settings/config/.mcp.json/hook; chattr; remount-rw; rootfs write; iptables flush; reach the
   gateway's squid config; CapEff has no NET_ADMIN.
5. CODEX WEAKER INTERIOR GATE (R-l): the L3 firewall contains egress even with the soft Codex
   interior assumed defeated (attacks run as a raw proxy-ignoring UID-1000 process).
6. SELFCHECK INTEGRITY (the profile-aware fix): adversarial re-check that the gateway cannot
   report HEALTHY while a blocked host is reachable, and that the positive probe cannot mask a
   broken/open boundary. Includes a simulated-open-boundary run of the real selfcheck.

## Run it

```
# all three profiles (builds claude + codex images, reuses copilot image):
bash tests/containment/rt25-run-profiles.sh

# one profile:
bash tests/containment/rt25-run-profiles.sh --profile codex

# skip build (images already present):
bash tests/containment/rt25-run-profiles.sh --profile copilot --no-build
```

Each profile comes up under a unique project (`rt25-claude` / `rt25-codex` / `rt25-copilot`)
with pre-created external networks on distinct subnets (10.45.x / 10.46.x / 10.47.x), so it
does NOT collide with acc15 (10.15.x), acc25 (10.25-26.x), rt16 (172.28-31.x), or production.
The runner tears each stack + its networks down after the attacks. Repeatable and
self-tearing-down.

## Results

`results/rt25-results.csv`: one row per attack, `attack-id,profile,expected,observed,attack-success`.
`attack-success=yes` is a CONTAINMENT BREACH (a real finding routed to implementer /
security-reviewer / threat-modeler). `no` = contained. `skip` = could not be staged in this env.

The boundary checks here are DETERMINISTIC (kernel + firewall), not probabilistic like a model
refusal, so a clean run per attack is the proof. Stability was confirmed by repeating the core
egress/escape attacks 5x with identical results (all blocked every run).

## Last run (2026-06-20, macOS Docker Desktop, server 25.0.2)

Per-profile attack-success (target 0):

| profile | attacks | contained | breach | skip |
|---------|---------|-----------|--------|------|
| copilot | 36      | 36        | 0      | 0    |
| claude  | 36      | 36        | 0      | 0    |
| codex   | 36      | 36        | 0      | 0    |

Total: 108 attacks, 0 breaches. Copilot remains at its 0/N baseline (matches rt16). Codex
image built with `@openai/codex@0.140.0`, came up healthy, and the L3 firewall contained every
egress attempt regardless of the incomplete app-level proxy honoring (R-l proven).
RED_TEAMED-clean for the credential-independent scope.
