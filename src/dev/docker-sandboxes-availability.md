# Docker Sandboxes Linux Availability (OI-09-D)

Date checked: 2026-06-14
ADR: ADR-004 D4 (top escalation tier)
Item: 09

## Finding

Docker Sandboxes (the microVM-isolated agent environment, formerly Docker AI Sandboxes)
reached production GA on 2026-01-30. Platform support at that launch:
- macOS Apple Silicon: GA
- Windows (x86_64, Win11): GA
- Linux: NOT listed as GA as of 2026-06-14

A Docker community forum thread (checked 2026-06-14) confirms the product is "not experimental
and generally stable" on supported platforms. A Docker representative noted that some features
(sbx kit) still carry an "Early Access" label. Linux support is on the roadmap but no GA date
is announced.

Sources checked 2026-06-14:
- https://docs.docker.com/ai/sandboxes/ (Docker Sandboxes documentation)
- https://docs.docker.com/ai/sandboxes/release-notes/ (release notes, GA 2026-01-30)
- https://forums.docker.com/t/what-is-the-current-release-status-of-docker-sandboxes-early-access-experimental-or-ga/151749
  (Docker community forum: status confirmation from Docker employee)

## Decision

Docker Sandboxes is NOT named as a concrete Linux escalation path. ADR-004 D4 (FLAG)
explicitly states: "Do NOT name Docker Sandboxes as a concrete Linux escalation path
until build-time verification confirms it. On Linux today, Sysbox / Kata / a full VM
are the concrete top-tier options."

As of 2026-06-14, Linux GA is still not confirmed. The ADR's conditional flag remains
in effect.

## Concrete Linux top-tier escalation options (as of 2026-06-14)

If the escalation trigger fires on a Linux host (ADR-004 D4 top tier), the concrete
options are:

1. **Sysbox (--runtime=sysbox-runc)**: Runs Docker/systemd inside an unprivileged container
   without --privileged or docker.sock. Acquired by Docker (2022), the engine behind Docker
   Desktop ECI. Supports Docker-in-Docker securely.
   Install: https://github.com/nestybox/sysbox

2. **Kata Containers**: OCI-compatible microVM runtime (Firecracker or QEMU backend).
   Per-container hardware-isolated VM. Plugs in as a runc replacement.
   Install: https://katacontainers.io/

3. **Full VM (Lima/Colima/UTM/Multipass)**: For nation-state threat models or regulated
   high-assurance data. The agent runs in a fully isolated VM, not a container at all.

## When to re-check

Re-check Docker Sandboxes Linux status when:
- Docker announces a Linux GA release
- The project's regression cadence (item 18) triggers an upstream update check
- ADR-004 D4 top-tier escalation is being evaluated on a Linux host

Update this file and ADR-004 D4 if Linux GA is confirmed.
