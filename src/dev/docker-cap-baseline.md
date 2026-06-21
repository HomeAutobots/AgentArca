# Docker Default Capability Set (OI-09-E)

Date confirmed: 2026-06-14
Docker version: 25.0.2
Host: Docker Desktop (macOS, LinuxKit VM, x86_64)
ADR: ADR-004 D2
Item: 09

## Verification Method

Ran a default Docker container (no --cap-add, no --cap-drop, no --privileged) and
read /proc/1/status:

```
docker run --rm ubuntu@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d \
  bash -c "cat /proc/1/status | grep Cap"
```

Output:
```
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

## Decoded capability set (0x00000000a80425fb)

Decoding the hex bitmask with python3 confirms these 14 capabilities are in the
Docker default set:

| Bit | Capability | Description |
|-----|-----------|-------------|
| 0   | CAP_CHOWN | Change file ownership |
| 1   | CAP_DAC_OVERRIDE | Bypass file permission checks |
| 3   | CAP_FOWNER | Bypass file owner restrictions |
| 4   | CAP_FSETID | Set UID/GID on file |
| 5   | CAP_KILL | Send signals to any process |
| 6   | CAP_SETGID | Set process GID |
| 7   | CAP_SETUID | Set process UID |
| 8   | CAP_SETPCAP | Transfer/remove capability from other processes |
| 10  | CAP_NET_BIND_SERVICE | Bind to privileged ports (<1024) |
| 13  | CAP_NET_RAW | Use raw sockets |
| 18  | CAP_SYS_CHROOT | Use chroot |
| 27  | CAP_MKNOD | Create device files |
| 29  | CAP_AUDIT_WRITE | Write to kernel audit log |
| 31  | CAP_SETFCAP | Set file capabilities |

Total: 14 capabilities (the "default 14-cap set" from ADR-004 D2).

## Verification of cap_drop: [ALL]

With `cap_drop: [ALL]` in docker-compose.yml, all 14 capabilities above are dropped.

Verification run (AC-09-P03):
```bash
docker exec copilot-devcontainer capsh --print
```
Expected: "Current: =" (empty effective capability set)
Actual result: [recorded in AC test run below]

## What a Node/Python dev workload needs

A Node.js + Python dev workload needs NONE of the 14 default caps:
- No raw sockets (CAP_NET_RAW)
- No privileged port binding (CAP_NET_BIND_SERVICE: dev servers use 3000+/8000+)
- No chroot (CAP_SYS_CHROOT)
- No device file creation (CAP_MKNOD)
- No audit log writing (CAP_AUDIT_WRITE)
- No UID/GID switching at runtime (CAP_SETUID/SETGID: user is fixed at 1000:1000)
- No DAC override (CAP_DAC_OVERRIDE: file permissions are respected)

Therefore `cap_drop: [ALL]` with no `cap_add` is correct for this workload.

## Never-add capabilities (ADR-004 D2 hard constraints)

The following capabilities MUST NEVER be added to the devcontainer:
- CAP_SYS_ADMIN: huge attack surface, near-root
- CAP_NET_ADMIN: would collapse ADR-002 D1 egress boundary (agent could iptables -F)
- CAP_SYS_PTRACE: process inspection/injection
- CAP_DAC_OVERRIDE: file permission bypass

Adding any of these is a stop-and-flag condition per ADR-004 D2.

## Historical note

The Docker default cap set has shifted historically (NET_RAW has been added/removed
in past releases). The ADR-004 D2 Verification note (2026-06-13) correctly flagged
this as a "build-time check rather than a permanent fact." This document is the
build-time check result for Docker 25.0.2.
