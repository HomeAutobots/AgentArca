# userns-remap Host-Conditional Decision (OI-09-B, AC-09-N03)

Date: 2026-06-14
ADR: ADR-004 D2 (threat-modeler tightening, 2026-06-13)
Item: 09

## Summary

userns-remap is the single largest escape-impact mitigation for R-e (kernel 0-day container escape). It converts "escape lands as host root" into "escape lands as an unprivileged nobody on the host." ADR-004 D2 (threat-modeler tightening) sets the policy as: MANDATORY-where-supported on Linux, recommended-but-gated on macOS.

## This host: macOS Docker Desktop 25.0.2

**Status: NOT ENABLED. Decision: NOT-EXECUTED-ON-THIS-HOST (macOS).**

Rationale (from ADR-004 D2 threat-modeler tightening):

On macOS Docker Desktop, all containers run inside a single LinuxKit VM (HyperKit/Hypervisor.framework). A container escape lands in the Linux VM, not on the macOS host. The LinuxKit VM hardware virtualization boundary between the container and the macOS host materially reduces the marginal benefit of userns-remap on this host class. The incidental backstop (present on macOS, absent on native Linux) is precisely why the threat-modeler accepted the architect's "recommended-but-gated" framing for macOS.

Additionally, enabling userns-remap on Docker Desktop requires:
1. Modifying daemon.json (typically at ~/Library/Group Containers/.../daemon.json on macOS)
2. Restarting Docker Desktop (which restarts the LinuxKit VM and interrupts ALL running containers)
3. This affects all containers on the host, not just this project

These changes constitute "undue friction" for a macOS dev host where the LinuxKit VM already provides the hardware backstop. Therefore, following ADR-004 D2 threat-modeler tightening, userns-remap is NOT enabled on this macOS host.

## How to enable on this macOS host (optional hardening)

If the operator wants the additional hardening:

1. Open Docker Desktop -> Settings -> Docker Engine
2. Add to daemon.json:
```json
{
  "userns-remap": "default"
}
```
3. Click "Apply & Restart"
4. Verify with: docker info | grep -i userns

Note: After enabling userns-remap, named volume permissions may need adjustment because the host UID mapping changes. Files owned by UID 1000 inside the container will map to a high UID (e.g., 100000+1000 = 101000) on the host. This can cause permission issues with pre-existing volumes.

## Linux production host: MANDATORY where kernel 5.11+ supports it

On a native Linux host (no Docker Desktop VM), userns-remap is MANDATORY per ADR-004 D2 threat-modeler tightening because:

- There is NO VM backstop (containers share the host kernel directly with NO hardware boundary)
- An escape at the bare runc tier lands as host root on the user's actual machine
- This is exactly escalation trigger D4(e): "Linux host, no Docker Desktop VM, running untrusted code"

### How to enable on Linux

```bash
# 1. Check kernel version (must be 5.11+)
uname -r

# 2. Verify subuid/subgid ranges exist
cat /etc/subuid
cat /etc/subgid
# If missing: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 <username>

# 3. Add to /etc/docker/daemon.json
sudo tee /etc/docker/daemon.json << 'EOF'
{
  "userns-remap": "default"
}
EOF

# 4. Restart Docker daemon
sudo systemctl restart docker

# 5. Verify
docker info | grep -i "user namespace"
# Expected: "User Namespace: enabled"

# 6. Verify container-root maps to high host UID
docker run --rm ubuntu id
# Inside container: uid=0(root)
# From host: the container PID is owned by e.g. UID 100000+ (not host root)
ps aux | grep "sleep"  # find the container process
ls -la /proc/<pid>/  # check owning UID on host
```

### If Linux host cannot support userns-remap (kernel < 5.11)

Per ADR-004 D2: this is a stop-and-flag condition. Record an explicitly accepted per-host gap. Treat running untrusted code on that host as a D4(e) escalation trigger (escalate to gVisor or microVM), not silently proceed at the bare runc tier.

Gap record:
- Risk elevated: R-e impact stays HIGH without userns-remap (escape lands as host root)
- Accepted? Only with explicit operator sign-off and an ADR annotation
- Mitigation: escalate to gVisor (D4 middle) or Kata/Firecracker microVM (D4 top)

## AC-09-N03 result

- Host: macOS Docker Desktop 25.0.2 (x86_64)
- userns-remap: NOT enabled
- Reason: macOS host with LinuxKit VM backstop; enabling requires daemon restart affecting all containers (undue friction per ADR-004 D2)
- LinuxKit VM backstop: PRESENT (hardware boundary between container and macOS host)
- Linux production host guidance: DOCUMENTED above (MANDATORY where kernel 5.11+)
- Gap accepted for macOS dev host: YES, with ADR-004 D2 rationale
