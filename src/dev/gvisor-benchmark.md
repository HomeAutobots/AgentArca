# gVisor Benchmark Decision (OI-09-C)

Date: 2026-06-14
ADR: ADR-004 D4 (middle escalation tier)
Item: 09

## Decision: gVisor NOT adopted. runc is proportionate.

### Rationale

Per ADR-004 D1, the hardened runc tier is proportionate as the default ONLY when three conditions hold:
(a) Production secrets are kept out (ADR-003: YES, headless + secrets-out posture)
(b) Egress is forced through the ADR-002 gateway sidecar (YES, wired in docker-compose.yml)
(c) Workspace is disposable / clone-into-volume (YES, named volume agent-workspace)

All three conditions hold. The runc tier is proportionate for the established threat.

The escalation trigger for gVisor (ADR-004 D4 middle tier) is:
"interior code may attempt kernel exploitation AND VM overhead unacceptable AND tooling tolerates syscall gaps (no GPU/DinD/exotic syscalls) AND you benchmarked your Node/Python workload."

The first condition does not currently hold: the established threat model is
code-we-broadly-trust under the Copilot agent model, not a dedicated kernel exploitation
attempt. The agent is a confused deputy that may be injection-manipulated, but the dominant
attack class is egress-through-allowlisted-channel (R-b) and credential access (R-c), not
kernel exploitation. The D4 escalation trigger for the middle tier ("interior code may attempt
kernel exploitation") does not currently fire for the headless Copilot CLI workload.

### Why benchmarking was NOT performed

ADR-004 D4 explicitly states: "Benchmark your own workload. Do NOT adopt gVisor on the
bracketed-range-from-research alone."

gVisor (runsc) is not readily available on Docker Desktop on macOS:
- Docker Desktop uses its own runtime infrastructure; runsc requires a separate
  installation of gVisor on the host and a runtime configuration in daemon.json.
- On macOS, the LinuxKit VM would need gVisor installed inside it, which requires
  modifying the Docker Desktop VM image.
- Benchmarking requires a Linux host with gVisor installed natively.

Fabricated benchmark numbers have been explicitly refused (CLAUDE.md: "Do NOT fabricate").

### How to benchmark gVisor if the escalation trigger fires in the future

On a Linux host with gVisor installed:

```bash
# Install gVisor (Systrap mode, no KVM requirement)
# https://gvisor.dev/docs/user_guide/install/
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc

# Add to /etc/docker/daemon.json:
# { "runtimes": { "runsc": { "path": "/usr/bin/runsc" } } }
# sudo systemctl restart docker

# Benchmark: run the same workload under runc and runsc, compare
# 1. runc baseline:
time docker run --rm ubuntu node -e "require('fs').writeFileSync('/tmp/t', 'x'); console.log('done')"

# 2. runsc (gVisor Systrap mode):
time docker run --rm --runtime=runsc ubuntu node -e "require('fs').writeFileSync('/tmp/t', 'x'); console.log('done')"

# 3. More comprehensive: npm install, pip install, file I/O, git operations
# Record: wall time, sys call count, memory overhead vs runc baseline.
```

### Escalation decision table entry

If the Node/Python Copilot workload starts running untrusted third-party code as a core function,
or if the threat model escalates to "interior code may attempt kernel exploitation," revisit this
decision and benchmark gVisor on a Linux host before adopting.

See ADR-004 D4 middle tier for the full trigger criteria.

### Research-cited gVisor overhead range (NOT workload-specific)

From Area 4 / Area 10 research (for context only; NOT a substitute for workload benchmarking):
- "<1-3% for 95% of apps" (Ant Group production, I/O-light workloads)
- Up to "125% execution-time increase on a single-threaded SQLite insertion benchmark" (syscall-heavy worst case)
- ~10-30% on I/O-heavy workloads (Area 10)
- Syscall coverage ~70-80% implemented; some tooling breaks (eBPF, advanced ioctls, some debuggers)

These ranges are cited from research. Actual Node.js + Python overhead on this specific workload is
unknown and MUST be benchmarked before adopting gVisor. Do NOT adopt on this range alone.
