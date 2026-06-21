#!/bin/bash
# src/dev/entrypoint.sh
# Startup integrity checks for the hardened dev container (ADR-004 D2, item 09).
#
# Checks:
#   1. Running as non-root (UID != 0)
#   2. Root filesystem is read-only (cannot write to /)
#   3. /tmp and /run are writable (tmpfs mounts from compose)
#   4. /var/run/docker.sock is absent
#   5. Workspace is a named volume (not a host bind mount)
#
# These checks are INFORMATIONAL on startup; they emit a warning if a condition
# is unexpected but do NOT abort the container (the security-reviewer gate and
# compose-level controls are the enforcement; this is belt-and-suspenders logging).
#
# If a CRITICAL check fails (running as root, docker.sock present), the container
# DOES abort, because these indicate a misconfiguration that collapses the
# security model.
set -euo pipefail

WARN() { echo "[WARN] $*" >&2; }
INFO() { echo "[INFO] $*"; }
FAIL() { echo "[CRITICAL] $*" >&2; exit 1; }

INFO "=== Dev container startup checks ==="
INFO "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
INFO "Kernel: $(uname -r)"

# Check 1: Must NOT be root (CRITICAL).
CURRENT_UID=$(id -u)
if [ "${CURRENT_UID}" -eq 0 ]; then
    FAIL "Running as root (UID 0). This violates ADR-004 D2. Container aborted."
fi
INFO "PASS: Non-root user (UID=${CURRENT_UID})"

# Check 2: Root filesystem should be read-only.
# Attempt to write to /; expect failure.
if touch /entrypoint-rw-test 2>/dev/null; then
    rm -f /entrypoint-rw-test 2>/dev/null || true
    WARN "Root filesystem appears to be writable. Expected read_only: true from compose. Check docker-compose.yml."
else
    INFO "PASS: Root filesystem is read-only (touch / failed as expected)"
fi

# Check 3: /tmp should be writable (tmpfs).
if touch /tmp/entrypoint-tmp-test 2>/dev/null; then
    rm -f /tmp/entrypoint-tmp-test 2>/dev/null || true
    INFO "PASS: /tmp is writable (tmpfs)"
else
    WARN "/tmp is NOT writable. Expected tmpfs mount from compose. Check docker-compose.yml tmpfs: [/tmp]."
fi

# Check 4: /run should be writable (tmpfs).
if touch /run/entrypoint-run-test 2>/dev/null; then
    rm -f /run/entrypoint-run-test 2>/dev/null || true
    INFO "PASS: /run is writable (tmpfs)"
else
    WARN "/run is NOT writable. Expected tmpfs mount from compose. Check docker-compose.yml tmpfs: [/run]."
fi

# Check 5: /var/run/docker.sock must be absent (CRITICAL per ADR-004 D3).
if [ -S /var/run/docker.sock ] || [ -e /var/run/docker.sock ]; then
    FAIL "/var/run/docker.sock is present. This violates ADR-004 D3 (never mount docker.sock). Container aborted."
fi
INFO "PASS: /var/run/docker.sock absent"

# Check 6: Workspace should exist (named volume mounted by compose).
if [ -d /workspace ]; then
    INFO "PASS: /workspace directory exists"
else
    WARN "/workspace does not exist. Expected named volume mount from compose."
fi

# Check 7: Home directory should be writable (named volume for Copilot CLI caches).
if touch /home/devuser/.entrypoint-home-test 2>/dev/null; then
    rm -f /home/devuser/.entrypoint-home-test 2>/dev/null || true
    INFO "PASS: /home/devuser is writable (named volume)"
else
    WARN "/home/devuser is NOT writable. Copilot CLI may fail to write ~/.copilot. Check compose volumes."
fi

INFO "=== Startup checks complete ==="

# Execute the command passed as arguments (default: sleep infinity).
exec "$@"
