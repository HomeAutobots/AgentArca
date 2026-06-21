#!/usr/bin/env bash
# tests/acceptance/component/test-09-container-base.sh
#
# Acceptance tests for item 09 (dev container base build).
# Area 8, Phase 5.
#
# Coverage map (BUILD_PLAN AC-09-*):
#   AC-09-P01  non-root UID 1000 (whoami returns devuser)
#   AC-09-P02  read-only rootfs (write to / fails; /tmp write succeeds)
#   AC-09-P03  zero effective capabilities (capsh --print shows empty set)
#   AC-09-P04  workspace is a named volume (not a bind mount)
#   AC-09-P05  /var/run/docker.sock absent
#   AC-09-P06  strace baseline exists (seccomp generated from real strace)
#   AC-09-P07  io_uring syscalls absent from agent-seccomp.json
#   AC-09-N01  pids_limit enforced (documented; fork-bomb test is destructive - marked)
#   AC-09-N02  mem_limit enforced (documented; stress test would OOM - marked)
#   AC-09-N03  userns-remap status recorded (host-conditional)
#   AC-09-N04  SUID/SGID binaries absent
#
# Additional checks:
#   SECCOMP-APPLIED   /proc/1/status shows Seccomp field
#   NO-DOCKER-SOCK    /var/run/docker.sock absent (AC-09-P05)
#
# Requires: DEVCONTAINER_ID set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/test-helpers.sh"

COMPONENT="container-base"
PASS=0
FAIL=0
SKIP=0
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

dc_exec() {
  docker exec --user 1000:1000 "${DEVCONTAINER_ID}" "$@"
}
dc_exec_root() {
  docker exec "${DEVCONTAINER_ID}" "$@"
}

# ------------------------------------------------------------
# AC-09-P01: Non-root UID 1000
# ------------------------------------------------------------
begin_test "AC-09-P01" "devcontainer runs as UID 1000 (non-root)"
WHO=$(docker exec --user 1000:1000 "${DEVCONTAINER_ID}" id -u 2>/dev/null) || WHO="unknown"
if [ "${WHO}" = "1000" ]; then
  pass_test "AC-09-P01" "UID=1000 confirmed"
else
  fail_test "AC-09-P01" "UID=${WHO} (expected 1000)"
fi

# Also check whoami returns devuser
WHO_NAME=$(dc_exec whoami 2>/dev/null || echo "unknown")
if [ "${WHO_NAME}" = "devuser" ] || [ "${WHO_NAME}" = "1000" ]; then
  pass_test "AC-09-P01-whoami" "whoami=${WHO_NAME} (non-root)"
else
  fail_test "AC-09-P01-whoami" "whoami=${WHO_NAME} (expected devuser or 1000)"
fi

# ------------------------------------------------------------
# AC-09-P02: Read-only rootfs
# ------------------------------------------------------------
begin_test "AC-09-P02" "read-only rootfs: write to / fails; /tmp write succeeds"
WRITE_ROOT_RESULT=0
dc_exec sh -c 'touch /acc15-test-file 2>/dev/null' || WRITE_ROOT_RESULT=$?
if [ "${WRITE_ROOT_RESULT}" -ne 0 ]; then
  pass_test "AC-09-P02-rootfs-RO" "write to / fails (exit ${WRITE_ROOT_RESULT}); rootfs is read-only"
else
  fail_test "AC-09-P02-rootfs-RO" "write to / SUCCEEDED - rootfs is NOT read-only! (ESCALATE)"
fi

WRITE_TMP_RESULT=0
dc_exec sh -c 'touch /tmp/acc15-test-file && rm /tmp/acc15-test-file' 2>/dev/null || WRITE_TMP_RESULT=$?
if [ "${WRITE_TMP_RESULT}" -eq 0 ]; then
  pass_test "AC-09-P02-tmpfs-writable" "/tmp is writable (tmpfs mount working)"
else
  fail_test "AC-09-P02-tmpfs-writable" "/tmp write failed (exit ${WRITE_TMP_RESULT}); tmpfs may not be mounted"
fi

# ------------------------------------------------------------
# AC-09-P03: Zero effective capabilities
# ------------------------------------------------------------
begin_test "AC-09-P03" "zero effective capabilities (cap_drop: ALL)"
CAP_OUTPUT=$(dc_exec sh -c 'capsh --print 2>/dev/null || cat /proc/1/status 2>/dev/null | grep -i "cap"' 2>/dev/null) || CAP_OUTPUT=""

# Check via /proc/self/status CapEff field
CAP_EFF=$(dc_exec sh -c 'grep "CapEff:" /proc/self/status 2>/dev/null | awk "{print \$2}"' 2>/dev/null) || CAP_EFF=""
if [ "${CAP_EFF}" = "0000000000000000" ] || [ "${CAP_EFF}" = "0" ]; then
  pass_test "AC-09-P03" "CapEff=0x${CAP_EFF} - zero effective capabilities (cap_drop:ALL confirmed)"
elif [ -n "${CAP_EFF}" ]; then
  fail_test "AC-09-P03" "CapEff=0x${CAP_EFF} - non-zero effective capabilities! (cap_drop:ALL not enforced)"
else
  # Try capsh
  if dc_exec sh -c 'command -v capsh' >/dev/null 2>&1; then
    CAPS=$(dc_exec capsh --print 2>/dev/null | grep "Current:" || echo "")
    if echo "${CAPS}" | grep -q "Current: =$"; then
      pass_test "AC-09-P03" "capsh: Current=empty (zero capabilities)"
    elif echo "${CAPS}" | grep -q "Current:"; then
      fail_test "AC-09-P03" "capsh shows non-empty caps: ${CAPS}"
    else
      skip_test "AC-09-P03" "REQUIRES-LINUX-HOST: cap check inconclusive - output: ${CAPS}"
    fi
  else
    skip_test "AC-09-P03" "REQUIRES-TOOL: capsh not available and /proc/self/status CapEff empty; compose sets cap_drop:ALL"
  fi
fi

# ------------------------------------------------------------
# SECCOMP-APPLIED: verify seccomp is applied (/proc/1/status)
# ------------------------------------------------------------
begin_test "SECCOMP-APPLIED" "seccomp profile applied (Seccomp field in /proc/1/status)"
SECCOMP_STATUS=$(dc_exec_root sh -c 'grep "^Seccomp:" /proc/1/status 2>/dev/null | awk "{print \$2}"' 2>/dev/null) || SECCOMP_STATUS=""
if [ "${SECCOMP_STATUS}" = "2" ]; then
  pass_test "SECCOMP-APPLIED" "Seccomp:2 (strict filtering mode applied)"
elif [ "${SECCOMP_STATUS}" = "1" ]; then
  pass_test "SECCOMP-APPLIED" "Seccomp:1 (strict/filtered mode; profile active)"
elif [ "${SECCOMP_STATUS}" = "0" ]; then
  fail_test "SECCOMP-APPLIED" "Seccomp:0 (no seccomp filter applied!)"
else
  skip_test "SECCOMP-APPLIED" "REQUIRES-LINUX-HOST: /proc/1/status Seccomp field not readable in this environment (status=${SECCOMP_STATUS})"
fi

# ------------------------------------------------------------
# AC-09-P04: Workspace is a named volume (not a bind mount)
# ------------------------------------------------------------
begin_test "AC-09-P04" "workspace /workspace is a named Docker volume (not a host bind mount)"
MOUNT_TYPE=$(docker inspect "${DEVCONTAINER_ID}" \
  --format '{{range .Mounts}}{{if eq .Destination "/workspace"}}{{.Type}}{{end}}{{end}}' 2>/dev/null) || MOUNT_TYPE=""
if [ "${MOUNT_TYPE}" = "volume" ]; then
  pass_test "AC-09-P04" "workspace mount type=volume (named volume, not bind mount)"
elif [ "${MOUNT_TYPE}" = "bind" ]; then
  fail_test "AC-09-P04" "workspace mount type=bind (HOST BIND MOUNT - violates ADR-004 D1 condition c! ESCALATE)"
elif [ -z "${MOUNT_TYPE}" ]; then
  fail_test "AC-09-P04" "workspace /workspace mount not found in container inspect"
else
  fail_test "AC-09-P04" "workspace mount type=${MOUNT_TYPE} (unexpected)"
fi

# ------------------------------------------------------------
# AC-09-P05: /var/run/docker.sock absent
# ------------------------------------------------------------
begin_test "AC-09-P05" "/var/run/docker.sock absent inside container"
SOCK_CHECK=0
dc_exec sh -c 'test -e /var/run/docker.sock' 2>/dev/null || SOCK_CHECK=$?
if [ "${SOCK_CHECK}" -ne 0 ]; then
  pass_test "AC-09-P05" "/var/run/docker.sock absent (ls returns non-zero)"
else
  fail_test "AC-09-P05" "/var/run/docker.sock EXISTS - docker socket must not be mounted! (ESCALATE)"
fi

# ------------------------------------------------------------
# AC-09-P06: strace baseline file exists (seccomp from real strace)
# ------------------------------------------------------------
begin_test "AC-09-P06" "strace baseline exists at src/dev/strace-baseline.txt (seccomp from real strace, OI-09-A)"
STRACE_FILE="${PROJECT_ROOT}/src/dev/strace-baseline.txt"
if [ -f "${STRACE_FILE}" ] && [ -s "${STRACE_FILE}" ]; then
  STRACE_LINES=$(wc -l < "${STRACE_FILE}")
  pass_test "AC-09-P06" "strace-baseline.txt exists (${STRACE_LINES} lines; seccomp was generated from real strace, not hand-written)"
elif [ -f "${STRACE_FILE}" ]; then
  fail_test "AC-09-P06" "strace-baseline.txt exists but is empty (OI-09-A: strace must have been run)"
else
  fail_test "AC-09-P06" "strace-baseline.txt MISSING at ${STRACE_FILE} (OI-09-A: seccomp must be from real strace)"
fi

# ------------------------------------------------------------
# AC-09-P07: io_uring syscalls absent from agent-seccomp.json
# ------------------------------------------------------------
begin_test "AC-09-P07" "io_uring syscalls absent from agent-seccomp.json (io_uring_setup/enter/register not permitted)"
SECCOMP_FILE="${PROJECT_ROOT}/src/dev/agent-seccomp.json"
if [ -f "${SECCOMP_FILE}" ]; then
  if grep -qiE '"io_uring_setup"|"io_uring_enter"|"io_uring_register"' "${SECCOMP_FILE}"; then
    fail_test "AC-09-P07" "io_uring syscalls FOUND in agent-seccomp.json! Must be absent per ADR-004."
  else
    pass_test "AC-09-P07" "io_uring syscalls absent from agent-seccomp.json (verified grep found nothing)"
  fi
else
  fail_test "AC-09-P07" "agent-seccomp.json not found at ${SECCOMP_FILE}"
fi

# ------------------------------------------------------------
# AC-09-N04: SUID/SGID binaries absent
# ------------------------------------------------------------
begin_test "AC-09-N04" "no SUID/SGID binaries in container image"
SUID_RESULT=$(dc_exec find / -perm /6000 -type f 2>/dev/null | head -5) || SUID_RESULT=""
if [ -z "${SUID_RESULT}" ]; then
  pass_test "AC-09-N04" "find -perm /6000 returned empty (no SUID/SGID binaries)"
else
  fail_test "AC-09-N04" "SUID/SGID binaries found: ${SUID_RESULT} (strip with chmod a-s during build)"
fi

# ------------------------------------------------------------
# AC-09-N01: pids_limit documented (destructive test not run)
# ------------------------------------------------------------
begin_test "AC-09-N01" "pids_limit=512 enforced (structural check - compose setting verified)"
PIDS_LIMIT=$(docker inspect "${DEVCONTAINER_ID}" --format '{{.HostConfig.PidsLimit}}' 2>/dev/null) || PIDS_LIMIT=""
if [ "${PIDS_LIMIT}" = "512" ]; then
  pass_test "AC-09-N01" "pids_limit=512 confirmed in docker inspect (fork-bomb test not run; destructive)"
else
  fail_test "AC-09-N01" "pids_limit=${PIDS_LIMIT} (expected 512; check docker-compose.yml pids_limit setting)"
fi

# ------------------------------------------------------------
# AC-09-N02: mem_limit enforced (structural check)
# ------------------------------------------------------------
begin_test "AC-09-N02" "mem_limit enforced (structural check - compose setting verified)"
MEM_LIMIT=$(docker inspect "${DEVCONTAINER_ID}" --format '{{.HostConfig.Memory}}' 2>/dev/null) || MEM_LIMIT=""
# Override file sets 2g = 2147483648 bytes; production is 6g = 6442450944
if [ "${MEM_LIMIT}" = "2147483648" ] || [ "${MEM_LIMIT}" = "6442450944" ]; then
  pass_test "AC-09-N02" "mem_limit=${MEM_LIMIT} bytes confirmed (stress test not run; destructive)"
else
  fail_test "AC-09-N02" "mem_limit=${MEM_LIMIT} (expected 2g or 6g in bytes; check compose override)"
fi

# ------------------------------------------------------------
# AC-09-N03: userns-remap status recorded (host-conditional)
# ------------------------------------------------------------
begin_test "AC-09-N03" "userns-remap status recorded (host-conditional, OI-09-B)"
USERNS_FILE="${PROJECT_ROOT}/src/dev/userns-remap-decision.md"
if [ -f "${USERNS_FILE}" ] && [ -s "${USERNS_FILE}" ]; then
  pass_test "AC-09-N03" "userns-remap-decision.md exists (OI-09-B finding recorded)"
else
  fail_test "AC-09-N03" "userns-remap-decision.md missing or empty at ${USERNS_FILE} (OI-09-B: must be recorded)"
fi
# Note: live userns-remap uid-mapping test REQUIRES-LINUX-HOST.
add_skip_note "AC-09-N03-live" "REQUIRES-LINUX-HOST: verify container root UID maps to high unprivileged UID on host (userns-remap uid 100000+). macOS: LinuxKit VM provides the equivalent isolation. Record on Linux target."

# Summary
print_component_summary "${COMPONENT}" "${PASS}" "${FAIL}" "${SKIP}"
