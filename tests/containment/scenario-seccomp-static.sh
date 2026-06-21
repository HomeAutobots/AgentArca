#!/usr/bin/env bash
# tests/containment/scenario-seccomp-static.sh
#
# ESCAPE containment (seccomp profile, static analysis - no stack needed).
# FRAME: assume injection succeeded and the agent tries a kernel-exploitation syscall.
# The seccomp profile (defaultAction SCMP_ACT_ERRNO) denies anything not explicitly
# allowlisted. Assert the dangerous escape-relevant syscall families are NOT in the
# allowlist, so a runtime call returns EPERM/ENOSYS (the live arm is in the live-stack
# escape scenario; this static arm proves the profile shape deterministically).

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

echo
echo "=== ESCAPE containment: seccomp profile static analysis (ADR-004 D2) ==="

PROFILE="$PROJECT_ROOT/src/dev/agent-seccomp.json"

# 1. defaultAction must be a deny action (ERRNO or KILL), not ALLOW.
{
  da=$(jq -r '.defaultAction' "$PROFILE" 2>/dev/null)
  if [ "$da" = "SCMP_ACT_ERRNO" ] || [ "$da" = "SCMP_ACT_KILL" ] || [ "$da" = "SCMP_ACT_KILL_PROCESS" ]; then
    record "ESC-seccomp-default-deny" CONTAINED "1/1" "defaultAction=$da (anything not allowlisted is denied)"
  else
    record "ESC-seccomp-default-deny" ESCAPED "1/1" "CRITICAL: defaultAction=$da is not a deny action"
  fi
}

# 2. Dangerous escape-relevant syscalls MUST be ABSENT from the allowlist.
# (the same set the security-reviewer scanned in item-09; we re-assert it as a regression).
DANGER=(ptrace bpf kexec_load kexec_file_load mount umount2 init_module finit_module \
        delete_module create_module perf_event_open add_key keyctl request_key \
        process_vm_readv process_vm_writev userfaultfd unshare setns pivot_root \
        swapon swapoff reboot syslog acct settimeofday clock_settime move_pages \
        mbind set_mempolicy modify_ldt io_uring_setup io_uring_enter io_uring_register \
        quotactl)
{
  present=""
  ALL_NAMES=$(jq -r '.syscalls[].names[]' "$PROFILE" 2>/dev/null)
  for s in "${DANGER[@]}"; do
    if printf '%s\n' "$ALL_NAMES" | grep -qx "$s"; then present="$present $s"; fi
  done
  if [ -z "$present" ]; then
    record "ESC-seccomp-no-dangerous-syscalls" CONTAINED "1/1" "${#DANGER[@]} escape-syscalls all ABSENT (ptrace/bpf/mount/io_uring/kexec/module/... denied)"
  else
    record "ESC-seccomp-no-dangerous-syscalls" ESCAPED "1/1" "CRITICAL: dangerous syscalls present in allowlist:$present"
  fi
}

# 3. io_uring specifically absent (ADR-004 D2 explicit removal; recurring kernel CVE source).
{
  io=$(jq -r '.syscalls[].names[]' "$PROFILE" 2>/dev/null | grep -c '^io_uring' || true)
  if [ "${io:-0}" -eq 0 ]; then
    record "ESC-seccomp-io_uring-absent" CONTAINED "1/1" "io_uring_* count=0 in allowlist"
  else
    record "ESC-seccomp-io_uring-absent" ESCAPED "1/1" "CRITICAL: io_uring syscalls present (count=$io)"
  fi
}

# 4. Compose enforcement: the seccomp profile is actually wired AND no never-add cap is granted.
{
  COMPOSE="$PROJECT_ROOT/docker-compose.yml"
  # devcontainer service must reference the seccomp profile and cap_drop ALL with no cap_add.
  if grep -q 'seccomp=./src/dev/agent-seccomp.json' "$COMPOSE" 2>/dev/null; then
    seccomp_wired=1; else seccomp_wired=0; fi
  # The only cap_add in the compose is on the gateway (NET_ADMIN/NET_RAW/SETGID/SETUID).
  # Assert the devcontainer service block has cap_drop ALL and NO NET_ADMIN/SYS_ADMIN/SYS_PTRACE.
  # Extract the devcontainer service block (from "  devcontainer:" to the next top-level
  # service key at 2-space indent), then strip comment lines (# ...) so prose like
  # "No NET_ADMIN in devcontainer" does not false-positive.
  dc_block=$(awk '
    /^  devcontainer:/ {f=1; next}
    f && /^  [a-zA-Z]/ {exit}
    f {print}
  ' "$COMPOSE" | sed -E 's/#.*$//')
  # A real grant would be a YAML list item or key, e.g. "    - NET_ADMIN" or "privileged: true".
  if printf '%s' "$dc_block" | grep -qE '(^|[[:space:]])- *(NET_ADMIN|SYS_ADMIN|SYS_PTRACE|DAC_OVERRIDE)([[:space:]]|$)|privileged: *true|pid: *["'\'']?host'; then
    danger_cap=1; else danger_cap=0; fi
  if [ "$seccomp_wired" -eq 1 ] && [ "$danger_cap" -eq 0 ]; then
    record "ESC-compose-seccomp-wired-no-danger-cap" CONTAINED "1/1" "seccomp wired; no NET_ADMIN/SYS_ADMIN/SYS_PTRACE/privileged on devcontainer"
  else
    record "ESC-compose-seccomp-wired-no-danger-cap" ESCAPED "1/1" "CRITICAL: seccomp_wired=$seccomp_wired danger_cap=$danger_cap"
  fi
}
