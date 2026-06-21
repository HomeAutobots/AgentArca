#!/usr/bin/env bash
# src/scripts/apply-immutability.sh
#
# Apply chattr +i to all canonical boundary-config files and verify with lsattr.
#
# CRITICAL CONSTRAINT (from item-10 security-review, OI-10-E / item-10 chattr capability gap):
#   In-container chattr +i CANNOT run because cap_drop:ALL removes CAP_LINUX_IMMUTABLE.
#   This script MUST be run from the HOST (or a privileged context that has CAP_LINUX_IMMUTABLE),
#   NOT from inside the devcontainer.
#
# PRIMARY IMMUTABILITY MECHANISM (item-11, SPEC-05 D6):
#   The primary "agent cannot edit boundary-config" enforcement is:
#   (a) chat.tools.edits.autoApprove hard-deny globs (managed-config/settings.json)
#   (b) PreToolUse hook ask/deny on boundary paths (.github/hooks/pretooluse.sh)
#   (c) managed-level config (not agent-writable)
#   (d) READ-ONLY MOUNT of the enforcement layer (hook script + managed settings)
#       mounted into the container at container start time.
#   chattr +i is the DEFENSE-IN-DEPTH leg, not the primary control.
#
# DiD LEG: this script provides defense-in-depth immutability for the boundary-config files
#   that can be chattr'd (those on an ext4-backed volume or native Linux filesystem where
#   the operator has CAP_LINUX_IMMUTABLE). It is NOT the primary control.
#
# READ-ONLY MOUNT ALTERNATIVE (PREFERRED per item-10 reviewer guidance):
#   For the enforcement layer (hook script + managed settings + mcp.json), a read-only
#   Docker volume mount is STRONGER than chattr +i and does not require any capability.
#   See docker-compose.yml for the read-only mount configuration.
#   Example:
#     volumes:
#       - type: bind
#         source: ./src/.github/hooks
#         target: /workspace/.github/hooks
#         read_only: true
#       - type: bind
#         source: ./src/managed-config
#         target: /etc/vscode
#         read_only: true
#
# OI-11-E (N-3): lsattr position-independent flag match.
#   lsattr output format varies across kernel versions and filesystems.
#   The 'i' flag may appear at different positions in the attribute string.
#   We check for 'i' as a CHARACTER in the attribute string (not a fixed column position).
#   Correct form: lsattr "$f" | awk '{print $1}' | grep -q 'i'
#   Wrong form:   lsattr "$f" | grep -q '^----i'  (fixed-column, fragile)
#
# USAGE:
#   Host-side (Linux host with CAP_LINUX_IMMUTABLE):
#     sudo bash src/scripts/apply-immutability.sh /path/to/workspace
#   Or from the host against a named volume:
#     WORKSPACE=/var/lib/docker/volumes/agent-workspace/_data
#     sudo bash src/scripts/apply-immutability.sh "$WORKSPACE"
#
# ARGS:
#   $1  Workspace root path (default: current directory)

set -euo pipefail

WORKSPACE_ROOT="${1:-.}"

echo "[immutability] Starting chattr +i pass over boundary-config files in: $WORKSPACE_ROOT" >&2
echo "[immutability] MUST run from host (requires CAP_LINUX_IMMUTABLE; not available in-container)." >&2

# Verify we're not running inside the devcontainer (cap_drop:ALL removes the needed capability).
# Heuristic: check if the process effective capabilities include LINUX_IMMUTABLE (cap 9).
# If running as root on the host this should be fine; if not, chattr will fail and we catch it.

# CANONICAL boundary-config files (SPEC-05 section 5 + section 6, one authoritative list).
# Any change here MUST be reflected in the section 5 edits glob and the section 7 hook patterns.
BOUNDARY_FILES=(
  "${WORKSPACE_ROOT}/.vscode/settings.json"
  "${WORKSPACE_ROOT}/.vscode/tasks.json"
  "${WORKSPACE_ROOT}/.vscode/mcp.json"
  "${WORKSPACE_ROOT}/.devcontainer/devcontainer.json"
  "${WORKSPACE_ROOT}/.devcontainer/docker-compose.yml"
  "${WORKSPACE_ROOT}/AGENTS.md"
  "${WORKSPACE_ROOT}/.github/copilot-instructions.md"
  "${WORKSPACE_ROOT}/.claude/settings.json"
)

BOUNDARY_DIRS=(
  "${WORKSPACE_ROOT}/.git/hooks"
  "${WORKSPACE_ROOT}/.github/hooks"
)

HOOK_SCRIPT="${WORKSPACE_ROOT}/.github/hooks/pretooluse.sh"

# Phase 1: apply chattr +i
echo "[immutability] Phase 1: applying chattr +i..."

for f in "${BOUNDARY_FILES[@]}"; do
  if [ -f "$f" ]; then
    if chattr +i "$f" 2>/dev/null; then
      echo "[immutability]   chattr +i OK: $f" >&2
    else
      echo "[immutability]   chattr +i FAILED (EPERM?): $f - check CAP_LINUX_IMMUTABLE" >&2
    fi
  else
    echo "[immutability]   SKIP (not found): $f" >&2
  fi
done

for d in "${BOUNDARY_DIRS[@]}"; do
  if [ -d "$d" ]; then
    find "$d" -type f | while read -r f; do
      if chattr +i "$f" 2>/dev/null; then
        echo "[immutability]   chattr +i OK: $f" >&2
      else
        echo "[immutability]   chattr +i FAILED (EPERM?): $f - check CAP_LINUX_IMMUTABLE" >&2
      fi
    done
  else
    echo "[immutability]   SKIP dir (not found): $d" >&2
  fi
done

if [ -f "$HOOK_SCRIPT" ]; then
  if chattr +i "$HOOK_SCRIPT" 2>/dev/null; then
    echo "[immutability]   chattr +i OK: $HOOK_SCRIPT" >&2
  else
    echo "[immutability]   chattr +i FAILED (EPERM?): $HOOK_SCRIPT - check CAP_LINUX_IMMUTABLE" >&2
  fi
fi

echo "[immutability] Phase 2: lsattr verification (position-independent 'i' flag check)..."

# OI-11-E: position-independent lsattr parsing.
# lsattr output: "<flags> <filename>" where flags is a string of characters.
# We extract the flags field (field 1) and check if 'i' appears anywhere in it.
# This is correct across kernel versions (the 'i' position varies).
_verify_immutable() {
  local f="$1"
  if [ ! -f "$f" ]; then
    echo "[immutability]   SKIP (not found): $f" >&2
    return 0
  fi
  local lsattr_output
  lsattr_output=$(lsattr "$f" 2>/dev/null || echo "")
  if [ -z "$lsattr_output" ]; then
    echo "[immutability]   WARN: lsattr returned empty for $f (filesystem may not support extended attrs)" >&2
    return 1
  fi
  # Extract the flags string (first field before the filename).
  # OI-11-E: use awk to get field 1, then grep for 'i' anywhere in the string.
  local flags_field
  flags_field=$(echo "$lsattr_output" | awk '{print $1}')
  if echo "$flags_field" | grep -q 'i'; then
    echo "[immutability]   OK (immutable bit set): $f  flags='$flags_field'" >&2
    return 0
  else
    echo "[immutability]   FAIL (immutable bit NOT set): $f  flags='$flags_field'" >&2
    return 1
  fi
}

VERIFY_FAILED=0

for f in "${BOUNDARY_FILES[@]}"; do
  if ! _verify_immutable "$f"; then
    VERIFY_FAILED=1
  fi
done

for d in "${BOUNDARY_DIRS[@]}"; do
  if [ -d "$d" ]; then
    find "$d" -type f | while read -r f; do
      if ! _verify_immutable "$f"; then
        VERIFY_FAILED=1
      fi
    done
  fi
done

if [ -f "$HOOK_SCRIPT" ]; then
  if ! _verify_immutable "$HOOK_SCRIPT"; then
    VERIFY_FAILED=1
  fi
fi

if [ "$VERIFY_FAILED" -eq 1 ]; then
  echo "" >&2
  echo "[immutability] FATAL: chattr +i verification failed on one or more boundary-config files." >&2
  echo "[immutability] Root causes:" >&2
  echo "[immutability]   (a) Running inside the devcontainer (cap_drop:ALL removes CAP_LINUX_IMMUTABLE)." >&2
  echo "[immutability]   (b) Filesystem does not support the immutable flag (e.g. tmpfs, some overlayfs)." >&2
  echo "[immutability]   (c) Not running as root / no CAP_LINUX_IMMUTABLE in effective set." >&2
  echo "[immutability] FALLBACK: mount boundary-config files as read-only volumes instead (PREFERRED)." >&2
  echo "[immutability] See docker-compose.yml for the read-only mount configuration." >&2
  echo "[immutability] PRIMARY CONTROL (hook + deny-glob + managed config) still holds without chattr." >&2
  exit 1
fi

echo "[immutability] All boundary-config files verified immutable." >&2
echo "[immutability] OI-11-E (position-independent lsattr): CONFIRMED." >&2
exit 0
