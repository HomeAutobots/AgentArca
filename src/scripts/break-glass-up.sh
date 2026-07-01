#!/usr/bin/env bash
# break-glass-up.sh <profile>
# Thin wrapper. Profile validation, venv check, loud warning, then delegates
# the guarded sequence (flock, refuse, audit, mint, compose) to _break_glass_up.py
# via the admin venv python (Python fcntl.flock; macOS-compatible).
set -euo pipefail

PROFILE="${1:-}"
ALLOWED_PROFILES=("copilot" "claude" "codex")

# Compute REPO_ROOT from this script's location: src/scripts/ -> repo root.
# Matches the _REPO_ROOT derivation in lifecycle.py:59.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VENV_PYTHON="${REPO_ROOT}/.venv-admin/bin/python"

usage() { echo "Usage: $0 <profile>   (profile: copilot | claude | codex)" >&2; exit 1; }

[[ -z "${PROFILE}" ]] && usage

# Validate profile name (injection guard; bash layer catches obvious mistakes early).
_valid=0
for _p in "${ALLOWED_PROFILES[@]}"; do
  [[ "${PROFILE}" == "${_p}" ]] && _valid=1 && break
done
[[ "${_valid}" -eq 0 ]] && { echo "ERROR: unknown profile '${PROFILE}'" >&2; exit 1; }

# Require the admin venv python (fail closed if not present).
if [[ ! -x "${VENV_PYTHON}" ]]; then
  echo "ERROR: admin venv not found at ${VENV_PYTHON}." >&2
  echo "ERROR: Run 'build-admin.sh --init' to set up the venv, then retry break-glass." >&2
  exit 1
fi

echo "[break-glass] WARNING: bypassing the portal UI. This action is audited."
echo "[break-glass] Profile: ${PROFILE}"
echo "[break-glass] Delegating guarded sequence to Python (fcntl.flock; macOS-safe)..."

# Delegate: one Python invocation owns the lifecycle lock for the entire
# flock -> refuse -> audit -> mint -> compose sequence.
exec "${VENV_PYTHON}" "${SCRIPT_DIR}/_break_glass_up.py" "${PROFILE}" "${REPO_ROOT}"
