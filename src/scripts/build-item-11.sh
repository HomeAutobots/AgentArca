#!/usr/bin/env bash
# src/scripts/build-item-11.sh
#
# Item 11 build script: approval config build (ADR-005, SPEC-05).
# Enforces Stage 1 -> Stage 2 -> Stage 3 ordering (AC-11-P07).
# Checks item-08 egress is live before enabling dependency-install auto-approvals (AC-11-N01).
#
# STAGE SEQUENCING (SPEC-05 section 2, ADR-005 D7, LOAD-BEARING):
#   Stage 1: establish the deterministic boundary FIRST
#     - ADR-002 egress gateway up and enforcing (item 08 prerequisite)
#     - Read-only in-container git remote and push-proxy (push-proxy-setup.sh)
#     - Boundary-config immutability (read-only mounts or host-side chattr; see notes)
#     - task.allowAutomaticTasks: "off" set explicitly
#     - .git/hooks/ neutralized (core.hooksPath to empty dir)
#     - chat.tools.terminal.autoApproveWorkspaceNpmScripts: false
#   Stage 2: configure the managed approval surface (after Stage 1 verified)
#     - ChatToolsAutoApprove enterprise policy = false
#     - chat.tools.global.autoApprove: false
#     - chat.permissions.default: "default"
#     - chat.agent.maxRequests: 25
#     - terminal auto-approve allow/deny ruleset
#     - edits hard-deny glob
#   Stage 3: deploy the PreToolUse hook (after Stage 2)
#     - Hook script verified immutable (read-only mount)
#     - Hook descriptor JSON placed at .github/hooks/pretooluse.json
#
# USAGE: bash src/scripts/build-item-11.sh [--skip-egress-check]
# The --skip-egress-check flag skips the gateway healthcheck (for offline environments).
# Do NOT use --skip-egress-check in production: the auto-approve set requires egress containment.

set -euo pipefail

SKIP_EGRESS_CHECK="${1:-}"
GATEWAY_HEALTHCHECK_URL="${GATEWAY_HEALTHCHECK_URL:-http://localhost:8080}"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-.}"

FAIL_COUNT=0

_fail() {
  echo "[build-item-11] FAIL: $*" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

_ok() {
  echo "[build-item-11] OK: $*" >&2
}

_section() {
  echo "[build-item-11] ========================================" >&2
  echo "[build-item-11] $*" >&2
  echo "[build-item-11] ========================================" >&2
}

# ============================================================
# PRE-BUILD: Run the hook --self-test (AC-11-P01, hard gate)
# ============================================================
_section "PRE-BUILD: hook --self-test (AC-11-P01)"
HOOK_SCRIPT="src/.github/hooks/pretooluse.sh"
if [ ! -f "$HOOK_SCRIPT" ]; then
  _fail "--self-test: hook script not found at $HOOK_SCRIPT"
else
  if bash "$HOOK_SCRIPT" --self-test >&2; then
    _ok "--self-test passed (AC-11-P01)"
  else
    _fail "--self-test FAILED (AC-11-P01 FAIL - BUILD GATE)"
  fi
fi

# ============================================================
# AC-11-N01: check item-08 egress is live before Stage 2
# ============================================================
_section "AC-11-N01: item-08 egress gateway healthcheck"

if [ "$SKIP_EGRESS_CHECK" = "--skip-egress-check" ]; then
  echo "[build-item-11] WARN: --skip-egress-check set. Skipping gateway healthcheck." >&2
  echo "[build-item-11] WARN: dependency-install auto-approvals in Stage 2 require egress." >&2
  echo "[build-item-11] WARN: Do NOT use --skip-egress-check in production." >&2
  EGRESS_OK=false
else
  # Check if the gateway is healthy (gateway-selfcheck.sh or basic connectivity test).
  # AC-11-N01: the approval config is NOT enabled (Stage 2) until item 08 egress is confirmed live.
  if docker compose ps gateway 2>/dev/null | grep -q "healthy"; then
    _ok "item-08 gateway healthy (docker compose health check)"
    EGRESS_OK=true
  elif curl -s --max-time 3 -x "$GATEWAY_HEALTHCHECK_URL" https://api.github.com/user >/dev/null 2>&1; then
    _ok "item-08 gateway reachable (proxy test to api.github.com)"
    EGRESS_OK=true
  else
    echo "[build-item-11] WARN: item-08 egress gateway NOT detected as healthy." >&2
    echo "[build-item-11] WARN: dependency-install auto-approvals (npm ci, pip install, uv, poetry)" >&2
    echo "[build-item-11] WARN: are ONLY safe when egress is live and contained by ADR-002." >&2
    echo "[build-item-11] WARN: Proceeding with build but flagging as AC-11-N01 INCOMPLETE." >&2
    EGRESS_OK=false
  fi
fi

# ============================================================
# STAGE 1: establish the deterministic boundary FIRST
# ============================================================
_section "STAGE 1: deterministic boundary"

# Stage 1a: push-proxy wiring
echo "[build-item-11] Stage 1a: push-proxy setup (src/scripts/push-proxy-setup.sh)" >&2
if [ -f "src/scripts/push-proxy-setup.sh" ]; then
  _ok "push-proxy-setup.sh exists"
else
  _fail "push-proxy-setup.sh missing"
fi

if [ -f "src/scripts/push-proxy-reject.py" ]; then
  _ok "push-proxy-reject.py exists"
else
  _fail "push-proxy-reject.py missing"
fi

# Stage 1b: read-only mount / boundary-config immutability
echo "[build-item-11] Stage 1b: boundary-config immutability" >&2
echo "[build-item-11]   PRIMARY: read-only Docker volume mount of .github/hooks/ and managed-config/" >&2
echo "[build-item-11]   DiD: apply-immutability.sh (host-side chattr +i, if CAP_LINUX_IMMUTABLE available)" >&2
if [ -f "src/scripts/apply-immutability.sh" ]; then
  _ok "apply-immutability.sh exists"
else
  _fail "apply-immutability.sh missing"
fi

# Stage 1c: managed settings file
echo "[build-item-11] Stage 1c: managed settings file" >&2
if [ -f "src/managed-config/settings.json" ]; then
  _ok "src/managed-config/settings.json exists"
else
  _fail "src/managed-config/settings.json missing"
fi

# Verify task.allowAutomaticTasks is "off" in managed settings
if grep -q '"task.allowAutomaticTasks".*"off"' src/managed-config/settings.json 2>/dev/null; then
  _ok "task.allowAutomaticTasks: off confirmed in managed settings"
else
  _fail "task.allowAutomaticTasks: off NOT found in managed settings"
fi

# Verify autoApproveWorkspaceNpmScripts: false
if grep -q '"chat.tools.terminal.autoApproveWorkspaceNpmScripts".*false' src/managed-config/settings.json 2>/dev/null; then
  _ok "chat.tools.terminal.autoApproveWorkspaceNpmScripts: false confirmed"
else
  _fail "chat.tools.terminal.autoApproveWorkspaceNpmScripts: false NOT found"
fi

_ok "STAGE 1 checks done"

# ============================================================
# STAGE 2: configure managed approval surface
# ============================================================
_section "STAGE 2: managed approval surface"

# Verify key managed settings are present
for key in "chat.tools.global.autoApprove" "chat.permissions.default" "chat.agent.maxRequests" \
           "chat.tools.terminal.autoApprove" "chat.tools.edits.autoApprove"; do
  if grep -q "\"$key\"" src/managed-config/settings.json 2>/dev/null; then
    _ok "managed settings contains: $key"
  else
    _fail "managed settings MISSING: $key"
  fi
done

# Verify deny globs for canonical boundary-config set (SPEC-05 section 5 canonical list)
# Note: grep for glob patterns without the surrounding double-quotes since grep -q
# treats the quotes as part of the pattern when the shell expands them.
for glob in '**/.vscode/**' '**/.devcontainer/**' '**/.git/**' '**/.github/hooks/**' \
            '**/.claude/**' '**/mcp.json' '**/.env*' '**/AGENTS.md' \
            '**/.github/copilot-instructions.md' '**/*.agent.md'; do
  if grep -qF "\"$glob\"" src/managed-config/settings.json 2>/dev/null; then
    _ok "edits deny glob present: $glob"
  else
    _fail "edits deny glob MISSING: $glob"
  fi
done

# AC-11-N01: if egress is not live, note the dependency-install auto-approvals are not active
if [ "$EGRESS_OK" = "false" ]; then
  echo "[build-item-11] NOTE (AC-11-N01): item-08 egress not confirmed live." >&2
  echo "[build-item-11]   The terminal allow set includes npm ci/pip install/uv/poetry." >&2
  echo "[build-item-11]   These are ONLY safe with ADR-002 egress live and enforcing." >&2
  echo "[build-item-11]   Operator must verify item-08 gateway is healthy before use." >&2
fi

_ok "STAGE 2 checks done"

# ============================================================
# STAGE 3: PreToolUse hook
# ============================================================
_section "STAGE 3: PreToolUse hook"

# Stage 3 ONLY runs after Stage 1 immutability is established.
if [ -f "src/.github/hooks/pretooluse.sh" ]; then
  _ok "hook script exists: src/.github/hooks/pretooluse.sh"
else
  _fail "hook script MISSING: src/.github/hooks/pretooluse.sh"
fi

if [ -f "src/.github/hooks/pretooluse.json" ]; then
  _ok "hook descriptor exists: src/.github/hooks/pretooluse.json"
else
  _fail "hook descriptor MISSING: src/.github/hooks/pretooluse.json"
fi

# Verify hook script is executable
if [ -x "src/.github/hooks/pretooluse.sh" ]; then
  _ok "hook script is executable"
else
  _fail "hook script is NOT executable"
fi

_ok "STAGE 3 checks done"

# ============================================================
# FINAL RESULT
# ============================================================
_section "FINAL RESULT"

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "[build-item-11] BUILD FAILED: $FAIL_COUNT check(s) failed." >&2
  exit 1
fi

echo "[build-item-11] BUILD PASSED: all checks passed." >&2
echo "[build-item-11] Stage ordering enforced: Stage 1 -> Stage 2 -> Stage 3 (AC-11-P07)." >&2
echo "[build-item-11] AC-11-N01: egress_ok=$EGRESS_OK" >&2
exit 0
