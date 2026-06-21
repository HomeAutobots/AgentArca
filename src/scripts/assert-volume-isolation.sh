#!/usr/bin/env bash
# src/scripts/assert-volume-isolation.sh
# Verifies per-profile token-store and cache volume isolation (SPEC-21 AC-21-N05, ADR-008 D6).
# This is an OFFLINE structural assertion (no live credentials needed).
#
# WHAT IT CHECKS:
#   1. Each profile's devcontainer service mounts ONLY its own token-store volume.
#   2. No cross-mounting: copilot service does NOT mount claude-token-store or codex-token-store.
#   3. Per-profile credential env vars are scoped: absence-of-declaration prevents bleed.
#   4. The SQUID_AGENT_FRAGMENT is set per-profile.
#   5. Per-profile cache volumes: each profile uses its own agent-npm-cache-{profile} and
#      agent-cache-{profile}. No profile mounts another profile's cache volume (FIX-3, R-m).
#
# USAGE (run from repo root):
#   bash src/scripts/assert-volume-isolation.sh
#
# EXIT CODES:
#   0 - all isolation assertions pass
#   1 - at least one isolation assertion failed
#
# SOURCE: SPEC-21 section 4 (AC-21-N05), ADR-008 D6 / R-m.

set -euo pipefail

COMPOSE_FILE="docker-compose.yml"
FAILED=0

pass() { echo "[assert-vol-iso] PASS: $*"; }
fail() { echo "[assert-vol-iso] FAIL: $*" >&2; FAILED=1; }

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "[assert-vol-iso] ERROR: docker-compose.yml not found. Run from repo root." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "[assert-vol-iso] ERROR: docker not found. Docker is required to resolve compose config." >&2
    exit 1
fi

echo "[assert-vol-iso] === Volume isolation assertions (SPEC-21 AC-21-N05) ==="
echo "[assert-vol-iso] Resolving compose config for each profile..."

# ============================================================
# Helper: get the resolved compose config for a profile
# ============================================================
get_profile_config() {
    local profile="$1"
    docker compose --profile "$profile" config 2>/dev/null
}

# ============================================================
# ASSERTION A-1: Copilot profile mounts copilot-token-store, NOT claude or codex stores
# ============================================================
echo "[assert-vol-iso] --- A-1: Copilot profile token-store isolation ---"
COPILOT_CONFIG=$(get_profile_config copilot)

if echo "$COPILOT_CONFIG" | grep -q "copilot-token-store"; then
    pass "copilot profile includes copilot-token-store"
else
    fail "copilot profile does NOT include copilot-token-store"
fi

if echo "$COPILOT_CONFIG" | grep -q "claude-token-store"; then
    fail "copilot profile CROSS-MOUNTS claude-token-store (isolation violation)"
else
    pass "copilot profile does NOT cross-mount claude-token-store"
fi

if echo "$COPILOT_CONFIG" | grep -q "codex-token-store"; then
    fail "copilot profile CROSS-MOUNTS codex-token-store (isolation violation)"
else
    pass "copilot profile does NOT cross-mount codex-token-store"
fi

# ============================================================
# ASSERTION A-2: Claude profile mounts claude-token-store, NOT copilot or codex stores
# ============================================================
echo "[assert-vol-iso] --- A-2: Claude profile token-store isolation ---"
CLAUDE_CONFIG=$(get_profile_config claude)

if echo "$CLAUDE_CONFIG" | grep -q "claude-token-store"; then
    pass "claude profile includes claude-token-store"
else
    fail "claude profile does NOT include claude-token-store"
fi

if echo "$CLAUDE_CONFIG" | grep -q "copilot-token-store"; then
    fail "claude profile CROSS-MOUNTS copilot-token-store (isolation violation)"
else
    pass "claude profile does NOT cross-mount copilot-token-store"
fi

if echo "$CLAUDE_CONFIG" | grep -q "codex-token-store"; then
    fail "claude profile CROSS-MOUNTS codex-token-store (isolation violation)"
else
    pass "claude profile does NOT cross-mount codex-token-store"
fi

# ============================================================
# ASSERTION A-3: Codex profile mounts codex-token-store, NOT copilot or claude stores
# ============================================================
echo "[assert-vol-iso] --- A-3: Codex profile token-store isolation ---"
CODEX_CONFIG=$(get_profile_config codex)

if echo "$CODEX_CONFIG" | grep -q "codex-token-store"; then
    pass "codex profile includes codex-token-store"
else
    fail "codex profile does NOT include codex-token-store"
fi

if echo "$CODEX_CONFIG" | grep -q "copilot-token-store"; then
    fail "codex profile CROSS-MOUNTS copilot-token-store (isolation violation)"
else
    pass "codex profile does NOT cross-mount copilot-token-store"
fi

if echo "$CODEX_CONFIG" | grep -q "claude-token-store"; then
    fail "codex profile CROSS-MOUNTS claude-token-store (isolation violation)"
else
    pass "codex profile does NOT cross-mount claude-token-store"
fi

# ============================================================
# ASSERTION B: Credential env-var scoping (absence-of-declaration isolation)
# ============================================================
echo "[assert-vol-iso] --- B: Credential env-var scoping (absence-of-declaration) ---"

# Copilot: ANTHROPIC_API_KEY and OPENAI_API_KEY must NOT appear
if echo "$COPILOT_CONFIG" | grep -q "ANTHROPIC_API_KEY"; then
    fail "copilot profile contains ANTHROPIC_API_KEY declaration (credential bleed risk)"
else
    pass "copilot profile does NOT declare ANTHROPIC_API_KEY"
fi
if echo "$COPILOT_CONFIG" | grep -q "OPENAI_API_KEY"; then
    fail "copilot profile contains OPENAI_API_KEY declaration (credential bleed risk)"
else
    pass "copilot profile does NOT declare OPENAI_API_KEY"
fi

# Claude: OPENAI_API_KEY must NOT appear; ANTHROPIC_API_KEY must appear
if echo "$CLAUDE_CONFIG" | grep -q "OPENAI_API_KEY"; then
    fail "claude profile contains OPENAI_API_KEY declaration (credential bleed risk)"
else
    pass "claude profile does NOT declare OPENAI_API_KEY"
fi
if echo "$CLAUDE_CONFIG" | grep -q "ANTHROPIC_API_KEY"; then
    pass "claude profile declares ANTHROPIC_API_KEY (correct)"
else
    fail "claude profile does NOT declare ANTHROPIC_API_KEY (missing credential wiring)"
fi

# Codex: ANTHROPIC_API_KEY must NOT appear; OPENAI_API_KEY must appear
if echo "$CODEX_CONFIG" | grep -q "ANTHROPIC_API_KEY"; then
    fail "codex profile contains ANTHROPIC_API_KEY declaration (credential bleed risk)"
else
    pass "codex profile does NOT declare ANTHROPIC_API_KEY"
fi
if echo "$CODEX_CONFIG" | grep -q "OPENAI_API_KEY"; then
    pass "codex profile declares OPENAI_API_KEY (correct)"
else
    fail "codex profile does NOT declare OPENAI_API_KEY (missing credential wiring)"
fi

# ============================================================
# ASSERTION C: SQUID_AGENT_FRAGMENT per profile
# ============================================================
echo "[assert-vol-iso] --- C: SQUID_AGENT_FRAGMENT per profile ---"

if echo "$COPILOT_CONFIG" | grep -q "SQUID_AGENT_FRAGMENT.*copilot"; then
    pass "copilot profile sets SQUID_AGENT_FRAGMENT=copilot.conf"
else
    fail "copilot profile does NOT set SQUID_AGENT_FRAGMENT=copilot.conf"
fi
if echo "$CLAUDE_CONFIG" | grep -q "SQUID_AGENT_FRAGMENT.*claude"; then
    pass "claude profile sets SQUID_AGENT_FRAGMENT=claude.conf"
else
    fail "claude profile does NOT set SQUID_AGENT_FRAGMENT=claude.conf"
fi
if echo "$CODEX_CONFIG" | grep -q "SQUID_AGENT_FRAGMENT.*codex"; then
    pass "codex profile sets SQUID_AGENT_FRAGMENT=codex.conf"
else
    fail "codex profile does NOT set SQUID_AGENT_FRAGMENT=codex.conf"
fi

# ============================================================
# ASSERTION D: Workspace volume is shared (the only cross-profile volume)
# ============================================================
echo "[assert-vol-iso] --- D: Workspace is the only cross-profile shared volume ---"

for profile in copilot claude codex; do
    CONFIG=$(get_profile_config "$profile")
    if echo "$CONFIG" | grep -q "workspace:"; then
        pass "${profile} profile mounts workspace volume"
    else
        fail "${profile} profile does NOT mount workspace volume"
    fi
done

# ============================================================
# ASSERTION E: Per-profile cache volumes (FIX-3, R-m cross-profile cache isolation)
# Each profile must mount ONLY its own named cache volumes.
# No profile may mount another profile's npm or general cache.
# ============================================================
echo "[assert-vol-iso] --- E: Per-profile cache volume isolation (FIX-3, R-m) ---"

# Copilot profile: must use copilot caches; must NOT use claude or codex caches
if echo "$COPILOT_CONFIG" | grep -q "agent-npm-cache-copilot"; then
    pass "copilot profile includes agent-npm-cache-copilot"
else
    fail "copilot profile does NOT include agent-npm-cache-copilot (shared cache volumes violate R-m)"
fi
if echo "$COPILOT_CONFIG" | grep -q "agent-cache-copilot"; then
    pass "copilot profile includes agent-cache-copilot"
else
    fail "copilot profile does NOT include agent-cache-copilot (shared cache volumes violate R-m)"
fi
if echo "$COPILOT_CONFIG" | grep -qE "agent-npm-cache-claude|agent-npm-cache-codex"; then
    fail "copilot profile CROSS-MOUNTS another profile's npm cache (isolation violation)"
else
    pass "copilot profile does NOT cross-mount claude or codex npm cache"
fi
if echo "$COPILOT_CONFIG" | grep -qE "agent-cache-claude|agent-cache-codex"; then
    fail "copilot profile CROSS-MOUNTS another profile's general cache (isolation violation)"
else
    pass "copilot profile does NOT cross-mount claude or codex general cache"
fi

# Claude profile: must use claude caches; must NOT use copilot or codex caches
if echo "$CLAUDE_CONFIG" | grep -q "agent-npm-cache-claude"; then
    pass "claude profile includes agent-npm-cache-claude"
else
    fail "claude profile does NOT include agent-npm-cache-claude (shared cache volumes violate R-m)"
fi
if echo "$CLAUDE_CONFIG" | grep -q "agent-cache-claude"; then
    pass "claude profile includes agent-cache-claude"
else
    fail "claude profile does NOT include agent-cache-claude (shared cache volumes violate R-m)"
fi
if echo "$CLAUDE_CONFIG" | grep -qE "agent-npm-cache-copilot|agent-npm-cache-codex"; then
    fail "claude profile CROSS-MOUNTS another profile's npm cache (isolation violation)"
else
    pass "claude profile does NOT cross-mount copilot or codex npm cache"
fi
if echo "$CLAUDE_CONFIG" | grep -qE "agent-cache-copilot|agent-cache-codex"; then
    fail "claude profile CROSS-MOUNTS another profile's general cache (isolation violation)"
else
    pass "claude profile does NOT cross-mount copilot or codex general cache"
fi

# Codex profile: must use codex caches; must NOT use copilot or claude caches
if echo "$CODEX_CONFIG" | grep -q "agent-npm-cache-codex"; then
    pass "codex profile includes agent-npm-cache-codex"
else
    fail "codex profile does NOT include agent-npm-cache-codex (shared cache volumes violate R-m)"
fi
if echo "$CODEX_CONFIG" | grep -q "agent-cache-codex"; then
    pass "codex profile includes agent-cache-codex"
else
    fail "codex profile does NOT include agent-cache-codex (shared cache volumes violate R-m)"
fi
if echo "$CODEX_CONFIG" | grep -qE "agent-npm-cache-copilot|agent-npm-cache-claude"; then
    fail "codex profile CROSS-MOUNTS another profile's npm cache (isolation violation)"
else
    pass "codex profile does NOT cross-mount copilot or claude npm cache"
fi
if echo "$CODEX_CONFIG" | grep -qE "agent-cache-copilot|agent-cache-claude"; then
    fail "codex profile CROSS-MOUNTS another profile's general cache (isolation violation)"
else
    pass "codex profile does NOT cross-mount copilot or claude general cache"
fi

# ============================================================
# FINAL RESULT
# ============================================================
echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "[assert-vol-iso] === ALL ISOLATION ASSERTIONS PASSED ==="
    echo "[assert-vol-iso] Profile mutual exclusion (ADR-008 D6 / R-m) confirmed by static config analysis."
    exit 0
else
    echo "[assert-vol-iso] === ISOLATION ASSERTIONS FAILED ===" >&2
    echo "[assert-vol-iso] Review the FAIL lines above and fix docker-compose.yml." >&2
    exit 1
fi
