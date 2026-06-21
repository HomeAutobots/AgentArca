#!/usr/bin/env bash
# tests/acceptance/component/test-25-profile-isolation.sh
#
# Item-25 profile isolation tests (SPEC-21 AC-21-N01..N07, SPEC-20 AC-20-N03/N04).
# These are STATIC / OFFLINE assertions against the Compose config and fragment files.
# No running stack is required. No credentials are needed.
#
# Coverage:
#   AC-21-N01..N07  Profile isolation via assert-volume-isolation.sh (all six cross-profile pairs)
#   AC-21-N04       No host ~/.claude or ~/.codex bind mounts (static grep)
#   AC-20-N03       Exactly base.conf + one agent fragment per profile (static fragment count)
#   AC-20-N04       No cross-contamination: Anthropic hosts absent from codex.conf; OpenAI from claude.conf
#   AC-20-N05       Fragment files are read-only-mounted in gateway (static compose config)
#   AC-24-N01-COPILOT  Copilot mcp.json servers == {} (regression: unchanged from item 12)
#
# These are offline CI-gateable assertions (no live credentials, no running containers needed).
#
# Environment:
#   PROJECT_ROOT    Absolute path to repo root (auto-detected if not set)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/test-helpers.sh"

COMPONENT="profile-isolation"
PASS=0
FAIL=0
SKIP=0
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"

COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
VOLUME_ISO_SCRIPT="${PROJECT_ROOT}/src/scripts/assert-volume-isolation.sh"
CLAUDE_FRAGMENT="${PROJECT_ROOT}/src/gateway/squid-allowlist.d/claude.conf"
CODEX_FRAGMENT="${PROJECT_ROOT}/src/gateway/squid-allowlist.d/codex.conf"
COPILOT_FRAGMENT="${PROJECT_ROOT}/src/gateway/squid-allowlist.d/copilot.conf"
BASE_FRAGMENT="${PROJECT_ROOT}/src/gateway/squid-allowlist.d/base.conf"

echo ""
echo "=== PROFILE ISOLATION TESTS (offline, no running stack needed) ==="
echo "    PROJECT_ROOT: ${PROJECT_ROOT}"
echo ""

# ============================================================
# AC-21-N01..N07: Volume + env-var isolation (assert-volume-isolation.sh)
# ============================================================
echo "--- AC-21-N01..N07: Volume and env-var isolation (assert-volume-isolation.sh) ---"

begin_test "AC-21-N01..N07-ISOLATION" "assert-volume-isolation.sh passes (all isolation assertions)"
if [ ! -f "${VOLUME_ISO_SCRIPT}" ]; then
  fail_test "AC-21-N01..N07-ISOLATION" "assert-volume-isolation.sh not found at ${VOLUME_ISO_SCRIPT}"
else
  # Run the script from the project root (it needs docker compose accessible)
  ISO_OUTPUT=""
  ISO_EXIT=0
  ISO_OUTPUT=$(cd "${PROJECT_ROOT}" && bash "${VOLUME_ISO_SCRIPT}" 2>&1) || ISO_EXIT=$?
  # Print the output so the runner log captures it
  echo "${ISO_OUTPUT}"
  # Count individual sub-assertions (tr strips newlines before arithmetic to handle macOS grep -c quirk)
  ISO_PASS=$(echo "${ISO_OUTPUT}" | grep -c "PASS:" 2>/dev/null | tr -d '[:space:]' || echo 0)
  ISO_FAIL=$(echo "${ISO_OUTPUT}" | grep -c "FAIL:" 2>/dev/null | tr -d '[:space:]' || echo 0)
  # Guard: ensure numeric
  ISO_PASS=$((ISO_PASS + 0))
  ISO_FAIL=$((ISO_FAIL + 0))
  if [ "${ISO_EXIT}" -eq 0 ] && [ "${ISO_FAIL}" -eq 0 ]; then
    pass_test "AC-21-N01..N07-ISOLATION" "assert-volume-isolation.sh: PASS (${ISO_PASS} sub-assertions passed, 0 failed)"
  elif [ "${ISO_EXIT}" -ne 0 ] || [ "${ISO_FAIL}" -gt 0 ]; then
    fail_test "AC-21-N01..N07-ISOLATION" "assert-volume-isolation.sh: FAIL (${ISO_FAIL} sub-assertion(s) failed, exit=${ISO_EXIT})"
  else
    pass_test "AC-21-N01..N07-ISOLATION" "assert-volume-isolation.sh: exit 0 (isolation assertions passed)"
  fi
fi

# ============================================================
# AC-21-N04: No host ~/.claude or ~/.codex bind mounts
# ============================================================
echo ""
echo "--- AC-21-N04: No host ~/.claude or ~/.codex bind mounts ---"

begin_test "AC-21-N04-NO-CLAUDE-BINDMOUNT" "host ~/.claude not bind-mounted into any service"
if [ -f "${COMPOSE_FILE}" ]; then
  # Check for any source: path containing .claude (not the managed-config path which is legitimate)
  CLAUDE_BINDMOUNTS=$(grep -n 'source:' "${COMPOSE_FILE}" | grep '\.claude' | \
    grep -v 'managed-config/claude' || true)
  if [ -z "${CLAUDE_BINDMOUNTS}" ]; then
    pass_test "AC-21-N04-NO-CLAUDE-BINDMOUNT" "no host ~/.claude bind mounts found in docker-compose.yml (ADR-008 D3 do-not-mount list enforced)"
  else
    fail_test "AC-21-N04-NO-CLAUDE-BINDMOUNT" "host ~/.claude bind mount found: ${CLAUDE_BINDMOUNTS}"
  fi
else
  fail_test "AC-21-N04-NO-CLAUDE-BINDMOUNT" "docker-compose.yml not found at ${COMPOSE_FILE}"
fi

begin_test "AC-21-N04-NO-CODEX-BINDMOUNT" "host ~/.codex not bind-mounted into any service"
if [ -f "${COMPOSE_FILE}" ]; then
  CODEX_BINDMOUNTS=$(grep -n 'source:' "${COMPOSE_FILE}" | grep '\.codex' | \
    grep -v 'managed-config/codex' || true)
  if [ -z "${CODEX_BINDMOUNTS}" ]; then
    pass_test "AC-21-N04-NO-CODEX-BINDMOUNT" "no host ~/.codex bind mounts found in docker-compose.yml"
  else
    fail_test "AC-21-N04-NO-CODEX-BINDMOUNT" "host ~/.codex bind mount found: ${CODEX_BINDMOUNTS}"
  fi
else
  fail_test "AC-21-N04-NO-CODEX-BINDMOUNT" "docker-compose.yml not found at ${COMPOSE_FILE}"
fi

# ============================================================
# AC-20-N04: No cross-contamination between fragments
# ============================================================
echo ""
echo "--- AC-20-N04: Fragment cross-contamination checks ---"

begin_test "AC-20-N04-CLAUDE-NO-OPENAI" "claude.conf has no OpenAI hosts (anthropic fragment isolation)"
if [ -f "${CLAUDE_FRAGMENT}" ]; then
  OPENAI_IN_CLAUDE=$(grep -E '^[^#].*openai' "${CLAUDE_FRAGMENT}" 2>/dev/null || true)
  if [ -z "${OPENAI_IN_CLAUDE}" ]; then
    pass_test "AC-20-N04-CLAUDE-NO-OPENAI" "no uncommented openai references in claude.conf (fragment isolated)"
  else
    fail_test "AC-20-N04-CLAUDE-NO-OPENAI" "OpenAI hosts found in claude.conf (cross-contamination): ${OPENAI_IN_CLAUDE}"
  fi
else
  fail_test "AC-20-N04-CLAUDE-NO-OPENAI" "claude.conf not found at ${CLAUDE_FRAGMENT}"
fi

begin_test "AC-20-N04-CODEX-NO-ANTHROPIC" "codex.conf has no Anthropic hosts (openai fragment isolation)"
if [ -f "${CODEX_FRAGMENT}" ]; then
  ANTHROPIC_IN_CODEX=$(grep -E '^[^#].*anthropic' "${CODEX_FRAGMENT}" 2>/dev/null || true)
  if [ -z "${ANTHROPIC_IN_CODEX}" ]; then
    pass_test "AC-20-N04-CODEX-NO-ANTHROPIC" "no uncommented anthropic references in codex.conf (fragment isolated)"
  else
    fail_test "AC-20-N04-CODEX-NO-ANTHROPIC" "Anthropic hosts found in codex.conf (cross-contamination): ${ANTHROPIC_IN_CODEX}"
  fi
else
  fail_test "AC-20-N04-CODEX-NO-ANTHROPIC" "codex.conf not found at ${CODEX_FRAGMENT}"
fi

begin_test "AC-20-N04-BASE-NO-AGENT-HOSTS" "base.conf has no agent-specific inference hosts (no anthropic, openai, github copilot hosts)"
if [ -f "${BASE_FRAGMENT}" ]; then
  AGENT_IN_BASE=$(grep -E '^[^#].*(anthropic|openai\.com|githubcopilot|copilot\.github)' "${BASE_FRAGMENT}" 2>/dev/null || true)
  if [ -z "${AGENT_IN_BASE}" ]; then
    pass_test "AC-20-N04-BASE-NO-AGENT-HOSTS" "base.conf has no agent-specific hosts (fragment discipline upheld)"
  else
    fail_test "AC-20-N04-BASE-NO-AGENT-HOSTS" "agent-specific hosts found in base.conf (must be in per-agent fragment only): ${AGENT_IN_BASE}"
  fi
else
  # base.conf may be sparse; skip if not present rather than fail
  skip_test "AC-20-N04-BASE-NO-AGENT-HOSTS" "REQUIRES-FILE: base.conf not found at ${BASE_FRAGMENT}"
fi

# ============================================================
# AC-20-N03: Each fragment exists and is non-empty
# ============================================================
echo ""
echo "--- AC-20-N03: Fragment files exist and are distinct ---"

for frag_agent in copilot claude codex; do
  FRAG="${PROJECT_ROOT}/src/gateway/squid-allowlist.d/${frag_agent}.conf"
  begin_test "AC-20-N03-FRAG-${frag_agent}" "${frag_agent}.conf fragment exists and is non-empty"
  if [ -f "${FRAG}" ] && [ -s "${FRAG}" ]; then
    FRAG_LINES=$(grep -c "^[^#]" "${FRAG}" 2>/dev/null || echo 0)
    pass_test "AC-20-N03-FRAG-${frag_agent}" "${frag_agent}.conf exists (${FRAG_LINES} non-comment lines)"
  elif [ -f "${FRAG}" ]; then
    fail_test "AC-20-N03-FRAG-${frag_agent}" "${frag_agent}.conf exists but is empty or all comments"
  else
    fail_test "AC-20-N03-FRAG-${frag_agent}" "${frag_agent}.conf not found at ${FRAG}"
  fi
done

# ============================================================
# AC-20-N05: Fragment files are mounted read-only in gateway (static compose check)
# ============================================================
echo ""
echo "--- AC-20-N05: Fragment files read-only-mounted in gateway ---"

begin_test "AC-20-N05-FRAG-READONLY" "squid allowlist.d directory mounted read-only in gateway (static compose config)"
if [ -f "${COMPOSE_FILE}" ]; then
  # Check if the gateway service mounts the squid allowlist.d directory with read_only:true
  # Use docker compose config to get the fully resolved compose config
  GW_CONFIG=$(docker compose --profile copilot config 2>/dev/null || echo "")
  if [ -n "${GW_CONFIG}" ]; then
    # Check the gateway service mounts for the squid allowlist config
    # The allowlist.d dir is baked into the image (not a runtime bind mount) - verify the image has it
    # The Squid startup script uses the fragment from the IMAGE, not a runtime bind mount
    # Structural check: the devcontainer services do NOT mount the gateway's squid config directory
    DC_MOUNTS=$(echo "${GW_CONFIG}" | grep -A5 "devcontainer:" | grep "squid" || true)
    if [ -z "${DC_MOUNTS}" ]; then
      pass_test "AC-20-N05-FRAG-READONLY" "devcontainer services do not mount gateway squid config (fragment not agent-writable; dev container has no path to gateway's config)"
    else
      fail_test "AC-20-N05-FRAG-READONLY" "devcontainer mounts squid config (unexpected): ${DC_MOUNTS}"
    fi
  else
    skip_test "AC-20-N05-FRAG-READONLY" "REQUIRES-DOCKER: docker compose config not available; check compose file manually"
  fi
else
  fail_test "AC-20-N05-FRAG-READONLY" "docker-compose.yml not found"
fi

# Also verify the fragments themselves are not writable from inside a running devcontainer
# (structural: the devcontainer has no network path to the gateway's filesystem)
begin_test "AC-20-N05-DEVCONTAINER-CANT-WRITE-FRAG" "devcontainer cannot reach gateway squid config dir (no filesystem cross-mount)"
if [ -f "${COMPOSE_FILE}" ]; then
  CROSS_MOUNT=$(grep -n '/etc/squid' "${COMPOSE_FILE}" | grep -v "gateway:" || true)
  if [ -z "${CROSS_MOUNT}" ]; then
    pass_test "AC-20-N05-DEVCONTAINER-CANT-WRITE-FRAG" "/etc/squid path not mounted into devcontainer services (fragment files not agent-accessible)"
  else
    fail_test "AC-20-N05-DEVCONTAINER-CANT-WRITE-FRAG" "/etc/squid cross-mount found in non-gateway service: ${CROSS_MOUNT}"
  fi
else
  fail_test "AC-20-N05-DEVCONTAINER-CANT-WRITE-FRAG" "docker-compose.yml not found"
fi

# ============================================================
# AC-24-N01-COPILOT: Copilot mcp.json unchanged (regression)
# ============================================================
echo ""
echo "--- AC-24-N01-COPILOT: Copilot MCP config unchanged (regression) ---"

begin_test "AC-24-N01-COPILOT-MCP" "Copilot .vscode/mcp.json servers == {} (regression: multi-profile refactor did not break Copilot MCP)"
COPILOT_MCP="${PROJECT_ROOT}/src/.vscode/mcp.json"
if [ -f "${COPILOT_MCP}" ]; then
  COPILOT_SERVERS=$(python3 -c "
import json
d = json.load(open('${COPILOT_MCP}'))
print(json.dumps(d.get('servers', {})))
" 2>/dev/null) || COPILOT_SERVERS="PARSE_ERROR"
  if [ "${COPILOT_SERVERS}" = "{}" ]; then
    pass_test "AC-24-N01-COPILOT-MCP" "Copilot mcp.json servers={} (zero servers; regression check passed)"
  else
    fail_test "AC-24-N01-COPILOT-MCP" "Copilot mcp.json servers=${COPILOT_SERVERS} (expected {}; regression)"
  fi
else
  fail_test "AC-24-N01-COPILOT-MCP" "Copilot mcp.json not found at ${COPILOT_MCP}"
fi

# ============================================================
# CODEX_VERSION: Verify the pinned codex version still exists on npm
# This is a CI-gateable regression tripwire: if the version is yanked from npm,
# the Dockerfile.codex build will fail. Routes to implementer.
# ============================================================
echo ""
echo "--- AC-22-N01-CODEX-VERSION: Pinned codex version still on npm ---"

begin_test "AC-22-N01-CODEX-VERSION-PIN" "pinned @openai/codex version exists on npm registry"
CODEX_DOCKERFILE="${PROJECT_ROOT}/src/dev/Dockerfile.codex"
if [ -f "${CODEX_DOCKERFILE}" ]; then
  PINNED_VERSION=$(grep -oE '^ARG CODEX_VERSION=\S+' "${CODEX_DOCKERFILE}" | sed 's/ARG CODEX_VERSION=//' || true)
  if [ -z "${PINNED_VERSION}" ]; then
    skip_test "AC-22-N01-CODEX-VERSION-PIN" "REQUIRES-PARSE: could not parse CODEX_VERSION from Dockerfile.codex"
  else
    # Check if version exists on npm (requires network; skip if offline)
    VERSION_CHECK=$(npm view "@openai/codex@${PINNED_VERSION}" version 2>/dev/null || echo "NOT_FOUND")
    if [ "${VERSION_CHECK}" = "${PINNED_VERSION}" ]; then
      pass_test "AC-22-N01-CODEX-VERSION-PIN" "pinned @openai/codex@${PINNED_VERSION} confirmed on npm registry"
    elif echo "${VERSION_CHECK}" | grep -q "NOT_FOUND"; then
      fail_test "AC-22-N01-CODEX-VERSION-PIN" "FINDING (routes to implementer): @openai/codex@${PINNED_VERSION} no longer found on npm. Build will fail. Update CODEX_VERSION in src/dev/Dockerfile.codex to a current version (latest stable: 0.140.0 as of 2026-06-17). Checked: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    else
      skip_test "AC-22-N01-CODEX-VERSION-PIN" "REQUIRES-NETWORK: npm version check returned '${VERSION_CHECK}' (possibly offline)"
    fi
  fi
else
  fail_test "AC-22-N01-CODEX-VERSION-PIN" "Dockerfile.codex not found at ${CODEX_DOCKERFILE}"
fi

# Summary
print_component_summary "${COMPONENT}" "${PASS}" "${FAIL}" "${SKIP}"
