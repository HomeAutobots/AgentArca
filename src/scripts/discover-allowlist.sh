#!/usr/bin/env bash
# src/scripts/discover-allowlist.sh
# Empirical allowlist discovery procedure for per-agent allowlist fragments.
# SPEC-20 section 7: run this to observe SNIs for claude or codex profiles,
# then update the relevant allowlist fragment with the discovered hosts.
#
# USAGE:
#   bash src/scripts/discover-allowlist.sh claude    # discover for Claude Code profile
#   bash src/scripts/discover-allowlist.sh codex     # discover for Codex CLI profile
#   bash src/scripts/discover-allowlist.sh copilot   # (informational; copilot is already locked)
#
# HOW IT WORKS:
#   1. Starts the stack with the discovery overlay (splice-ALL mode; nothing blocked).
#   2. Spawns an interactive shell in the gateway netns.
#   3. You authenticate and run a representative workflow for the agent.
#   4. After exit, the gateway's Squid access.log is harvested and unique SNIs extracted.
#   5. You review the SNIs and update the agent's fragment.
#   6. Stop the discovery stack and re-run with the production profile to validate.
#
# PREREQUISITES:
#   - Docker + docker compose installed and running.
#   - src/gateway/discovery/squid-discovery.conf exists (from item 08).
#   - AGENT auth credentials available in the shell environment.
#
# PRODUCED OUTPUT:
#   - /tmp/discovery-snIs-<AGENT>.txt: unique SNIs observed during the session.
#   - Console instructions for updating src/gateway/squid-allowlist.d/<AGENT>.conf.
#
# SOURCE: SPEC-20 section 7; ADR-002 D4 (empirical-discovery methodology).
# ANALOG: This is the per-agent equivalent of the OI-08-C Copilot discovery run.

set -euo pipefail

AGENT="${1:-}"

case "$AGENT" in
  copilot|claude|codex) ;;
  "")
    echo "USAGE: $0 <copilot|claude|codex>" >&2
    exit 1
    ;;
  *)
    echo "ERROR: Unknown agent '$AGENT'. Must be one of: copilot claude codex" >&2
    exit 1
    ;;
esac

echo "[discover] === Allowlist discovery for agent: ${AGENT} ==="
echo "[discover] This will start the gateway in splice-ALL mode (nothing blocked)."
echo "[discover] All SNIs the ${AGENT} workflow contacts will be logged."
echo "[discover] IMPORTANT: Do NOT run this with production credentials in a secure environment."
echo "[discover] The discovery gateway does not enforce the allowlist."
echo ""

# Step 1: Start gateway in discovery mode.
# The discovery overlay overrides squid.conf with squid-discovery.conf (splice-all).
# We also set SQUID_AGENT_FRAGMENT to the target agent's fragment so the production
# fragment is still copied (though squid.conf is overridden by the discovery conf,
# the entrypoint fragment selection still runs and is visible in the log).
echo "[discover] Starting gateway in discovery mode..."
SQUID_AGENT_FRAGMENT="${AGENT}.conf" \
docker compose \
    -f docker-compose.yml \
    -f docker-compose.discovery.yml \
    up -d gateway

echo "[discover] Waiting for gateway to be healthy..."
for i in $(seq 1 30); do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' copilot-gateway 2>/dev/null || echo "starting")
    if [ "$STATUS" = "healthy" ]; then
        echo "[discover] Gateway is healthy."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[discover] ERROR: Gateway did not become healthy after 30s. Check logs:" >&2
        docker logs copilot-gateway 2>&1 | tail -20 >&2
        exit 1
    fi
    sleep 1
done

# Step 2: Start the discovery container (ubuntu shell in gateway netns).
echo "[discover] Starting discovery container (interactive shell)..."
echo "[discover] === INTERACTIVE SESSION ==="
echo "[discover] You are now in the discovery container's shell."
echo "[discover] The gateway is in splice-ALL mode; all your HTTPS traffic is logged."
echo "[discover] Run your ${AGENT} workflow:"
case "$AGENT" in
  claude)
    echo "[discover]   export HTTPS_PROXY=http://localhost:8080"
    echo "[discover]   export HTTP_PROXY=http://localhost:8080"
    echo "[discover]   claude login  (or set ANTHROPIC_API_KEY)"
    echo "[discover]   claude --help"
    echo "[discover]   # run a representative task"
    ;;
  codex)
    echo "[discover]   export HTTPS_PROXY=http://localhost:8080"
    echo "[discover]   export HTTP_PROXY=http://localhost:8080"
    echo "[discover]   codex login  (or set OPENAI_API_KEY)"
    echo "[discover]   codex --help"
    echo "[discover]   # run a representative task"
    ;;
  copilot)
    echo "[discover]   export HTTPS_PROXY=http://localhost:8080"
    echo "[discover]   gh auth login --web"
    echo "[discover]   gh copilot suggest 'list files'"
    ;;
esac
echo "[discover] When done, type 'exit' to end the session and harvest SNIs."
echo ""

SQUID_AGENT_FRAGMENT="${AGENT}.conf" \
docker compose \
    -f docker-compose.yml \
    -f docker-compose.discovery.yml \
    run --rm \
    --service-ports \
    discovery \
    /bin/bash || true

# Step 3: Harvest SNIs from Squid access.log.
echo ""
echo "[discover] === Harvesting SNIs from Squid access.log ==="
SNI_OUTPUT="/tmp/discovery-snIs-${AGENT}.txt"
docker exec copilot-gateway \
    sh -c 'grep CONNECT /var/log/squid/access.log 2>/dev/null | awk '"'"'{print $7}'"'"' | sort -u' \
    > "$SNI_OUTPUT" 2>/dev/null || \
docker exec copilot-gateway \
    sh -c 'cat /var/log/squid/access.log 2>/dev/null | grep -oE "[A-Za-z0-9._-]+\.[a-z]{2,}" | sort -u' \
    > "$SNI_OUTPUT" 2>/dev/null || \
    echo "(could not harvest SNIs from gateway log; check docker exec access)" > "$SNI_OUTPUT"

echo "[discover] Discovered SNIs saved to: ${SNI_OUTPUT}"
echo "[discover] Contents:"
cat "$SNI_OUTPUT"

echo ""
echo "[discover] === Next steps ==="
echo "[discover] 1. Review the SNI list above."
echo "[discover] 2. For each SNI that is required for ${AGENT} operation:"
echo "[discover]    Add it to: src/gateway/squid-allowlist.d/${AGENT}.conf"
echo "[discover]    Format: acl allowed_SNI ssl::server_name <hostname>"
echo "[discover] 3. Annotate each entry as OBSERVED-<DATE> or DOCUMENTED-not-observed."
echo "[discover] 4. Comment out Section C / Section B hosts that are NOT required in steady-state."
echo "[discover] 5. Stop the discovery stack:"
echo "[discover]    docker compose -f docker-compose.yml -f docker-compose.discovery.yml down"
echo "[discover] 6. Re-test with the production profile:"
echo "[discover]    docker compose --profile ${AGENT} up"
echo "[discover] 7. When satisfied, update the STATUS line in ${AGENT}.conf:"
echo "[discover]    STATUS: LOCKED <DATE> (empirical discovery complete)"
echo "[discover] 8. Re-generate the MCP integrity manifest if config.toml changed:"
echo "[discover]    bash src/managed-mcp/generate-mcp-integrity-manifest.sh"

echo ""
echo "[discover] Stopping discovery gateway..."
docker compose \
    -f docker-compose.yml \
    -f docker-compose.discovery.yml \
    down gateway 2>/dev/null || true
echo "[discover] Discovery session complete."
