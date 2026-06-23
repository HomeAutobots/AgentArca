#!/usr/bin/env bash
# src/scripts/discover-allowlist.sh
# Empirical allowlist discovery for per-agent allowlist fragments.
# SPEC-20 section 7; ADR-002 D4 (empirical-discovery methodology).
#
# UPDATED 2026-06-22 for the F2 per-profile-gateway topology. The agent CLI lives in the
# profile's DEVCONTAINER (<agent>-devcontainer), not in a bare shell, and each profile has
# its own gateway (<agent>-gateway). This matches the manually-validated Codex discovery run
# of 2026-06-22 (the pre-F2 version targeted a single `gateway` / `copilot-gateway` and a bare
# `discovery` ubuntu shell, neither of which fits the per-profile build).
#
# USAGE:
#   bash src/scripts/discover-allowlist.sh <copilot|claude|codex>
#
# HOW IT WORKS:
#   1. Brings up the agent's FULL profile (devcontainer + gateway + caches) with the discovery
#      overlay, which swaps squid.conf for squid-discovery.conf (splice-ALL: nothing is blocked,
#      every SNI is logged).
#   2. You authenticate and run a representative workflow INSIDE <agent>-devcontainer (HTTPS_PROXY
#      is preset to the gateway). Instructions are printed per agent.
#   3. Press ENTER; the script harvests unique SNIs from the agent's gateway access.log.
#   4. You review the hosts and lock src/gateway/squid-allowlist.d/<agent>.conf.
#   5. The discovery stack is torn down.
#
# PREREQUISITES:
#   - Docker + docker compose running.
#   - Profile mutual exclusion (invariant 9): no OTHER agent profile may be up. If one is, bring
#     it down first: docker compose --profile <other> down  (named volumes persist).
#   - Agent credentials: you authenticate interactively in step 2.
#
# IMPORTANT: the discovery gateway does NOT enforce the allowlist (splice-all). Do not run this
# against secrets you would not expose to every host the workflow happens to contact.

set -euo pipefail

AGENT="${1:-}"
case "$AGENT" in
  copilot|claude|codex) ;;
  "") echo "USAGE: $0 <copilot|claude|codex>" >&2; exit 1 ;;
  *)  echo "ERROR: unknown agent '$AGENT' (want copilot|claude|codex)" >&2; exit 1 ;;
esac

GATEWAY="${AGENT}-gateway"
DEVC="${AGENT}-devcontainer"
# Native-Linux DNS overlay (docker-compose.linux.yml): layered automatically on Linux, inert on
# macOS. Without it the discovery gateway never reaches healthy on Linux (embedded-resolver DNS).
# Layered before the discovery overlay so squid-discovery.conf still wins the squid.conf mount.
LINUX_OVERLAY=()
if [ "$(uname -s)" = "Linux" ]; then LINUX_OVERLAY=(-f docker-compose.linux.yml); fi
COMPOSE=(docker compose -f docker-compose.yml "${LINUX_OVERLAY[@]}" -f docker-compose.discovery.yml --profile "$AGENT")
SNI_OUTPUT="/tmp/discovery-snis-${AGENT}.txt"

echo "[discover] === Allowlist discovery for agent: ${AGENT} (splice-ALL observe mode) ==="
echo "[discover] The discovery gateway does NOT enforce the allowlist. Do not use secrets you"
echo "[discover] would not expose to arbitrary hosts. Ensure no other profile is running."
echo ""
echo "[discover] Bringing up the ${AGENT} profile with the discovery overlay..."
"${COMPOSE[@]}" up -d

echo "[discover] Waiting for ${GATEWAY} to be healthy..."
for i in $(seq 1 60); do
  STATUS="$(docker inspect --format='{{.State.Health.Status}}' "$GATEWAY" 2>/dev/null || echo starting)"
  [ "$STATUS" = "healthy" ] && { echo "[discover] ${GATEWAY} healthy."; break; }
  if [ "$i" -eq 60 ]; then
    echo "[discover] ERROR: ${GATEWAY} not healthy after 60s. Logs:" >&2
    docker logs "$GATEWAY" 2>&1 | tail -20 >&2
    exit 1
  fi
  sleep 1
done

echo ""
echo "[discover] === RUN A REPRESENTATIVE WORKFLOW (in a separate terminal) ==="
echo "[discover] The agent CLI lives in ${DEVC}; HTTPS_PROXY is preset so all traffic is logged."
case "$AGENT" in
  claude)
    echo "[discover]   docker exec -it ${DEVC} claude   # or mint a narrow token on the HOST: claude setup-token"
    echo "[discover]   # then run a representative task that triggers inference"
    ;;
  codex)
    echo "[discover]   # API-key path: put OPENAI_API_KEY in the repo-root .env BEFORE 'up' (no login step)."
    echo "[discover]   # ChatGPT-subscription path (device code) MUST run in a real TTY terminal:"
    echo "[discover]   docker exec -it ${DEVC} codex login --device-auth"
    echo "[discover]     # NOTE: codex buffers its output without a TTY, so the device URL + code do"
    echo "[discover]     # NOT appear from a non-TTY exec (or the editor '!' box). Use a real terminal."
    echo "[discover]   docker exec ${DEVC} bash -lc 'cd /workspace && codex exec --skip-git-repo-check \"say hello\" </dev/null'"
    ;;
  copilot)
    echo "[discover]   docker exec -it ${DEVC} gh auth login"
    echo "[discover]   docker exec -it ${DEVC} gh copilot suggest 'list files'"
    ;;
esac

echo ""
read -r -p "[discover] Press ENTER when the workflow is done to harvest SNIs... " _ || true

echo "[discover] === Harvesting hosts from ${GATEWAY} access.log ==="
# The gateway access.log is proxy:proxy 0640 and root is restricted in the hardened gateway,
# so read it as the 'proxy' user. For CONNECT lines the target (host:port) is field 7 of the
# copilot_combined logformat; we strip :443 and de-duplicate.
docker exec -u proxy "$GATEWAY" sh -c \
  "awk '/CONNECT/ {print \$7}' /var/log/squid/access.log | sed 's/:443\$//' | sort -u" \
  > "$SNI_OUTPUT" 2>/dev/null || \
  echo "(could not harvest; try: docker exec -u proxy ${GATEWAY} cat /var/log/squid/access.log)" > "$SNI_OUTPUT"

echo "[discover] Hosts saved to ${SNI_OUTPUT}:"
cat "$SNI_OUTPUT"

echo ""
echo "[discover] === Next steps ==="
echo "[discover] 1. Separate AGENT traffic from cache infra: npm/pypi registry hosts arrive via the"
echo "[discover]    caches (cache-net source) and are covered by base.conf, NOT ${AGENT}.conf."
echo "[discover] 2. For each host required for ${AGENT} steady-state, ensure it is in"
echo "[discover]    src/gateway/squid-allowlist.d/${AGENT}.conf  (acl allowed_SNI ssl::server_name <host>)."
echo "[discover] 3. Drop login-only / non-essential hosts where the auth path allows; document the choice."
echo "[discover] 4. Validate under ENFORCEMENT (production profile, allowlist on):"
echo "[discover]      ${COMPOSE[*]} down"
echo "[discover]      docker compose --profile ${AGENT} up -d"
echo "[discover]    confirm the agent works AND non-allowlisted hosts are blocked (HTTP 000)."
echo "[discover] 5. Update the STATUS line in ${AGENT}.conf to LOCKED <date>."
echo ""
echo "[discover] Tearing down the discovery stack..."
"${COMPOSE[@]}" down

echo "[discover] Discovery session complete."
