#!/bin/bash
# src/dev/jit-secret-template.sh
# Item 10, ADR-003 D6 (JIT secret delivery template).
#
# TEMPLATE ONLY - NOT WIRED LIVE. This script is a reference template showing the
# JIT (just-in-time) / tmpfs secret-delivery pattern from ADR-003 D6. It is NOT
# executed automatically. Copy, adapt, and invoke it manually when a workflow
# genuinely requires a short-lived secret inside the container.
#
# POSTURE: Keep secrets OUT of the container by default. The agent does not get
# cloud credentials, registry write tokens, or signing keys unless a workflow
# genuinely needs them locally. "Treat the agent like a new intern: if a human
# intern wouldn't get production credentials to triage GitHub issues, neither
# should the agent" (ADR-003 D6).
#
# ESCALATION TRIGGER: If real production secrets are unavoidable in-container,
# escalate to the ADR-004 microVM/VM tier (ADR-003 D6, Area 10 Tier 2). The
# runc-tier credential design does NOT accept production secrets at rest in the
# container. Never store long-lived secrets at rest in the container.
#
# PRINCIPLES:
#   1. Mint a short-lived, least-privilege, NON-PROD credential on the host.
#   2. Deliver it into a tmpfs (memory-backed, ephemeral) mount in the container.
#   3. It expires within the session. Spending caps on the identity.
#   4. The container's read_only: true + tmpfs mounts (from docker-compose.yml)
#      mean /tmp is already tmpfs - use /tmp for ephemeral secret storage.
#
# The secret delivered here is in ADR-003 D5: "no secrets in environment variables."
# Write to a tmpfs file, not to an env var, to avoid /proc/[pid]/environ exposure.
# The agent still runs as UID 1000 and can read files it owns; the protection is
# that the secret is short-lived and cannot be exfiltrated via env dump.
#
# SUPPORTED FLOWS (see comments in each section below):
#   A. aws-vault (AWS STS temporary credentials)
#   B. 1Password op run (secret in-memory for the process duration only)
#   C. HashiCorp Vault dynamic secrets (auto-revoked at lease expiry)
#   D. GitHub App installation token (1-hour expiry)
#   E. Single-repo fine-grained PAT (minimum next-day expiry)
#
# USAGE (caller runs this on the HOST, not inside the container):
#   ./jit-secret-template.sh <flow> <container-name>
#
# The script writes a short-lived credential to a tmpfs path inside the container
# by piping via `docker exec`. The credential file is mode 0600, owned by devuser.

set -euo pipefail

FLOW="${1:-help}"
CONTAINER="${2:-copilot-devcontainer}"

# Destination inside the container: /tmp (tmpfs, ephemeral, wiped on restart).
# Mode 0600 so only UID 1000 (devuser) can read it.
DEST_PATH="/tmp/.jit-secret"

usage() {
    echo "Usage: $0 <flow> [container-name]"
    echo ""
    echo "Flows:"
    echo "  aws-vault  - AWS STS temporary credentials via aws-vault"
    echo "  op-run     - 1Password op run (Vault Managed version)"
    echo "  vault      - HashiCorp Vault dynamic secret"
    echo "  gh-app     - GitHub App installation token (1h expiry)"
    echo "  fgpat      - GitHub fine-grained PAT (single-repo, Copilot Requests)"
    echo ""
    echo "Default container: copilot-devcontainer"
    exit 0
}

deliver() {
    # $1 = the secret value to deliver
    # Writes the secret to DEST_PATH inside the container via docker exec.
    # The file is mode 0600, owned by devuser (UID 1000).
    local SECRET="$1"
    docker exec -i "${CONTAINER}" bash -c \
        "install -m 0600 /dev/stdin '${DEST_PATH}'" <<< "${SECRET}"
    echo "[jit-secret] Delivered to container:${DEST_PATH} (mode 0600)"
    echo "[jit-secret] Source the secret in the container: source ${DEST_PATH}"
    echo "[jit-secret] Or: export TOKEN=\$(cat ${DEST_PATH})"
    echo "[jit-secret] REMINDER: This file is in /tmp (tmpfs) and will be wiped on container restart."
}

case "${FLOW}" in

help|--help|-h)
    usage
    ;;

# ---------------------------------------------------------------------------
# Flow A: aws-vault (AWS STS temporary credentials)
# Mints time-limited STS credentials using aws-vault on the HOST.
# Requires: aws-vault installed on host, a profile configured.
# The credentials are short-lived (configurable, default 1h) and are
# scoped to a non-prod identity with spending caps.
#
# USAGE: ./jit-secret-template.sh aws-vault copilot-devcontainer
# Adapt: replace 'your-profile' with your aws-vault profile name.
# ---------------------------------------------------------------------------
aws-vault)
    echo "[jit-secret] Flow A: aws-vault (AWS STS temporary credentials)"
    echo "[jit-secret] Adapt: replace 'your-profile' with your aws-vault profile name."
    echo ""
    echo "# Run on HOST (not in container):"
    echo "# aws-vault exec your-profile --duration=1h -- env | grep AWS > /tmp/aws-creds"
    echo "# Then deliver to container:"
    echo "# ./jit-secret-template.sh aws-vault copilot-devcontainer"
    echo ""
    # TEMPLATE: uncomment and adapt:
    # SECRET=$(aws-vault exec your-profile --duration=1h -- sh -c 'echo "export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID; export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY; export AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN"')
    # deliver "${SECRET}"
    echo "[jit-secret] TEMPLATE ONLY: uncomment and adapt the lines above."
    ;;

# ---------------------------------------------------------------------------
# Flow B: 1Password op run
# Runs a command with 1Password secrets injected for the process duration only.
# Requires: 1Password CLI (op) installed on host, 1Password account configured.
# The secret is available only during the command's lifetime.
#
# USAGE: Run inside the container via:
#   docker exec -it copilot-devcontainer op run --env-file=.env -- your-command
# Or use op run with a reference to a specific 1Password item.
# ---------------------------------------------------------------------------
op-run)
    echo "[jit-secret] Flow B: 1Password op run"
    echo "[jit-secret] Adapt: replace the op:// URI with your 1Password item reference."
    echo ""
    echo "# Run on HOST or pipe into container:"
    echo "# op read 'op://YourVault/YourItem/token' | docker exec -i ${CONTAINER} bash -c 'cat > /tmp/.jit-secret && chmod 0600 /tmp/.jit-secret'"
    echo "[jit-secret] TEMPLATE ONLY: adapt the op:// URI and item name."
    ;;

# ---------------------------------------------------------------------------
# Flow C: HashiCorp Vault dynamic secrets
# Mints a short-lived dynamic secret (e.g. AWS creds, DB password) via Vault.
# Requires: vault CLI installed on host, VAULT_ADDR and VAULT_TOKEN set.
# The secret has an auto-revocation TTL configured in Vault policy.
#
# USAGE: Adapt the path and secret key for your Vault configuration.
# ---------------------------------------------------------------------------
vault)
    echo "[jit-secret] Flow C: HashiCorp Vault dynamic secret"
    echo "[jit-secret] Adapt: replace 'secret/data/your-path' with your Vault path."
    echo ""
    echo "# Run on HOST:"
    echo "# vault kv get -field=token secret/data/your-path | docker exec -i ${CONTAINER} bash -c 'cat > /tmp/.jit-secret && chmod 0600 /tmp/.jit-secret'"
    echo ""
    echo "# For AWS dynamic credentials:"
    echo "# vault read -field=token aws/creds/your-role | docker exec -i ${CONTAINER} ..."
    echo "[jit-secret] TEMPLATE ONLY: adapt the Vault path and role."
    ;;

# ---------------------------------------------------------------------------
# Flow D: GitHub App installation token (1-hour expiry)
# Mints a GitHub App installation token that expires after 1 hour.
# Requires: GitHub App with the required permissions, App ID + private key on host.
# The token is scoped to a specific installation (repo or org) with minimal perms.
#
# USAGE: Use the GitHub Apps API or the `actions/create-github-app-token` Action.
# For local use, the `gh` CLI or a simple curl call can mint the token.
# ---------------------------------------------------------------------------
gh-app)
    echo "[jit-secret] Flow D: GitHub App installation token (1h expiry)"
    echo "[jit-secret] Adapt: set APP_ID, INSTALLATION_ID, and the private key path."
    echo ""
    echo "# See: https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app"
    echo "# Use a JWT (signed with the App private key) to request an installation token:"
    echo "# APP_TOKEN=\$(gh api -X POST /app/installations/YOUR_INSTALLATION_ID/access_tokens --jq .token)"
    echo "# echo \"\${APP_TOKEN}\" | docker exec -i ${CONTAINER} bash -c 'cat > /tmp/.jit-secret && chmod 0600 /tmp/.jit-secret'"
    echo "[jit-secret] TEMPLATE ONLY: adapt the App ID, Installation ID, and key path."
    ;;

# ---------------------------------------------------------------------------
# Flow E: Single-repo fine-grained PAT (minimum next-day expiry)
# The VERIFIED Copilot CLI token minimization path (ADR-003 D3).
# A fine-grained PAT scoped to a single repository with the "Copilot Requests"
# permission, minimum expiry set to next-day (or shorter if supported).
# Supplied via COPILOT_GITHUB_TOKEN / GH_TOKEN / GITHUB_TOKEN (in that order).
#
# NOTE: This is the committed minimization path for Copilot CLI auth.
# The PAT is still agent-readable (R-c posture); containment is the egress boundary.
# See: src/dev/copilot-token-exposure-finding.md for the R-c analysis.
# ---------------------------------------------------------------------------
fgpat)
    echo "[jit-secret] Flow E: GitHub fine-grained PAT (single-repo, Copilot Requests)"
    echo "[jit-secret] This is the ADR-003 D3 VERIFIED Copilot CLI token minimization path."
    echo ""
    echo "# 1. Create a fine-grained PAT at github.com/settings/personal-access-tokens"
    echo "#    Scope: single repository, 'Copilot Requests' permission only."
    echo "#    Expiry: minimum next-day (or shortest supported)."
    echo "# 2. Deliver to container:"
    echo "#    read -rs PAT_VALUE"
    echo "#    echo \"\${PAT_VALUE}\" | docker exec -i ${CONTAINER} bash -c 'cat > /tmp/.jit-secret && chmod 0600 /tmp/.jit-secret'"
    echo "# 3. Inside container:"
    echo "#    export COPILOT_GITHUB_TOKEN=\$(cat /tmp/.jit-secret)"
    echo "#    github-copilot ..."
    echo "[jit-secret] TEMPLATE ONLY: follow the steps above."
    ;;

*)
    echo "[jit-secret] Unknown flow: ${FLOW}"
    usage
    ;;

esac
