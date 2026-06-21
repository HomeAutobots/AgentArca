#!/usr/bin/env bash
# src/detect/canary-placement.sh
# Places fake credentials in agent-reachable locations.
# Item 13, ADR-007 D4, SPEC-07 section 2e + section A5.
#
# DESIGN PRINCIPLES:
#   - All canaries are FAKE. They look real enough to attract an agent but have
#     no actual credentials. Token provider callbacks are optional (Thinkst/self-hosted).
#   - auditd watch rules (in auditd.rules) cover each placement path.
#   - A token registry (docs/decisions/canary-token-registry.yaml) is created/updated.
#   - OI-10-A finding: include ~/.config/github-copilot/hosts.json as a canary
#     (this is the real Copilot CLI token location, most high-value canary).
#   - Token provider: use a PLACEHOLDER token ID in the shipped artifact.
#     Replace with real Thinkst/self-hosted tokens before deploying.
#     DO NOT use canarytokens.org tokens: TruffleHog can fingerprint them statically.
#   - SPEC-07 section 2e: vary placement across types; do not rely on a single canary.
#
# Usage:
#   ./canary-placement.sh [--dry-run] [--home HOME_DIR] [--workspace WORKSPACE_DIR]
#
#   --dry-run   : print actions without executing them
#   --home DIR  : path to the agent home directory (default: /home/devuser)
#   --workspace : path to the workspace (default: /workspace)
#
# After running this script, update docs/decisions/canary-token-registry.yaml
# with the real token IDs from your Thinkst/self-hosted token provider.
#
# CLEANUP: call ./canary-placement.sh --remove to remove all canaries (for teardown).

set -euo pipefail

DRY_RUN=0
HOME_DIR="${HOME_DIR:-/home/devuser}"
WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
REMOVE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --remove) REMOVE=1 ;;
    --home) shift; HOME_DIR="$1" ;;
    --workspace) shift; WORKSPACE_DIR="$1" ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRY-RUN] $*" >&2
  else
    "$@"
  fi
}

# ============================================================
# CANARY 1: Fake AWS credentials (highest-value bait)
# ============================================================
# OI-10-A: the Copilot CLI token is readable from ~/.config/github-copilot/hosts.json.
# A fake AWS credentials file at ~/.aws/credentials is the classic agent tripwire.
# The auditd watch (-w ~/.aws/credentials -p r -k canary_read) fires on any read.
# Replace AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI with a real Thinkst AWS canary token.
place_aws_canary() {
  local path="$HOME_DIR/.aws/credentials"
  echo "[canary] Placing fake AWS credentials at: $path" >&2
  run mkdir -p "$(dirname "$path")"
  if [ "$DRY_RUN" -eq 0 ]; then
    cat > "$path" <<'EOF'
[default]
# FAKE CREDENTIALS - CANARY TRIPWIRE
# Any use of these credentials will trigger an alert.
# Replace the token IDs below with real Thinkst/self-hosted AWS canary tokens.
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
EOF
    chmod 600 "$path"
  fi
  echo "[canary] AWS canary placed. auditd watch: -w $path -p r -k canary_read" >&2
}

# ============================================================
# CANARY 2: Fake Copilot token file (OI-10-A informed)
# ============================================================
# This is the highest-value canary per OI-10-A: the Copilot CLI stores its
# OAuth token at ~/.config/github-copilot/hosts.json. If the agent reads this
# file, it is specifically targeting the Copilot token (the R-c exfil vector).
# The canary here is a FAKE token in a plausible location; the real token
# (if copilot login has been run) is in the same file. The auditd watch
# covers the entire directory.
place_copilot_token_canary() {
  local path="$HOME_DIR/.config/github-copilot/hosts.json"
  echo "[canary] Placing fake Copilot token at: $path" >&2
  run mkdir -p "$(dirname "$path")"
  if [ "$DRY_RUN" -eq 0 ]; then
    # Only place the canary if the file does not exist (do not overwrite a real token).
    if [ ! -f "$path" ]; then
      cat > "$path" <<'EOF'
{
  "github.com": {
    "oauth_token": "ghu_FAKECANARYTOKENPLACEHOLDER1234567890AB",
    "user": "copilot-agent",
    "git_protocol": "https"
  }
}
EOF
      chmod 600 "$path"
      echo "[canary] Copilot token canary placed (file did not exist)." >&2
    else
      echo "[canary] SKIP: $path already exists (real token may be present). Not overwriting." >&2
      echo "[canary] auditd watch will still fire on reads of the real file." >&2
    fi
  fi
  echo "[canary] auditd watch: -w $HOME_DIR/.config/github-copilot/ -p r -k canary_read" >&2
}

# ============================================================
# CANARY 3: Fake .env file (plausible dev workspace credential store)
# ============================================================
# A .env.canary file at the home dir with fake credentials.
# An agent scanning for secrets will try to read this.
place_env_canary() {
  local path="$HOME_DIR/.env.canary"
  echo "[canary] Placing fake .env canary at: $path" >&2
  if [ "$DRY_RUN" -eq 0 ]; then
    cat > "$path" <<'EOF'
# FAKE CREDENTIALS - CANARY TRIPWIRE
# Any read of this file triggers an auditd alert.
DATABASE_URL=postgresql://admin:FAKEPASSWORD123@db.internal:5432/prod
API_SECRET_KEY=fake-api-key-CANARY-DO-NOT-USE-abcdef1234567890
STRIPE_SECRET_KEY=sk_live_FAKECANARYTOKENFORSTRIPE1234567890
SLACK_BOT_TOKEN=xoxb-FAKE-CANARY-TOKEN-1234567890abcdef
EOF
    chmod 600 "$path"
  fi
  echo "[canary] .env canary placed. auditd watch: -w $path -p r -k canary_read" >&2
}

# ============================================================
# CANARY 4: DNS canary hostname in .bash_history (fires on DNS resolution)
# ============================================================
# A fake hostname planted in .bash_history (simulating a "remembered" webhook URL).
# If the agent reads .bash_history and tries to resolve the DNS canary hostname,
# the Thinkst/self-hosted DNS canary fires.
# Replace REPLACE_WITH_REAL_DNS_CANARY_HOSTNAME with a real Thinkst DNS token.
place_dns_canary() {
  local history_path="$HOME_DIR/.bash_history"
  local dns_canary_hostname="REPLACE-WITH-REAL-THINKST-DNS-CANARY.canarytokens.com"
  echo "[canary] Seeding DNS canary hostname in .bash_history: $dns_canary_hostname" >&2
  if [ "$DRY_RUN" -eq 0 ]; then
    # Append to history (do not overwrite existing history).
    printf '\n# Backup webhook (INTERNAL - do not share)\ncurl -s https://%s/notify\n' \
      "$dns_canary_hostname" >> "$history_path" 2>/dev/null || true
  fi
  echo "[canary] DNS canary seeded. No auditd file-watch needed (DNS query fires the canary)." >&2
}

# ============================================================
# CANARY 5: Tokenized ops runbook (doc with embedded canary string)
# ============================================================
# A plausible operational document with an embedded canary string.
# An agent that reads this document and tries to use the "credentials" section
# fires the Thinkst/self-hosted token.
place_doc_canary() {
  local path="$WORKSPACE_DIR/docs/ops-runbook.md"
  echo "[canary] Placing tokenized ops runbook at: $path" >&2
  run mkdir -p "$(dirname "$path")"
  if [ "$DRY_RUN" -eq 0 ]; then
    if [ ! -f "$path" ]; then
      cat > "$path" <<'EOF'
# Operations Runbook (INTERNAL)

## Emergency Credentials

In case of emergency access requirements:

- **Database admin token**: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.FAKECANARYTOKEN`
- **Internal webhook**: `https://REPLACE-WITH-REAL-HTTP-CANARY.canarytokens.com/notify`
- **Legacy API key**: `Token FAKE-LEGACY-API-CANARY-PLACEHOLDER-1234567890`

## Standard Deployment

See docs/DEPLOYMENT.md for the standard deployment process.
EOF
    else
      echo "[canary] SKIP: $path already exists. Not overwriting." >&2
    fi
  fi
  echo "[canary] Ops runbook canary placed. auditd watch: -w $path -p r -k canary_read" >&2
}

# ============================================================
# REMOVE all canaries (for teardown / container rebuild)
# ============================================================
remove_canaries() {
  echo "[canary] Removing canary files..." >&2
  run rm -f "$HOME_DIR/.aws/credentials"
  # Do NOT remove ~/.config/github-copilot/hosts.json (may be a real token file).
  # Only remove it if it contains our fake canary token.
  if [ -f "$HOME_DIR/.config/github-copilot/hosts.json" ]; then
    if grep -q "FAKECANARYTOKENPLACEHOLDER" "$HOME_DIR/.config/github-copilot/hosts.json" 2>/dev/null; then
      run rm -f "$HOME_DIR/.config/github-copilot/hosts.json"
      echo "[canary] Removed fake Copilot token canary." >&2
    else
      echo "[canary] SKIP: ~/.config/github-copilot/hosts.json appears to be a real token file." >&2
    fi
  fi
  run rm -f "$HOME_DIR/.env.canary"
  # .bash_history seeding is hard to cleanly remove; document it.
  echo "[canary] NOTE: DNS canary hostname in .bash_history was not removed (append-only history)." >&2
  if [ -f "$WORKSPACE_DIR/docs/ops-runbook.md" ]; then
    if grep -q "FAKECANARYTOKEN\|REPLACE-WITH-REAL" "$WORKSPACE_DIR/docs/ops-runbook.md" 2>/dev/null; then
      run rm -f "$WORKSPACE_DIR/docs/ops-runbook.md"
      echo "[canary] Removed ops runbook canary." >&2
    fi
  fi
  echo "[canary] Canary removal complete." >&2
}

# ============================================================
# MAIN
# ============================================================
if [ "$REMOVE" -eq 1 ]; then
  remove_canaries
  exit 0
fi

echo "[canary] Placing canary tokens... (DRY_RUN=${DRY_RUN})" >&2
place_aws_canary
place_copilot_token_canary
place_env_canary
place_dns_canary
place_doc_canary

echo "[canary] All canaries placed." >&2
echo "[canary] NEXT STEPS:" >&2
echo "[canary]   1. Replace placeholder token IDs with real Thinkst/self-hosted tokens." >&2
echo "[canary]   2. Update docs/decisions/canary-token-registry.yaml with real token IDs." >&2
echo "[canary]   3. Verify auditd rules in src/detect/auditd.rules cover all placement paths." >&2
echo "[canary]   4. Re-run after any container rebuild (canaries are in named volumes)." >&2
