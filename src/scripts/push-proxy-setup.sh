#!/usr/bin/env bash
# src/scripts/push-proxy-setup.sh
#
# Configure the in-container git remote as read-only by pointing pushurl at a
# no-op / always-reject local listener. Wires the pre-receive gate (SPEC-05 section 8).
#
# ADR-005 D5: the R-c/R-b write-path control.
# Three interlocking components:
#   (i)   Human-gated git push (PreToolUse hook asks on git push; terminal deny list blocks it).
#   (ii)  Read-only in-container remote: pushurl points to localhost:9999 (always-reject proxy).
#   (iii) Single-branch/single-repo credential scope (ADR-003 D6 fine-grained PAT).
#
# WHY THIS IS LOAD-BEARING (Comment-and-Control, Aonan Guan, April 2026):
#   git push is "a whitelisted operation indistinguishable from normal Copilot workflow activity."
#   It was used to exfiltrate GITHUB_TOKEN past env-filtering, secret-scanning, AND firewall
#   layers. github.com is allowlisted by design, so the network layer alone cannot close it.
#   A readable token (R-c) plus a writable allowlisted destination (R-b) is the full exfil
#   chain; this control breaks the write half of that chain.
#
# HONEST LIMIT (R-b, never claimed solved):
#   A patient, low-bandwidth exfil through a human-APPROVED push (human rubber-stamps a push
#   carrying a few smuggled bytes in a commit message or file) remains possible. R-b stays
#   accepted + partially mitigated, HIGH/HIGH. State loudly; never claim solved.
#
# USAGE (run at container startup, after git remote is configured):
#   bash src/scripts/push-proxy-setup.sh [remote-name] [fetch-url]
#   Defaults: remote-name=origin, fetch-url=read from existing remote

set -euo pipefail

REMOTE_NAME="${1:-origin}"
PUSH_PROXY_URL="http://localhost:9999/no-push"

echo "[push-proxy-setup] Configuring git remote '$REMOTE_NAME' as read-only..." >&2

# Verify we are inside a git repository.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "[push-proxy-setup] ERROR: not inside a git repository. Run from workspace root." >&2
  exit 1
fi

# Get the current fetch URL (to preserve read access).
CURRENT_FETCH_URL=$(git remote get-url "$REMOTE_NAME" 2>/dev/null || echo "")
if [ -z "$CURRENT_FETCH_URL" ]; then
  echo "[push-proxy-setup] WARN: remote '$REMOTE_NAME' not found or has no URL." >&2
  echo "[push-proxy-setup] Setting push URL only (no fetch URL change)." >&2
else
  echo "[push-proxy-setup] Fetch URL: $CURRENT_FETCH_URL" >&2
fi

# Set the push URL to the always-reject local proxy.
# The fetch URL is unchanged (read access is preserved for git fetch/clone).
git remote set-url --push "$REMOTE_NAME" "$PUSH_PROXY_URL"

echo "[push-proxy-setup] Push URL set to: $PUSH_PROXY_URL (always-reject)" >&2

# Verify the configuration took.
CONFIGURED_PUSHURL=$(git remote get-url --push "$REMOTE_NAME" 2>/dev/null || echo "")
if [ "$CONFIGURED_PUSHURL" = "$PUSH_PROXY_URL" ]; then
  echo "[push-proxy-setup] VERIFIED: pushurl = $PUSH_PROXY_URL" >&2
else
  echo "[push-proxy-setup] WARN: pushurl verification failed. Got: '$CONFIGURED_PUSHURL'" >&2
fi

echo "[push-proxy-setup] Git remote configuration:" >&2
git remote -v >&2

echo "[push-proxy-setup] Done. Agent cannot autonomously push (AC-20)." >&2
echo "[push-proxy-setup] To push: review agent commits and push MANUALLY from outside the container." >&2
