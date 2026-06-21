#!/usr/bin/env bash
# src/scripts/mcp-integrity-manifest-generate.sh
#
# Generates the known-good SHA-256 manifest for mcp.json.
#
# MUST run as root (UID 0) so the manifest's owner UID differs from the agent's UID.
# The owner-UID separation is the prerequisite for mode 444 to be meaningful as the
# primary protection mechanism when chattr +i is not available (overlay2 environments).
#
# When to run:
#   1. At container image build time (as root in the Dockerfile RUN layer), BEFORE the
#      container starts and BEFORE the agent user is created.
#   2. When an authorized operator (NOT the agent) updates mcp.json after a server
#      clears the gate (SPEC-06 section 3) and checklist (SPEC-06 section 4).
#      Steps for an authorized update:
#        a. Temporarily remove chattr +i (if applied): chattr -i /etc/managed-mcp/mcp-integrity.sha256
#        b. Apply the mcp.json change (as root or via sudo).
#        c. Re-apply chattr +i: chattr +i /path/to/mcp.json (via SPEC-05 apply-immutability.sh)
#        d. Re-run THIS script to update the manifest hash.
#        e. Verify with mcp-integrity-check.sh before committing.
#        f. Record the change in the gate-decision record (SPEC-06 section 3).
#
# Fail-closed on chattr +i failure:
#   If chattr +i does not take (overlay2 silent-no-op), the script exits 1 and the build
#   MUST NOT proceed relying on mode 444 alone for the manifest. The fallback is a
#   read-only Docker volume mount for /etc/managed-mcp/ (see SPEC-06 section 8
#   "Overlay2 fallback" and docker-compose.yml volumes block).
#
# Source: SPEC-06 section 8 "Known-good manifest". ADR-006 D7, CVE-2025-54136 (MCPoison).

set -euo pipefail

MCP_JSON_PATH="${MCP_JSON_PATH:-${WORKSPACE_ROOT:-/workspace}/.vscode/mcp.json}"
MANIFEST_PATH="${MCP_MANIFEST_PATH:-/etc/managed-mcp/mcp-integrity.sha256}"
CHECK_SCRIPT="${MCP_CHECK_SCRIPT:-/usr/local/bin/mcp-integrity-check.sh}"

# This script MUST run as root so the manifest owner UID differs from the agent's UID.
# Mode 444 (read-only for all) is meaningful only when the file owner is root and the
# agent runs as a different UID. Without this UID separation, mode 444 would not stop
# the file's own owner from writing it.
if [ "$(id -u)" -ne 0 ]; then
  echo "[mcp-integrity] FATAL: manifest-generation script must run as root (UID 0)." >&2
  echo "[mcp-integrity] The manifest owner UID must differ from the agent UID so that" >&2
  echo "[mcp-integrity] mode 444 prevents agent modification. Run as root or via sudo." >&2
  exit 1
fi

if ! [ -f "$MCP_JSON_PATH" ]; then
  echo "[mcp-integrity] FATAL: mcp.json not found at $MCP_JSON_PATH." >&2
  exit 1
fi

# Determine sha256 tool
if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256_CMD="shasum -a 256"
else
  echo "[mcp-integrity] FATAL: No sha256sum or shasum found." >&2
  exit 1
fi

mkdir -p "$(dirname "$MANIFEST_PATH")"
eval "$SHA256_CMD \"$MCP_JSON_PATH\"" > "$MANIFEST_PATH"
chown root:root "$MANIFEST_PATH"
chmod 444 "$MANIFEST_PATH"

# Attempt chattr +i on the manifest and the integrity-check script.
# FAIL CLOSED: if chattr +i does not take (overlay2 silent-no-op), the build must fail.
# The fallback is mounting /etc/managed-mcp/ as a read-only Docker volume.
for target in "$MANIFEST_PATH" "$CHECK_SCRIPT"; do
  if [ -f "$target" ]; then
    chattr +i "$target" 2>/dev/null || true
    # Verify the immutable bit took effect (mirrors SPEC-05 section 6 layer iii approach).
    if ! lsattr "$target" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      echo "[mcp-integrity] FATAL: chattr +i did NOT take on $target (overlay2 silent-no-op?)." >&2
      echo "[mcp-integrity] The immutable bit is absent. Build MUST NOT proceed." >&2
      echo "[mcp-integrity] Fallback: mount /etc/managed-mcp/ as a read-only Docker volume." >&2
      echo "[mcp-integrity] See SPEC-06 section 8 'Overlay2 fallback' and docker-compose.yml." >&2
      exit 1
    fi
    echo "[mcp-integrity] OK: immutable bit verified on $target"
  fi
done

echo "[mcp-integrity] Manifest written: $(cat "$MANIFEST_PATH")"
