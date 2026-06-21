#!/usr/bin/env bash
# ci/mcp-supply-chain-scan.sh
#
# CI gate: fail the build if any prohibited supply-chain pattern appears in MCP config
# files, Dockerfiles, or compose files.
#
# Prohibited patterns (ADR-006 D4, SPEC-06 section 5 "Hard prohibitions"):
#   - npx -y <anything>          (runtime-fetch, bypass pinning)
#   - npx @<scope>/pkg@latest    (unpinned @latest)
#   - npx <pkg>@latest           (unpinned @latest, unscoped)
#   - npx <anything>             (any npx invocation; all npx runtime-fetches prohibited)
#   - uvx <anything>             (runtime-fetch, Python equivalent)
#   - Docker image ref without @sha256: digest (tagged but not digest-pinned)
#   - Docker image ref without tag AND without digest (e.g. FROM ubuntu, FROM node)
#     FIX OI-12-A (N-A): tag-less bare images (e.g. FROM ubuntu with no :tag or @sha256:)
#     are now caught by UNDIGESTED_BARE_IMAGE_PATTERN in addition to tagged-undigested.
#   - Undigested image in mcp.json server args (e.g. docker run node:20 in args)
#     FIX OI-12-B (N-B): mcp.json .servers[].args is now scanned for undigested image refs.
#
# BUG fixes from plan-validator round-2 (BUG-1, BUG-2):
#   BUG-1: replaced inert "2>/dev/null" glob guard with "shopt -s nullglob" so an
#          empty directory does not produce a literal *.json loop token.
#          The no-match case still fails closed (no servers = OK for zero-server default).
#   BUG-2: SPEC-06 section 3 prose said "union of all records' covered-sets" but the
#          composability gate (ci/mcp-composability-gate.sh) requires a SINGLE record
#          whose covered-set exactly equals the current set. This script does not duplicate
#          the composability gate; the prose in SPEC-06 section 3 was updated to say
#          "a single record" to match the script behavior. See ci/mcp-composability-gate.sh.
#
# Zero-server default: on a fresh checkout with the shipped mcp.json (empty servers
# object), this script produces NO prohibited-pattern matches and exits 0. This is the
# correct behavior: the zero-server file has no npx/uvx/undigested-image references.
#
# Exit codes:
#   0 - no prohibited patterns found (OK)
#   1 - at least one prohibited pattern found (build MUST fail)
#
# Source: SPEC-06 section 5. Enforces AC-MCP-N01 and RT-MCP-05.
# Also runs mcp-scan if a server is present and mcp-scan is available (OI-12-G).

set -euo pipefail

MCP_JSON_PATH="${MCP_JSON_PATH:-.vscode/mcp.json}"

# Additional per-agent MCP config paths (SPEC-24 section 5, multi-agent extension).
# Claude Code: .mcp.json (workspace root, project-level)
CLAUDE_MCP_JSON_PATH="${CLAUDE_MCP_JSON_PATH:-.mcp.json}"
# Codex: ~/.codex/config.toml (per-profile named volume, baked into managed-config)
CODEX_CONFIG_PATH="${CODEX_CONFIG_PATH:-src/managed-config/codex/config.toml}"

# Files to scan for prohibited npx/uvx patterns.
# shopt -s nullglob (BUG-1 fix): ensures globs that match nothing produce an empty list,
# not a literal pattern token. This is set ONCE at the top so it applies to all file loops below.
shopt -s nullglob

FILES_TO_SCAN=(
  # Copilot (existing)
  ".vscode/mcp.json"
  "mcp.json"
  # Claude Code (SPEC-24 section 5)
  ".mcp.json"
  # Dockerfiles and compose (existing + new per-agent Dockerfiles)
  "Dockerfile"
  "Dockerfile.dev"
  "Dockerfile.gateway"
  "Dockerfile.claude"
  "Dockerfile.codex"
  ".devcontainer/devcontainer.json"
)

# Collect Dockerfile.* and *.Dockerfile and docker-compose*.yml using globbing.
# nullglob (set above) means these arrays are empty if no match - not a literal-token error.
# We use += to build the scan list safely; "${ARRAY[@]+${ARRAY[@]}}" expands safely even
# when the array is empty under set -u (the ${var+val} form suppresses the nounset error).
DOCKERFILE_GLOBS=(Dockerfile.* *.Dockerfile)
COMPOSE_GLOBS=(docker-compose.yml docker-compose.*.yml)
# EXCLUSION: docker-compose.discovery.yml is the gateway discovery-only scaffolding
# (explicitly labeled DISCOVERY-ONLY by item 08 security reviewer). It is activated
# only as an explicit overlay override (never by the normal stack) and uses ubuntu:22.04
# for an ephemeral discovery environment, not for a shipped MCP server image.
# Exclude it from the MCP supply-chain scan scope.
COMPOSE_GLOBS_FILTERED=()
for cf in "${COMPOSE_GLOBS[@]}"; do
  case "$cf" in
    *discovery*) echo "[mcp-supply-chain] NOTE: excluding $cf (discovery scaffolding, not MCP server config)" >&2 ;;
    *) COMPOSE_GLOBS_FILTERED+=("$cf") ;;
  esac
done
COMPOSE_GLOBS=("${COMPOSE_GLOBS_FILTERED[@]+"${COMPOSE_GLOBS_FILTERED[@]}"}")

# Combine into the full scan list.
# Use "${array[@]+"${array[@]}"}" idiom to handle empty arrays safely under set -u.
ALL_FILES_TO_SCAN=("${FILES_TO_SCAN[@]}")
[ "${#DOCKERFILE_GLOBS[@]}" -gt 0 ] && ALL_FILES_TO_SCAN+=("${DOCKERFILE_GLOBS[@]}")
[ "${#COMPOSE_GLOBS[@]}" -gt 0 ] && ALL_FILES_TO_SCAN+=("${COMPOSE_GLOBS[@]}")

# === Pattern definitions ===

# Pattern 1: npx -y or --yes (auto-yes runtime-fetch)
NPX_AUTO_PATTERN='npx[[:space:]]+(--yes|-y)[[:space:]]'

# Pattern 2: npx ...@latest (unpinned @latest)
NPX_LATEST_PATTERN='npx[[:space:]]+[^[:space:]]*@latest'

# Pattern 3: any npx invocation (fail-closed: ALL npx runtime fetches are prohibited;
# only pre-built binaries are permitted for MCP server delivery)
NPX_ANY_PATTERN='npx[[:space:]]'

# Pattern 4: uvx (any invocation: always runtime-fetch, always prohibited)
UVX_PATTERN='uvx[[:space:]]'

# Pattern 5a: Docker image reference with a tag but WITHOUT a @sha256: digest.
# Catches: "image: node:20", "FROM node:20-slim", etc.
# Does NOT catch digest-pinned refs like "node@sha256:abc123" (the [^@] stops before @).
# False-positive note: this may flag non-image uses of "image:" or "FROM" in comments.
# The CI gate treats all matches as violations; review the match before overriding.
UNDIGESTED_TAGGED_IMAGE_PATTERN='(^|[[:space:]])(image:|FROM)[[:space:]]+[^[:space:]@#]+:[^[:space:]@#]+'

# Pattern 5b: FIX OI-12-A (N-A): Docker image reference WITHOUT a tag AND without a @sha256: digest.
# Catches bare references like "FROM ubuntu", "FROM node", "FROM python" (implicit :latest, no digest).
# The tagged pattern above requires a colon; this pattern catches the no-colon-no-@ case.
# Pattern: (image:|FROM) followed by a bare name with NO colon and NO @ sign.
UNDIGESTED_BARE_IMAGE_PATTERN='(^|[[:space:]])(image:|FROM)[[:space:]]+[^[:space:]:@#]+'

FAILED=0

# === Scan text-based files for npx/uvx/undigested-image patterns ===
for f in "${ALL_FILES_TO_SCAN[@]}"; do
  if [ ! -f "$f" ]; then
    continue
  fi

  # Check npx -y / --yes
  if grep -qE "$NPX_AUTO_PATTERN" "$f" 2>/dev/null; then
    echo "[mcp-supply-chain] FAIL: 'npx -y' (auto-yes, runtime-fetch) found in $f" >&2
    grep -nE "$NPX_AUTO_PATTERN" "$f" >&2 || true
    FAILED=1
  fi

  # Check npx @latest / pkg@latest
  if grep -qE "$NPX_LATEST_PATTERN" "$f" 2>/dev/null; then
    echo "[mcp-supply-chain] FAIL: 'npx ...@latest' (unpinned) found in $f" >&2
    grep -nE "$NPX_LATEST_PATTERN" "$f" >&2 || true
    FAILED=1
  fi

  # Check any npx invocation (fail-closed)
  if grep -qE "$NPX_ANY_PATTERN" "$f" 2>/dev/null; then
    echo "[mcp-supply-chain] FAIL: 'npx' invocation found in $f (all npx runtime-fetches are prohibited; use pre-built binary instead)" >&2
    grep -nE "$NPX_ANY_PATTERN" "$f" >&2 || true
    FAILED=1
  fi

  # Check uvx
  if grep -qE "$UVX_PATTERN" "$f" 2>/dev/null; then
    echo "[mcp-supply-chain] FAIL: 'uvx' invocation found in $f (runtime-fetch prohibited)" >&2
    grep -nE "$UVX_PATTERN" "$f" >&2 || true
    FAILED=1
  fi

  # Check undigested image references in Dockerfile/compose files ONLY (not mcp.json text).
  # mcp.json args are handled separately below (FIX OI-12-B).
  #
  # DIGEST-EXCLUSION (FIX FINDING-15-01): grep -v '@sha256:' filters out lines that are
  # already digest-pinned in the form "image:tag@sha256:<digest>" or "image@sha256:<digest>".
  # The ERE pattern for UNDIGESTED_TAGGED_IMAGE_PATTERN matches the "name:tag" sub-string even
  # when the full reference is "name:tag@sha256:digest" (the pattern stops before @, but
  # grep still reports the line as matching). Without this filter, properly pinned
  # "name:tag@sha256:digest" references are flagged as false positives.
  # The same exclusion applies to UNDIGESTED_BARE_IMAGE_PATTERN: "name@sha256:digest" would
  # match the bare-name pattern since [^[:space:]:@#]+ matches "name" up to @.
  # Fix: pipe through "grep -v '@sha256:'" so that any line already containing a @sha256:
  # digest is excluded from the violation set. A line with a @sha256: digest IS pinned.
  case "$f" in
    Dockerfile*|*.Dockerfile|docker-compose*.yml)
      # Tagged but not digest-pinned (e.g. FROM node:20).
      # Lines with "@sha256:" already present are excluded (those are properly pinned).
      if grep -E "$UNDIGESTED_TAGGED_IMAGE_PATTERN" "$f" 2>/dev/null | grep -qv '@sha256:'; then
        echo "[mcp-supply-chain] FAIL: image reference with tag but without @sha256: digest found in $f" >&2
        grep -nE "$UNDIGESTED_TAGGED_IMAGE_PATTERN" "$f" 2>/dev/null | grep -v '@sha256:' >&2 || true
        FAILED=1
      fi
      # FIX OI-12-A (N-A): bare image with no tag and no digest (e.g. FROM ubuntu).
      # Lines with "@sha256:" already present are excluded (those are properly pinned).
      if grep -E "$UNDIGESTED_BARE_IMAGE_PATTERN" "$f" 2>/dev/null | grep -qv '@sha256:'; then
        echo "[mcp-supply-chain] FAIL: bare image reference (no tag, no digest) found in $f - even tagless images must be digest-pinned" >&2
        grep -nE "$UNDIGESTED_BARE_IMAGE_PATTERN" "$f" 2>/dev/null | grep -v '@sha256:' >&2 || true
        FAILED=1
      fi
      ;;
  esac
done

# === SPEC-24 SECTION 5: Codex config.toml scan for [mcp_servers.*] tables ===
# Zero MCP servers for Codex = no [mcp_servers.*] tables in config.toml.
# Source: SPEC-24 section 4; developers.openai.com/codex/config-advanced (2026-06-17).
# AC-24-N03: Adding a [mcp_servers.*] table to Codex config.toml must fail this scan.
if [ -f "$CODEX_CONFIG_PATH" ]; then
  if grep -qE '^\[mcp_servers\.' "$CODEX_CONFIG_PATH" 2>/dev/null; then
    echo "[mcp-supply-chain] FAIL: [mcp_servers.*] table found in Codex config at $CODEX_CONFIG_PATH" >&2
    echo "[mcp-supply-chain] Review: are these servers cleared by SPEC-06 section 3 gate and section 4 checklist?" >&2
    grep -nE '^\[mcp_servers\.' "$CODEX_CONFIG_PATH" >&2 || true
    FAILED=1
  else
    echo "[mcp-supply-chain] OK: no [mcp_servers.*] tables in Codex config at $CODEX_CONFIG_PATH (zero-MCP default confirmed)" >&2
  fi
fi

# === SPEC-24 SECTION 5: Claude .mcp.json structured scan (mcpServers key) ===
# AC-24-N01: Adding a server to .mcp.json without clearing the gate must fail this scan.
if [ -f "$CLAUDE_MCP_JSON_PATH" ] && command -v jq >/dev/null 2>&1; then
  CLAUDE_MCP_COUNT=$(jq -r '(.mcpServers // {}) | length' "$CLAUDE_MCP_JSON_PATH" 2>/dev/null || echo "0")
  if [ "$CLAUDE_MCP_COUNT" != "0" ]; then
    echo "[mcp-supply-chain] FAIL: non-empty mcpServers in Claude MCP config at $CLAUDE_MCP_JSON_PATH" >&2
    echo "[mcp-supply-chain] Review: are these servers cleared by SPEC-06 section 3 gate and section 4 checklist?" >&2
    jq '.mcpServers' "$CLAUDE_MCP_JSON_PATH" >&2 || true
    FAILED=1
  else
    echo "[mcp-supply-chain] OK: mcpServers is empty in Claude MCP config at $CLAUDE_MCP_JSON_PATH (zero-MCP default confirmed)" >&2
  fi
fi

# === RC-1 FIX: scan mcp.json .servers[].command and .args[] tokens for npx/uvx/runtime-fetch ===
# FIX OI-12-B (N-B): scan mcp.json .servers[].args for undigested image references.
#
# RC-1 (security-reviewer required change): the text-based npx/uvx patterns above require
# trailing whitespace (e.g. "npx[[:space:]]"), so they do NOT catch the idiomatic JSON form
# where npx or uvx appears as a standalone token:
#   "command": "npx", "args": ["-y", "@evil/mcp-server"]
# Use jq to extract each server's .command field AND each .args[] element, then match
# bare npx/uvx tokens, npx -y/--yes flags, @latest version tags, and tagged-no-digest
# image refs. This closes AC-MCP-N01 / RT-MCP-05 for the idiomatic npx-as-command form.
#
# The existing text-based scan (above) continues to catch cases in Dockerfiles, compose
# files, and any inline text forms. This jq block catches the structured JSON token forms
# that the text-scan misses.
if [ -f "$MCP_JSON_PATH" ] && command -v jq >/dev/null 2>&1; then
  # Extract each server entry's command field and all args[] tokens as separate lines.
  # Output format: one token per line, interleaving command then args for each server.
  # jq expression: for each server entry, yield (.value.command // "") then each .value.args[] element.
  # NOTE: Copilot mcp.json uses "servers" key; Claude .mcp.json uses "mcpServers" key.
  # This RC-1 block scans the Copilot mcp.json (.servers). The Claude .mcp.json scan
  # uses the SPEC-24 section above (.mcpServers empty check) - no RC-1 structured scan
  # needed for Claude if mcpServers is confirmed empty by the SPEC-24 check.
  SERVER_TOKENS=$(jq -r '(.servers // {}) | to_entries[] |
    (.value.command // ""),
    (.value.args // [] | .[])' "$MCP_JSON_PATH" 2>/dev/null || true)

  if [ -n "$SERVER_TOKENS" ]; then
    # We also need to know which tokens are command values (not args) for the bare npx/uvx check.
    # Re-extract just the command fields for the "bare command" check.
    SERVER_COMMANDS=$(jq -r '(.servers // {}) | to_entries[] | .value.command // ""' "$MCP_JSON_PATH" 2>/dev/null || true)
    # Re-extract just the args for the arg-specific checks.
    SERVER_ARGS=$(jq -r '(.servers // {}) | to_entries[] | .value.args // [] | .[]' "$MCP_JSON_PATH" 2>/dev/null || true)

    # Check .command fields: bare npx or uvx as the command value is a runtime-fetch invocation.
    if [ -n "$SERVER_COMMANDS" ]; then
      while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        # Bare npx or uvx as the .command value (RC-1: the exact gap identified by the security reviewer).
        if echo "$cmd" | grep -qE '^(npx|uvx)$' 2>/dev/null; then
          echo "[mcp-supply-chain] FAIL: mcp.json server .command is '${cmd}' (runtime-fetch runtime loader - prohibited; pre-build the server binary into the image instead)" >&2
          FAILED=1
        fi
      done <<< "$SERVER_COMMANDS"
    fi

    # Check .args[] tokens: npx/uvx appearing as first arg, -y/--yes flags, @latest tags,
    # and undigested image references (N-B fix, extended to cover more arg positions).
    if [ -n "$SERVER_ARGS" ]; then
      while IFS= read -r arg; do
        [ -z "$arg" ] && continue

        # npx or uvx as a bare arg token (e.g. args: ["npx", "-y", "@pkg"]).
        if echo "$arg" | grep -qE '^(npx|uvx)$' 2>/dev/null; then
          echo "[mcp-supply-chain] FAIL: mcp.json server args contain '${arg}' as a bare token (runtime-fetch loader - prohibited)" >&2
          FAILED=1
        fi

        # -y / --yes flag (npx auto-yes, runtime-fetch bypass).
        if echo "$arg" | grep -qE '^(-y|--yes)$' 2>/dev/null; then
          echo "[mcp-supply-chain] FAIL: mcp.json server args contain '${arg}' (npx auto-yes runtime-fetch flag - prohibited)" >&2
          FAILED=1
        fi

        # @latest version tag in any arg (e.g. "@scope/pkg@latest" or "pkg@latest").
        if echo "$arg" | grep -qE '@latest' 2>/dev/null; then
          echo "[mcp-supply-chain] FAIL: mcp.json server args contain '@latest' in '${arg}' (unpinned @latest version tag - prohibited; pin to exact digest)" >&2
          FAILED=1
        fi

        # Tagged-but-no-digest image reference in args (N-B fix): contains : but not @sha256:.
        # Skip flags (--*) and paths (/*).
        if [[ "$arg" == --* ]] || [[ "$arg" == /* ]]; then
          continue
        fi
        if echo "$arg" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9._-]+$' 2>/dev/null; then
          echo "[mcp-supply-chain] FAIL: possible undigested image reference in mcp.json server args: '${arg}' (has :tag but no @sha256: digest)" >&2
          FAILED=1
        fi
      done <<< "$SERVER_ARGS"
    fi
  fi
elif [ -f "$MCP_JSON_PATH" ] && ! command -v jq >/dev/null 2>&1; then
  # Fallback text scan of mcp.json for image-like patterns in the raw text.
  # This is less precise than the jq path but catches obvious cases.
  if grep -qE '"[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9._-]+"' "$MCP_JSON_PATH" 2>/dev/null; then
    echo "[mcp-supply-chain] WARNING: possible tagged image reference in $MCP_JSON_PATH (jq not available for precise args scan)" >&2
    echo "[mcp-supply-chain] Install jq for accurate mcp.json args scanning (OI-12-B)." >&2
    # Do not fail the build on the fallback text scan alone: too many false positives
    # (JSON strings with colons are common). The precise scan requires jq.
  fi
fi

# === OI-12-G: mcp-scan in CI ===
# Run mcp-scan if a server is present and the tool is available.
# For the zero-server default, this block does nothing (jq returns empty servers).
# The CI step MUST EXIST so a future server addition triggers the scan automatically.
# If mcp-scan is not installed, stub the check with a clear TODO.
if [ -f "$MCP_JSON_PATH" ] && command -v jq >/dev/null 2>&1; then
  SERVER_COUNT=$(jq '(.servers // {}) | length' "$MCP_JSON_PATH" 2>/dev/null || echo "0")
  if [ "$SERVER_COUNT" -gt 0 ]; then
    echo "[mcp-supply-chain] $SERVER_COUNT server(s) detected in $MCP_JSON_PATH - running mcp-scan..." >&2
    if command -v mcp-scan >/dev/null 2>&1; then
      # Run mcp-scan with tool-pinning to detect tool-description hash changes.
      # The exact flag name (--stored / --tool-pinning) must be verified against the
      # installed mcp-scan version. This is the OI-12-G CI step.
      if mcp-scan scan "$MCP_JSON_PATH" 2>&1; then
        echo "[mcp-supply-chain] mcp-scan: CLEAN" >&2
      else
        echo "[mcp-supply-chain] FAIL: mcp-scan found issues in $MCP_JSON_PATH" >&2
        FAILED=1
      fi
    else
      echo "[mcp-supply-chain] WARNING: mcp-scan is not installed." >&2
      echo "[mcp-supply-chain] TODO: Install mcp-scan (pip install mcp-scan or equivalent) and" >&2
      echo "[mcp-supply-chain] re-run this CI step to scan for tool poisoning / FSP (SPEC-06 section 10)." >&2
      echo "[mcp-supply-chain] Exact install command: pip install mcp-scan  (verify version against installed)" >&2
      echo "[mcp-supply-chain] Exact scan command:    mcp-scan scan $MCP_JSON_PATH" >&2
      echo "[mcp-supply-chain] This is a REQUIRED gate when servers are present (OI-12-G, AC-MCP-07)." >&2
      # Fail the build when servers are present and mcp-scan is not installed.
      # The scan MUST run when servers exist; its absence is a gap, not a pass.
      FAILED=1
    fi
  else
    echo "[mcp-supply-chain] Zero servers in $MCP_JSON_PATH - mcp-scan step skipped (nothing to scan)." >&2
  fi
fi

if [ "$FAILED" -eq 1 ]; then
  echo "[mcp-supply-chain] FATAL: prohibited supply-chain pattern found or mcp-scan required but missing." >&2
  echo "[mcp-supply-chain] Fix: pre-build MCP server binaries into the image at build time." >&2
  echo "[mcp-supply-chain] Fix: pin all image references to @sha256: digests." >&2
  echo "[mcp-supply-chain] Fix: install mcp-scan if servers are present." >&2
  echo "[mcp-supply-chain] See SPEC-06 section 5, ADR-006 D4." >&2
  exit 1
fi

echo "[mcp-supply-chain] OK: no prohibited supply-chain patterns found."
