#!/usr/bin/env bash
# src/scripts/allowlist-local.sh
#
# Developer-local egress allowlist manager for AgentArca.
#
# Adds/removes extra hosts the ACTIVE agent profile may reach, on top of the shipped
# (baked, locked) base allowlist, WITHOUT editing the committed config and WITHOUT a Docker
# or gateway restart. Changes are written to a machine-local, gitignored file that the gateway
# bind-mounts READ-ONLY, then hot-applied with `squid -k reconfigure`.
#
# SECURITY MODEL (why this does not weaken the boundary):
#   - The local file is mounted READ-ONLY into the gateway. The agent shares the gateway's
#     netns but cannot write the mount, and has no docker.sock, so it cannot reconfigure Squid.
#     Only the HOST operator (you, running this script) can widen egress. The agent never can.
#   - Additions only EXTEND `allowed_SNI`; peek+splice+terminate and the L3 default-DROP are
#     unchanged. A non-listed host is still terminated.
#   - Each host added widens the writable-destination exfil surface (residual risk R-b). Add the
#     narrowest host that works; prefer discovering real needs with discover-allowlist.sh first.
#
# This script is the stable operator primitive (file format + reconfigure). A future admin UI
# is expected to drive the SAME contract.
#
# USAGE:
#   src/scripts/allowlist-local.sh add <host>      # add an SNI and hot-apply
#   src/scripts/allowlist-local.sh remove <host>   # remove an SNI and hot-apply
#   src/scripts/allowlist-local.sh list            # show local additions + active gateway
#   src/scripts/allowlist-local.sh reload          # re-apply the file (squid -k reconfigure)
#   src/scripts/allowlist-local.sh help
#
# <host> is a TLS SNI: an exact host (api.example.com) or a leading-dot subdomain wildcard
# (.internal.example.com = that domain and all subdomains; broader, use sparingly).
#
# The target gateway is auto-detected from the running profile (copilot/claude/codex).
# Override with AGENTARCA_PROFILE=claude (etc.) if needed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
LOCAL_DIR="$REPO_ROOT/config/allowlist.local.d"
LOCAL_FILE="$LOCAL_DIR/overrides.conf"
# Matches a real SNI ACL line (anchored on `acl`, so '#' comment lines never match).
ACL_RE='^[[:space:]]*acl[[:space:]]+allowed_SNI[[:space:]]+ssl::server_name[[:space:]]+'

log()  { echo "[allowlist-local] $*"; }
die()  { echo "[allowlist-local] ERROR: $*" >&2; exit 1; }

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# ---- host validation -------------------------------------------------------------------
# Accept an optional leading dot, dot-separated labels (alnum + internal hyphens), alpha TLD.
# Reject anything with shell/Squid metacharacters, whitespace, '*', etc. — the value is written
# verbatim into squid.conf, so this is the injection guard.
valid_host() {
  local h="$1"
  case "$h" in
    *[!A-Za-z0-9.-]*) return 1 ;;                           # only [A-Za-z0-9.-] (and a leading dot)
    *.*) ;;                                                 # must contain at least one dot (FQDN)
    *) return 1 ;;
  esac
  [[ "$h" =~ ^\.?([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]
}

# ---- active gateway detection ----------------------------------------------------------
running_container() {  # prints the container name if running, else nothing
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1" && echo "$1" || true
}

detect_gateway() {
  if [ -n "${AGENTARCA_PROFILE:-}" ]; then
    echo "${AGENTARCA_PROFILE}-gateway"; return
  fi
  local found=()
  local c
  for p in copilot claude codex; do
    c="$(running_container "${p}-gateway")"
    [ -n "$c" ] && found+=("$c")
  done
  if [ "${#found[@]}" -gt 1 ]; then
    die "multiple gateways running (${found[*]}); profiles must be mutually exclusive. Set AGENTARCA_PROFILE to pick one."
  fi
  [ "${#found[@]}" -eq 1 ] && echo "${found[0]}" || echo ""
}

ensure_file() {
  mkdir -p "$LOCAL_DIR"
  if [ ! -f "$LOCAL_FILE" ]; then
    {
      echo "# config/allowlist.local.d/overrides.conf"
      echo "# Developer-local egress allowlist additions for AgentArca (machine-local, gitignored)."
      echo "# Managed by src/scripts/allowlist-local.sh. One 'acl allowed_SNI ssl::server_name <host>' per line."
    } > "$LOCAL_FILE"
    log "created $LOCAL_FILE"
  fi
}

# ---- reconfigure -----------------------------------------------------------------------
reload_gateway() {
  local gw; gw="$(detect_gateway)"
  if [ -z "$gw" ]; then
    log "no running gateway detected; the local file will apply on the next 'docker compose --profile <agent> up'."
    return 0
  fi
  if ! running_container "$gw" >/dev/null; then
    log "gateway '$gw' is not running; changes will apply on next 'up'."
    return 0
  fi
  # Validate the MERGED config before applying (the :ro mount reflects host edits live).
  if ! docker exec "$gw" squid -k parse >/dev/null 2>&1; then
    docker exec "$gw" squid -k parse 2>&1 | tail -15 >&2 || true
    die "squid config did not parse in '$gw'; NOT reconfiguring. Fix $LOCAL_FILE and retry."
  fi
  # Reconfigure by sending SIGHUP to Squid directly. `squid -k reconfigure` does NOT work here:
  # Squid runs as the container's PID 1 (squid -N), and it refuses to signal a PID-file value of 1
  # ("unreasonably small PID"). SIGHUP to PID 1 triggers a graceful in-place re-read with no restart.
  #
  # FAIL-SAFE NOTE (do not weaken): under `squid -N` there is NO master process, so a FATAL during
  # the SIGHUP re-read kills PID 1 and the container EXITS — it does NOT keep the old config running.
  # That exit is itself fail-closed for the boundary (no gateway => no egress), but it is disruptive.
  # The `squid -k parse` gate ABOVE is therefore the SOLE protection against a bad overlay. Any caller
  # of this primitive (including a future admin UI) MUST parse-before-HUP, or a bad file bricks the gateway.
  docker exec "$gw" sh -c 'kill -HUP 1'
  log "reconfigured '$gw' (SIGHUP) — changes are live (no restart)."
}

acl_line() { echo "acl allowed_SNI ssl::server_name $1"; }

cmd_add() {
  local host="${1:-}"
  [ -n "$host" ] || die "usage: allowlist-local.sh add <host>"
  valid_host "$host" || die "'$host' is not a valid SNI host (expected e.g. api.example.com or .example.com; letters/digits/dots/hyphens only)."
  ensure_file
  if grep -qE "^[[:space:]]*acl[[:space:]]+allowed_SNI[[:space:]]+ssl::server_name[[:space:]]+${host//./\\.}[[:space:]]*$" "$LOCAL_FILE"; then
    log "'$host' already present; nothing to add."
  else
    acl_line "$host" >> "$LOCAL_FILE"
    log "added '$host' to $LOCAL_FILE"
  fi
  reload_gateway
}

cmd_remove() {
  local host="${1:-}"
  [ -n "$host" ] || die "usage: allowlist-local.sh remove <host>"
  [ -f "$LOCAL_FILE" ] || die "no local overrides file ($LOCAL_FILE)."
  local before after
  before="$(grep -cE "$ACL_RE" "$LOCAL_FILE" || true)"
  # Delete the exact matching ACL line (host is regex-escaped on the dots).
  grep -vE "^[[:space:]]*acl[[:space:]]+allowed_SNI[[:space:]]+ssl::server_name[[:space:]]+${host//./\\.}[[:space:]]*$" "$LOCAL_FILE" > "$LOCAL_FILE.tmp"
  mv "$LOCAL_FILE.tmp" "$LOCAL_FILE"
  after="$(grep -cE "$ACL_RE" "$LOCAL_FILE" || true)"
  if [ "$before" = "$after" ]; then
    log "'$host' was not present; nothing removed."
  else
    log "removed '$host' from $LOCAL_FILE"
  fi
  reload_gateway
}

cmd_list() {
  local gw; gw="$(detect_gateway || true)"
  log "active gateway: ${gw:-<none running>}"
  if [ -f "$LOCAL_FILE" ] && grep -qE "$ACL_RE" "$LOCAL_FILE"; then
    log "local additions ($LOCAL_FILE):"
    grep -E "$ACL_RE" "$LOCAL_FILE" | sed -E "s/$ACL_RE/  /"
  else
    log "no local additions yet. Add one with: allowlist-local.sh add <host>"
  fi
}

main() {
  local sub="${1:-help}"
  case "$sub" in
    add)    shift; cmd_add "${1:-}" ;;
    remove|rm) shift; cmd_remove "${1:-}" ;;
    list|ls)   cmd_list ;;
    reload)    ensure_file; reload_gateway ;;
    help|-h|--help) usage 0 ;;
    *) die "unknown subcommand '$sub' (try: add | remove | list | reload | help)" ;;
  esac
}

main "$@"
