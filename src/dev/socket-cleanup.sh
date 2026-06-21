#!/bin/bash
# src/dev/socket-cleanup.sh
# Item 10, ADR-003 D1 (socket-cleanup daemon, VS Code FALLBACK MODEL ONLY).
#
# FALLBACK-ONLY: This script is ONLY relevant when the VS Code FALLBACK model is
# used (VS Code server attached to the container with IPC sockets present). Under
# the headless default (ADR-003 D2), NO vscode-*.sock files are created and this
# script is a NO-OP (the sweep finds nothing to delete).
#
# PURPOSE: Periodically delete the VS Code credential-forwarding sockets that VS
# Code creates inside the container after attaching (the fallback model). VS Code
# creates these sockets AFTER the devcontainer.json remoteEnv nulling has already
# been applied and AFTER the container starts. The .bashrc-hardening.sh re-clears
# the env vars; this script deletes the actual socket files.
#
# SOCKETS SWEPT:
#   /tmp/vscode-ipc-*.sock          - VS Code IPC channel (VSCODE_IPC_HOOK_CLI)
#   /tmp/vscode-git-*.sock          - VS Code git IPC channel
#   /tmp/vscode-ssh-auth-*.sock     - SSH agent forwarding socket
#   /tmp/vscode-remote-containers-*.js - The credential-helper brokering script
#                                      injected by VS Code to point git at the
#                                      host credential broker.
#
# RACE WINDOW (UNAVOIDABLE):
# VS Code creates some sockets 60+ seconds after the container attaches. A sweep
# that runs immediately on container start will miss those sockets; a sweep running
# at 30s intervals has up to a ~30s window where a socket exists and could be used
# by an injected agent. This race window CANNOT be closed without removing the
# VS Code server from the container entirely - which is exactly what the headless
# default (ADR-003 D2) achieves. This script is best-effort defense-in-depth, NOT
# a security boundary. If zero race window is required, use the headless default.
#
# USAGE:
# Run as a background process from the container entrypoint or via a compose
# command override. The script sweeps for ~10 minutes (20 iterations x 30s) to
# cover the VS Code post-attach socket-creation window. After that, the socket
# lifecycle stabilizes and periodic cleanup is less critical.
#
# Example (run in background at container start):
#   /usr/local/bin/socket-cleanup.sh &
#
# Or wire via systemd/supervisord if those are present (not in this image by default).
#
# SIGNAL HANDLING: SIGTERM causes a clean exit (the container orchestrator may
# send SIGTERM before SIGKILL; we clean up on the way out).

set -euo pipefail

SWEEP_INTERVAL_SECONDS=30
SWEEP_COUNT=20       # 20 * 30s = 10 minutes of active sweeping
LOG_PREFIX="[socket-cleanup]"

log() { echo "${LOG_PREFIX} $*" >&2; }

# Graceful exit on SIGTERM
trap 'log "SIGTERM received, exiting."; exit 0' TERM

log "Starting socket-cleanup daemon (FALLBACK-ONLY: no-op under headless default)."
log "Sweep interval: ${SWEEP_INTERVAL_SECONDS}s, sweeps: ${SWEEP_COUNT}."

SWEEP_NUM=0
while [ "${SWEEP_NUM}" -lt "${SWEEP_COUNT}" ]; do
    sleep "${SWEEP_INTERVAL_SECONDS}" &
    SLEEP_PID=$!
    # Wait for sleep, catch SIGTERM cleanly.
    wait "${SLEEP_PID}" 2>/dev/null || { log "Interrupted, exiting."; exit 0; }

    SWEEP_NUM=$(( SWEEP_NUM + 1 ))
    DELETED=0

    # Sweep /tmp for VS Code IPC sockets and credential-helper scripts.
    # -maxdepth 1: only /tmp itself, not subdirectories (the sockets are directly in /tmp).
    # 2>/dev/null: suppress "no such file" and permission errors.
    while IFS= read -r SOCK_PATH; do
        if rm -f "${SOCK_PATH}" 2>/dev/null; then
            log "Sweep ${SWEEP_NUM}: deleted ${SOCK_PATH}"
            DELETED=$(( DELETED + 1 ))
        fi
    done < <(find /tmp -maxdepth 1 \( \
        -name 'vscode-ipc-*.sock' \
        -o -name 'vscode-git-*.sock' \
        -o -name 'vscode-ssh-auth-*.sock' \
        -o -name 'vscode-remote-containers-*.js' \
    \) -type f 2>/dev/null || true)

    if [ "${DELETED}" -gt 0 ]; then
        log "Sweep ${SWEEP_NUM}: removed ${DELETED} sockets/scripts."
    else
        log "Sweep ${SWEEP_NUM}: no VS Code sockets found (expected under headless default)."
    fi
done

log "Sweep cycle complete (${SWEEP_COUNT} sweeps done). Exiting."
exit 0
