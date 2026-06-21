#!/bin/bash
# src/dev/.bashrc-hardening.sh
# Item 10, ADR-003 D1 (defense-in-depth shell hardening).
#
# PURPOSE: Re-clears the VS Code credential-forwarding variables at shell start.
#
# HEADLESS DEFAULT (ADR-003 D2): Under the headless Copilot CLI model (no VS Code
# server inside the container), the variables cleared below DO NOT EXIST. VS Code
# never injects IPC sockets or credential helpers into a headless container. This
# script is a STRUCTURAL NO-OP under the headless default.
#
# VS CODE FALLBACK MODEL ONLY: When the fallback model is used (VS Code server
# attached to the container), VS Code RE-INJECTS some of these vars after
# devcontainer.json's remoteEnv has already cleared them. Area 3 verified:
# "despite remoteEnv clearing them, echo $VSCODE_IPC_HOOK_CLI still returns a
# live socket path." This script provides defense-in-depth by re-clearing at
# shell start for every new terminal/shell session.
#
# This script is sourced from /home/devuser/.bashrc (or equivalent). It does NOT
# replace the devcontainer.json remoteEnv block; it is a defense-in-depth layer
# ON TOP of that block. The socket-cleanup.sh daemon (also FALLBACK-ONLY) handles
# the socket file cleanup.
#
# DETECTION WIRING: If HOOK_LOG_SINK is set (item 13 wires this to the external
# detection sink), this script emits a startup event to the sink. Under the headless
# default HOOK_LOG_SINK is not yet set at shell start; this block is a no-op.
# Item 13 sets HOOK_LOG_SINK; this block picks it up automatically on later shells.
#
# MAINTENANCE: If VS Code adds new IPC or credential-forwarding variables in a
# future release, add them here AND to the containerEnv/remoteEnv blocks in
# devcontainer.json. This script is a lagging defense; devcontainer.json is the
# primary control.

# --- Clear credential-forwarding variables (ADR-003 D1) ----------------------

# SSH agent forwarding socket: clearing this prevents in-container processes
# from accessing the host SSH agent (the Red Guild demonstrated SSH'ing onward
# from inside the container via this socket).
unset SSH_AUTH_SOCK

# Git credential brokering via VS Code UI: prevents credential prompt callbacks
# to the host desktop (the askpass flow routes credential prompts to the VS Code
# UI on the host).
unset GIT_ASKPASS
unset VSCODE_GIT_ASKPASS_MAIN
unset VSCODE_GIT_ASKPASS_NODE
unset VSCODE_GIT_ASKPASS_EXTRA_ARGS

# GitHub token inheritance: prevents the host GH_TOKEN or GITHUB_TOKEN from
# being usable inside the container. NOTE: this does NOT break the Copilot CLI.
# The CLI authenticates via its own device-flow, storing the token in ~/.copilot/
# (a named volume, agent-home). It does not rely on an inherited GH_TOKEN.
unset GH_TOKEN
unset GITHUB_TOKEN

# Browser forwarding: prevents host browser callbacks (used by some auth flows
# and by GIT_ASKPASS to open a browser-based auth page).
unset BROWSER

# GPG agent forwarding: prevents host pinentry and GPG key access.
unset GPG_AGENT_INFO

# VS Code IPC channel (FALLBACK-ONLY, see header):
# VSCODE_IPC_HOOK_CLI is the primary container-escape vector identified in Area 3.
# The TerminalService API accessible via this socket allows in-container code to
# execute arbitrary commands on the HOST (the Red Guild demo). VS Code re-injects
# this after remoteEnv clears it; we clear it again here at shell start.
# Under the headless default this var was never set; unset is harmless.
unset VSCODE_IPC_HOOK_CLI
unset VSCODE_GIT_IPC_HANDLE
unset REMOTE_CONTAINERS_IPC
unset REMOTE_CONTAINERS_SOCKETS
unset REMOTE_CONTAINERS_DISPLAY_SOCK

# Ephemeralize shell history (ADR-003 D5: no-secrets-in-env, HISTFILE/HISTSIZE).
# A typed secret (e.g. a PAT pasted into the terminal) must not persist to a
# readable history file.
export HISTFILE=/dev/null
export HISTSIZE=0
unset HISTFILE

# --- Detection wiring (item 13 picks this up via HOOK_LOG_SINK) ---------------
if [ -n "${HOOK_LOG_SINK:-}" ]; then
    # HOOK_LOG_SINK is set when item 13's detection wiring is active.
    # Emit a shell-start event to the sink for audit trail.
    # Format is compatible with the item 13 enriched log-line format (SPEC-07 section 2a).
    _TS=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")
    _MSG="{\"timestamp\":\"${_TS}\",\"component\":\"bashrc-hardening\",\"event\":\"shell_start\",\"uid\":\"$(id -u 2>/dev/null || echo unknown)\",\"pid\":\"$$\"}"
    # Fire-and-forget: do not block shell startup on sink availability.
    curl -s -X POST -H "Content-Type: application/json" \
        -d "${_MSG}" "${HOOK_LOG_SINK}" >/dev/null 2>&1 &
    disown $! 2>/dev/null || true
fi
