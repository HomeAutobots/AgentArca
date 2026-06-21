#!/bin/sh
# src/caches/devpi-entrypoint.sh
# devpi-server initialization entrypoint.
# Initializes the devpi server data directory on first run, then starts the server.

set -e

SERVERDIR="${DEVPI_SERVERDIR:-/devpi}"

# Initialize devpi-server if the data directory is empty.
if [ ! -f "${SERVERDIR}/.nodeinfo" ]; then
    echo "[devpi-entrypoint] Initializing devpi server at ${SERVERDIR}..."
    devpi-init --serverdir "${SERVERDIR}"
    echo "[devpi-entrypoint] Initialization complete."
else
    echo "[devpi-entrypoint] devpi server data found at ${SERVERDIR}, skipping init."
fi

echo "[devpi-entrypoint] Starting devpi-server on 0.0.0.0:3141..."
exec devpi-server --host 0.0.0.0 --port 3141 --serverdir "${SERVERDIR}"
