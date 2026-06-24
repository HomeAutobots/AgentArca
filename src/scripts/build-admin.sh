#!/usr/bin/env bash
# build-admin.sh - CI build gate for the admin control plane.
#
# Exits 0 only if all assertions pass. Does NOT require Docker.
#
# Usage:
#   src/scripts/build-admin.sh           # run all assertions + non-integration tests
#   src/scripts/build-admin.sh --init    # create ~/.agentarca/ and generate admin-secret
#
# Assertions performed:
#   1. Constant-time compare: grep for == in auth.py outside compare_digest context.
#   2. Secret not in startup log: run with known test secret, grep output.
#   3. Bind assertion: run with --host 0.0.0.0, assert non-zero exit.
#   4. Startup log contains bind address: run with --host 127.0.0.1, grep output.
#   5. Unit test suite: pytest -m "not integration".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VENV_DIR="${REPO_ROOT}/.venv-admin"
PYTHON="${VENV_DIR}/bin/python"
PIP="${VENV_DIR}/bin/pip"
PYTEST="${VENV_DIR}/bin/pytest"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ---------------------------------------------------------------------------
# --init mode: generate admin secret and session directories
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--init" ]]; then
    AGENTARCA_DIR="${HOME}/.agentarca"
    SECRET_FILE="${AGENTARCA_DIR}/admin-secret"
    info "Initializing AgentArca admin directories..."
    mkdir -p "${AGENTARCA_DIR}"
    chmod 700 "${AGENTARCA_DIR}"
    if [[ -f "${SECRET_FILE}" ]]; then
        echo "Secret file already exists at ${SECRET_FILE}. Delete it first to regenerate."
        exit 1
    fi
    openssl rand -hex 32 > "${SECRET_FILE}"
    chmod 600 "${SECRET_FILE}"
    echo "Admin secret generated at ${SECRET_FILE} (mode 0600)."
    echo "IMPORTANT: treat this file as a credential. Do not commit it, log it, or share it."
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 0: Create venv and install deps
# ---------------------------------------------------------------------------
info "Creating virtual environment at ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"

info "Installing runtime dependencies (--require-hashes)..."
"${PIP}" install --quiet --require-hashes -r "${REPO_ROOT}/requirements-admin.txt"

info "Installing test dependencies (--require-hashes)..."
"${PIP}" install --quiet --require-hashes -r "${REPO_ROOT}/requirements-admin-test.txt"

# ---------------------------------------------------------------------------
# Assertion 1: No == comparison of the secret in auth.py outside compare_digest
# ---------------------------------------------------------------------------
info "Assertion 1: checking auth.py for == outside hmac.compare_digest..."
AUTH_FILE="${REPO_ROOT}/src/admin/auth.py"

# Find any line in auth.py that:
#   - contains ==
#   - is not a comment (does not start with # after stripping whitespace)
#   - does not reference compare_digest on the same logical line
BAD_LINES=$(
    grep -n '==' "${AUTH_FILE}" \
    | grep -v '#' \
    | grep -v 'compare_digest' \
    || true
)

if [[ -n "${BAD_LINES}" ]]; then
    fail "Assertion 1 FAILED: found == comparisons in auth.py outside compare_digest:\n${BAD_LINES}"
fi
pass "Assertion 1: no == comparisons outside compare_digest in auth.py."

# ---------------------------------------------------------------------------
# Assertion 2: Secret not in startup log
# ---------------------------------------------------------------------------
info "Assertion 2: checking that the secret never appears in startup log output..."
TEST_SECRET_VALUE="test-secret-value-12345"
TMPDIR_ASSERT2=$(mktemp -d)
SECRET_FILE_ASSERT2="${TMPDIR_ASSERT2}/admin-secret"
AUDIT_FILE_ASSERT2="${TMPDIR_ASSERT2}/admin-audit.jsonl"

echo "${TEST_SECRET_VALUE}" > "${SECRET_FILE_ASSERT2}"
chmod 600 "${SECRET_FILE_ASSERT2}"

# Run the app briefly, capturing all output. We expect it to log startup and then
# we kill it (or it exits if uvicorn is not started because we only call create_app).
STARTUP_LOG=$(
    AGENTARCA_ADMIN_SECRET_FILE="${SECRET_FILE_ASSERT2}" \
    AGENTARCA_ADMIN_AUDIT_LOG="${AUDIT_FILE_ASSERT2}" \
    AGENTARCA_ADMIN_SESSION_KEY="test-session-key-placeholder-$(openssl rand -hex 8)" \
    "${PYTHON}" -c "
import sys
sys.path.insert(0, '${REPO_ROOT}')
from src.admin.config import Settings
from src.admin.main import create_app
import logging
import io

# Capture log output
stream = io.StringIO()
handler = logging.StreamHandler(stream)
logging.getLogger('src.admin.main').addHandler(handler)
logging.getLogger('src.admin.main').setLevel(logging.DEBUG)

import os
from pathlib import Path
settings = Settings(
    host='127.0.0.1',
    port=8080,
    secret_file=Path('${SECRET_FILE_ASSERT2}'),
    audit_log_path=Path('${AUDIT_FILE_ASSERT2}'),
    session_secret_key='test-session-key-placeholder-xxxxx',
)
try:
    app = create_app(settings)
except SystemExit:
    pass
print(stream.getvalue())
" 2>&1
)
rm -rf "${TMPDIR_ASSERT2}"

if echo "${STARTUP_LOG}" | grep -qF "${TEST_SECRET_VALUE}"; then
    fail "Assertion 2 FAILED: the test secret appeared in startup log output. This is a BLOCK condition."
fi
pass "Assertion 2: secret not found in startup log output."

# ---------------------------------------------------------------------------
# Assertion 3: Non-loopback bind causes SystemExit (non-zero exit)
# ---------------------------------------------------------------------------
info "Assertion 3: --host 0.0.0.0 must cause non-zero exit..."
TMPDIR_ASSERT3=$(mktemp -d)
SECRET_FILE_ASSERT3="${TMPDIR_ASSERT3}/admin-secret"
echo "assertion3-secret" > "${SECRET_FILE_ASSERT3}"
chmod 600 "${SECRET_FILE_ASSERT3}"

EXIT_CODE=0
"${PYTHON}" -c "
import sys
sys.path.insert(0, '${REPO_ROOT}')
from pathlib import Path
from src.admin.config import Settings
from src.admin.main import create_app
settings = Settings(
    host='0.0.0.0',
    port=8080,
    allow_non_loopback=False,
    secret_file=Path('${SECRET_FILE_ASSERT3}'),
    audit_log_path=Path('${TMPDIR_ASSERT3}/audit.jsonl'),
    session_secret_key='x' * 32,
)
create_app(settings)
" 2>/dev/null && EXIT_CODE=0 || EXIT_CODE=$?
rm -rf "${TMPDIR_ASSERT3}"

if [[ "${EXIT_CODE}" -eq 0 ]]; then
    fail "Assertion 3 FAILED: --host 0.0.0.0 did not cause a non-zero exit. The loopback-bind assertion is broken."
fi
pass "Assertion 3: --host 0.0.0.0 causes non-zero exit (exit code: ${EXIT_CODE})."

# ---------------------------------------------------------------------------
# Assertion 4: Startup log contains bind address
# ---------------------------------------------------------------------------
info "Assertion 4: startup log must contain '127.0.0.1'..."
TMPDIR_ASSERT4=$(mktemp -d)
SECRET_FILE_ASSERT4="${TMPDIR_ASSERT4}/admin-secret"
echo "assertion4-secret" > "${SECRET_FILE_ASSERT4}"
chmod 600 "${SECRET_FILE_ASSERT4}"

STARTUP_LOG4=$(
    "${PYTHON}" -c "
import sys, logging, io
sys.path.insert(0, '${REPO_ROOT}')
from pathlib import Path
from src.admin.config import Settings
from src.admin.main import create_app

stream = io.StringIO()
handler = logging.StreamHandler(stream)
logging.getLogger('src.admin.main').addHandler(handler)
logging.getLogger('src.admin.main').setLevel(logging.INFO)

settings = Settings(
    host='127.0.0.1',
    port=8080,
    secret_file=Path('${SECRET_FILE_ASSERT4}'),
    audit_log_path=Path('${TMPDIR_ASSERT4}/audit.jsonl'),
    session_secret_key='x' * 32,
)
create_app(settings)
print(stream.getvalue())
" 2>&1
)
rm -rf "${TMPDIR_ASSERT4}"

if ! echo "${STARTUP_LOG4}" | grep -qF "127.0.0.1"; then
    fail "Assertion 4 FAILED: '127.0.0.1' not found in startup log output. Log was: ${STARTUP_LOG4}"
fi
pass "Assertion 4: '127.0.0.1' found in startup log output."

# ---------------------------------------------------------------------------
# Assertion 5: Unit test suite (excluding integration tests)
# ---------------------------------------------------------------------------
info "Assertion 5: running pytest -m 'not integration'..."
cd "${REPO_ROOT}"
"${PYTEST}" tests/admin/ -m "not integration" -v --tb=short

pass "Assertion 5: all non-integration tests passed."

echo ""
echo -e "${GREEN}All build gate assertions passed.${NC}"
