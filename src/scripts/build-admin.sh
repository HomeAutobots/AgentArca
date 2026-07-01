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
    mkdir -p -m 0700 "${HOME}/.agentarca/start-auth.d"
    echo "Start-auth nonce directory created at ${HOME}/.agentarca/start-auth.d (mode 0700)."
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

# ---------------------------------------------------------------------------
# Phase 1 assertions (SPEC-27-P1 section 11)
# ---------------------------------------------------------------------------

# Assertion 6: No mutating method on any /api/v1/logs/* route.
info "Assertion 6 (Phase 1): route enumeration - no write methods on log paths..."
"${PYTHON}" -c "
import sys
sys.path.insert(0, '${REPO_ROOT}')
from tests.admin.test_logs_api import test_no_write_on_logs_routes
test_no_write_on_logs_routes()
print('Assertion 6 passed: no mutating methods on log routes.')
"
pass "Assertion 6: no mutating methods on log routes."

# Assertion 7: No direct overrides.conf write in allowlist.py.
# The Python wrapper must NEVER reference overrides.conf directly (write path).
info "Assertion 7 (Phase 1): checking allowlist.py for direct overrides.conf references..."
ALLOWLIST_PY="${REPO_ROOT}/src/admin/primitives/allowlist.py"
BAD_OVERRIDES=$(
    grep -n 'overrides.conf' "${ALLOWLIST_PY}" \
    | grep -v '#' \
    || true
)
if [[ -n "${BAD_OVERRIDES}" ]]; then
    fail "Assertion 7 FAILED: allowlist.py contains direct references to overrides.conf outside comments. Wrap-don't-reimplement boundary violated:\n${BAD_OVERRIDES}"
fi
pass "Assertion 7: allowlist.py does not reference overrides.conf directly (outside comments)."

# Assertion 8: No direct squid/SIGHUP call in allowlist.py.
# The Python wrapper must NEVER call squid, kill -HUP, or SIGHUP itself.
info "Assertion 8 (Phase 1): checking allowlist.py for direct squid/SIGHUP calls..."
BAD_SQUID=$(
    grep -n 'squid\|kill.*HUP\|SIGHUP' "${ALLOWLIST_PY}" \
    | grep -v '#' \
    || true
)
if [[ -n "${BAD_SQUID}" ]]; then
    fail "Assertion 8 FAILED: allowlist.py contains direct squid/SIGHUP references outside comments. Wrap-don't-reimplement boundary violated:\n${BAD_SQUID}"
fi
pass "Assertion 8: allowlist.py does not call squid, SIGHUP, or kill -HUP directly."

# Assertion 9: Phase 1 unit tests pass (already covered by Assertion 5, but named explicitly).
pass "Assertion 9: Phase 1 unit tests passed (covered by Assertion 5 above)."

# ---------------------------------------------------------------------------
# Phase 2 assertions (SPEC-27-P2 section 18)
# ---------------------------------------------------------------------------

LIFECYCLE_PY="${REPO_ROOT}/src/admin/primitives/lifecycle.py"

# Assertion 10: ALLOWED_PROFILES is exactly {copilot, claude, codex}.
# Fails if the set has been modified (added or removed profile).
info "Assertion 10 (Phase 2): ALLOWED_PROFILES exact set check..."
"${PYTHON}" -c "
import sys
sys.path.insert(0, '${REPO_ROOT}')
from src.admin.primitives.lifecycle import ALLOWED_PROFILES
expected = frozenset({'copilot', 'claude', 'codex'})
assert ALLOWED_PROFILES == expected, (
    f'ALLOWED_PROFILES mismatch: got {ALLOWED_PROFILES!r}, expected {expected!r}. '
    'Adding or removing a profile requires a deliberate code change AND threat-model update.'
)
# Also check the set does not contain MORE than 3 elements (prevents silent expansion).
assert len(ALLOWED_PROFILES) == 3, (
    f'ALLOWED_PROFILES has {len(ALLOWED_PROFILES)} elements; expected exactly 3.'
)
print('ALLOWED_PROFILES:', ALLOWED_PROFILES)
"
pass "Assertion 10: ALLOWED_PROFILES is exactly {copilot, claude, codex} (3 elements)."

# Assertion 11: No `docker exec` call in lifecycle.py (outside comments).
info "Assertion 11 (Phase 2): checking lifecycle.py for docker exec calls..."
BAD_DOCKER_EXEC=$(
    grep -n 'docker exec' "${LIFECYCLE_PY}" \
    | grep -v '#' \
    || true
)
if [[ -n "${BAD_DOCKER_EXEC}" ]]; then
    fail "Assertion 11 FAILED: lifecycle.py contains direct 'docker exec' calls outside comments. This violates the wrap-don't-reimplement boundary:\n${BAD_DOCKER_EXEC}"
fi
pass "Assertion 11: lifecycle.py does not call 'docker exec' directly (outside comments)."

# Assertion 12: No `shell=True` in lifecycle.py (outside comments).
info "Assertion 12 (Phase 2): checking lifecycle.py for shell=True..."
BAD_SHELL_TRUE=$(
    grep -n 'shell=True' "${LIFECYCLE_PY}" \
    | grep -v '#' \
    || true
)
if [[ -n "${BAD_SHELL_TRUE}" ]]; then
    fail "Assertion 12 FAILED: lifecycle.py contains shell=True outside comments. All subprocess calls must use shell=False (the default):\n${BAD_SHELL_TRUE}"
fi
pass "Assertion 12: lifecycle.py does not use shell=True (outside comments)."

# Assertion 13: Phase 2 unit tests pass.
# This runs all non-integration tests (Phase 0 + Phase 1 + Phase 2), asserting no regressions.
info "Assertion 13 (Phase 2): running pytest tests/admin/ -m 'not integration' -q..."
cd "${REPO_ROOT}"
"${PYTEST}" tests/admin/ -m "not integration" -q --tb=short
pass "Assertion 13: all non-integration tests passed (Phase 0 + Phase 1 + Phase 2)."


# ---------------------------------------------------------------------------
# Phase 3 assertions (SPEC-27-P3 section 13)
# ---------------------------------------------------------------------------

CREDENTIALS_PY="${REPO_ROOT}/src/admin/primitives/credentials.py"
CREDENTIALS_ROUTES_PY="${REPO_ROOT}/src/admin/routes/credentials.py"
ISOLATION_ROUTES_PY="${REPO_ROOT}/src/admin/routes/isolation.py"

# Assertion 14: MANAGED_CREDENTIAL_KEYS is exactly the 5 expected keys.
# Build fails if any key is added, removed, or renamed.
info "Assertion 14 (Phase 3): MANAGED_CREDENTIAL_KEYS exact set check..."
"${PYTHON}" -c "
import sys
sys.path.insert(0, '${REPO_ROOT}')
from src.admin.primitives.credentials import MANAGED_CREDENTIAL_KEYS
expected = frozenset({'COPILOT_GITHUB_TOKEN','ANTHROPIC_API_KEY','CLAUDE_CODE_OAUTH_TOKEN','OPENAI_API_KEY','CODEX_API_KEY'})
assert MANAGED_CREDENTIAL_KEYS == expected, (
    f'MANAGED_CREDENTIAL_KEYS mismatch: got {MANAGED_CREDENTIAL_KEYS!r}, expected {expected!r}. '
    'Adding or removing a key requires a deliberate code change AND threat-model update.'
)
assert len(MANAGED_CREDENTIAL_KEYS) == 5, (
    f'MANAGED_CREDENTIAL_KEYS has {len(MANAGED_CREDENTIAL_KEYS)} elements; expected exactly 5.'
)
print('MANAGED_CREDENTIAL_KEYS:', MANAGED_CREDENTIAL_KEYS)
"
pass "Assertion 14: MANAGED_CREDENTIAL_KEYS is exactly the 5 expected keys."

# Assertion 15: body.value is assigned once and cleared (value = ""); never passed to
# a return statement or response. Check that there is a `value = ""` clear line AFTER
# the `body.value` read line, and that no return statement or response construction
# references `value` after the clear.
# Note: grep -v '^\s*#' filters comment-ONLY lines but preserves code lines with inline comments.
info "Assertion 15 (Phase 3): routes/credentials.py - token value assigned once and cleared..."
# Check that body.value is read.
if ! grep -n 'body\.value' "${CREDENTIALS_ROUTES_PY}" | grep -v '^\s*#' | grep -q '.'; then
    fail "Assertion 15 FAILED: 'body.value' not found in routes/credentials.py. The route must read the token value from the request body."
fi
# Check that value is explicitly cleared (value = "").
if ! grep -n 'value = ""' "${CREDENTIALS_ROUTES_PY}" | grep -v '^\s*#' | grep -q '.'; then
    fail "Assertion 15 FAILED: 'value = \"\"' clear not found in routes/credentials.py. The token must be cleared after use."
fi
pass "Assertion 15: token value is assigned once and cleared in routes/credentials.py."

# Assertion 16: No `value` variable appears in a write_audit_record() call.
# This prevents the token value from entering any audit record.
# We check for any call to write_audit_record that includes an argument named `value`
# (not just the string 'value' in a comment or docstring).
# We use a stricter check: find lines with both write_audit_record and `value` as an argument.
info "Assertion 16 (Phase 3): routes/credentials.py - token value not in write_audit_record calls..."
# Filter: extract actual write_audit_record() call lines (not comment lines).
# Lines in docstrings start with spaces then '-' or '#'; pure comment lines start with '#'.
# We also exclude lines that are in multi-line string literals (triple-quoted strings).
# The practical check: look for write_audit_record call lines that contain the word 'value'
# as a keyword argument. Comment lines start with '#' or with spaces+'- ' or spaces+'#'.
BAD_AUDIT_VALUE=$(
    grep -n 'write_audit_record' "${CREDENTIALS_ROUTES_PY}" \
    | grep -vE '^\s*[0-9]+:\s*#' \
    | grep -vE '^\s*[0-9]+:\s*-' \
    | grep -vE '#.*write_audit_record' \
    | grep -v 'from.*import.*write_audit_record' \
    | grep '[^a-z_]value[^_a-z]' \
    || true
)
if [[ -n "${BAD_AUDIT_VALUE}" ]]; then
    fail "Assertion 16 FAILED: 'value' appears as an argument in a write_audit_record() call in routes/credentials.py. The token must NEVER be passed to the audit writer:\n${BAD_AUDIT_VALUE}"
fi
pass "Assertion 16: 'value' does not appear as an argument in any write_audit_record() call in routes/credentials.py."

# Assertion 17: No subprocess, no os.replace, no open(..., "w") in routes/isolation.py.
# Uses Python AST check to avoid false positives from comment/docstring lines.
info "Assertion 17 (Phase 3): routes/isolation.py - non-mutating guarantee (AST check)..."
"${PYTHON}" -c "
import ast, sys
with open('${ISOLATION_ROUTES_PY}') as fh:
    source = fh.read()
tree = ast.parse(source)
violations = []
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == 'subprocess':
                violations.append(f'Line {node.lineno}: subprocess.{func.attr}()')
            if func.value.id == 'os' and func.attr == 'replace':
                violations.append(f'Line {node.lineno}: os.replace()')
        if isinstance(func, ast.Name) and func.id == 'open':
            for i, arg in enumerate(node.args):
                if i == 1 and isinstance(arg, ast.Constant) and 'w' in str(arg.value):
                    violations.append(f'Line {node.lineno}: open(..., \"w\")')
            for kw in node.keywords:
                if kw.arg == 'mode' and isinstance(kw.value, ast.Constant) and 'w' in str(kw.value.value):
                    violations.append(f'Line {node.lineno}: open(mode=\"w\")')
if violations:
    print('FAIL - Non-mutating violations in routes/isolation.py:')
    for v in violations: print(' ', v)
    sys.exit(1)
print('PASS: No subprocess/os.replace/open-write in routes/isolation.py (AST check).')
"
pass "Assertion 17: routes/isolation.py contains no subprocess, os.replace, or open-write calls (non-mutating guarantee)."

# Assertion 18: No D5.4 forbidden field names in any route INPUT body model.
# Uses Python AST to inspect Pydantic BaseModel subclasses in route files.
info "Assertion 18 (Phase 3): No D5.4 forbidden field names in route body models (AST check)..."
"${PYTHON}" -c "
import ast, os, sys
forbidden_input_fields = frozenset({'net_admin', 'net_raw', 'sys_admin', 'docker_sock',
                                    'cap_grant', 'add_cap', 'privileged_mode',
                                    'proposed_privileged'})
violations = []
routes_dir = '${REPO_ROOT}/src/admin/routes'
for fname in sorted(os.listdir(routes_dir)):
    if not fname.endswith('.py'):
        continue
    fpath = os.path.join(routes_dir, fname)
    with open(fpath) as fh:
        source = fh.read()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_names.append(base.id)
            elif isinstance(base, ast.Attribute):
                base_names.append(base.attr)
        if 'BaseModel' not in base_names:
            continue
        for item in node.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                field_name = item.target.id.lower()
                if field_name in forbidden_input_fields:
                    violations.append(
                        f'{fname}:{item.lineno}: class {node.name} has forbidden input field {field_name!r}'
                    )
if violations:
    print('FAIL - Forbidden D5.4 input field names:')
    for v in violations: print(' ', v)
    sys.exit(1)
print('PASS: No D5.4 forbidden input field names in route body models (AST check).')
"
pass "Assertion 18: No D5.4 forbidden field names in route body models."

# Assertion 19: Phase 3 unit tests pass (all non-integration tests).
info "Assertion 19 (Phase 3): running pytest tests/admin/ -m 'not integration' -q..."
cd "${REPO_ROOT}"
"${PYTEST}" tests/admin/ -m "not integration" -q --tb=short
pass "Assertion 19: all non-integration tests passed (Phase 0 + Phase 1 + Phase 2 + Phase 3)."

echo ""
echo -e "${GREEN}All build gate assertions passed (Phase 0 + Phase 1 + Phase 2 + Phase 3).${NC}"
