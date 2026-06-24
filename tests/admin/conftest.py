"""
conftest.py - Shared fixtures for admin tests.

Provides:
  - test_app: a FastAPI app created via create_app() with a test secret and
    an audit log in a temp directory.
  - client: a Starlette TestClient configured with the default loopback Host header.
  - async_client: an httpx AsyncClient for tests that need async access.
  - test_secret: the test shared secret value (never commit a real secret).
  - audit_log_path: the temp path for the audit log.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure the repo root is on sys.path so "src.admin.*" imports resolve.
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings  # noqa: E402
from src.admin.main import create_app  # noqa: E402

TEST_SECRET = "test-secret-value-12345"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"
VALID_HOST = f"{TEST_HOST}:{TEST_PORT}"


@pytest.fixture(scope="function")
def tmp_audit_dir(tmp_path):
    """Return a temporary directory outside the repo root for the audit log."""
    return tmp_path


@pytest.fixture(scope="function")
def audit_log_path(tmp_audit_dir):
    """Return the path to a temp audit log file."""
    return tmp_audit_dir / "admin-audit.jsonl"


@pytest.fixture(scope="function")
def test_settings(tmp_audit_dir, tmp_path):
    """Return a Settings instance configured for testing."""
    secret_file = tmp_path / "admin-secret"
    secret_file.write_text(TEST_SECRET + "\n", encoding="utf-8")
    os.chmod(secret_file, 0o600)

    session_key_file = tmp_path / "session-key"
    session_key_file.write_text("test-session-key-aaabbbccc" * 4 + "\n", encoding="utf-8")
    os.chmod(session_key_file, 0o600)

    return Settings(
        host=TEST_HOST,
        port=TEST_PORT,
        allow_non_loopback=False,
        secret_file=secret_file,
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST",
        audit_log_path=tmp_audit_dir / "admin-audit.jsonl",
        session_secret_key="test-session-key-aaabbbccc" * 4,
    )


@pytest.fixture(scope="function")
def test_app(test_settings):
    """Return a FastAPI app created with test settings."""
    return create_app(test_settings)


@pytest.fixture(scope="function")
def client(test_app):
    """Return a Starlette TestClient with default loopback Host header."""
    from starlette.testclient import TestClient
    with TestClient(test_app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        # Set the default Host header to a valid loopback value.
        c.headers.update({"Host": f"{TEST_HOST}:{TEST_PORT}"})
        yield c


@pytest.fixture(scope="function")
def loopback_host_header():
    """Return the valid Host header value for tests."""
    return f"{TEST_HOST}:{TEST_PORT}"
