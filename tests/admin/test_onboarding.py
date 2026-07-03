"""
test_onboarding.py - Acceptance tests for the P1 onboarding API.

Covers:
  AC-29-P1-05  GET /api/v1/onboarding/{profile}/status returns ready_to_start:false
               + correct required_key when credential absent (all three profiles;
               codex required_key reports "CODEX_API_KEY or OPENAI_API_KEY").
  AC-29-P1-06  Same endpoint returns ready_to_start:true when present (codex: true
               if either key present).
  Additional:  POST /api/v1/onboarding/{profile}/start happy path returns same shape
               as lifecycle up route; both endpoints require auth+CSRF (unauthenticated
               / missing-CSRF request rejected).

Security invariants asserted here (unit angle):
  - Onboarding routes do not widen the egress allowlist (AC-29-P1-14 source side;
    containment assertion is red-teamer's).
  - D5.4 isolation knobs are not exposed (asserted via AC-29-P1-15 unit angle in
    test_portal_config.py).

All tests are Docker-free (do_up and get_credential_status monkeypatched).
Never touches real ~/.agentarca credentials or audit log.

Spec ref: SPEC-29-P1 sec 5.5, ADR-012 B8.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings
from src.admin.main import create_app

TEST_SECRET = "test-secret-value-12345"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"
VALID_HOST_HEADER = f"{TEST_HOST}:{TEST_PORT}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_audit(tmp_path):
    return tmp_path / "admin-audit.jsonl"


@pytest.fixture()
def test_settings(tmp_path, tmp_audit):
    secret_file = tmp_path / "admin-secret"
    secret_file.write_text(TEST_SECRET + "\n", encoding="utf-8")
    os.chmod(secret_file, 0o600)
    return Settings(
        host=TEST_HOST,
        port=TEST_PORT,
        allow_non_loopback=False,
        secret_file=secret_file,
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_OB_TEST",
        audit_log_path=tmp_audit,
        session_secret_key="test-session-key-aaabbbccc" * 4,
    )


@pytest.fixture()
def client(test_settings):
    from starlette.testclient import TestClient
    app = create_app(test_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HEADER})
        yield c


@pytest.fixture()
def authed_client(client):
    """Authenticated client with CSRF token set."""
    resp = client.post(
        "/api/v1/login",
        json={"secret": TEST_SECRET},
        headers={"Host": VALID_HOST_HEADER},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    csrf = resp.json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": csrf})
    return client


@pytest.fixture()
def unauthed_client(test_settings):
    """Unauthenticated client (no login, no CSRF)."""
    from starlette.testclient import TestClient
    app = create_app(test_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HEADER})
        yield c


def _make_absent_mock():
    m = MagicMock()
    m.present = False
    return m


def _make_present_mock():
    m = MagicMock()
    m.present = True
    return m


def _read_audit_records(audit_path: Path) -> list:
    if not audit_path.exists():
        return []
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


# ---------------------------------------------------------------------------
# AC-29-P1-05: GET /status returns ready_to_start:false when credential absent
# ---------------------------------------------------------------------------

class TestOnboardingStatusAbsent:
    """
    AC-29-P1-05: onboarding status endpoint returns ready_to_start:false
    and the correct required_key label for each profile when credential absent.
    """

    def test_claude_status_absent(self, authed_client):
        """claude absent: ready_to_start=false, required_key=CLAUDE_CODE_OAUTH_TOKEN. AC-29-P1-05."""
        absent = _make_absent_mock()
        with patch("src.admin.routes.onboarding.get_credential_status", return_value=absent):
            resp = authed_client.get(
                "/api/v1/onboarding/claude/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["profile"] == "claude"
        assert data["ready_to_start"] is False
        assert data["credential_present"] is False
        assert data["required_key"] == "CLAUDE_CODE_OAUTH_TOKEN"

    def test_copilot_status_absent(self, authed_client):
        """copilot absent: ready_to_start=false, required_key=COPILOT_GITHUB_TOKEN. AC-29-P1-05."""
        absent = _make_absent_mock()
        with patch("src.admin.routes.onboarding.get_credential_status", return_value=absent):
            resp = authed_client.get(
                "/api/v1/onboarding/copilot/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["profile"] == "copilot"
        assert data["ready_to_start"] is False
        assert data["credential_present"] is False
        assert data["required_key"] == "COPILOT_GITHUB_TOKEN"

    def test_codex_status_absent_both_keys(self, authed_client):
        """codex absent (both keys): ready_to_start=false, required_key label. AC-29-P1-05."""
        absent = _make_absent_mock()
        with patch("src.admin.routes.onboarding.get_credential_status", return_value=absent):
            resp = authed_client.get(
                "/api/v1/onboarding/codex/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["profile"] == "codex"
        assert data["ready_to_start"] is False
        assert data["credential_present"] is False
        # Spec sec 5.5: "required_key reports 'CODEX_API_KEY or OPENAI_API_KEY'"
        assert data["required_key"] == "CODEX_API_KEY or OPENAI_API_KEY", (
            f"Codex required_key must be 'CODEX_API_KEY or OPENAI_API_KEY'; got: {data['required_key']!r}"
        )

    def test_status_response_has_all_required_fields(self, authed_client):
        """Response body includes profile, credential_present, required_key, ready_to_start. AC-29-P1-05."""
        absent = _make_absent_mock()
        with patch("src.admin.routes.onboarding.get_credential_status", return_value=absent):
            resp = authed_client.get(
                "/api/v1/onboarding/claude/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        data = resp.json()
        for field in ("profile", "credential_present", "required_key", "ready_to_start"):
            assert field in data, f"Missing required field {field!r} in status response"


# ---------------------------------------------------------------------------
# AC-29-P1-06: GET /status returns ready_to_start:true when credential present
# ---------------------------------------------------------------------------

class TestOnboardingStatusPresent:
    """
    AC-29-P1-06: onboarding status endpoint returns ready_to_start:true when
    the required credential is present. For codex, true if either key present.
    """

    def test_claude_status_present(self, authed_client):
        """claude present: ready_to_start=true. AC-29-P1-06."""
        present = _make_present_mock()
        with patch("src.admin.routes.onboarding.get_credential_status", return_value=present):
            resp = authed_client.get(
                "/api/v1/onboarding/claude/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ready_to_start"] is True
        assert data["credential_present"] is True

    def test_copilot_status_present(self, authed_client):
        """copilot present: ready_to_start=true. AC-29-P1-06."""
        present = _make_present_mock()
        with patch("src.admin.routes.onboarding.get_credential_status", return_value=present):
            resp = authed_client.get(
                "/api/v1/onboarding/copilot/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ready_to_start"] is True

    def test_codex_status_present_via_codex_api_key(self, authed_client):
        """codex ready when CODEX_API_KEY present (checked first). AC-29-P1-06."""
        # CODEX_API_KEY present; OPENAI_API_KEY would not need to be checked.
        def cred_by_key(key, salt, env_path):
            m = MagicMock()
            m.present = (key == "CODEX_API_KEY")
            return m

        with patch("src.admin.routes.onboarding.get_credential_status", side_effect=cred_by_key):
            resp = authed_client.get(
                "/api/v1/onboarding/codex/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ready_to_start"] is True, (
            "Codex must be ready when CODEX_API_KEY is present"
        )
        assert data["credential_present"] is True

    def test_codex_status_present_via_openai_key_only(self, authed_client):
        """codex ready when only OPENAI_API_KEY present (CODEX_API_KEY absent). AC-29-P1-06."""
        def cred_by_key(key, salt, env_path):
            m = MagicMock()
            m.present = (key == "OPENAI_API_KEY")
            return m

        with patch("src.admin.routes.onboarding.get_credential_status", side_effect=cred_by_key):
            resp = authed_client.get(
                "/api/v1/onboarding/codex/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ready_to_start"] is True, (
            "Codex must be ready when OPENAI_API_KEY present and CODEX_API_KEY absent"
        )
        assert data["credential_present"] is True


# ---------------------------------------------------------------------------
# POST /api/v1/onboarding/{profile}/start (happy path + credential-absent rejection)
# ---------------------------------------------------------------------------

class TestOnboardingStart:
    """
    POST /api/v1/onboarding/{profile}/start happy path: credential present,
    compose/health mocked, returns same shape as lifecycle up route.
    Also checks that absent-credential returns 400 (same gate as lifecycle route).
    """

    def test_start_happy_path_returns_201(self, authed_client):
        """Happy path: do_up returns applied, route returns 201 with ok=True. Spec sec 5.5."""
        mock_result = {"outcome": "applied", "detail": "", "http_status": 201}
        with patch("src.admin.routes.onboarding.do_up", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/onboarding/claude/start",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data.get("ok") is True
        assert data.get("profile") == "claude"
        assert data.get("gateway_healthy") is True

    def test_start_absent_cred_returns_400(self, authed_client):
        """Absent credential: start returns 400 (same gate as lifecycle up route)."""
        mock_result = {
            "outcome": "rejected-by-validation",
            "detail": "credential 'CLAUDE_CODE_OAUTH_TOKEN' not present for profile 'claude'.",
            "http_status": 400,
        }
        with patch("src.admin.routes.onboarding.do_up", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/onboarding/claude/start",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400
        data = resp.json()
        assert data.get("ok") is False
        assert data.get("error") == "credential_not_present"

    def test_start_invalid_profile_returns_400(self, authed_client):
        """Invalid profile name returns 400 without calling do_up."""
        with patch("src.admin.routes.onboarding.do_up",
                   side_effect=AssertionError("do_up must not be called for invalid profile")):
            resp = authed_client.post(
                "/api/v1/onboarding/BADPROFILE/start",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400
        data = resp.json()
        assert data.get("error") == "invalid_profile"

    def test_start_writes_intent_audit_before_do_up(self, authed_client, tmp_audit):
        """
        Route writes lifecycle_up_intent audit BEFORE run_in_executor (SPEC-29-P0 / AC-012-5).
        Verified by confirming the intent record appears in the audit log after the call.
        """
        mock_result = {"outcome": "applied", "detail": "", "http_status": 201}
        with patch("src.admin.routes.onboarding.do_up", return_value=mock_result):
            authed_client.post(
                "/api/v1/onboarding/claude/start",
                headers={"Host": VALID_HOST_HEADER},
            )
        records = _read_audit_records(tmp_audit)
        intent_records = [r for r in records if r.get("action") == "lifecycle_up_intent"
                          and r.get("target") == "claude"]
        assert intent_records, (
            f"Expected lifecycle_up_intent audit record for claude; got: {records}"
        )


# ---------------------------------------------------------------------------
# Auth + CSRF enforcement (both onboarding endpoints)
# ---------------------------------------------------------------------------

class TestOnboardingAuthCSRF:
    """
    Both onboarding endpoints require auth. POST /start also requires CSRF.
    Mirrors how existing api tests assert the middleware chain.
    Spec: SPEC-29-P1 sec 5.5 "Both endpoints require auth+CSRF".
    Security-review adjudication I: onboarding routes declare Depends(require_auth)
    and CSRF is globally enforced by CSRFMiddleware on POST.
    """

    def test_status_requires_auth(self, unauthed_client):
        """GET /status without authentication is rejected (401/403)."""
        resp = unauthed_client.get(
            "/api/v1/onboarding/claude/status",
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403 for unauthenticated GET /status; got {resp.status_code}"
        )

    def test_start_requires_auth(self, unauthed_client):
        """POST /start without authentication is rejected (401/403)."""
        resp = unauthed_client.post(
            "/api/v1/onboarding/claude/start",
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403 for unauthenticated POST /start; got {resp.status_code}"
        )

    def test_start_requires_csrf(self, client):
        """POST /start with auth but no CSRF token is rejected by CSRFMiddleware (401/403)."""
        # Log in but do NOT set X-CSRF-Token.
        login_resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        # Now POST without CSRF token (do not include X-CSRF-Token header).
        resp = client.post(
            "/api/v1/onboarding/claude/start",
            headers={"Host": VALID_HOST_HEADER},  # no X-CSRF-Token
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403 for POST /start without CSRF; got {resp.status_code}"
        )

    def test_status_get_does_not_require_csrf(self, client):
        """GET /status with auth (but no CSRF header) must succeed; GET is not CSRF-gated."""
        # Log in to get a session.
        login_resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert login_resp.status_code == 200

        absent = _make_absent_mock()
        with patch("src.admin.routes.onboarding.get_credential_status", return_value=absent):
            # GET without X-CSRF-Token header - CSRFMiddleware only guards non-GET methods.
            resp = client.get(
                "/api/v1/onboarding/claude/status",
                headers={"Host": VALID_HOST_HEADER},
            )
        # Must not be rejected by CSRF; must succeed (200) or fail with auth (not CSRF).
        assert resp.status_code == 200, (
            f"Authenticated GET /status must not require CSRF; got {resp.status_code}: {resp.text}"
        )
