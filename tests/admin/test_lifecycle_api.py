"""
test_lifecycle_api.py - Isolation-runnable tests for the lifecycle API routes.

Covers (non-integration ACs):
  AC-27-P2-01   Profile-name validation rejects (IR)
  AC-27-P2-02-ir Mutual-exclusion with mocked running state (IR)
  AC-27-P2-03-ir Up idempotent with mocked state (IR)
  AC-27-P2-04   Down idempotent (IR)
  AC-27-P2-06   Audit record written before HTTP response (IR, mocked)
  AC-27-P2-06b  No audit record contains admin secret (canary test, mocked stderr)
  AC-27-P2-08   No concurrent-up during switch (IR assertion via route ordering)
  AC-27-P2-09-api Switch fail-closed on down failure (route layer, IR)
  AC-27-P2-10-api Gateway timeout route response (IR)
  AC-27-P2-12   lifecycle.lock path assertion (IR)
  AC-27-P2-13   Auth+CSRF enforcement on all lifecycle POSTs (IR)

Integration-gated ACs (tagged @pytest.mark.integration, pytest.fail if stack absent):
  AC-27-P2-02   Mutual-exclusion with live stack
  AC-27-P2-05   Health gating with live stack
  AC-27-P2-15   Crash-does-not-weaken (SIGKILL mid-switch)

All isolation-runnable tests mock `do_up`, `do_down`, `do_switch` or the lower-level
primitives so no Docker stack is required.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_LC_TEST",
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
    """Client with an authenticated session and a valid CSRF token."""
    resp = client.post(
        "/api/v1/login",
        json={"secret": TEST_SECRET},
        headers={"Host": VALID_HOST_HEADER},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    csrf = resp.json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": csrf})
    return client


def _read_audit_records(audit_path: Path) -> list:
    """Read all audit records from the audit log."""
    if not audit_path.exists():
        return []
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _read_last_audit(audit_path: Path) -> dict:
    records = _read_audit_records(audit_path)
    assert records, "Audit log is empty"
    return records[-1]


def _lifecycle_audit_records(audit_path: Path) -> list:
    """Return only lifecycle-domain audit records."""
    return [r for r in _read_audit_records(audit_path) if r.get("domain") == "lifecycle"]


# ---------------------------------------------------------------------------
# AC-27-P2-01: Profile-name validation rejects
# ---------------------------------------------------------------------------

class TestProfileNameValidation:
    """
    AC-27-P2-01 (BLOCK): invalid profile names must return 400,
    no subprocess called, audit record written.
    """

    INVALID_NAMES = [
        "COPILOT",
        "Copilot",
        "codex extra",  # space
        "evil;rm-rf",
        "gpt4",
    ]

    VALID_NAMES = ["copilot", "claude", "codex"]

    @pytest.mark.parametrize("name", INVALID_NAMES)
    def test_invalid_profile_up_returns_400(self, authed_client, tmp_audit, name):
        """Invalid profile names must return 400, no compose called."""
        # URL-encode spaces for the path parameter.
        encoded = name.replace(" ", "%20")
        subprocess_calls = []

        def fake_run(*args, **kwargs):
            subprocess_calls.append(args)
            return MagicMock(returncode=0)

        with patch("subprocess.run", side_effect=fake_run), \
             patch("src.admin.primitives.lifecycle.subprocess.run", side_effect=fake_run):
            resp = authed_client.post(
                f"/api/v1/profiles/{encoded}/up",
                headers={"Host": VALID_HOST_HEADER},
            )

        assert resp.status_code == 400, (
            f"Expected 400 for invalid profile {name!r}, got {resp.status_code}: {resp.text}"
        )
        data = resp.json()
        assert data.get("error") == "invalid_profile"
        # No subprocess call for compose (may have calls for compose ls via lock, but
        # validation must fire before any lock acquisition or subprocess).
        # The lifecycle lock itself is acquired before compose calls but after validation.
        # For the invalid-profile path, no compose call of any kind should happen.
        compose_calls = [
            a for a in subprocess_calls
            if a and isinstance(a[0], list) and "compose" in a[0]
        ]
        assert len(compose_calls) == 0, (
            f"compose subprocess must not be called for invalid profile {name!r}: {compose_calls}"
        )

    def test_invalid_profile_up_writes_audit(self, authed_client, tmp_audit):
        """Invalid profile name: audit record written with rejected-by-validation."""
        resp = authed_client.post(
            "/api/v1/profiles/INVALID_PROFILE/up",
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 400
        records = _lifecycle_audit_records(tmp_audit)
        assert records, "No lifecycle audit records written"
        last = records[-1]
        assert last["outcome"] == "rejected-by-validation"
        assert last["action"] == "lifecycle_up"
        assert last["domain"] == "lifecycle"

    def test_invalid_profile_down_returns_400(self, authed_client, tmp_audit):
        resp = authed_client.post(
            "/api/v1/profiles/BADPROFILE/down",
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data.get("error") == "invalid_profile"

    @pytest.mark.parametrize("name", VALID_NAMES)
    def test_valid_profiles_reach_lock_step(self, authed_client, name):
        """Valid profile names must pass validation and reach the lock+compose step."""
        # Mock do_up to return a controlled result (proves validation passed).
        mock_result = {"outcome": "idempotent", "detail": "idempotent", "http_status": 200}
        with patch("src.admin.routes.lifecycle.do_up", return_value=mock_result):
            resp = authed_client.post(
                f"/api/v1/profiles/{name}/up",
                headers={"Host": VALID_HOST_HEADER},
            )
        # Should not get 400 (which would indicate validation rejection).
        assert resp.status_code != 400, (
            f"Valid profile {name!r} was rejected by validation (got 400)"
        )

    def test_path_traversal_rejected(self, authed_client):
        """Path traversal attempts via the profile parameter are rejected."""
        resp = authed_client.post(
            "/api/v1/profiles/../../../etc/up",
            headers={"Host": VALID_HOST_HEADER},
        )
        # FastAPI may return 400, 404, 405, or 422 for path traversal attempts;
        # must NOT return 200 or 201.
        assert resp.status_code not in (200, 201), (
            f"Path traversal must not succeed, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# AC-27-P2-02-ir: Mutual-exclusion (mocked running state)
# ---------------------------------------------------------------------------

class TestMutexRouteLayer:
    """
    AC-27-P2-02-ir (BLOCK): mutual-exclusion enforced at route level with mocked
    running state. Uses mock of do_up to simulate the mutex-refused outcome.
    """

    def test_up_409_when_different_profile_running(self, authed_client, tmp_audit):
        """409 response when mutex is refused, audit record written."""
        mock_result = {
            "outcome": "rejected_mutex",
            "running_profile": "copilot",
            "detail": "profile 'copilot' is already running",
            "http_status": 409,
        }
        with patch("src.admin.routes.lifecycle.do_up", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": VALID_HOST_HEADER},
            )

        assert resp.status_code == 409
        data = resp.json()
        assert data["error"] == "mutual_exclusion"
        assert data["running_profile"] == "copilot"
        assert "bring it down" in data["detail"].lower() or "running" in data["detail"].lower()
        # NEVER offer "run both" in the response body.
        assert "run both" not in json.dumps(data).lower()

        # Audit record written with rejected-by-stop-and-flag.
        records = _lifecycle_audit_records(tmp_audit)
        assert records, "No lifecycle audit records"
        last = records[-1]
        assert last["outcome"] == "rejected-by-stop-and-flag"
        assert last["domain"] == "lifecycle"

    def test_up_201_when_no_profile_running(self, authed_client, tmp_audit):
        """201 response when no profile is running and compose succeeds."""
        mock_result = {
            "outcome": "applied",
            "detail": "",
            "http_status": 201,
        }
        with patch("src.admin.routes.lifecycle.do_up", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": VALID_HOST_HEADER},
            )

        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["profile"] == "claude"
        assert data["gateway_healthy"] is True

        records = _lifecycle_audit_records(tmp_audit)
        assert records
        last = records[-1]
        assert last["outcome"] == "applied"


# ---------------------------------------------------------------------------
# AC-27-P2-03-ir: Up idempotent
# ---------------------------------------------------------------------------

class TestUpIdempotentRoute:
    """AC-27-P2-03-ir: already running returns 200 idempotent=true."""

    def test_up_idempotent_returns_200(self, authed_client, tmp_audit):
        mock_result = {
            "outcome": "idempotent",
            "detail": "idempotent",
            "http_status": 200,
        }
        with patch("src.admin.routes.lifecycle.do_up", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": VALID_HOST_HEADER},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data.get("idempotent") is True

        records = _lifecycle_audit_records(tmp_audit)
        assert records
        last = records[-1]
        assert last["outcome"] == "applied"
        assert last["detail"] == "idempotent"


# ---------------------------------------------------------------------------
# AC-27-P2-04: Down idempotent
# ---------------------------------------------------------------------------

class TestDownIdempotentRoute:
    """AC-27-P2-04: already down returns 200 idempotent=true."""

    def test_down_idempotent_returns_200(self, authed_client, tmp_audit):
        mock_result = {
            "outcome": "idempotent",
            "detail": "idempotent_down",
            "http_status": 200,
        }
        with patch("src.admin.routes.lifecycle.do_down", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/profiles/copilot/down",
                headers={"Host": VALID_HOST_HEADER},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data.get("idempotent") is True

        records = _lifecycle_audit_records(tmp_audit)
        assert records
        last = records[-1]
        assert last["outcome"] == "applied"
        assert "idempotent" in last.get("detail", "")


# ---------------------------------------------------------------------------
# AC-27-P2-06: Audit record written before HTTP response
# ---------------------------------------------------------------------------

class TestAuditBeforeResponse:
    """
    AC-27-P2-06 (BLOCK): every lifecycle action writes an audit record
    with required fields; the record is written before the HTTP response.

    We verify by checking: audit file is written AND the response is returned
    AND the audit record domain/action/outcome are correct.
    """

    def test_audit_on_up_applied(self, authed_client, tmp_audit):
        with patch("src.admin.routes.lifecycle.do_up",
                   return_value={"outcome": "applied", "detail": "", "http_status": 201}):
            resp = authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 201
        records = _lifecycle_audit_records(tmp_audit)
        assert records, "Audit log must have at least one lifecycle record"
        last = records[-1]
        assert last["domain"] == "lifecycle"
        assert last["action"] == "lifecycle_up"
        assert last["target"] == "claude"
        assert last["outcome"] == "applied"
        # Required fields present.
        for field in ("schema_version", "timestamp_utc", "session_id", "domain", "action",
                      "target", "outcome"):
            assert field in last, f"Audit record missing field: {field!r}"

    def test_audit_on_down_applied(self, authed_client, tmp_audit):
        with patch("src.admin.routes.lifecycle.do_down",
                   return_value={"outcome": "applied", "detail": "", "http_status": 200}):
            resp = authed_client.post(
                "/api/v1/profiles/copilot/down",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        records = _lifecycle_audit_records(tmp_audit)
        assert records
        last = records[-1]
        assert last["domain"] == "lifecycle"
        assert last["action"] == "lifecycle_down"
        assert last["outcome"] == "applied"

    def test_audit_on_switch_applied(self, authed_client, tmp_audit):
        with patch("src.admin.routes.lifecycle.do_switch",
                   return_value={"outcome": "applied", "detail": "", "from_was_running": True,
                                 "http_status": 200}):
            resp = authed_client.post(
                "/api/v1/profiles/switch",
                json={"from": "copilot", "to": "claude"},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        records = _lifecycle_audit_records(tmp_audit)
        assert records
        last = records[-1]
        assert last["domain"] == "lifecycle"
        assert last["action"] == "lifecycle_switch"
        assert last["target"] == "copilot->claude"
        assert last["outcome"] == "applied"

    def test_audit_on_mutex_refused(self, authed_client, tmp_audit):
        with patch("src.admin.routes.lifecycle.do_up",
                   return_value={"outcome": "rejected_mutex", "running_profile": "copilot",
                                 "detail": "profile 'copilot' is already running", "http_status": 409}):
            resp = authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 409
        records = _lifecycle_audit_records(tmp_audit)
        assert records
        last = records[-1]
        assert last["outcome"] == "rejected-by-stop-and-flag"


# ---------------------------------------------------------------------------
# AC-27-P2-06b: No audit record contains admin secret
# ---------------------------------------------------------------------------

class TestAuditNoSecret:
    """
    AC-27-P2-06b (BLOCK): audit records must not contain the admin secret,
    even when compose stderr contains the secret (canary test).
    """

    def test_compose_error_stderr_sanitized_in_audit(self, authed_client, tmp_audit, test_settings):
        """
        Simulate: compose_up returns non-zero exit and stderr contains the admin secret.
        The audit record's detail field must NOT contain the secret.
        """
        secret = TEST_SECRET  # The admin secret value.
        # do_up returns a compose_error where the detail (derived from stderr) contains the secret.
        mock_result = {
            "outcome": "compose_error",
            # _sanitize in do_up should have already scrubbed it, but the route
            # also sanitizes via _write_audit -> _sanitize at the chokepoint.
            "detail": f"Error output containing {secret} in stderr",
            "http_status": 500,
        }
        with patch("src.admin.routes.lifecycle.do_up", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 500
        # The route's _write_audit sanitizes the detail field.
        records = _lifecycle_audit_records(tmp_audit)
        assert records, "No lifecycle audit records"
        for record in records:
            record_str = json.dumps(record)
            assert secret not in record_str, (
                f"Admin secret found in audit record: {record_str[:300]}"
            )

    def test_response_body_does_not_contain_secret(self, authed_client, tmp_audit):
        """Response bodies must not contain the admin secret."""
        secret = TEST_SECRET
        mock_result = {
            "outcome": "compose_error",
            "detail": f"Some stderr with {secret} inside",
            "http_status": 500,
        }
        with patch("src.admin.routes.lifecycle.do_up", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert secret not in resp.text, (
            f"Admin secret appeared in HTTP response body: {resp.text[:300]}"
        )


# ---------------------------------------------------------------------------
# AC-27-P2-08: No concurrent-up during switch
# ---------------------------------------------------------------------------

class TestNoConcurrentUpDuringSwitch:
    """
    AC-27-P2-08 (BLOCK): the switch route uses a single lock acquisition;
    the route itself enforces the down-verify-up sequence with no lock release in between.

    For isolation-runnable assertion: verify the route calls do_switch (not do_down + do_up
    separately), meaning it delegates to the single-lock implementation.
    """

    def test_switch_calls_do_switch_not_separate_down_up(self, authed_client, tmp_audit):
        """
        The switch route must delegate to do_switch (one lock acquisition), not
        call do_down then do_up separately (which would have a window between locks).
        """
        do_switch_calls = []
        do_down_calls = []
        do_up_calls = []

        def fake_do_switch(from_profile, to_profile, secret, *args, **kwargs):
            do_switch_calls.append((from_profile, to_profile))
            return {"outcome": "applied", "detail": "", "from_was_running": True, "http_status": 200}

        def fake_do_down(profile, secret):
            do_down_calls.append(profile)
            return {"outcome": "applied", "detail": "", "http_status": 200}

        def fake_do_up(profile, secret, *args, **kwargs):
            do_up_calls.append(profile)
            return {"outcome": "applied", "detail": "", "http_status": 201}

        with patch("src.admin.routes.lifecycle.do_switch", side_effect=fake_do_switch), \
             patch("src.admin.routes.lifecycle.do_down", side_effect=fake_do_down), \
             patch("src.admin.routes.lifecycle.do_up", side_effect=fake_do_up):
            resp = authed_client.post(
                "/api/v1/profiles/switch",
                json={"from": "copilot", "to": "claude"},
                headers={"Host": VALID_HOST_HEADER},
            )

        assert resp.status_code == 200
        assert len(do_switch_calls) == 1, "do_switch must be called exactly once"
        assert do_switch_calls[0] == ("copilot", "claude")
        assert len(do_down_calls) == 0, "Route must not call do_down separately"
        assert len(do_up_calls) == 0, "Route must not call do_up separately"


# ---------------------------------------------------------------------------
# AC-27-P2-09: Switch fail-closed route response
# ---------------------------------------------------------------------------

class TestSwitchDownFailClosedRoute:
    """AC-27-P2-09: switch returns 500 when down did not stop from-profile."""

    def test_switch_returns_500_on_down_did_not_stop(self, authed_client, tmp_audit):
        mock_result = {
            "outcome": "down_did_not_stop",
            "detail": "down_did_not_stop_profile:copilot",
            "http_status": 500,
        }
        with patch("src.admin.routes.lifecycle.do_switch", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/profiles/switch",
                json={"from": "copilot", "to": "claude"},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 500
        data = resp.json()
        assert data["error"] == "down_did_not_stop_profile"

        records = _lifecycle_audit_records(tmp_audit)
        assert records
        last = records[-1]
        assert last["outcome"] == "error"
        assert "down_did_not_stop" in last.get("detail", "")


# ---------------------------------------------------------------------------
# AC-27-P2-10: Gateway timeout route response
# ---------------------------------------------------------------------------

class TestGatewayHealthTimeoutRoute:
    """AC-27-P2-10: gateway timeout returns 503; audit records error."""

    def test_up_returns_503_on_health_timeout(self, authed_client, tmp_audit):
        mock_result = {
            "outcome": "gateway_timeout",
            "detail": "gateway_health_timeout; profile torn down",
            "timeout_seconds": 120,
            "http_status": 503,
        }
        with patch("src.admin.routes.lifecycle.do_up", return_value=mock_result):
            resp = authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 503
        data = resp.json()
        assert data["error"] == "gateway_health_timeout"
        assert "torn down" in data["detail"]
        assert data["profile"] == "claude"

        records = _lifecycle_audit_records(tmp_audit)
        assert records
        last = records[-1]
        assert last["outcome"] == "error"
        assert "gateway_health_timeout" in last.get("detail", "")


# ---------------------------------------------------------------------------
# AC-27-P2-12: lifecycle.lock path assertion (startup)
# ---------------------------------------------------------------------------

class TestLifecycleLockPathStartup:
    """AC-27-P2-12: create_app creates the lock file in the right location."""

    def test_lifecycle_lock_file_created_on_startup(self, test_settings, tmp_path):
        """
        create_app() must call ensure_lifecycle_lock_file(), which creates the lock file.
        We patch LIFECYCLE_LOCK_PATH to a temp path for this test.
        """
        temp_lock = tmp_path / "test-lifecycle.lock"
        with patch("src.admin.primitives.lifecycle.LIFECYCLE_LOCK_PATH", temp_lock):
            app = create_app(test_settings)
        # The lock file should have been created by ensure_lifecycle_lock_file().
        assert temp_lock.exists(), (
            "lifecycle.lock was not created at startup"
        )

    def test_lock_path_is_outside_repo(self):
        from src.admin.primitives.lifecycle import LIFECYCLE_LOCK_PATH
        try:
            LIFECYCLE_LOCK_PATH.relative_to(REPO_ROOT)
            pytest.fail(
                f"LIFECYCLE_LOCK_PATH {LIFECYCLE_LOCK_PATH!r} is inside the repo root {REPO_ROOT!r}; "
                "it must be on the host filesystem outside the repo."
            )
        except ValueError:
            pass  # Expected.


# ---------------------------------------------------------------------------
# AC-27-P2-13: Auth and CSRF enforcement on all lifecycle POSTs
# ---------------------------------------------------------------------------

class TestAuthCsrfEnforcement:
    """
    AC-27-P2-13 (BLOCK): all lifecycle POST endpoints require auth and CSRF.
    """

    # --- Unauthenticated requests ---

    def test_up_without_session_returns_401_or_403(self, client, tmp_audit):
        """
        No session cookie: must return 401 or 403.
        In the Phase 0 middleware stack (HostValidation -> Session -> CSRF -> Auth),
        CSRF middleware runs before the route's auth dependency. When there is no
        session cookie AND no X-CSRF-Token header, CSRF fires first (403). Either
        401 or 403 is acceptable as long as the request is rejected.
        """
        with patch("src.admin.routes.lifecycle.do_up",
                   return_value={"outcome": "applied", "detail": "", "http_status": 201}):
            resp = client.post(
                "/api/v1/profiles/copilot/up",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403 (auth/CSRF rejection), got {resp.status_code}: {resp.text}"
        )

    def test_down_without_session_returns_401_or_403(self, client):
        with patch("src.admin.routes.lifecycle.do_down",
                   return_value={"outcome": "applied", "detail": "", "http_status": 200}):
            resp = client.post(
                "/api/v1/profiles/copilot/down",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403, got {resp.status_code}: {resp.text}"
        )

    def test_switch_without_session_returns_401_or_403(self, client):
        resp = client.post(
            "/api/v1/profiles/switch",
            json={"from": "copilot", "to": "claude"},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403, got {resp.status_code}: {resp.text}"
        )

    # --- Missing CSRF token (authenticated but no CSRF header) ---

    def test_up_without_csrf_returns_403(self, client):
        """Authenticated session but no CSRF token: 403."""
        # Authenticate to get a session.
        login = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert login.status_code == 200
        # Do NOT set the X-CSRF-Token header.
        with patch("src.admin.routes.lifecycle.do_up",
                   return_value={"outcome": "applied", "detail": "", "http_status": 201}):
            resp = client.post(
                "/api/v1/profiles/copilot/up",
                headers={"Host": VALID_HOST_HEADER},
                # X-CSRF-Token header intentionally omitted.
            )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"

    def test_down_without_csrf_returns_403(self, client):
        login = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert login.status_code == 200
        resp = client.post(
            "/api/v1/profiles/copilot/down",
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 403

    def test_switch_without_csrf_returns_403(self, client):
        login = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert login.status_code == 200
        resp = client.post(
            "/api/v1/profiles/switch",
            json={"from": "copilot", "to": "claude"},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 403

    # --- Wrong Host header (HostValidationMiddleware fires first) ---

    def test_up_wrong_host_returns_403(self, authed_client):
        """Phase 0 HostValidationMiddleware must reject non-loopback Host headers."""
        with patch("src.admin.routes.lifecycle.do_up",
                   return_value={"outcome": "applied", "detail": "", "http_status": 201}):
            resp = authed_client.post(
                "/api/v1/profiles/copilot/up",
                headers={"Host": "evil.example.com"},
            )
        assert resp.status_code in (400, 403), (
            f"Expected 400 or 403 for invalid Host header, got {resp.status_code}"
        )

    # --- Authenticated + valid CSRF: request proceeds ---

    def test_switch_with_valid_auth_and_csrf_proceeds(self, authed_client):
        """Valid session + CSRF token: the request reaches the route handler."""
        with patch("src.admin.routes.lifecycle.do_switch",
                   return_value={"outcome": "applied", "detail": "", "from_was_running": True,
                                 "http_status": 200}):
            resp = authed_client.post(
                "/api/v1/profiles/switch",
                json={"from": "copilot", "to": "claude"},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200, (
            f"Expected 200 for valid authed switch, got {resp.status_code}: {resp.text}"
        )


# ---------------------------------------------------------------------------
# AC-27-P2-15: Crash-does-not-weaken (integration-gated)
# ---------------------------------------------------------------------------

def _hold_lifecycle_lock_forever(lock_path: str, ready_event) -> None:
    """Module-level (so it is picklable under the macOS 'spawn' start method) helper that
    acquires the lifecycle flock, signals readiness, then holds it until the parent SIGKILLs
    this child. A local function defined inside the test cannot be pickled and fails
    Process.start() on macOS; readiness is signalled via an Event because spawn startup is
    slow and a fixed sleep in the parent races the child's acquisition."""
    import fcntl
    import time
    lf = open(lock_path, "w")
    fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
    ready_event.set()
    time.sleep(60)


@pytest.mark.integration
def test_crash_does_not_weaken_flock_releases_on_sigkill():
    """
    AC-27-P2-15 (BLOCK, integration): verify the OS releases the flock when
    the admin process is killed with SIGKILL.

    Requires a live Docker stack. Skips (fails with pytest.fail) if no stack is available.

    Test procedure:
    1. Verify the lock can be acquired normally.
    2. Start a child process that holds the lock.
    3. SIGKILL the child process.
    4. Verify the lock can be acquired immediately after the kill.
    """
    import multiprocessing
    import signal
    import time
    import fcntl
    from src.admin.primitives.lifecycle import LIFECYCLE_LOCK_PATH, ensure_lifecycle_lock_file

    ensure_lifecycle_lock_file()

    # Verify initial state: lock is not held.
    lf = open(LIFECYCLE_LOCK_PATH, "w")
    try:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except OSError:
        pytest.fail("Lock is held before test begins; clean up and retry.")
    finally:
        lf.close()

    # Start a subprocess that acquires the lock and holds it indefinitely.
    # Use a MODULE-LEVEL target (picklable under macOS 'spawn'); a local function is not.
    ready = multiprocessing.Event()
    p = multiprocessing.Process(
        target=_hold_lifecycle_lock_forever,
        args=(str(LIFECYCLE_LOCK_PATH), ready),
    )
    p.start()
    # Wait until the child SIGNALS it has acquired the lock (spawn startup is slow; a fixed
    # sleep races it). Then confirm the lock is genuinely held (a non-blocking acquire fails).
    if not ready.wait(timeout=15):
        p.kill()
        p.join()
        pytest.fail("Child did not acquire the lock within 15s; test setup failed.")

    lf2 = open(LIFECYCLE_LOCK_PATH, "w")
    try:
        fcntl.flock(lf2.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        # If we get here, the lock is NOT held though the child signalled ready; setup failed.
        fcntl.flock(lf2.fileno(), fcntl.LOCK_UN)
        lf2.close()
        p.kill()
        p.join()
        pytest.fail("Child signalled ready but the lock was not held; test setup failed.")
    except OSError:
        pass  # Expected: lock is held by the child.
    finally:
        lf2.close()

    # SIGKILL the child process.
    os.kill(p.pid, signal.SIGKILL)
    p.join(timeout=2)

    # Verify the OS released the lock.
    deadline = time.monotonic() + 1.0
    acquired = False
    while time.monotonic() < deadline:
        lf3 = open(LIFECYCLE_LOCK_PATH, "w")
        try:
            fcntl.flock(lf3.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lf3.fileno(), fcntl.LOCK_UN)
            acquired = True
            break
        except OSError:
            time.sleep(0.05)
        finally:
            lf3.close()

    assert acquired, (
        "Lock was NOT released within 1 second after SIGKILL. "
        "The OS must release advisory flock locks when a process dies."
    )


# ---------------------------------------------------------------------------
# Integration-gated: Live stack mutual-exclusion and health gating
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_mutex_live_stack(test_settings):
    """
    AC-27-P2-02 (integration): mutual-exclusion with a live Docker stack.

    Requires no profile pre-running. If a profile is already running, the test
    cannot run (operator state would be disrupted). pytest.fail() with instructions.
    """
    from src.admin.primitives.lifecycle import get_running_profiles

    try:
        running = get_running_profiles()
    except Exception as exc:
        pytest.fail(f"Cannot connect to Docker: {exc}. Run this test with a live Docker host.")

    if running:
        pytest.fail(
            f"A profile is already running: {running}. This test requires a clean Docker state "
            "(no profiles up). Do NOT force this test to run; bring down the running profile first."
        )

    # With a live stack, test that bringing up copilot blocks bringing up claude.
    # (This is a minimal live-stack smoke test; the full race test is in test_lifecycle_mutex.py.)
    from starlette.testclient import TestClient
    app = create_app(test_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HEADER})
        login = c.post("/api/v1/login", json={"secret": TEST_SECRET},
                       headers={"Host": VALID_HOST_HEADER})
        assert login.status_code == 200
        csrf = login.json()["csrf_token"]
        c.headers.update({"X-CSRF-Token": csrf})

        # Bring copilot up (this is a live stack operation - may take time).
        up_resp = c.post("/api/v1/profiles/copilot/up", headers={"Host": VALID_HOST_HEADER})
        if up_resp.status_code == 503:
            pytest.fail(f"compose up failed (health timeout or lock): {up_resp.text}")
        if up_resp.status_code not in (201, 200):
            pytest.fail(f"Unexpected up response: {up_resp.status_code} {up_resp.text}")

        try:
            # Now try to bring claude up; must get 409.
            claude_resp = c.post("/api/v1/profiles/claude/up", headers={"Host": VALID_HOST_HEADER})
            assert claude_resp.status_code == 409, (
                f"Expected 409 (mutex refusal), got {claude_resp.status_code}: {claude_resp.text}"
            )
            data = claude_resp.json()
            assert data["error"] == "mutual_exclusion"
            assert data["running_profile"] == "copilot"
        finally:
            # Clean up: bring copilot down.
            c.post("/api/v1/profiles/copilot/down", headers={"Host": VALID_HOST_HEADER})


@pytest.mark.integration
def test_health_gating_live_stack(test_settings):
    """
    AC-27-P2-05 (integration): up not declared success until gateway is healthy.

    Verifies the 201 response only arrives after gateway_healthy=true.
    Requires a live Docker stack.
    """
    from src.admin.primitives.lifecycle import get_running_profiles

    try:
        running = get_running_profiles()
    except Exception as exc:
        pytest.fail(f"Cannot connect to Docker: {exc}")

    if running:
        pytest.fail(
            f"Profiles already running: {running}. Clean Docker state required."
        )

    from starlette.testclient import TestClient
    app = create_app(test_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HEADER})
        login = c.post("/api/v1/login", json={"secret": TEST_SECRET},
                       headers={"Host": VALID_HOST_HEADER})
        assert login.status_code == 200
        csrf = login.json()["csrf_token"]
        c.headers.update({"X-CSRF-Token": csrf})

        resp = c.post("/api/v1/profiles/copilot/up", headers={"Host": VALID_HOST_HEADER})
        try:
            if resp.status_code == 201:
                data = resp.json()
                assert data["gateway_healthy"] is True, (
                    "201 response must include gateway_healthy=true"
                )
            elif resp.status_code == 503 and "gateway_health_timeout" in resp.text:
                pass  # Expected if gateway doesn't start in time; 503 is correct behavior.
            else:
                pytest.fail(f"Unexpected response: {resp.status_code} {resp.text}")
        finally:
            c.post("/api/v1/profiles/copilot/down", headers={"Host": VALID_HOST_HEADER})
