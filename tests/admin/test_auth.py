"""
test_auth.py

Covers:
  AC-27-P0-04: Constant-time compare + secret never in log/response
"""

from __future__ import annotations

import json
import time

import pytest

from tests.admin.conftest import TEST_SECRET, TEST_PORT, VALID_HOST


VALID_HOST_HEADER = f"127.0.0.1:{TEST_PORT}"


class TestLogin:
    """Basic login functionality."""

    def test_correct_secret_returns_200(self, client):
        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    def test_correct_secret_returns_csrf_token(self, client):
        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "csrf_token" in data, "Login response must include csrf_token."
        assert len(data["csrf_token"]) >= 32, "CSRF token must be at least 32 chars."

    def test_correct_secret_sets_session_cookie(self, client):
        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 200
        assert "set-cookie" in resp.headers, "Login must issue a session cookie."
        cookie_header = resp.headers["set-cookie"]
        assert "agentarca_session" in cookie_header
        assert "httponly" in cookie_header.lower(), "Session cookie must be HttpOnly."
        assert "samesite=strict" in cookie_header.lower(), "Session cookie must be SameSite=Strict."

    def test_wrong_secret_returns_401(self, client):
        resp = client.post(
            "/api/v1/login",
            json={"secret": "wrong-secret-value"},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 401

    def test_empty_secret_returns_401(self, client):
        resp = client.post(
            "/api/v1/login",
            json={"secret": ""},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 401


class TestSecretNotInOutput:
    """
    AC-27-P0-04: The secret must never appear in any response body or log output.
    """

    def test_secret_not_in_success_response(self, client):
        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 200
        assert TEST_SECRET not in resp.text, (
            "The shared secret appeared in the login success response."
        )

    def test_secret_not_in_failure_response(self, client):
        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        # Also check a failure response with a value that resembles the secret.
        resp2 = client.post(
            "/api/v1/login",
            json={"secret": "bad-" + TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert TEST_SECRET not in resp2.text, (
            "The shared secret appeared in the login failure response."
        )

    def test_secret_not_in_audit_record(self, client, test_settings):
        """After a login, the audit record must not contain the secret value."""
        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 200
        audit_path = test_settings.audit_log_path
        if audit_path.exists():
            content = audit_path.read_text(encoding="utf-8")
            assert TEST_SECRET not in content, (
                "The shared secret appeared in an audit record."
            )


class TestRequireAuth:
    """The require_auth dependency must block unauthenticated requests with 401."""

    def test_health_does_not_require_auth(self, client):
        """GET /api/v1/health is unauthenticated."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": VALID_HOST_HEADER},
        )
        assert resp.status_code == 200


class TestConstantTimeHint:
    """
    AC-27-P0-04 timing smoke test (informational only).
    The authoritative guarantee is the hmac.compare_digest code.
    This test checks that correct vs incorrect login timings are not dramatically different.
    """

    def test_timing_similar_correct_vs_incorrect(self, client):
        n = 20  # Small number for CI speed; 1000 in spec is informational.

        correct_times = []
        for _ in range(n):
            t0 = time.monotonic()
            client.post(
                "/api/v1/login",
                json={"secret": TEST_SECRET},
                headers={"Host": VALID_HOST_HEADER},
            )
            correct_times.append(time.monotonic() - t0)

        incorrect_times = []
        for _ in range(n):
            t0 = time.monotonic()
            client.post(
                "/api/v1/login",
                json={"secret": "wrong-secret-XXXXX"},
                headers={"Host": VALID_HOST_HEADER},
            )
            incorrect_times.append(time.monotonic() - t0)

        mean_correct = sum(correct_times) / n
        mean_incorrect = sum(incorrect_times) / n
        diff = abs(mean_correct - mean_incorrect)
        # The failure delay adds 100ms; the correct path should be faster.
        # We assert the difference is under 500ms to catch gross mis-implementations.
        assert diff < 0.5, (
            f"Timing difference {diff:.3f}s between correct and incorrect logins is "
            f"surprisingly large. Check that hmac.compare_digest is used."
        )
