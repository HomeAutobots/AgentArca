"""
test_csrf.py

Covers:
  AC-27-P0-07: CSRF token required on POST/PUT/DELETE; absent = 403
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.admin.conftest import TEST_SECRET, TEST_PORT

VALID_HOST = f"127.0.0.1:{TEST_PORT}"


def _login(client) -> str:
    """Log in and return the CSRF token from the response."""
    resp = client.post(
        "/api/v1/login",
        json={"secret": TEST_SECRET},
        headers={"Host": VALID_HOST},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["csrf_token"]


class TestCSRFOnStateChangingRequests:
    """
    AC-27-P0-07: State-changing requests without a valid CSRF token return 403.
    """

    def test_post_without_csrf_token_returns_403(self, client):
        """POST without X-CSRF-Token must return 403 even with a valid session."""
        # Log in to get a session cookie (client stores it).
        _login(client)

        # POST without a CSRF token.
        resp = client.post(
            "/api/v1/health",
            json={},
            headers={"Host": VALID_HOST},
            # No X-CSRF-Token header.
        )
        assert resp.status_code == 403, (
            f"Expected 403 on POST without CSRF token, got {resp.status_code}."
        )

    def test_post_with_correct_csrf_token_succeeds(self, client):
        """POST with the correct X-CSRF-Token must succeed (200 or 405)."""
        csrf_token = _login(client)

        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={
                "Host": VALID_HOST,
                "X-CSRF-Token": csrf_token,
            },
        )
        # Login itself is POST, and with a valid CSRF token it should not be blocked.
        # It might succeed (200) since credentials are correct.
        assert resp.status_code != 403, (
            f"POST with correct CSRF token was rejected with 403."
        )

    def test_post_with_wrong_csrf_token_returns_403(self, client):
        """POST with an incorrect CSRF token must return 403."""
        _login(client)

        resp = client.post(
            "/api/v1/health",
            json={},
            headers={
                "Host": VALID_HOST,
                "X-CSRF-Token": "completely-wrong-token-value",
            },
        )
        assert resp.status_code == 403

    def test_get_does_not_require_csrf_token(self, client):
        """GET requests are exempt from CSRF validation."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": VALID_HOST},
            # No X-CSRF-Token header.
        )
        assert resp.status_code == 200

    def test_session_rotation_invalidates_old_csrf_token(self, client):
        """After a new login (session rotation), the old CSRF token must be invalid."""
        csrf_token_first = _login(client)

        # Log out by clearing cookies, then log in again (new session).
        client.cookies.clear()

        # Second login issues a new session + new CSRF token.
        csrf_token_second = _login(client)

        # The two tokens should differ (different sessions).
        assert csrf_token_first != csrf_token_second, (
            "CSRF token did not change after session rotation."
        )

        # Using the OLD token on a POST should fail (403) because the new session
        # has a different token.
        resp = client.post(
            "/api/v1/health",
            json={},
            headers={
                "Host": VALID_HOST,
                "X-CSRF-Token": csrf_token_first,  # old token
            },
        )
        assert resp.status_code == 403, (
            "Old CSRF token should be invalid after session rotation."
        )


class TestCSRFNoRouteForAuditTruncation:
    """
    AC-27-P0-05b: Assert no API endpoint exists that would truncate, clear,
    or overwrite the audit log.
    """

    def test_no_audit_delete_route(self, test_app):
        """There must be no DELETE/PUT/PATCH route for /api/v1/logs/audit."""
        banned_methods = {"DELETE", "PUT", "PATCH"}
        for route in test_app.routes:
            path = getattr(route, "path", "")
            methods = getattr(route, "methods", set()) or set()
            if "/logs/audit" in path and methods & banned_methods:
                pytest.fail(
                    f"Found a route that would allow audit log truncation: "
                    f"{methods} {path}"
                )

    def test_put_to_audit_path_returns_403_or_404_or_405(self, client):
        """
        A PUT to a fabricated audit truncation endpoint must not succeed (200).
        It may return 403 (CSRF gate), 404 (route not found), or 405 (method not allowed).
        The key assertion is that it does NOT return 200.
        """
        resp = client.put(
            "/api/v1/logs/audit",
            json={},
            headers={"Host": VALID_HOST},
        )
        assert resp.status_code in (403, 404, 405), (
            f"Unexpected status {resp.status_code} for PUT /api/v1/logs/audit. "
            f"A 200 would indicate the audit log is writable via the API."
        )
