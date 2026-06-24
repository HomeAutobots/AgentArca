"""
test_host_validation.py

Covers:
  AC-27-P0-02: Host-validation-before-auth ordering
  AC-27-P0-03: Rebinding red-team (bad Host/Origin returns 403)
  AC-27-P0-03b: Read-only GET with non-loopback Host returns 403
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

TEST_PORT = 8080
VALID_HOST = f"127.0.0.1:{TEST_PORT}"
VALID_LOCALHOST = f"localhost:{TEST_PORT}"


# ---------------------------------------------------------------------------
# AC-27-P0-02: Host-validation-before-auth ordering
# ---------------------------------------------------------------------------

class TestHostValidationBeforeAuth:
    """
    AC-27-P0-02: A request with a bad Host header returns 403.
    No session cookie is issued. Auth is never reached.
    """

    def test_bad_host_returns_403(self, client, test_app):
        """A GET with a non-loopback Host header must return 403."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": "attacker.example.com"},
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

    def test_bad_host_no_set_cookie(self, client):
        """A 403 from Host validation must not issue any Set-Cookie header."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": "attacker.example.com"},
        )
        assert resp.status_code == 403
        assert "set-cookie" not in resp.headers, (
            "Session cookie was issued on a bad-Host request; auth ran before Host validation."
        )

    def test_bad_host_response_body_does_not_contain_secret(self, client):
        """The 403 response body must not contain any secret value."""
        from tests.admin.conftest import TEST_SECRET
        resp = client.get(
            "/api/v1/health",
            headers={"Host": "attacker.example.com"},
        )
        assert resp.status_code == 403
        assert TEST_SECRET not in resp.text, "Secret leaked into 403 response body."

    def test_valid_loopback_host_passes(self, client):
        """A GET with a valid loopback Host header must return 200."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": VALID_HOST},
        )
        assert resp.status_code == 200

    def test_valid_localhost_host_passes(self, client):
        """localhost:<port> is in the allowlist and must return 200."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": VALID_LOCALHOST},
        )
        assert resp.status_code == 200

    def test_ipv6_loopback_rejected(self, client):
        """[::1] is NOT in the allowlist and must return 403."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": f"[::1]:{TEST_PORT}"},
        )
        assert resp.status_code == 403, (
            "[::1] must not be in the Host allowlist (plan-validator decision 2)."
        )

    def test_no_host_header_rejected(self, client):
        """A request with no Host header must return 403."""
        # Remove the Host header by passing an empty string.
        resp = client.get(
            "/api/v1/health",
            headers={"Host": ""},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# AC-27-P0-03: Rebinding red-team
# ---------------------------------------------------------------------------

class TestRebindingRedTeam:
    """
    AC-27-P0-03: Canonical DNS-rebinding scenarios.
    """

    def test_evil_host_and_origin_returns_403(self, client):
        """
        Canonical rebinding: browser connects to 127.0.0.1 but Host carries
        the attacker's domain. Must return 403.
        """
        resp = client.post(
            "/api/v1/login",
            json={"secret": "any"},
            headers={
                "Host": "evil.example.com",
                "Origin": "http://evil.example.com",
            },
        )
        assert resp.status_code == 403

    def test_valid_host_evil_origin_returns_403(self, client):
        """
        Good Host, bad Origin: defense-in-depth secondary check must return 403.
        """
        resp = client.get(
            "/api/v1/health",
            headers={
                "Host": VALID_HOST,
                "Origin": "http://evil.example.com",
            },
        )
        assert resp.status_code == 403

    def test_evil_host_valid_origin_returns_403(self, client):
        """
        Bad Host, good Origin: Host check is primary; bad Host overrides good Origin.
        Must return 403.
        """
        resp = client.get(
            "/api/v1/health",
            headers={
                "Host": "evil.example.com",
                "Origin": f"http://{VALID_HOST}",
            },
        )
        assert resp.status_code == 403

    def test_no_origin_valid_host_passes(self, client):
        """
        No Origin header with valid Host must pass (Origin is optional for non-CORS).
        """
        resp = client.get(
            "/api/v1/health",
            headers={"Host": VALID_HOST},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# AC-27-P0-03b: Read-only GET with non-loopback Host returns 403
# (plan-validator Finding A - distinct from AC-27-P0-02)
# ---------------------------------------------------------------------------

class TestReadOnlyGetHostValidation:
    """
    AC-27-P0-03b: Host validation applies to ALL methods, not just state-changing ones.
    A future implementer must not exempt GETs from Host validation.
    """

    def test_get_health_evil_host_returns_403(self, client):
        """GET /api/v1/health with a non-loopback Host must return 403."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": "evil.example.com"},
        )
        assert resp.status_code == 403, (
            "Read-only GET with non-loopback Host must return 403 "
            "(plan-validator Finding A, AC-27-P0-03b)."
        )

    def test_get_health_attacker_subdomain_returns_403(self, client):
        """GET with a subdomain of 127.0.0.1 must also return 403 (no wildcard matching)."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": "sub.127.0.0.1"},
        )
        assert resp.status_code == 403

    def test_get_health_ip_without_port_returns_403(self, client):
        """GET with 127.0.0.1 (no port) must return 403 (exact match required)."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": "127.0.0.1"},
        )
        assert resp.status_code == 403, (
            "Host header must include the port for exact-match validation."
        )
