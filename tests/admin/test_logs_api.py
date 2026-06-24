"""
test_logs_api.py - Tests for the read-only logs API endpoints.

Covers ACs: 06, 13-17.

AC-27-P1-06: GET /api/v1/logs/audit returns entries; PUT/DELETE/PATCH return 405.
AC-27-P1-13 (BLOCK): All read-only log endpoints return 405 on POST/DELETE/PATCH/PUT.
AC-27-P1-14: GET /api/v1/logs/egress returns empty list with status disclosure when no gateway.
AC-27-P1-15: GET /api/v1/logs/health returns profile=null and empty services when no gateway.
AC-27-P1-16 (BLOCK): No route in the app has DELETE/PUT/PATCH/POST at any /api/v1/logs/ path.

Most tests are isolation-runnable (Docker-free).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings
from src.admin.main import create_app

TEST_SECRET = "test-secret-value-12345"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"


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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_LOGS",
        audit_log_path=tmp_audit,
        session_secret_key="test-session-key-aaabbbccc" * 4,
    )


@pytest.fixture()
def client(test_settings):
    from starlette.testclient import TestClient
    app = create_app(test_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": f"{TEST_HOST}:{TEST_PORT}"})
        yield c


@pytest.fixture()
def authed_client(client):
    resp = client.post("/api/v1/login", json={"secret": TEST_SECRET})
    assert resp.status_code == 200
    csrf = resp.json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": csrf})
    return client


# ---------------------------------------------------------------------------
# AC-27-P1-06: GET /api/v1/logs/audit returns entries; mutation methods 405
# ---------------------------------------------------------------------------

class TestAuditEndpoint:
    """AC-27-P1-06: audit endpoint read works; mutations return 405."""

    def test_get_audit_empty_file(self, authed_client, tmp_audit):
        """GET when audit file has no records returns valid empty response."""
        # Note: the authed_client fixture performs a login which writes a login
        # audit record. So tmp_audit may already exist with one record.
        # We test this by truncating the file to simulate an empty state,
        # then verifying the empty-list path works.
        # We also verify that when the file does NOT exist, we get an empty list.

        # Test 1: file does not exist -> use a fresh path.
        from src.admin.config import Settings
        import tempfile, os as _os
        tmp = tempfile.mkdtemp()
        secret_file = Path(tmp) / "admin-secret"
        secret_file.write_text("test-empty-audit-secret\n", encoding="utf-8")
        _os.chmod(secret_file, 0o600)
        empty_audit = Path(tmp) / "empty-audit.jsonl"
        # empty_audit does not exist yet.
        assert not empty_audit.exists()

        settings = Settings(
            host=TEST_HOST,
            port=TEST_PORT,
            allow_non_loopback=False,
            secret_file=secret_file,
            secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_EMPTY",
            audit_log_path=empty_audit,
            session_secret_key="empty-audit-session-key-aaabbbccc" * 4,
        )
        from src.admin.main import create_app as _create_app
        from starlette.testclient import TestClient
        app = _create_app(settings)
        with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
            c.headers.update({"Host": f"{TEST_HOST}:{TEST_PORT}"})
            # Log in.
            resp = c.post("/api/v1/login", json={"secret": "test-empty-audit-secret"})
            assert resp.status_code == 200
            csrf = resp.json()["csrf_token"]
            c.headers.update({"X-CSRF-Token": csrf})

            # GET audit. The login wrote one record, but the endpoint should work.
            resp = c.get("/api/v1/logs/audit")
            assert resp.status_code == 200
            body = resp.json()
            assert "entries" in body
            assert "total_lines" in body
            # There may be one login record; that is valid.

        # Test 2: explicitly truncate to simulate empty file.
        empty_audit.write_text("", encoding="utf-8")
        from src.admin.primitives.logs import read_audit_log
        result = read_audit_log(empty_audit, limit=100, offset=0)
        assert result["entries"] == []
        assert result["total_lines"] == 0

    def test_get_audit_with_records(self, authed_client, tmp_audit):
        """GET returns parsed audit records."""
        record = {
            "schema_version": "1",
            "timestamp_utc": "2026-06-24T10:00:00.000Z",
            "session_id": "abc123",
            "domain": "allowlist",
            "action": "allowlist_add",
            "target": "api.example.com",
            "before": None,
            "after": "api.example.com",
            "outcome": "applied",
        }
        tmp_audit.write_text(json.dumps(record) + "\n", encoding="utf-8")

        resp = authed_client.get("/api/v1/logs/audit")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_lines"] == 1
        assert len(body["entries"]) == 1
        assert body["entries"][0]["action"] == "allowlist_add"

    def test_get_audit_pagination(self, authed_client, tmp_audit):
        """Pagination: limit and offset work correctly."""
        records = [
            json.dumps({
                "schema_version": "1",
                "timestamp_utc": f"2026-06-24T10:00:0{i}.000Z",
                "session_id": "abc123",
                "domain": "allowlist",
                "action": "allowlist_add",
                "target": f"host{i}.example.com",
                "outcome": "applied",
            }) for i in range(5)
        ]
        tmp_audit.write_text("\n".join(records) + "\n", encoding="utf-8")

        resp = authed_client.get("/api/v1/logs/audit?limit=2&offset=0")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_lines"] == 5
        assert len(body["entries"]) == 2

        resp2 = authed_client.get("/api/v1/logs/audit?limit=2&offset=2")
        assert resp2.status_code == 200
        assert len(resp2.json()["entries"]) == 2

    def test_post_audit_returns_405(self, authed_client):
        """POST /api/v1/logs/audit returns 405 (no write path)."""
        resp = authed_client.post("/api/v1/logs/audit", json={})
        assert resp.status_code == 405

    def test_delete_audit_returns_405(self, authed_client):
        """DELETE /api/v1/logs/audit returns 405 (no delete path)."""
        resp = authed_client.delete("/api/v1/logs/audit")
        assert resp.status_code == 405

    def test_put_audit_returns_405(self, authed_client):
        """PUT /api/v1/logs/audit returns 405."""
        resp = authed_client.put("/api/v1/logs/audit", json={})
        assert resp.status_code == 405

    def test_patch_audit_returns_405(self, authed_client):
        """PATCH /api/v1/logs/audit returns 405."""
        resp = authed_client.patch("/api/v1/logs/audit", json={})
        assert resp.status_code == 405

    def test_get_audit_requires_auth(self, client):
        """Unauthenticated GET returns 401."""
        resp = client.get("/api/v1/logs/audit")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# AC-27-P1-13 (BLOCK): All log endpoints return 405 on mutation methods
# ---------------------------------------------------------------------------

class TestLogEndpointMutationForbidden:
    """AC-27-P1-13 (BLOCK): POST/DELETE/PATCH/PUT return 405 on all log endpoints."""

    LOG_PATHS = [
        "/api/v1/logs/audit",
        "/api/v1/logs/egress",
        "/api/v1/logs/health",
    ]

    MUTATION_METHODS = ["POST", "DELETE", "PUT", "PATCH"]

    @pytest.mark.parametrize("path", LOG_PATHS)
    @pytest.mark.parametrize("method", MUTATION_METHODS)
    def test_mutation_returns_405(self, authed_client, path, method):
        """Each mutation method on each log path returns 405."""
        resp = authed_client.request(method, path, json={})
        assert resp.status_code == 405, (
            f"Expected 405 for {method} {path}, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# AC-27-P1-14: GET /api/v1/logs/egress empty when no gateway
# ---------------------------------------------------------------------------

class TestEgressLogEndpoint:
    """AC-27-P1-14: Egress endpoint returns empty with disclosure when no gateway."""

    def test_egress_no_gateway_returns_ok_with_disclosure(self, authed_client):
        """When no gateway is running, return empty entries with a status field."""
        with (
            patch("src.admin.routes.logs.detect_active_gateway", return_value=None),
            patch("src.admin.primitives.logs.read_egress_log",
                  return_value={"status": "no_gateway_running", "gateway": None, "entries": []}),
        ):
            resp = authed_client.get("/api/v1/logs/egress")

        assert resp.status_code == 200
        body = resp.json()
        assert "entries" in body
        assert isinstance(body["entries"], list)
        assert "status" in body

    def test_egress_docker_not_available_returns_disclosure(self, authed_client):
        """When docker is not available, return status disclosure."""
        with patch("src.admin.routes.logs.detect_active_gateway", return_value="copilot-gateway"), \
             patch("src.admin.primitives.logs._check_docker_available", return_value=False):
            resp = authed_client.get("/api/v1/logs/egress")

        assert resp.status_code == 200
        body = resp.json()
        assert body["entries"] == [] or isinstance(body["entries"], list)
        assert "status" in body

    def test_egress_requires_auth(self, client):
        """Unauthenticated egress GET returns 401."""
        resp = client.get("/api/v1/logs/egress")
        assert resp.status_code == 401

    def test_egress_post_returns_405(self, authed_client):
        """POST /api/v1/logs/egress returns 405."""
        resp = authed_client.post("/api/v1/logs/egress", json={})
        assert resp.status_code == 405

    def test_egress_delete_returns_405(self, authed_client):
        """DELETE /api/v1/logs/egress returns 405."""
        resp = authed_client.delete("/api/v1/logs/egress")
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# AC-27-P1-15: GET /api/v1/logs/health empty when no gateway
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    """AC-27-P1-15: Health endpoint returns null profile and empty services when no gateway."""

    def test_health_no_gateway_returns_null_profile(self, authed_client):
        """When no gateway is running, active_profile=null, services=[]."""
        with patch("src.admin.primitives.logs._check_docker_available", return_value=False):
            resp = authed_client.get("/api/v1/logs/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body.get("active_profile") is None
        assert isinstance(body.get("services", []), list)

    def test_health_with_running_gateway(self, authed_client):
        """When a gateway is detected, active_profile and services are populated."""
        mock_services = [
            {"name": "copilot-gateway", "status": "running", "health": "healthy", "ports": []},
        ]
        with patch("src.admin.primitives.logs._check_docker_available", return_value=True), \
             patch("src.admin.primitives.logs._run_docker_compose_ps",
                   return_value=[
                       {"Name": "copilot-gateway", "Status": "running", "Health": "healthy", "Ports": ""},
                   ]):
            resp = authed_client.get("/api/v1/logs/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body.get("active_profile") == "copilot"
        assert len(body.get("services", [])) > 0

    def test_health_requires_auth(self, client):
        """Unauthenticated health GET returns 401."""
        resp = client.get("/api/v1/logs/health")
        assert resp.status_code == 401

    def test_health_post_returns_405(self, authed_client):
        """POST /api/v1/logs/health returns 405."""
        resp = authed_client.post("/api/v1/logs/health", json={})
        assert resp.status_code == 405

    def test_health_delete_returns_405(self, authed_client):
        """DELETE /api/v1/logs/health returns 405."""
        resp = authed_client.delete("/api/v1/logs/health")
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# AC-27-P1-16 (BLOCK): Route enumeration - no write methods on log paths
# ---------------------------------------------------------------------------

def test_no_write_on_logs_routes():
    """
    AC-27-P1-16 (BLOCK): No route in the app has a DELETE/PUT/PATCH/POST method
    at any /api/v1/logs/ path.

    This is a permanent regression barrier. The route table is inspected directly.
    FastAPI routes are of type fastapi.routing.APIRoute; these have a .path and
    .methods attribute. We walk all routes including those nested inside routers.
    """
    import os
    import tempfile
    from pathlib import Path as _Path
    from fastapi.routing import APIRoute

    tmp = tempfile.mkdtemp()
    secret_file = _Path(tmp) / "admin-secret"
    secret_file.write_text("test-route-enum-secret\n", encoding="utf-8")
    os.chmod(secret_file, 0o600)

    settings = Settings(
        host="127.0.0.1",
        port=8080,
        allow_non_loopback=False,
        secret_file=secret_file,
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_ENUM",
        audit_log_path=_Path(tmp) / "audit.jsonl",
        session_secret_key="route-enum-session-key-aaabbbccc" * 4,
    )

    app = create_app(settings)

    mutating_methods = {"DELETE", "PUT", "PATCH", "POST"}

    # Collect all APIRoute instances from the app.
    # FastAPI 0.138+ wraps included routers in _IncludedRouter objects on app.routes.
    # The actual APIRoute objects live in each _IncludedRouter.original_router.routes.
    # We walk both levels to find all routes.
    all_routes = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            all_routes.append(route)
        elif hasattr(route, "original_router"):
            # _IncludedRouter: the included router's routes live here.
            for sub_route in getattr(route.original_router, "routes", []):
                if isinstance(sub_route, APIRoute):
                    all_routes.append(sub_route)

    log_routes = [
        r for r in all_routes
        if str(r.path).startswith("/api/v1/logs/")
    ]

    violations = []
    for route in log_routes:
        route_methods = route.methods or set()
        overlap = route_methods & mutating_methods
        if overlap:
            violations.append(
                f"Log route {route.path!r} has mutating method(s): {overlap}"
            )

    assert not violations, (
        "BLOCK: The following log routes have mutating methods (AC-27-P1-16 violation):\n"
        + "\n".join(violations)
    )

    # Also confirm at least the three expected GET routes exist.
    log_path_strings = {str(r.path) for r in log_routes}
    for expected in ["/api/v1/logs/audit", "/api/v1/logs/egress", "/api/v1/logs/health"]:
        assert expected in log_path_strings, (
            f"Expected log route {expected} not found in route table. "
            f"Found: {log_path_strings}"
        )
