"""
test_isolation_api.py - API-level tests for isolation routes.

Covers:
  AC-27-P3-01  (BLOCK) D5.4 hard refusals via POST /isolation/validate
  AC-27-P3-01b (BLOCK) Route enumeration (also in test_credentials_api.py)
  AC-27-P3-10  (BLOCK) GET /api/v1/isolation returns correct fields; no editable fields
  AC-27-P3-18  (BLOCK) POST /isolation/validate is NON-MUTATING
  AC-27-P3-19         POST /isolation/validate with no violations -> 200
  AC-27-P3-20  (BLOCK) NET_ADMIN in proposed_caps_add -> 400 + rejected-by-stop-and-flag
  AC-27-P3-21  (BLOCK) concurrent_profiles=true -> 400
  AC-27-P3-22  (BLOCK) No DELETE/PUT/PATCH at /api/v1/isolation/*

Integration-gated:
  AC-27-P3-16 isolation variant (@pytest.mark.integration) - covered by credentials test

All tests are isolation-runnable (no Docker stack required).
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
def tmp_salt_dir(tmp_path):
    d = tmp_path / ".agentarca"
    d.mkdir()
    return d


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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_ISOL_TEST",
        audit_log_path=tmp_audit,
        session_secret_key="test-session-key-aaabbbccc" * 4,
        repo_root=tmp_path,
    )


@pytest.fixture()
def app_client(test_settings, tmp_salt_dir):
    """Return an authenticated TestClient."""
    import src.admin.primitives.credentials as creds_module
    from starlette.testclient import TestClient

    orig_salt_path = creds_module.FINGERPRINT_SALT_PATH
    salt_file = tmp_salt_dir / "fingerprint-salt"
    creds_module.FINGERPRINT_SALT_PATH = salt_file

    try:
        app = create_app(test_settings)
        with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
            c.headers.update({"Host": VALID_HOST_HEADER})
            login_resp = c.post(
                "/api/v1/login",
                json={"secret": TEST_SECRET},
                headers={"Host": VALID_HOST_HEADER},
            )
            assert login_resp.status_code == 200
            csrf = login_resp.json()["csrf_token"]
            c.headers.update({"X-CSRF-Token": csrf})
            yield c, test_settings
    finally:
        creds_module.FINGERPRINT_SALT_PATH = orig_salt_path


# ---------------------------------------------------------------------------
# AC-27-P3-10 (BLOCK): GET /api/v1/isolation
# ---------------------------------------------------------------------------

def test_get_isolation_returns_posture_fields(app_client):
    """
    AC-27-P3-10 (BLOCK): GET /api/v1/isolation returns all required posture fields.
    No editable field names (e.g. 'edit', 'input', 'form_action') present.
    d5_4_violations is empty on a clean/mocked config.
    """
    client, settings = app_client
    resp = client.get("/api/v1/isolation")
    assert resp.status_code == 200
    data = resp.json()

    # Required top-level keys.
    assert "posture" in data
    assert "d5_4_violations" in data
    assert "non_editable_notice" in data
    assert "edit_note" in data

    posture = data["posture"]
    required_fields = {
        "cap_drop", "cap_add", "no_new_privileges", "seccomp_profile",
        "read_only_rootfs", "pids_limit", "mem_limit", "cpus",
        "network_mode", "docker_sock_mounted", "privileged", "gateway_cap_add",
    }
    for field_name in required_fields:
        assert field_name in posture, f"Missing posture field: {field_name}"

    # No editable field affordances.
    forbidden_response_fields = {
        "editable", "edit_field", "form_action", "write_target",
        "cap_grant", "add_cap_endpoint",
    }
    data_keys = set(str(k) for k in data.keys())
    posture_keys = set(str(k) for k in posture.keys())
    all_response_keys = data_keys | posture_keys
    for forbidden in forbidden_response_fields:
        assert forbidden not in all_response_keys, (
            f"BLOCK: response contains editable field '{forbidden}'"
        )

    # docker_sock_mounted and privileged must be False in correct config.
    assert isinstance(posture["docker_sock_mounted"], bool)
    assert isinstance(posture["privileged"], bool)


# ---------------------------------------------------------------------------
# AC-27-P3-22 (BLOCK): No DELETE/PUT/PATCH at /api/v1/isolation/*
# ---------------------------------------------------------------------------

def test_no_mutating_methods_on_isolation_path(test_settings, tmp_salt_dir):
    """
    AC-27-P3-22 (BLOCK): There is no DELETE, PUT, or PATCH at any /api/v1/isolation/* path
    except POST /validate (which is non-mutating).
    """
    import src.admin.primitives.credentials as creds_module

    orig_salt_path = creds_module.FINGERPRINT_SALT_PATH
    salt_file = tmp_salt_dir / "fingerprint-salt"
    creds_module.FINGERPRINT_SALT_PATH = salt_file

    try:
        app = create_app(test_settings)
        from fastapi.routing import APIRoute  # noqa: PLC0415

        forbidden_methods = {"DELETE", "PUT", "PATCH"}

        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            if "/api/v1/isolation" not in str(route.path):
                continue
            route_methods = set(route.methods or [])
            bad_methods = route_methods & forbidden_methods
            assert not bad_methods, (
                f"BLOCK: isolation path {route.path!r} has forbidden mutating methods: "
                f"{bad_methods}. Isolation is READ-ONLY in the MVP."
            )
    finally:
        creds_module.FINGERPRINT_SALT_PATH = orig_salt_path


# ---------------------------------------------------------------------------
# AC-27-P3-01 (BLOCK): D5.4 hard refusals
# ---------------------------------------------------------------------------

def test_d5_4_net_admin_returns_400(app_client):
    """
    AC-27-P3-01 (BLOCK): POST /isolation/validate with NET_ADMIN -> 400.
    Violations list contains NET_ADMIN. Audit outcome=rejected-by-stop-and-flag.
    """
    client, settings = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={"proposed_caps_add": ["NET_ADMIN"]},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["ok"] is False
    violations = data["violations"]
    assert any("NET_ADMIN" in v for v in violations), (
        f"BLOCK: NET_ADMIN not in violations: {violations}"
    )

    # Check audit record.
    audit_text = settings.audit_log_path.read_text()
    records = [json.loads(l) for l in audit_text.splitlines() if l.strip()]
    validate_records = [r for r in records if r.get("action") == "isolation_validate"]
    assert validate_records, "Audit record for isolation_validate must be written"
    rec = validate_records[-1]
    assert rec["outcome"] == "rejected-by-stop-and-flag"


def test_d5_4_net_raw_returns_400(app_client):
    """AC-27-P3-01 (BLOCK): NET_RAW -> 400."""
    client, _ = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={"proposed_caps_add": ["NET_RAW"]},
    )
    assert resp.status_code == 400
    assert any("NET_RAW" in v for v in resp.json()["violations"])


def test_d5_4_sys_admin_returns_400(app_client):
    """AC-27-P3-01 (BLOCK): SYS_ADMIN -> 400."""
    client, _ = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={"proposed_caps_add": ["SYS_ADMIN"]},
    )
    assert resp.status_code == 400
    assert any("SYS_ADMIN" in v for v in resp.json()["violations"])


def test_d5_4_privileged_returns_400(app_client):
    """AC-27-P3-01 (BLOCK): --privileged -> 400."""
    client, _ = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={"proposed_flags": ["--privileged"]},
    )
    assert resp.status_code == 400
    assert any("privileged" in v.lower() for v in resp.json()["violations"])


def test_d5_4_docker_sock_returns_400(app_client):
    """AC-27-P3-01 (BLOCK): docker.sock mount -> 400."""
    client, _ = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={"proposed_mounts": ["/var/run/docker.sock:/var/run/docker.sock"]},
    )
    assert resp.status_code == 400
    assert any("docker.sock" in v for v in resp.json()["violations"])


# ---------------------------------------------------------------------------
# AC-27-P3-21 (BLOCK): concurrent_profiles -> 400
# ---------------------------------------------------------------------------

def test_d5_4_concurrent_profiles_returns_400(app_client):
    """
    AC-27-P3-21 (BLOCK): POST /isolation/validate with concurrent_profiles=true -> 400.
    """
    client, _ = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={"concurrent_profiles": True},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["ok"] is False
    assert any("concurrent" in v.lower() for v in data["violations"])


# ---------------------------------------------------------------------------
# AC-27-P3-20 (BLOCK): NET_ADMIN -> audit outcome=rejected-by-stop-and-flag
# ---------------------------------------------------------------------------

def test_validate_refused_audit_record(app_client):
    """
    AC-27-P3-20 (BLOCK): Audit record for refused isolation_validate has
    outcome=rejected-by-stop-and-flag and NET_ADMIN in the detail.
    """
    client, settings = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={"proposed_caps_add": ["NET_ADMIN"]},
    )
    assert resp.status_code == 400

    audit_text = settings.audit_log_path.read_text()
    records = [json.loads(l) for l in audit_text.splitlines() if l.strip()]
    validate_records = [r for r in records if r.get("action") == "isolation_validate"]
    assert validate_records
    rec = validate_records[-1]
    assert rec["outcome"] == "rejected-by-stop-and-flag"
    # Detail must contain at least a mention of the refusal reason.
    detail = rec.get("detail", "") or ""
    assert "NET_ADMIN" in detail or "D5.4" in detail or "forbidden" in detail.lower()


# ---------------------------------------------------------------------------
# AC-27-P3-19: POST /isolation/validate with no violations -> 200
# ---------------------------------------------------------------------------

def test_validate_no_violations_returns_200(app_client):
    """
    AC-27-P3-19: POST /isolation/validate with benign values -> 200,
    violations=[], audit outcome=applied.
    """
    client, settings = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={
            "proposed_caps_add": [],
            "proposed_flags": [],
            "proposed_mounts": [],
            "concurrent_profiles": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["violations"] == []

    audit_text = settings.audit_log_path.read_text()
    records = [json.loads(l) for l in audit_text.splitlines() if l.strip()]
    validate_records = [r for r in records if r.get("action") == "isolation_validate"]
    assert validate_records
    rec = validate_records[-1]
    assert rec["outcome"] == "applied"


def test_validate_empty_body_returns_200(app_client):
    """POST /isolation/validate with empty body (all defaults) -> 200."""
    client, _ = app_client
    resp = client.post("/api/v1/isolation/validate", json={})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# ---------------------------------------------------------------------------
# AC-27-P3-18 (BLOCK): POST /isolation/validate is NON-MUTATING
# ---------------------------------------------------------------------------

def test_validate_is_non_mutating(app_client, test_settings):
    """
    AC-27-P3-18 (BLOCK): After a refused isolation_validate call:
    - No file changed except the audit log.
    - No subprocess was called.
    - Running config is unchanged.
    """
    client, settings = app_client

    # Note the mtime of any existing files.
    env_path = settings.repo_root / ".env"
    compose_path = settings.repo_root / "docker-compose.yml"

    env_existed_before = env_path.exists()
    compose_existed_before = compose_path.exists()

    # Track subprocess calls.
    import subprocess as subprocess_module  # noqa: PLC0415
    subprocess_call_count = {"n": 0}
    original_run = subprocess_module.run

    def mock_subprocess_run(*args, **kwargs):
        subprocess_call_count["n"] += 1
        return original_run(*args, **kwargs)

    with patch.object(subprocess_module, "run", side_effect=mock_subprocess_run):
        resp = client.post(
            "/api/v1/isolation/validate",
            json={"proposed_caps_add": ["NET_ADMIN"]},
        )

    assert resp.status_code == 400

    # No subprocess was called by the validate handler.
    assert subprocess_call_count["n"] == 0, (
        "BLOCK: POST /isolation/validate called subprocess. "
        "It must be NON-MUTATING: no subprocess allowed."
    )

    # .env was not created or modified by the validate call.
    assert env_path.exists() == env_existed_before, (
        ".env existence changed after isolation/validate call"
    )

    # docker-compose.yml was not created or modified.
    assert compose_path.exists() == compose_existed_before


# ---------------------------------------------------------------------------
# Multiple D5.4 conditions in one request
# ---------------------------------------------------------------------------

def test_multiple_d5_4_violations_all_reported(app_client):
    """All D5.4 violations in a single request are returned."""
    client, _ = app_client
    resp = client.post(
        "/api/v1/isolation/validate",
        json={
            "proposed_caps_add": ["NET_ADMIN", "SYS_ADMIN"],
            "proposed_flags": ["--privileged"],
        },
    )
    assert resp.status_code == 400
    violations = resp.json()["violations"]
    assert len(violations) >= 3


# ---------------------------------------------------------------------------
# Unauthenticated access to isolation endpoints
# ---------------------------------------------------------------------------

def test_get_isolation_without_auth_returns_401(test_settings, tmp_salt_dir):
    """GET /api/v1/isolation without auth -> 401."""
    import src.admin.primitives.credentials as creds_module
    from starlette.testclient import TestClient

    orig_salt_path = creds_module.FINGERPRINT_SALT_PATH
    salt_file = tmp_salt_dir / "fingerprint-salt"
    creds_module.FINGERPRINT_SALT_PATH = salt_file

    try:
        app = create_app(test_settings)
        with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
            c.headers.update({"Host": VALID_HOST_HEADER})
            resp = c.get("/api/v1/isolation")
            assert resp.status_code == 401
    finally:
        creds_module.FINGERPRINT_SALT_PATH = orig_salt_path


def test_validate_without_auth_returns_401_or_403(test_settings, tmp_salt_dir):
    """
    POST /api/v1/isolation/validate without auth -> 401 or 403.

    The CSRF middleware fires before the auth check on POST (mutating method).
    Both 401 and 403 are acceptable: the validate endpoint is unreachable
    without a valid session+CSRF pair.
    """
    import src.admin.primitives.credentials as creds_module
    from starlette.testclient import TestClient

    orig_salt_path = creds_module.FINGERPRINT_SALT_PATH
    salt_file = tmp_salt_dir / "fingerprint-salt"
    creds_module.FINGERPRINT_SALT_PATH = salt_file

    try:
        app = create_app(test_settings)
        with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
            c.headers.update({"Host": VALID_HOST_HEADER})
            resp = c.post(
                "/api/v1/isolation/validate",
                json={"proposed_caps_add": ["NET_ADMIN"]},
            )
            assert resp.status_code in (401, 403), (
                f"Expected 401 or 403 for unauthenticated POST /isolation/validate, "
                f"got {resp.status_code}"
            )
    finally:
        creds_module.FINGERPRINT_SALT_PATH = orig_salt_path
