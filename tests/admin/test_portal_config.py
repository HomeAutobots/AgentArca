"""
test_portal_config.py - Acceptance tests for the portal-config store and route.

Covers:
  AC-29-P1-07  load_portal_config() returns {"detection_enabled": False} when file absent.
  AC-29-P1-08  save_portal_config({"detection_enabled": True}) writes a mode-0600 file;
               content round-trips; unknown keys already in the file are preserved on
               write (spec sec 3.2/3.4 round-trip-safe). Assert st_mode & 0o777 == 0o600.
  AC-29-P1-10  PATCH /api/v1/portal-config {"unknown_key":"x"} returns 400 and does NOT
               write the file (assert file unchanged/absent). Also: non-bool value for
               detection_enabled rejected 400; isolation-knob name {"net_admin_enabled": true}
               returns 400 (unit assertion of AC-29-P1-15 unit angle).
  Additional:  GET /api/v1/portal-config returns current config.
               Valid PATCH {"detection_enabled": true} returns updated config and writes
               an applied audit record.
  N1 (security-review note): audit domain "portal_config" is valid; an unknown domain
               still raises ValueError.

All unit tests monkeypatch PORTAL_CONFIG_PATH to a tmp_path subdirectory so the real
~/.agentarca/portal-config.json is never touched.

Spec ref: SPEC-29-P1 sec 3, sec 6.4, B9; security-review adjudications A and G.
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
from src.admin.primitives.portal_config import load_portal_config, save_portal_config

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
def tmp_portal_config_path(tmp_path):
    """Temp path for portal-config.json; never touches real ~/.agentarca."""
    return tmp_path / "portal-config.json"


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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_PC_TEST",
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
    if not audit_path.exists():
        return []
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


# ---------------------------------------------------------------------------
# AC-29-P1-07: load_portal_config() returns defaults when file absent
# ---------------------------------------------------------------------------

class TestLoadPortalConfig:
    """
    AC-29-P1-07: load_portal_config() returns {"detection_enabled": False}
    when the config file does not exist (monkeypatched to a nonexistent tmp file).
    """

    def test_returns_defaults_when_file_absent(self, tmp_portal_config_path, monkeypatch):
        """File absent -> returns {"detection_enabled": False}. AC-29-P1-07."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)
        assert not tmp_portal_config_path.exists(), "Test precondition: file must not exist"

        result = load_portal_config()

        assert result == {"detection_enabled": False}, (
            f"Expected {{'detection_enabled': False}} when file absent, got: {result!r}"
        )

    def test_returns_detection_enabled_false_specifically(self, tmp_portal_config_path, monkeypatch):
        """Absence default is exactly False (bool, not truthy). AC-29-P1-07."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)

        result = load_portal_config()

        assert result["detection_enabled"] is False
        assert isinstance(result["detection_enabled"], bool)

    def test_returns_defaults_when_file_is_invalid_json(self, tmp_portal_config_path, monkeypatch):
        """Unreadable/corrupt JSON falls back to defaults (spec sec 3.3)."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)
        tmp_portal_config_path.write_text("not-valid-json", encoding="utf-8")

        result = load_portal_config()

        assert result == {"detection_enabled": False}

    def test_returns_defaults_when_file_is_not_a_dict(self, tmp_portal_config_path, monkeypatch):
        """Non-dict JSON falls back to defaults (spec sec 3.3: 'if not isinstance(data, dict)')."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)
        tmp_portal_config_path.write_text(json.dumps([1, 2, 3]) + "\n", encoding="utf-8")

        result = load_portal_config()

        assert result == {"detection_enabled": False}


# ---------------------------------------------------------------------------
# AC-29-P1-08: save_portal_config writes mode-0600 file; round-trip safe
# ---------------------------------------------------------------------------

class TestSavePortalConfig:
    """
    AC-29-P1-08: save_portal_config({"detection_enabled": True}) writes a mode-0600
    file with the correct content. Unknown keys already in the file are preserved on
    write (spec sec 3.2/3.4 round-trip-safe).
    """

    def test_save_creates_file(self, tmp_portal_config_path, monkeypatch):
        """save_portal_config creates the file when it does not exist. AC-29-P1-08."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)

        save_portal_config({"detection_enabled": True})

        assert tmp_portal_config_path.exists(), "save_portal_config must create the file"

    def test_save_writes_correct_content(self, tmp_portal_config_path, monkeypatch):
        """save_portal_config writes detection_enabled=True correctly. AC-29-P1-08."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)

        save_portal_config({"detection_enabled": True})

        content = json.loads(tmp_portal_config_path.read_text(encoding="utf-8"))
        assert content["detection_enabled"] is True

    def test_save_file_mode_is_0600(self, tmp_portal_config_path, monkeypatch):
        """File must be created at exactly mode 0600 (operator-private). AC-29-P1-08."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)

        save_portal_config({"detection_enabled": True})

        mode = tmp_portal_config_path.stat().st_mode & 0o777
        assert mode == 0o600, (
            f"portal-config.json must be mode 0600; got {oct(mode)}"
        )

    def test_round_trip_preserves_unknown_keys(self, tmp_portal_config_path, monkeypatch):
        """
        Unknown keys in the file are preserved on write (forward-compat, spec sec 3.2/3.4).
        Spec: "Unknown keys in the file are preserved on write (round-trip safe)
        but ignored by the portal."
        AC-29-P1-08.
        """
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)

        # Pre-seed the file with an unknown future key.
        existing = {"detection_enabled": False, "future_feature_flag": "preserved_value"}
        tmp_portal_config_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        tmp_portal_config_path.chmod(0o600)

        # Save an update to detection_enabled only.
        save_portal_config({"detection_enabled": True})

        content = json.loads(tmp_portal_config_path.read_text(encoding="utf-8"))
        assert content["detection_enabled"] is True, "Updated key must be written"
        assert content.get("future_feature_flag") == "preserved_value", (
            f"Unknown key must be preserved on round-trip write; got: {content!r}"
        )

    def test_round_trip_file_still_0600_after_update(self, tmp_portal_config_path, monkeypatch):
        """File mode remains 0600 after an update (not only on first creation)."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)

        # Create then update.
        save_portal_config({"detection_enabled": False})
        save_portal_config({"detection_enabled": True})

        mode = tmp_portal_config_path.stat().st_mode & 0o777
        assert mode == 0o600, f"Mode must remain 0600 after update; got {oct(mode)}"

    def test_load_after_save_round_trips_value(self, tmp_portal_config_path, monkeypatch):
        """load_portal_config() after save_portal_config() returns the saved value."""
        import src.admin.primitives.portal_config as pc_mod
        monkeypatch.setattr(pc_mod, "PORTAL_CONFIG_PATH", tmp_portal_config_path)

        save_portal_config({"detection_enabled": True})
        result = load_portal_config()

        assert result["detection_enabled"] is True


# ---------------------------------------------------------------------------
# Route tests: GET and PATCH /api/v1/portal-config
# ---------------------------------------------------------------------------

class TestPortalConfigRoute:
    """
    Route-level tests for GET/PATCH /api/v1/portal-config.

    AC-29-P1-10: PATCH with unknown key returns 400, file not written.
    Additional: GET returns defaults; valid PATCH returns updated config + audit.
    Security-review adjudication G: PATCH key allowlist enforced before any file I/O.
    """

    # --- GET ---

    def test_get_returns_defaults_when_no_file(self, authed_client, tmp_portal_config_path):
        """GET /api/v1/portal-config returns defaults when portal-config.json absent."""
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.get(
                "/api/v1/portal-config",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["detection_enabled"] is False

    def test_get_returns_current_config_when_file_exists(self, authed_client, tmp_portal_config_path):
        """GET returns current file contents when portal-config.json exists."""
        tmp_portal_config_path.write_text(
            json.dumps({"detection_enabled": True}, indent=2) + "\n", encoding="utf-8"
        )
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.get(
                "/api/v1/portal-config",
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        assert resp.json()["detection_enabled"] is True

    # --- PATCH: valid ---

    def test_patch_valid_returns_200_with_updated_config(self, authed_client, tmp_portal_config_path):
        """Valid PATCH returns 200 with updated config."""
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.patch(
                "/api/v1/portal-config",
                json={"detection_enabled": True},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["detection_enabled"] is True

    def test_patch_valid_writes_file(self, authed_client, tmp_portal_config_path):
        """Valid PATCH writes the config file."""
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            authed_client.patch(
                "/api/v1/portal-config",
                json={"detection_enabled": True},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert tmp_portal_config_path.exists(), "PATCH must write portal-config.json"
        content = json.loads(tmp_portal_config_path.read_text(encoding="utf-8"))
        assert content["detection_enabled"] is True

    def test_patch_valid_writes_applied_audit_record(self, authed_client, tmp_portal_config_path, tmp_audit):
        """Valid PATCH writes an audit record with outcome=applied and domain=portal_config."""
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            authed_client.patch(
                "/api/v1/portal-config",
                json={"detection_enabled": True},
                headers={"Host": VALID_HOST_HEADER},
            )
        records = _read_audit_records(tmp_audit)
        pc_records = [r for r in records if r.get("domain") == "portal_config"]
        assert pc_records, f"Expected portal_config domain audit records; got: {records}"
        applied = [r for r in pc_records if r.get("outcome") == "applied"]
        assert applied, (
            f"Expected applied outcome in portal_config audit; got: {pc_records}"
        )

    # --- PATCH: unknown key (AC-29-P1-10) ---

    def test_patch_unknown_key_returns_400(self, authed_client, tmp_portal_config_path):
        """PATCH with unknown key returns 400 (B9 / AC-29-P1-10)."""
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.patch(
                "/api/v1/portal-config",
                json={"unknown_key": "x"},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400

    def test_patch_unknown_key_does_not_write_file(self, authed_client, tmp_portal_config_path):
        """PATCH with unknown key does NOT write the file (no I/O before validation). AC-29-P1-10."""
        assert not tmp_portal_config_path.exists(), "Precondition: file absent before test"
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            authed_client.patch(
                "/api/v1/portal-config",
                json={"unknown_key": "x"},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert not tmp_portal_config_path.exists(), (
            "portal-config.json must NOT be written for a rejected-by-validation PATCH"
        )

    def test_patch_non_bool_detection_enabled_returns_400(self, authed_client, tmp_portal_config_path):
        """Non-bool detection_enabled (string 'true') is rejected with 400. AC-29-P1-10."""
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.patch(
                "/api/v1/portal-config",
                json={"detection_enabled": "true"},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400

    def test_patch_int_detection_enabled_returns_400(self, authed_client, tmp_portal_config_path):
        """Integer detection_enabled (1) is rejected (strict bool check). AC-29-P1-10."""
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.patch(
                "/api/v1/portal-config",
                json={"detection_enabled": 1},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400

    def test_patch_isolation_knob_returns_400(self, authed_client, tmp_portal_config_path):
        """
        D5.4 isolation knob name net_admin_enabled returns 400 (unit assertion of AC-29-P1-15).
        The red-teamer covers the containment angle; this is the unit assertion.
        Security-review: PATCH key allowlist rejects net_admin_enabled as an unknown key
        BEFORE any file I/O (adjudication G).
        """
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.patch(
                "/api/v1/portal-config",
                json={"net_admin_enabled": True},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400, (
            "Isolation knob net_admin_enabled must be rejected by PATCH key allowlist"
        )

    def test_patch_isolation_knob_does_not_write_file(self, authed_client, tmp_portal_config_path):
        """D5.4 isolation knob PATCH does NOT write the file. AC-29-P1-15 unit angle."""
        assert not tmp_portal_config_path.exists()
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            authed_client.patch(
                "/api/v1/portal-config",
                json={"net_admin_enabled": True},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert not tmp_portal_config_path.exists(), (
            "portal-config.json must NOT be written when isolation knob is rejected"
        )

    def test_patch_requires_auth(self):
        """PATCH /api/v1/portal-config without auth is rejected (401/403)."""
        from starlette.testclient import TestClient
        # Build a minimal settings object on-the-fly; safe because no real path is touched.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            sf = td_path / "s"
            sf.write_text(TEST_SECRET + "\n")
            os.chmod(sf, 0o600)
            s = Settings(
                host=TEST_HOST,
                port=TEST_PORT,
                allow_non_loopback=False,
                secret_file=sf,
                secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_PC_AUTH_TEST",
                audit_log_path=td_path / "audit.jsonl",
                session_secret_key="test-session-key-aaabbbccc" * 4,
            )
            app = create_app(s)
            with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
                c.headers.update({"Host": VALID_HOST_HEADER})
                resp = c.patch(
                    "/api/v1/portal-config",
                    json={"detection_enabled": True},
                    headers={"Host": VALID_HOST_HEADER},
                )
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 for unauthenticated PATCH; got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# N1 (security-review): audit domain "portal_config" is valid; unknown domain raises
# ---------------------------------------------------------------------------

class TestAuditPortalConfigDomain:
    """
    Security-review note N1: "recommend test-engineer add a unit assertion that
    write_audit_record(domain='portal_config', ...) succeeds and that an unknown
    domain still raises, so the audit-domain contract for the new endpoint is pinned."
    """

    def test_portal_config_domain_is_valid(self, tmp_path):
        """write_audit_record with domain='portal_config' must succeed. N1."""
        from src.admin.audit import write_audit_record

        audit_path = tmp_path / "audit.jsonl"
        write_audit_record(
            audit_path,
            session_id="test-session",
            domain="portal_config",
            action="portal_config_patch",
            target="portal-config",
            outcome="applied",
            detail="detection_enabled set to True",
        )
        assert audit_path.exists(), "Audit record must be written for valid domain"
        records = [json.loads(l) for l in audit_path.read_text().splitlines() if l.strip()]
        assert len(records) == 1
        assert records[0]["domain"] == "portal_config"
        assert records[0]["outcome"] == "applied"

    def test_unknown_domain_raises_value_error(self, tmp_path):
        """write_audit_record with unknown domain raises ValueError. N1."""
        from src.admin.audit import write_audit_record

        audit_path = tmp_path / "audit.jsonl"
        with pytest.raises(ValueError, match="Invalid audit domain"):
            write_audit_record(
                audit_path,
                session_id="test-session",
                domain="nonexistent_domain",
                action="some_action",
                target="target",
                outcome="applied",
            )
