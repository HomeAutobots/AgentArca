"""
test_startup.py

Covers:
  AC-27-P0-01: Loopback-bind refuse-to-start
  AC-27-P0-05c: Audit log not in any Docker-volume path (startup assertion)
  AC-27-P0-08: Startup log contains effective bind address
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class TestLoopbackBindAssertion:
    """AC-27-P0-01: The app must refuse to start if host is not 127.0.0.1."""

    def test_non_loopback_host_causes_system_exit(self, tmp_path):
        """create_app() with host=0.0.0.0 and allow_non_loopback=False must raise SystemExit(1)."""
        from src.admin.config import Settings
        from src.admin.main import create_app

        secret_file = tmp_path / "admin-secret"
        secret_file.write_text("test-secret\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)

        settings = Settings(
            host="0.0.0.0",
            port=8080,
            allow_non_loopback=False,
            secret_file=secret_file,
            audit_log_path=tmp_path / "audit.jsonl",
            session_secret_key="test-session-key" * 8,
        )
        with pytest.raises(SystemExit) as exc_info:
            create_app(settings)
        assert exc_info.value.code != 0, (
            "SystemExit must have a non-zero exit code for a non-loopback bind attempt."
        )

    def test_loopback_host_starts_successfully(self, tmp_path):
        """create_app() with host=127.0.0.1 must succeed."""
        from src.admin.config import Settings
        from src.admin.main import create_app

        secret_file = tmp_path / "admin-secret"
        secret_file.write_text("test-secret\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)

        settings = Settings(
            host="127.0.0.1",
            port=8080,
            allow_non_loopback=False,
            secret_file=secret_file,
            audit_log_path=tmp_path / "audit.jsonl",
            session_secret_key="test-session-key" * 8,
        )
        # Must not raise.
        app = create_app(settings)
        assert app is not None

    def test_non_loopback_with_override_flag_logs_warning(self, tmp_path, caplog):
        """When allow_non_loopback=True, the app starts with a WARNING log."""
        import logging
        from src.admin.config import Settings
        from src.admin.main import create_app

        secret_file = tmp_path / "admin-secret"
        secret_file.write_text("test-secret\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)

        settings = Settings(
            host="0.0.0.0",
            port=8080,
            allow_non_loopback=True,
            secret_file=secret_file,
            audit_log_path=tmp_path / "audit.jsonl",
            session_secret_key="test-session-key" * 8,
        )
        with caplog.at_level(logging.WARNING, logger="src.admin.main"):
            app = create_app(settings)
        assert app is not None
        # The WARNING message must contain the override text.
        warning_texts = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("NON-LOOPBACK BIND OVERRIDE ACTIVE" in t for t in warning_texts), (
            "Expected 'NON-LOOPBACK BIND OVERRIDE ACTIVE' in WARNING log when "
            "allow_non_loopback=True. Log messages: " + str(warning_texts)
        )

    def test_override_warning_contains_effective_host(self, tmp_path, caplog):
        """The NON-LOOPBACK override warning must name the effective bind host."""
        import logging
        from src.admin.config import Settings
        from src.admin.main import create_app

        secret_file = tmp_path / "admin-secret"
        secret_file.write_text("test-secret\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)

        settings = Settings(
            host="0.0.0.0",
            port=8080,
            allow_non_loopback=True,
            secret_file=secret_file,
            audit_log_path=tmp_path / "audit.jsonl",
            session_secret_key="test-session-key" * 8,
        )
        with caplog.at_level(logging.WARNING, logger="src.admin.main"):
            create_app(settings)

        warning_texts = " ".join(
            r.message for r in caplog.records if r.levelno >= logging.WARNING
        )
        assert "0.0.0.0" in warning_texts, (
            "The NON-LOOPBACK warning must name the effective host (0.0.0.0)."
        )


class TestNoSecretAtStartup:
    """AC-27-P0-01: No secret file and no env var -> SystemExit(1)."""

    def test_missing_secret_causes_system_exit(self, tmp_path):
        """create_app() with no secret file and no env var must raise SystemExit."""
        from src.admin.config import Settings
        from src.admin.main import create_app

        settings = Settings(
            host="127.0.0.1",
            port=8080,
            allow_non_loopback=False,
            secret_file=tmp_path / "nonexistent-secret",
            secret_env_var="AGENTARCA_ADMIN_SECRET_DOES_NOT_EXIST_AT_ALL",
            audit_log_path=tmp_path / "audit.jsonl",
            session_secret_key="test-session-key" * 8,
        )
        # Ensure the env var is not accidentally set.
        env_backup = os.environ.pop("AGENTARCA_ADMIN_SECRET_DOES_NOT_EXIST_AT_ALL", None)
        try:
            with pytest.raises(SystemExit) as exc_info:
                create_app(settings)
            assert exc_info.value.code != 0
        finally:
            if env_backup is not None:
                os.environ["AGENTARCA_ADMIN_SECRET_DOES_NOT_EXIST_AT_ALL"] = env_backup


class TestAuditPathNotInVolume:
    """AC-27-P0-05c: Audit log must not be inside a Docker volume path."""

    def test_audit_path_inside_src_raises(self, tmp_path):
        """Setting audit_log_path to a path under src/ must raise RuntimeError at startup."""
        from src.admin.config import Settings
        from src.admin.main import create_app

        secret_file = tmp_path / "admin-secret"
        secret_file.write_text("test-secret\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)

        # Use a path under the repo's src/ directory (a known bind-mount area).
        bad_audit_path = REPO_ROOT / "src" / "admin-audit.jsonl"

        settings = Settings(
            host="127.0.0.1",
            port=8080,
            allow_non_loopback=False,
            secret_file=secret_file,
            audit_log_path=bad_audit_path,
            session_secret_key="test-session-key" * 8,
        )
        with pytest.raises((RuntimeError, SystemExit)):
            create_app(settings)

    def test_audit_path_in_home_dir_passes(self, tmp_path):
        """A path under a temp directory outside the repo must pass the startup check."""
        from src.admin.config import Settings
        from src.admin.main import create_app

        secret_file = tmp_path / "admin-secret"
        secret_file.write_text("test-secret\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)

        settings = Settings(
            host="127.0.0.1",
            port=8080,
            allow_non_loopback=False,
            secret_file=secret_file,
            audit_log_path=tmp_path / "admin-audit.jsonl",
            session_secret_key="test-session-key" * 8,
        )
        app = create_app(settings)
        assert app is not None


class TestStartupLogContainsBind:
    """AC-27-P0-08: Startup log must contain the effective bind address."""

    def test_startup_log_contains_bind_address(self, tmp_path, caplog):
        """The INFO log emitted at startup must contain host:port."""
        import logging
        from src.admin.config import Settings
        from src.admin.main import create_app

        secret_file = tmp_path / "admin-secret"
        secret_file.write_text("test-secret\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)

        settings = Settings(
            host="127.0.0.1",
            port=8080,
            allow_non_loopback=False,
            secret_file=secret_file,
            audit_log_path=tmp_path / "audit.jsonl",
            session_secret_key="test-session-key" * 8,
        )
        with caplog.at_level(logging.INFO, logger="src.admin.main"):
            create_app(settings)

        all_log_text = " ".join(r.message for r in caplog.records)
        assert "127.0.0.1" in all_log_text, (
            "Startup log must contain the bind address 127.0.0.1. "
            "Log messages: " + all_log_text
        )

    def test_startup_log_does_not_contain_secret(self, tmp_path, caplog):
        """The startup log must never contain the secret value."""
        import logging
        from src.admin.config import Settings
        from src.admin.main import create_app

        known_secret = "super-secret-startup-test-value-9999"
        secret_file = tmp_path / "admin-secret"
        secret_file.write_text(known_secret + "\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)

        settings = Settings(
            host="127.0.0.1",
            port=8080,
            allow_non_loopback=False,
            secret_file=secret_file,
            audit_log_path=tmp_path / "audit.jsonl",
            session_secret_key="test-session-key" * 8,
        )
        with caplog.at_level(logging.DEBUG, logger="src.admin.main"):
            create_app(settings)

        all_log_text = " ".join(r.message for r in caplog.records)
        assert known_secret not in all_log_text, (
            "The secret value appeared in the startup log. This is a BLOCK condition."
        )
