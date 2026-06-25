"""
config.py - Settings dataclass for the admin control plane.

Priority order (highest to lowest):
1. Command-line flags (--host, --port, --allow-non-loopback)
2. Environment variables (AGENTARCA_ADMIN_* prefix)
3. Config file at ~/.agentarca/admin.conf (or AGENTARCA_ADMIN_CONFIG_FILE override)
4. Compiled defaults
"""

from __future__ import annotations

import configparser
import logging
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _expand(p: str) -> Path:
    return Path(os.path.expanduser(p))


def _parse_bool(v: str) -> bool:
    return v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    host: str = "127.0.0.1"
    # Default 8770, deliberately NOT 8080: the per-profile egress gateway runs Squid on
    # 8080 inside the netns the devcontainer shares (ADR-009 D-A), so an 8080 default
    # collides with the proxy and confuses reachability checks. See R-s implementation note.
    port: int = 8770
    allow_non_loopback: bool = False
    secret_file: Path = field(default_factory=lambda: _expand("~/.agentarca/admin-secret"))
    secret_env_var: str = "AGENTARCA_ADMIN_SECRET"
    audit_log_path: Path = field(default_factory=lambda: _expand("~/.agentarca/admin-audit.jsonl"))
    # session_secret_key is loaded/generated at startup; default empty forces explicit init.
    session_secret_key: str = ""
    session_ttl: int = 8 * 3600  # 8 hours in seconds
    # repo_root: optional override for the repo root path (used by Phase 3 credential/isolation
    # routes to locate the .env file and docker-compose.yml). If None, each primitive
    # resolves the path from its own __file__ location (the default).
    repo_root: Optional[Path] = None


def load_settings(
    host: str | None = None,
    port: int | None = None,
    allow_non_loopback: bool | None = None,
) -> Settings:
    """Load settings applying the priority order described in the module docstring."""
    settings = Settings()

    # Layer 3: config file
    config_file_path_str = os.environ.get(
        "AGENTARCA_ADMIN_CONFIG_FILE",
        os.path.expanduser("~/.agentarca/admin.conf"),
    )
    config_file = Path(config_file_path_str)
    if config_file.exists():
        _check_file_permissions(config_file)
        parser = configparser.ConfigParser()
        parser.read(str(config_file))
        section = "admin"
        if parser.has_section(section):
            if parser.has_option(section, "host"):
                settings.host = parser.get(section, "host")
            if parser.has_option(section, "port"):
                settings.port = int(parser.get(section, "port"))
            if parser.has_option(section, "allow_non_loopback"):
                settings.allow_non_loopback = _parse_bool(
                    parser.get(section, "allow_non_loopback")
                )
            if parser.has_option(section, "secret_file"):
                settings.secret_file = _expand(parser.get(section, "secret_file"))
            if parser.has_option(section, "audit_log_path"):
                settings.audit_log_path = _expand(
                    parser.get(section, "audit_log_path")
                )

    # Layer 2: environment variables
    env_host = os.environ.get("AGENTARCA_ADMIN_HOST")
    if env_host:
        settings.host = env_host

    env_port = os.environ.get("AGENTARCA_ADMIN_PORT")
    if env_port:
        settings.port = int(env_port)

    env_non_loopback = os.environ.get("AGENTARCA_ADMIN_ALLOW_NON_LOOPBACK")
    if env_non_loopback is not None:
        settings.allow_non_loopback = _parse_bool(env_non_loopback)

    env_secret_file = os.environ.get("AGENTARCA_ADMIN_SECRET_FILE")
    if env_secret_file:
        settings.secret_file = _expand(env_secret_file)

    env_audit = os.environ.get("AGENTARCA_ADMIN_AUDIT_LOG")
    if env_audit:
        settings.audit_log_path = _expand(env_audit)

    env_session_key = os.environ.get("AGENTARCA_ADMIN_SESSION_KEY")
    if env_session_key:
        settings.session_secret_key = env_session_key

    env_ttl = os.environ.get("AGENTARCA_ADMIN_SESSION_TTL")
    if env_ttl:
        settings.session_ttl = int(env_ttl)

    # Layer 1: explicit CLI args (highest priority)
    if host is not None:
        settings.host = host
    if port is not None:
        settings.port = port
    if allow_non_loopback is not None:
        settings.allow_non_loopback = allow_non_loopback

    return settings


def _check_file_permissions(path: Path) -> None:
    """Warn if a sensitive file has overly broad permissions."""
    try:
        file_stat = path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        if mode & 0o077:
            logger.warning(
                "Sensitive file %s has permissions %o; expected 0600", path, mode
            )
    except OSError:
        pass
