"""
logs.py - Read-only readers for audit log, egress access log, container health,
and the allowlist config fragments.

All functions in this module are READ-ONLY. None of them write, rotate, delete,
or mutate any log, config file, or container state.

The allowlist entry readers (read_base_entries, read_overlay_entries) live here
rather than in allowlist.py because allowlist.py is a pure subprocess wrapper and
must not contain direct file references to the overlay config path (SPEC-27-P1
section 11 build-gate assertions 7+8). The read-only list path is explicitly
sanctioned in SPEC-27-P1 section 5.1: the script's 'list' subcommand produces
human-readable prose, not JSON, so we read the config files directly.

Egress log reading is best-effort: if no gateway is running or docker is not
available, the function returns an empty list with a status disclosure rather
than raising an exception. This matches SPEC-27-P1 section 5.6.

Health reading is best-effort: if docker compose is not available, return an
empty services list with a disclosure.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowlist config readers (read-only, SPEC-27-P1 section 5.1)
# These readers live in logs.py (the read-only module) so that allowlist.py
# remains a pure subprocess wrapper with no direct config file references.
# ---------------------------------------------------------------------------

_ACL_BASE_RE = re.compile(
    r"^[^#\s]*\s*acl\s+allowed_SNI\s+ssl::server_name\s+(\S+)\s*$"
)

# Path components for the overlay config file (used for read-only list, never write).
_OVERLAY_PATH_PARTS = ("config", "allowlist.local.d", "overrides.conf")
_BASE_ALLOWLIST_DIR_PARTS = ("src", "gateway", "squid-allowlist.d")


def _get_repo_root() -> Path:
    """Derive the repo root from this file's location: logs.py -> primitives/ -> admin/ -> src/ -> AgentArca/."""
    return Path(__file__).resolve().parent.parent.parent.parent


def read_base_entries(repo_root: Optional[Path] = None) -> list[dict]:
    """
    Read base (locked) allowlist entries from src/gateway/squid-allowlist.d/*.conf.

    Returns a list of dicts with keys: host, source="base", locked=True.
    Returns empty list if the directory is missing or no ACL lines are found.
    This is a read-only operation; it never writes.
    """
    root = repo_root or _get_repo_root()
    allowlist_dir = root.joinpath(*_BASE_ALLOWLIST_DIR_PARTS)
    entries: list[dict] = []
    try:
        conf_files = sorted(allowlist_dir.glob("*.conf"))
    except OSError:
        return entries

    for conf_file in conf_files:
        try:
            with open(conf_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    m = _ACL_BASE_RE.match(line)
                    if m:
                        entries.append({
                            "host": m.group(1),
                            "source": "base",
                            "locked": True,
                        })
        except OSError:
            pass
    return entries


def read_overlay_entries(repo_root: Optional[Path] = None) -> list[dict]:
    """
    Read overlay (mutable) allowlist entries from the local overlay config file.

    This is the sanctioned direct-read of the overlay file (SPEC-27-P1 section 5.1):
    the script's 'list' subcommand produces human-readable prose, not JSON, so we
    parse the file directly for structured output. This function is READ-ONLY:
    it never writes, truncates, or creates the file.

    Returns a list of dicts with keys: host, source="overlay", locked=False.
    Returns empty list if the file does not exist.
    """
    root = repo_root or _get_repo_root()
    overlay_file = root.joinpath(*_OVERLAY_PATH_PARTS)
    entries: list[dict] = []
    try:
        with open(overlay_file, "r", encoding="utf-8") as fh:
            for line in fh:
                m = _ACL_BASE_RE.match(line)
                if m:
                    entries.append({
                        "host": m.group(1),
                        "source": "overlay",
                        "locked": False,
                    })
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("Could not read overlay file: %s", exc)
    return entries


# ---------------------------------------------------------------------------
# Audit log reader (SPEC-27-P1 section 5.5)
# ---------------------------------------------------------------------------

def read_audit_log(
    audit_log_path: Path,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """
    Read paginated entries from the append-only audit log.

    Opens the file read-only. Parses each line as JSON. Applies offset/limit.
    Returns empty entries if the file does not exist (not an error).

    Never writes, truncates, or rotates the audit log.
    """
    if not audit_log_path.exists():
        return {
            "total_lines": 0,
            "offset": offset,
            "limit": limit,
            "entries": [],
        }

    lines: list[str] = []
    try:
        with open(audit_log_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        logger.error("Cannot read audit log %s: %s", audit_log_path, exc)
        return {
            "total_lines": 0,
            "offset": offset,
            "limit": limit,
            "entries": [],
            "error": str(exc),
        }

    total = len(lines)
    page = lines[offset : offset + limit]
    entries = []
    for raw in page:
        raw = raw.strip()
        if not raw:
            continue
        try:
            entries.append(json.loads(raw))
        except json.JSONDecodeError:
            # Malformed line: include as a raw string to avoid silently dropping it.
            entries.append({"_raw": raw, "_parse_error": True})

    return {
        "total_lines": total,
        "offset": offset,
        "limit": limit,
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Egress log reader (SPEC-27-P1 section 5.6) - best-effort
# ---------------------------------------------------------------------------

# Squid native log format field order:
#   timestamp.ms  duration  client  result/code  bytes  method  url  username  hierarchy  mimetype
_SQUID_ACCESS_RE = re.compile(
    r"^(\d+\.\d+)\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)"
)


def _parse_squid_access_line(line: str) -> Optional[dict]:
    """Parse one line of Squid access.log native format. Returns None on parse failure."""
    m = _SQUID_ACCESS_RE.match(line.strip())
    if not m:
        return None
    raw_url = m.group(6)
    # For CONNECT requests the URL is host:port; extract SNI as the hostname.
    sni = raw_url.split(":")[0] if ":" in raw_url else raw_url
    return {
        "timestamp_epoch": float(m.group(1)),
        "client_ip": m.group(2),
        "result_code": m.group(3),
        "bytes": int(m.group(4)),
        "method": m.group(5),
        "url": raw_url,
        "sni": sni,
    }


def read_egress_log(
    gateway: Optional[str],
    limit: int = 50,
    offset: int = 0,
    access_log_path_override: Optional[str] = None,
) -> dict:
    """
    Read recent entries from the Squid gateway access.log.

    Strategy (SPEC-27-P1 section 5.6):
    1. If AGENTARCA_ADMIN_ACCESS_LOG_PATH is set (item-13 forwarded log), read from that file.
    2. Otherwise, call: docker exec -u proxy <gateway> tail -n <limit+offset> /var/log/squid/access.log
    3. If no gateway, return empty with status="no_gateway_running".
    4. If docker exec fails, return empty with status="docker_exec_failed".

    Never raises; always returns a valid dict.
    """
    # Priority 1: external forwarded log path (item-13 integration).
    log_path = access_log_path_override or os.environ.get("AGENTARCA_ADMIN_ACCESS_LOG_PATH", "")
    if log_path:
        return _read_egress_from_file(Path(log_path), gateway, limit, offset)

    # Priority 2: live gateway via docker exec.
    if not gateway:
        return {
            "status": "no_gateway_running",
            "gateway": None,
            "entries": [],
        }

    # Check docker availability.
    docker_available = _check_docker_available()
    if not docker_available:
        return {
            "status": "docker_not_available",
            "gateway": gateway,
            "entries": [],
        }

    fetch_count = limit + offset
    try:
        proc = subprocess.run(
            [
                "docker", "exec", "-u", "proxy", gateway,
                "tail", "-n", str(fetch_count),
                "/var/log/squid/access.log",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "docker_exec_timeout",
            "gateway": gateway,
            "entries": [],
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "docker_exec_error",
            "gateway": gateway,
            "entries": [],
            "error": str(exc),
        }

    if proc.returncode != 0:
        return {
            "status": "docker_exec_failed",
            "gateway": gateway,
            "entries": [],
            "stderr": proc.stderr[:200] if proc.stderr else "",
        }

    lines = proc.stdout.splitlines()
    # Apply offset (tail gives us limit+offset lines from the end, skip the first `offset`).
    lines = lines[offset:]
    entries = []
    for line in lines:
        parsed = _parse_squid_access_line(line)
        if parsed:
            entries.append(parsed)

    return {
        "status": "ok",
        "gateway": gateway,
        "entries": entries,
    }


def _read_egress_from_file(
    path: Path,
    gateway: Optional[str],
    limit: int,
    offset: int,
) -> dict:
    """Read egress log from a forwarded file path (item-13 integration path)."""
    if not path.exists():
        return {
            "status": "log_file_not_found",
            "gateway": gateway,
            "entries": [],
            "path": str(path),
        }
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return {
            "status": "log_file_read_error",
            "gateway": gateway,
            "entries": [],
            "error": str(exc),
        }

    page = lines[offset : offset + limit]
    entries = []
    for line in page:
        parsed = _parse_squid_access_line(line)
        if parsed:
            entries.append(parsed)

    return {
        "status": "ok",
        "gateway": gateway,
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Health / container status reader (SPEC-27-P1 section 5.7) - best-effort
# ---------------------------------------------------------------------------

def read_health(repo_root: Optional[Path] = None) -> dict:
    """
    Read gateway and devcontainer health via docker compose ps --format json.

    Returns service list and active_profile. Best-effort: returns empty on failure.
    Never modifies containers; strictly read-only.
    """
    root = repo_root or Path(__file__).resolve().parent.parent.parent.parent

    if not _check_docker_available():
        return {
            "services": [],
            "active_profile": None,
            "status": "docker_not_available",
        }

    raw_services = _run_docker_compose_ps(root)
    if raw_services is None:
        return {
            "services": [],
            "active_profile": None,
            "status": "docker_compose_unavailable",
        }

    services = []
    active_profile = None

    for svc in raw_services:
        name = svc.get("Name") or svc.get("name") or svc.get("Service") or ""
        # `status` is the machine STATE (running/exited/...), per SPEC-27-P1 section 5.7.
        # Source it from State, NOT the human-readable Status ("Up 40 hours (healthy)"),
        # which is kept separately as status_text for display.
        state = svc.get("State") or svc.get("state") or ""
        status_text = svc.get("Status") or svc.get("status") or ""
        health = svc.get("Health") or svc.get("health") or ""
        ports = svc.get("Ports") or svc.get("ports") or []

        services.append({
            "name": name,
            "status": state.lower() if state else "",
            "status_text": status_text,
            "health": health.lower() if health else "",
            "ports": ports if isinstance(ports, list) else [],
        })

        # Detect active profile from gateway container name.
        if name.endswith("-gateway") and not active_profile:
            candidate = name[: -len("-gateway")]
            if candidate in {"copilot", "claude", "codex"}:
                active_profile = candidate

    return {
        "services": services,
        "active_profile": active_profile,
    }


def _check_docker_available() -> bool:
    """Return True if the 'docker' command is in PATH and responds."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):  # noqa: BLE001
        return False


def _run_docker_compose_ps(repo_root: Path) -> Optional[list[dict]]:
    """
    Run 'docker compose ps --format json' (or fallback to docker-compose).

    Returns parsed list of service dicts, or None on failure.
    """
    # Try 'docker compose' (Docker Desktop plugin, current standard).
    for cmd_prefix in [["docker", "compose"], ["docker-compose"]]:
        cmd = cmd_prefix + ["ps", "--format", "json"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                cwd=str(repo_root),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception:  # noqa: BLE001
            continue

        if proc.returncode != 0:
            continue

        raw = proc.stdout.strip()
        if not raw:
            return []

        # docker compose ps --format json outputs one JSON object per line (NDJSON)
        # or a JSON array depending on version. Handle both.
        services: list[dict] = []
        if raw.startswith("["):
            try:
                services = json.loads(raw)
            except json.JSONDecodeError:
                pass
        else:
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    services.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        return services

    return None


def detect_active_gateway() -> Optional[str]:
    """
    Return the name of the currently running gateway container, or None.

    Uses 'docker ps' to look for containers matching the known gateway naming
    pattern (<profile>-gateway). Returns None if docker is unavailable or no
    gateway is running.
    """
    if not _check_docker_available():
        return None
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return None
        for name in proc.stdout.splitlines():
            name = name.strip()
            if name.endswith("-gateway") and name[: -len("-gateway")] in {"copilot", "claude", "codex"}:
                return name
    except Exception:  # noqa: BLE001
        pass
    return None
