"""
lifecycle.py - Profile lifecycle primitive: flock, running-state, subprocess calls.

WRAP-DON'T-REIMPLEMENT contract (SPEC-27-P2 section 7, ADR-010 D2):
  - This module calls `docker compose` via subprocess (up/down/ls/ps subcommands only).
  - This module does NOT reimplement healthcheck logic in Python; it reads the
    Health field that Docker reports via `docker compose ps --format json`.
  - This module does NOT manage credentials, isolation knobs, or any other domain.

Mutual-exclusion contract (SPEC-27-P2 section 4, CLAUDE.md invariant 9):
  - The lifecycle_lock context manager serializes ALL mutating lifecycle operations
    (up, down, switch) via fcntl.flock on ~/.agentarca/lifecycle.lock.
  - The lock is held from check-running-state through health-gate completion.
  - Two profiles CANNOT both be running when operations go through this module.
  - If a different profile is running when `up` or `switch` is called, the call
    raises LifecycleMutexError (hard refuse, never a warning).

Build-gate assertions (SPEC-27-P2 section 18):
  - ALLOWED_PROFILES is exactly frozenset({"copilot", "claude", "codex"}).
  - The build gate verifies: no compose-exec calls; list-args only (not shell strings).
  - subprocess is always called with a list arg (shell=False is the default).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Profile allowlist (injection guard, SPEC-27-P2 section 3)
# ---------------------------------------------------------------------------

ALLOWED_PROFILES = frozenset({"copilot", "claude", "codex"})


def validate_profile(name: str) -> bool:
    """Returns True if name is in the allowed profile set. Case-sensitive exact match."""
    return name in ALLOWED_PROFILES


# ---------------------------------------------------------------------------
# File paths (host filesystem, outside all Docker volumes)
# ---------------------------------------------------------------------------

LIFECYCLE_LOCK_PATH = Path("~/.agentarca/lifecycle.lock").expanduser()

# Repo root derived from this file's location:
#   primitives/ -> admin/ -> src/ -> AgentArca/ (repo root)
_REPO_ROOT: Path = Path(__file__).resolve().parent.parent.parent.parent


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------

class LifecycleLockError(RuntimeError):
    """Raised when the lifecycle lock cannot be acquired within the timeout."""


class LifecycleStateError(RuntimeError):
    """Raised when running-state cannot be determined (compose ls failed)."""


class LifecycleMutexError(RuntimeError):
    """
    Raised when a different profile is already running (mutual-exclusion hard refuse).
    Carries the name of the running profile for the 409 response body.
    """
    def __init__(self, running_profile: str) -> None:
        self.running_profile = running_profile
        super().__init__(f"profile {running_profile!r} is already running")


class LifecycleComposeError(RuntimeError):
    """Raised when a docker compose subprocess exits non-zero."""
    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class LifecycleDownFailedError(RuntimeError):
    """
    Raised during switch when compose down returned exit 0 but the profile
    still appears running. Fail-closed: the target up is never attempted.
    """
    def __init__(self, profile: str) -> None:
        self.profile = profile
        super().__init__(f"compose down claimed success but {profile!r} is still running")


# ---------------------------------------------------------------------------
# Startup: ensure lock file and ~/.agentarca/ exist
# ---------------------------------------------------------------------------

def ensure_lifecycle_lock_file() -> None:
    """
    Create the lifecycle lock file at LIFECYCLE_LOCK_PATH with 0600 permissions
    if it does not already exist. Must be called at admin startup (in create_app).

    The file is on the host filesystem, outside all Docker volumes.
    """
    LIFECYCLE_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not LIFECYCLE_LOCK_PATH.exists():
        LIFECYCLE_LOCK_PATH.touch(mode=0o600)
        logger.info("Created lifecycle lock file at %s (0600).", LIFECYCLE_LOCK_PATH)
    else:
        # Harden permissions if someone created it with a wrong mode.
        try:
            os.chmod(LIFECYCLE_LOCK_PATH, 0o600)
        except OSError as exc:
            logger.warning("Could not chmod lifecycle lock file: %s", exc)


# ---------------------------------------------------------------------------
# Lock acquisition (SPEC-27-P2 section 4.2)
# ---------------------------------------------------------------------------

def _lock_timeout() -> float:
    """Return the lifecycle lock timeout in seconds from env or default (10s)."""
    try:
        raw = os.environ.get("AGENTARCA_ADMIN_LIFECYCLE_LOCK_TIMEOUT", "10")
        val = float(raw)
        return max(1.0, min(60.0, val))
    except (ValueError, TypeError):
        return 10.0


@contextlib.contextmanager
def lifecycle_lock(timeout_seconds: Optional[float] = None):
    """
    Acquire an exclusive advisory lock on the lifecycle lock file.

    If the lock cannot be acquired within timeout_seconds, raises LifecycleLockError.
    On exit (normal or exception), releases the lock.

    Uses fcntl.flock (POSIX advisory lock). The OS releases the lock automatically
    if the process dies (SIGKILL, SIGTERM, or normal exit), so AC-27-P2-15 holds.
    """
    if timeout_seconds is None:
        timeout_seconds = _lock_timeout()

    # Open in write mode to create the file if absent, and to hold the fd.
    lock_file = open(LIFECYCLE_LOCK_PATH, "w")  # noqa: WPS515
    try:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break  # lock acquired
            except OSError:
                if time.monotonic() >= deadline:
                    raise LifecycleLockError(
                        "lifecycle lock held by another request; try again"
                    )
                time.sleep(0.05)
        yield
    finally:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


# ---------------------------------------------------------------------------
# Running-state detection (SPEC-27-P2 section 4.4)
# ---------------------------------------------------------------------------

def get_running_profiles() -> set:
    """
    Returns the set of profile names (from ALLOWED_PROFILES) currently running.

    AgentArca is a SINGLE compose project ("agentarca"); a live profile is identified
    at SERVICE/CONTAINER granularity, NOT the project name. We therefore read
    `docker compose ps --format json` (the same source the health gate uses) and map a
    profile to "running" when its gateway service (`gateway-<profile>`) or container
    (`<profile>-gateway`) is in State "running". The gateway is the uniform per-profile
    indicator (every profile has exactly one); the devcontainer is an additional signal.

    SECURITY NOTE: the earlier implementation matched `docker compose ls` per-PROJECT Name
    against the profile and so NEVER saw the running profile (the project is "agentarca",
    not "agentarca-codex"), returning the empty set against the real topology -- which
    defeated mutual exclusion (invariant 9 / R-m). Fixed to service/container granularity.

    Handles both JSONL format (Docker Compose 2.21.0+, one object per line) and legacy
    array format (pre-2.21.0). Raises LifecycleStateError if the subprocess fails.
    """
    result = subprocess.run(
        ["docker", "compose", "ps", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=str(_REPO_ROOT),
    )
    if result.returncode != 0:
        raise LifecycleStateError(
            f"docker compose ps failed: {result.stderr[:500]}"
        )

    running: set = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Normalize legacy array format (pre-2.21.0): strip a leading "[" or "," and
        # a trailing ",]" so both JSONL and array forms parse one object per line.
        if line.startswith("["):
            line = line.lstrip("[").rstrip(",]").strip()
            if not line:
                continue
        cleaned = line.lstrip(",").rstrip(",]").strip()
        if not cleaned:
            continue
        try:
            obj = json.loads(cleaned)
        except json.JSONDecodeError:
            continue
        svc = obj.get("Service", "") or ""
        name = obj.get("Name", "") or ""
        state = (obj.get("State", "") or "").lower()
        status = (obj.get("Status", "") or "").lower()
        # Only count actually-running containers (not exited/created).
        if state != "running" and not status.startswith("up"):
            continue
        for profile in ALLOWED_PROFILES:
            if (
                svc == f"gateway-{profile}"
                or svc == f"devcontainer-{profile}"
                or name == f"{profile}-gateway"
                or name == f"{profile}-devcontainer"
                or name.endswith(f"{profile}-gateway")
            ):
                running.add(profile)
    return running


# ---------------------------------------------------------------------------
# Gateway healthcheck gate (SPEC-27-P2 section 4.5)
# ---------------------------------------------------------------------------

def _gateway_health_timeout() -> int:
    """Return the gateway health timeout in seconds from env or default (120s)."""
    try:
        raw = os.environ.get("AGENTARCA_ADMIN_GATEWAY_HEALTH_TIMEOUT", "120")
        val = int(raw)
        return max(10, min(300, val))
    except (ValueError, TypeError):
        return 120


def wait_for_gateway_healthy(profile: str, timeout_seconds: Optional[int] = None) -> bool:
    """
    Poll `docker compose ps --format json` until the gateway service for `profile`
    reports Health=="healthy" or the timeout elapses.

    Returns True on healthy, False on timeout or error.

    The lock MUST be held by the caller for the entire duration of this call
    (SPEC-27-P2 section 4.2 / 4.3 step 4): the lock must NOT be released
    between compose up and the health poll completing.
    """
    if timeout_seconds is None:
        timeout_seconds = _gateway_health_timeout()

    gateway_service = f"{profile}-gateway"
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(_REPO_ROOT),
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("["):
                    line = line.lstrip("[").rstrip(",]").strip()
                    if not line:
                        continue
                cleaned = line.lstrip(",").rstrip(",]").strip()
                if not cleaned:
                    continue
                try:
                    obj = json.loads(cleaned)
                except json.JSONDecodeError:
                    continue
                svc = obj.get("Service", "")
                container_name = obj.get("Name", "")
                is_gateway = (
                    svc == gateway_service
                    or container_name.endswith(gateway_service)
                    or svc.endswith(f"-gateway") and profile in svc
                )
                if is_gateway and obj.get("Health") == "healthy":
                    return True
        time.sleep(2)
    return False


# ---------------------------------------------------------------------------
# Compose subprocess calls (SPEC-27-P2 section 7)
# ---------------------------------------------------------------------------

def compose_up(profile: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """
    Run `docker compose --profile <profile> up -d`.

    profile MUST be validated against ALLOWED_PROFILES before this call.
    Arguments are passed as a list (shell=False by default), not a shell string.
    cwd is the repo root so compose reads docker-compose.yml from there.
    """
    return subprocess.run(
        ["docker", "compose", "--profile", profile, "up", "-d"],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(_REPO_ROOT),
    )


def compose_down(profile: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """
    Run `docker compose --profile <profile> down`.

    profile MUST be validated against ALLOWED_PROFILES before this call.
    Arguments are passed as a list (shell=False by default), not a shell string.
    """
    return subprocess.run(
        ["docker", "compose", "--profile", profile, "down"],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(_REPO_ROOT),
    )


# ---------------------------------------------------------------------------
# High-level lifecycle operations (called synchronously, under the lock)
# ---------------------------------------------------------------------------
# These are the functions the route handlers call via run_in_executor.
# All acquire the lock internally except the tear-down call on health failure,
# which is always called while the lock is already held.

def _teardown_profile(profile: str, secret: str) -> None:
    """
    Tear down a profile that failed the health gate. Called while lock is held.
    Logs to stderr on failure; does NOT raise (best-effort cleanup).
    """
    try:
        result = compose_down(profile)
        if result.returncode != 0:
            stderr_sanitized = _sanitize(result.stderr[:500], secret)
            logger.error(
                "Teardown of failed profile %r returned non-zero: %s",
                profile,
                stderr_sanitized,
            )
    except Exception as exc:  # noqa: BLE001
        logger.error("Teardown of failed profile %r raised: %s", profile, exc)


def _sanitize(value: str, secret: str) -> str:
    """Replace the admin secret in a string with [sanitized]. Chokepoint for audit detail."""
    if not secret or not isinstance(value, str):
        return value
    if secret in value:
        print(
            "[AUDIT-SANITIZE] Prevented admin secret from appearing in lifecycle audit detail.",
            file=sys.stderr,
        )
        return "[sanitized: contained sensitive data]"
    return value


def do_up(profile: str, secret: str) -> dict:
    """
    Execute the up lifecycle operation under the lifecycle lock.

    Returns a result dict with keys:
      outcome: "applied" | "idempotent" | "rejected_mutex" | "error" | "lock_timeout"
                | "gateway_timeout" | "compose_error"
      running_profile: str (only for rejected_mutex)
      detail: str
      http_status: int

    Raises nothing; all exceptions are caught and returned as error dicts.
    The lock is held from check-state through health-gate completion.
    """
    try:
        with lifecycle_lock() as _:
            running = get_running_profiles()
            others = running - {profile}
            if others:
                running_profile = next(iter(others))
                return {
                    "outcome": "rejected_mutex",
                    "running_profile": running_profile,
                    "detail": f"profile {running_profile!r} is already running",
                    "http_status": 409,
                }
            if profile in running:
                return {
                    "outcome": "idempotent",
                    "detail": "idempotent",
                    "http_status": 200,
                }
            # Bring the profile up.
            result = compose_up(profile)
            if result.returncode != 0:
                detail = _sanitize(result.stderr[:500], secret)
                return {
                    "outcome": "compose_error",
                    "detail": detail,
                    "http_status": 500,
                }
            # Health gate (lock is still held).
            healthy = wait_for_gateway_healthy(profile)
            if not healthy:
                _teardown_profile(profile, secret)
                timeout_secs = _gateway_health_timeout()
                return {
                    "outcome": "gateway_timeout",
                    "detail": f"gateway_health_timeout; profile torn down",
                    "timeout_seconds": timeout_secs,
                    "http_status": 503,
                }
            return {
                "outcome": "applied",
                "detail": "",
                "http_status": 201,
            }
    except LifecycleLockError as exc:
        return {
            "outcome": "lock_timeout",
            "detail": "lock_timeout",
            "http_status": 503,
        }
    except LifecycleStateError as exc:
        return {
            "outcome": "error",
            "detail": str(exc)[:500],
            "http_status": 500,
        }
    except subprocess.TimeoutExpired:
        return {
            "outcome": "error",
            "detail": "compose subprocess timed out",
            "http_status": 503,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "outcome": "error",
            "detail": str(exc)[:500],
            "http_status": 500,
        }


def do_down(profile: str, secret: str) -> dict:
    """
    Execute the down lifecycle operation under the lifecycle lock.

    The lock is acquired to serialize with any concurrent up or switch.
    No mutual-exclusion check is needed (down cannot cause concurrent-up).

    Returns a result dict with keys: outcome, detail, http_status.
    """
    try:
        with lifecycle_lock() as _:
            running = get_running_profiles()
            if profile not in running:
                return {
                    "outcome": "idempotent",
                    "detail": "idempotent_down",
                    "http_status": 200,
                }
            result = compose_down(profile)
            if result.returncode != 0:
                detail = _sanitize(result.stderr[:500], secret)
                return {
                    "outcome": "compose_error",
                    "detail": detail,
                    "http_status": 500,
                }
            return {
                "outcome": "applied",
                "detail": "",
                "http_status": 200,
            }
    except LifecycleLockError:
        return {
            "outcome": "lock_timeout",
            "detail": "lock_timeout",
            "http_status": 503,
        }
    except LifecycleStateError as exc:
        return {
            "outcome": "error",
            "detail": str(exc)[:500],
            "http_status": 500,
        }
    except subprocess.TimeoutExpired:
        return {
            "outcome": "error",
            "detail": "compose subprocess timed out",
            "http_status": 503,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "outcome": "error",
            "detail": str(exc)[:500],
            "http_status": 500,
        }


def do_switch(from_profile: str, to_profile: str, secret: str) -> dict:
    """
    Execute the switch lifecycle operation under the lifecycle lock.

    Sequence (all under one lock acquisition, SPEC-27-P2 section 4.6):
      1. Check running state. Refuse 409 if a profile OTHER than from_profile is running.
      2. If from_profile is running: compose down from_profile.
      3. Verify from_profile is no longer running (fail-closed: if still running, 500, do NOT start to_profile).
      4. compose up to_profile.
      5. Health gate for to_profile (still under lock).
      6. On health timeout: tear down to_profile, 503.
      7. On success: 200.

    Returns a result dict with keys: outcome, detail, http_status.
    """
    try:
        with lifecycle_lock() as _:
            running = get_running_profiles()
            others = running - {from_profile}
            if others:
                running_profile = next(iter(others))
                return {
                    "outcome": "rejected_mutex",
                    "running_profile": running_profile,
                    "detail": f"profile {running_profile!r} is running (not from_profile {from_profile!r})",
                    "http_status": 409,
                }

            # Step 2: bring from_profile down (if it is actually running).
            from_was_running = from_profile in running
            if from_was_running:
                result = compose_down(from_profile)
                if result.returncode != 0:
                    detail = _sanitize(result.stderr[:500], secret)
                    return {
                        "outcome": "compose_error",
                        "detail": detail,
                        "http_status": 500,
                    }

            # Step 3: verify from_profile is down.
            running_after_down = get_running_profiles()
            if from_profile in running_after_down:
                return {
                    "outcome": "down_did_not_stop",
                    "detail": f"down_did_not_stop_profile:{from_profile}",
                    "http_status": 500,
                }

            # Step 4: bring to_profile up.
            result = compose_up(to_profile)
            if result.returncode != 0:
                detail = _sanitize(result.stderr[:500], secret)
                return {
                    "outcome": "compose_error",
                    "detail": detail,
                    "http_status": 500,
                }

            # Step 5: health gate (lock still held).
            healthy = wait_for_gateway_healthy(to_profile)
            if not healthy:
                _teardown_profile(to_profile, secret)
                timeout_secs = _gateway_health_timeout()
                return {
                    "outcome": "gateway_timeout",
                    "detail": f"gateway_health_timeout; to-profile torn down",
                    "timeout_seconds": timeout_secs,
                    "http_status": 503,
                }

            return {
                "outcome": "applied",
                "detail": "",
                "from_was_running": from_was_running,
                "http_status": 200,
            }
    except LifecycleLockError:
        return {
            "outcome": "lock_timeout",
            "detail": "lock_timeout",
            "http_status": 503,
        }
    except LifecycleStateError as exc:
        return {
            "outcome": "error",
            "detail": str(exc)[:500],
            "http_status": 500,
        }
    except subprocess.TimeoutExpired:
        return {
            "outcome": "error",
            "detail": "compose subprocess timed out",
            "http_status": 503,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "outcome": "error",
            "detail": str(exc)[:500],
            "http_status": 500,
        }
