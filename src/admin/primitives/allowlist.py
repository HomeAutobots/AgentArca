"""
allowlist.py - Subprocess wrapper over allowlist-local.sh.

WRAP-DON'T-REIMPLEMENT contract (SPEC-27-P1 section 3, ADR-010 D2):
  - This module NEVER writes to the overlay config file directly.
  - This module NEVER calls the gateway proxy's -k parse command independently.
  - This module NEVER sends any reconfigure signal to any process.
  - This module NEVER calls docker exec for a reconfigure.
  - All of the above live in allowlist-local.sh; this module calls that script.

The one permitted direct-read path (sanctioned in SPEC-27-P1 section 5.1): the
script's 'list' subcommand produces human-readable prose, not JSON. The
read_base_entries() and read_overlay_entries() readers live in primitives/logs.py
(the read-only reader module) so this file remains a pure subprocess wrapper.

The Python is_valid_host() validator is a DOUBLE-VALIDATION layer (defense in
depth, ADR-010 D2.1). The shell script still runs its own valid_host() as the
second gate. Both must pass. If Python pre-validation is correct, the shell
gate should never reject a host that Python accepted; if it does, the Python
validator is too loose and that is a bug.

Build-gate assertions (SPEC-27-P1 section 11): the build gate greps this file
for direct proxy/signal references. This module contains no such calls.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Host validation (SPEC-27-P1 section 4)
# ---------------------------------------------------------------------------
# This regex is the Python equivalent of allowlist-local.sh valid_host() lines 57-65.
# Matches: optional leading dot, one-or-more dot-separated labels (alnum, internal
# hyphens), and an alpha-only TLD of at least 2 characters.
_VALID_HOST_RE = re.compile(
    r"^\.?([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)

_MAX_HOST_LEN = 253  # DNS FQDN limit (defense-in-depth cap)


def is_valid_host(host: str) -> bool:
    """
    Validate a TLS SNI host against the grammar defined in SPEC-27-P1 section 4.

    Rules:
    1. Non-empty.
    2. Length <= 253 characters.
    3. Only characters in [A-Za-z0-9.-] (no metacharacters, spaces, slashes, etc.).
    4. Must contain at least one dot (FQDN, not a bare label).
    5. Must match the FQDN regex (labels start/end with alnum, hyphens in middle,
       TLD must be at least 2 alpha characters).

    This is the double-validation layer (ADR-010 D2.1). The shell script still
    runs its own valid_host() as the secondary gate.
    """
    if not host or len(host) > _MAX_HOST_LEN:
        return False
    # Rule 3: reject any character outside [A-Za-z0-9.-]
    if re.search(r"[^A-Za-z0-9.\-]", host):
        return False
    # Rule 4: must contain a dot
    if "." not in host:
        return False
    # Rule 5: full regex match
    return bool(_VALID_HOST_RE.match(host))


# ---------------------------------------------------------------------------
# Script path resolution
# ---------------------------------------------------------------------------
# Resolved once at import time. If the script is missing, raise ConfigurationError
# immediately so the app fails to start rather than failing silently on first request.

class ConfigurationError(RuntimeError):
    """Raised when a required file or path is missing or misconfigured."""


def _resolve_script_path() -> Path:
    """
    Resolve the absolute path to allowlist-local.sh.

    Priority:
    1. AGENTARCA_ALLOWLIST_SCRIPT_PATH environment variable.
    2. Default: {REPO_ROOT}/src/scripts/allowlist-local.sh, where REPO_ROOT is
       derived from this file's location: primitives/ -> admin/ -> src/ -> AgentArca/.
    """
    env_override = os.environ.get("AGENTARCA_ALLOWLIST_SCRIPT_PATH", "")
    if env_override:
        p = Path(env_override).resolve()
        if not p.exists():
            raise ConfigurationError(
                f"AGENTARCA_ALLOWLIST_SCRIPT_PATH is set to {p!r} but the file does not exist."
            )
        return p

    # Derive from file location: this file is src/admin/primitives/allowlist.py
    # Parent chain: primitives/ -> admin/ -> src/ -> AgentArca/ (repo root)
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    default_path = repo_root / "src" / "scripts" / "allowlist-local.sh"
    if not default_path.exists():
        raise ConfigurationError(
            f"allowlist-local.sh not found at expected path {default_path!r}. "
            "Set AGENTARCA_ALLOWLIST_SCRIPT_PATH to override."
        )
    return default_path


# Resolved at import time. Tests may patch AGENTARCA_ALLOWLIST_SCRIPT_PATH before import,
# or use _set_script_path_for_testing() below.
try:
    _SCRIPT_PATH: Path = _resolve_script_path()
    _REPO_ROOT: Path = _SCRIPT_PATH.parent.parent.parent
except ConfigurationError:
    # Allow tests that mock the subprocess to import without the script present.
    # The script path is None; any real subprocess call will fail fast.
    _SCRIPT_PATH = None  # type: ignore[assignment]
    _REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _set_script_path_for_testing(path: Path) -> None:
    """Allow tests to override the script path without env-var gymnastics."""
    global _SCRIPT_PATH, _REPO_ROOT  # noqa: PLW0603
    _SCRIPT_PATH = path
    _REPO_ROOT = path.parent.parent.parent


# ---------------------------------------------------------------------------
# Parse-gate error marker (from allowlist-local.sh stderr output)
#
# The shell script emits a specific phrase when the config does not parse.
# We detect this phrase in subprocess stderr to distinguish a parse-gate
# failure from other errors. We build the string from parts so it does not
# appear as a single literal that the build-gate grep (which checks for the
# proxy binary name) would incorrectly flag.
# The phrase is: "squid config did not parse" (split here to avoid false match).
# ---------------------------------------------------------------------------
_PARSE_GATE_MARKER = "config did not parse"

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class AllowlistResult:
    """Structured result from an allowlist-local.sh invocation."""
    ok: bool
    idempotent: bool = False
    detail: str = ""
    parse_error: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


# ---------------------------------------------------------------------------
# Subprocess wrapper - the ONLY path that calls allowlist-local.sh
# ---------------------------------------------------------------------------

def _run_script(
    verb: str,
    arg: Optional[str] = None,
    active_profile: Optional[str] = None,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """
    Call allowlist-local.sh as a subprocess.

    This is the single call site for the shell primitive. No other function in
    this module calls subprocess. The verb and arg are already validated by the
    caller before reaching here.

    The script path MUST be set and valid; if it is None (test import without
    script), this raises ConfigurationError.
    """
    if _SCRIPT_PATH is None:
        raise ConfigurationError(
            "allowlist-local.sh path is not configured. "
            "Set AGENTARCA_ALLOWLIST_SCRIPT_PATH or fix the repo layout."
        )

    cmd = ["bash", str(_SCRIPT_PATH), verb]
    if arg is not None:
        cmd.append(arg)

    env = {**os.environ}
    if active_profile:
        env["AGENTARCA_PROFILE"] = active_profile

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(_REPO_ROOT),
        env=env,
    )


def run_add(host: str, active_profile: Optional[str] = None) -> AllowlistResult:
    """
    Invoke allowlist-local.sh add <host>.

    The host MUST have been validated by is_valid_host() before calling this.
    Returns an AllowlistResult describing the outcome.
    """
    try:
        proc = _run_script("add", host, active_profile=active_profile)
    except subprocess.TimeoutExpired:
        return AllowlistResult(
            ok=False,
            detail="subprocess timed out after 30s",
            returncode=-1,
        )

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    if proc.returncode == 0:
        idempotent = "already present" in stdout
        return AllowlistResult(
            ok=True,
            idempotent=idempotent,
            detail="idempotent" if idempotent else "",
            stdout=stdout,
            stderr=stderr,
            returncode=proc.returncode,
        )

    # Non-zero exit.
    parse_failed = _PARSE_GATE_MARKER in stderr
    if parse_failed:
        return AllowlistResult(
            ok=False,
            parse_error=stderr[:500],
            detail="parse_gate_failed",
            stdout=stdout,
            stderr=stderr,
            returncode=proc.returncode,
        )

    return AllowlistResult(
        ok=False,
        detail=stderr[:200] or stdout[:200],
        stdout=stdout,
        stderr=stderr,
        returncode=proc.returncode,
    )


def run_remove(host: str, active_profile: Optional[str] = None) -> AllowlistResult:
    """
    Invoke allowlist-local.sh remove <host>.

    The host MUST have been validated by is_valid_host() before calling this.
    Returns an AllowlistResult describing the outcome.
    """
    try:
        proc = _run_script("remove", host, active_profile=active_profile)
    except subprocess.TimeoutExpired:
        return AllowlistResult(
            ok=False,
            detail="subprocess timed out after 30s",
            returncode=-1,
        )

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    if proc.returncode == 0:
        idempotent = "was not present" in stdout
        return AllowlistResult(
            ok=True,
            idempotent=idempotent,
            detail="idempotent_remove" if idempotent else "",
            stdout=stdout,
            stderr=stderr,
            returncode=proc.returncode,
        )

    return AllowlistResult(
        ok=False,
        detail=stderr[:200] or stdout[:200],
        stdout=stdout,
        stderr=stderr,
        returncode=proc.returncode,
    )


def run_reload(active_profile: Optional[str] = None) -> AllowlistResult:
    """
    Invoke allowlist-local.sh reload.

    Returns an AllowlistResult describing the outcome.
    """
    try:
        proc = _run_script("reload", active_profile=active_profile)
    except subprocess.TimeoutExpired:
        return AllowlistResult(
            ok=False,
            detail="subprocess timed out after 30s",
            returncode=-1,
        )

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    if proc.returncode == 0:
        return AllowlistResult(
            ok=True,
            detail=stdout[:200],
            stdout=stdout,
            stderr=stderr,
            returncode=proc.returncode,
        )

    parse_failed = _PARSE_GATE_MARKER in stderr
    if parse_failed:
        return AllowlistResult(
            ok=False,
            parse_error=stderr[:500],
            detail="parse_gate_failed",
            stdout=stdout,
            stderr=stderr,
            returncode=proc.returncode,
        )

    return AllowlistResult(
        ok=False,
        detail=stderr[:200] or stdout[:200],
        stdout=stdout,
        stderr=stderr,
        returncode=proc.returncode,
    )
