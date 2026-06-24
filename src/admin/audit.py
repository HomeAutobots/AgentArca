"""
audit.py - Append-only audit sink writer.

Every write uses open(path, "a") so POSIX O_APPEND semantics apply: each write
atomically positions the file offset at end-of-file before writing, preventing
any overwrite of prior records.

The file is opened and closed on every write (not held open). This is
intentional: it keeps the file descriptor out of process state and ensures
that a future process inspection cannot find an fd to the audit log.

A write failure logs to stderr and raises AuditWriteError so the caller
can surface it to the operator. The application continues serving requests.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuditWriteError(Exception):
    """Raised when the audit sink cannot write a record."""


VALID_OUTCOMES = frozenset(
    {
        "applied",
        "rejected-by-validation",
        "rejected-by-parse",
        "rejected-by-stop-and-flag",
        "error",
    }
)

VALID_DOMAINS = frozenset(
    {"skeleton", "allowlist", "lifecycle", "credentials", "isolation"}
)


def write_audit_record(
    audit_log_path: Path,
    *,
    session_id: str,
    domain: str,
    action: str,
    outcome: str,
    target: str = "",
    before: Any = None,
    after: Any = None,
    detail: str = "",
) -> None:
    """
    Write one structured JSON audit record to the append-only audit log.

    Never includes a secret value. Caller is responsible for ensuring
    'target', 'before', 'after', and 'detail' contain no credential values.
    """
    if domain not in VALID_DOMAINS:
        raise ValueError(f"Invalid audit domain: {domain!r}")
    if outcome not in VALID_OUTCOMES:
        raise ValueError(f"Invalid audit outcome: {outcome!r}")

    record: dict[str, Any] = {
        "schema_version": "1",
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") +
                         f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z",
        "session_id": session_id,
        "domain": domain,
        "action": action,
        "target": target,
        "before": before,
        "after": after,
        "outcome": outcome,
    }
    if detail:
        record["detail"] = detail

    # Serialize before opening the file to avoid a partial write on serialization failure.
    try:
        line = json.dumps(record, separators=(",", ":")) + "\n"
    except (TypeError, ValueError) as exc:
        print(
            f"[AUDIT] Failed to serialize audit record: {exc}",
            file=sys.stderr,
        )
        raise AuditWriteError(f"Serialization failed: {exc}") from exc

    # Ensure parent directory exists.
    try:
        audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(
            f"[AUDIT] Cannot create audit log directory {audit_log_path.parent}: {exc}",
            file=sys.stderr,
        )
        raise AuditWriteError(f"Directory creation failed: {exc}") from exc

    # Open in append mode (O_APPEND). Never open with "w" or O_TRUNC.
    try:
        with open(audit_log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as exc:
        print(
            f"[AUDIT] Write failure on {audit_log_path}: {exc}",
            file=sys.stderr,
        )
        raise AuditWriteError(f"Write failed: {exc}") from exc


def make_timestamp_utc() -> str:
    """Return current UTC time as ISO 8601 with millisecond precision and Z suffix."""
    now = datetime.now(timezone.utc)
    ms = now.microsecond // 1000
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


def assert_audit_path_not_in_volume(audit_log_path: Path, repo_root: Path) -> None:
    """
    Assert that audit_log_path is not inside any directory that is a Docker
    bind-mount target in the project's compose files.

    Raises RuntimeError if the assertion fails; this is called at startup
    before any socket is opened.

    The check resolves both paths to absolute form and checks prefix membership.
    """
    # Paths known to be (or contain) Docker bind-mount targets in this project.
    # Derived from docker-compose.yml source: entries (grep "source:" in compose).
    # Any path under the repo root that is a bind-mount source is considered
    # a volume-adjacent path. The audit log must not live under the repo root
    # src/ or tests/ directories.
    forbidden_prefixes = [
        repo_root / "src",
        repo_root / "tests",
        repo_root / "config",
        repo_root,  # broad: catch any accidental placement inside the repo
    ]

    resolved_audit = audit_log_path.resolve()
    for prefix in forbidden_prefixes:
        resolved_prefix = prefix.resolve()
        try:
            resolved_audit.relative_to(resolved_prefix)
            raise RuntimeError(
                f"FATAL: audit_log_path {audit_log_path!r} resolves to "
                f"{resolved_audit!r}, which is under a Docker bind-mount area "
                f"({resolved_prefix!r}). Move the audit log to a path outside "
                f"the repository (e.g. ~/.agentarca/admin-audit.jsonl)."
            )
        except ValueError:
            # Not a subpath, which is what we want.
            pass
