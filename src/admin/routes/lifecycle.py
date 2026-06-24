"""
routes/lifecycle.py - FastAPI router for profile lifecycle management.

Endpoints:
  POST /api/v1/profiles/{profile}/up     - bring a profile up (mutual-exclusion enforced)
  POST /api/v1/profiles/{profile}/down   - bring a profile down
  POST /api/v1/profiles/switch           - switch from one profile to another

Security invariants (all inherited from Phase 0):
  - HostValidationMiddleware -> SessionMiddleware -> CSRFMiddleware runs before every route.
  - require_auth dependency enforces authentication on every handler.
  - CSRF tokens are required on POST (enforced by Phase 0 CSRFMiddleware).
  - Every mutating call writes an audit record BEFORE returning the HTTP response.
  - Secret sanitization: all audit fields are scrubbed at the single chokepoint.
  - The lifecycle primitive (primitives/lifecycle.py) enforces the flock-serialized
    check-and-act sequence. Routes do NOT implement any locking or subprocess calls.

Phase 0/1 middleware stack is NOT modified by Phase 2.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Optional

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from src.admin.auth import get_session_id, require_auth
from src.admin.audit import AuditWriteError, write_audit_record
from src.admin.primitives.lifecycle import (
    ALLOWED_PROFILES,
    do_down,
    do_switch,
    do_up,
    validate_profile,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Truncation limit for invalid profile names in audit records (prevent log-bloat).
_MAX_INVALID_NAME_AUDIT_LEN = 64


# ---------------------------------------------------------------------------
# Secret sanitization (same chokepoint pattern as Phase 1 routes/allowlist.py)
# ---------------------------------------------------------------------------

def _sanitize(value, secret: str):
    """
    Scan value for the admin secret and substitute a safe string if found.
    Handles None and non-string values safely.
    This is the single audit-write chokepoint (Phase 1 red-team lesson).
    """
    if not secret or not isinstance(value, str):
        return value
    if secret in value:
        print(
            "[AUDIT-SANITIZE] Prevented admin secret from entering a lifecycle "
            "audit field or response body.",
            file=sys.stderr,
        )
        return "[sanitized: contained sensitive data]"
    return value


def _write_audit(
    request: Request,
    session_id: str,
    action: str,
    target: Optional[str],
    before: Optional[str],
    after: Optional[str],
    outcome: str,
    detail: str = "",
) -> None:
    """
    Write one audit record for a lifecycle action. Sanitizes ALL fields against
    the admin secret at this single chokepoint (Phase 1 red-team lesson).

    domain is always "lifecycle" for Phase 2.
    Logs errors to stderr; does NOT raise (application continues on audit failure).
    """
    audit_path = getattr(request.app.state, "audit_log_path", None)
    if audit_path is None:
        logger.error("audit_log_path not set on app.state; skipping lifecycle audit record.")
        return

    secret = getattr(request.app.state, "secret", "") or ""
    # Sanitize EVERY field at this single chokepoint (not per-field opt-in).
    safe_target = _sanitize(target, secret)
    safe_before = _sanitize(before, secret)
    safe_after = _sanitize(after, secret)
    safe_detail = _sanitize(detail, secret)

    try:
        write_audit_record(
            audit_path,
            session_id=session_id,
            domain="lifecycle",
            action=action,
            target=safe_target or "",
            before=safe_before,
            after=safe_after,
            outcome=outcome,
            detail=safe_detail,
        )
    except AuditWriteError as exc:
        logger.error("Audit write failed for lifecycle action=%s: %s", action, exc)



# ---------------------------------------------------------------------------
# POST /api/v1/profiles/{profile}/up (SPEC-27-P2 section 5.1)
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/profiles/{profile}/up",
    dependencies=[Depends(require_auth)],
)
async def profile_up(request: Request, profile: str) -> JSONResponse:
    """
    Bring the named profile up. Enforces mutual exclusion. Health-gates the response.

    Processing:
    1. Validate profile against ALLOWED_PROFILES. On failure: 400, audit rejected-by-validation.
    2. Run do_up() in a thread (synchronous, holds the flock for the entire operation).
    3. Write audit record BEFORE returning the HTTP response.
    4. Return appropriate HTTP response.
    """
    session_id = get_session_id(request)
    secret = getattr(request.app.state, "secret", "") or ""

    # Step 1: Profile-name validation (first, before lock, before any subprocess).
    if not validate_profile(profile):
        truncated = profile[:_MAX_INVALID_NAME_AUDIT_LEN]
        _write_audit(
            request, session_id,
            action="lifecycle_up",
            target=truncated,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail="invalid profile name",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_profile",
                "detail": "Profile name must be one of: copilot, claude, codex",
            },
        )

    # Step 2: Run the lifecycle operation in a thread (synchronous flock + compose).
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, do_up, profile, secret)

    outcome_map = {
        "applied": "applied",
        "idempotent": "applied",
        "rejected_mutex": "rejected-by-stop-and-flag",
        "gateway_timeout": "error",
        "compose_error": "error",
        "lock_timeout": "error",
        "error": "error",
    }
    audit_outcome = outcome_map.get(res["outcome"], "error")

    # Step 3: Write audit record BEFORE returning the response.
    if res["outcome"] == "applied":
        _write_audit(
            request, session_id,
            action="lifecycle_up",
            target=profile,
            before="none",
            after=f"{profile}:up:healthy",
            outcome="applied",
            detail="",
        )
    elif res["outcome"] == "idempotent":
        _write_audit(
            request, session_id,
            action="lifecycle_up",
            target=profile,
            before=f"{profile}:up",
            after=f"{profile}:up:healthy",
            outcome="applied",
            detail="idempotent",
        )
    elif res["outcome"] == "rejected_mutex":
        running_profile = res.get("running_profile", "unknown")
        _write_audit(
            request, session_id,
            action="lifecycle_up",
            target=profile,
            before=None,
            after=None,
            outcome="rejected-by-stop-and-flag",
            detail=f"profile {running_profile!r} is already running",
        )
    elif res["outcome"] == "gateway_timeout":
        _write_audit(
            request, session_id,
            action="lifecycle_up",
            target=profile,
            before=None,
            after=None,
            outcome="error",
            detail="gateway_health_timeout; profile torn down",
        )
    elif res["outcome"] == "lock_timeout":
        _write_audit(
            request, session_id,
            action="lifecycle_up",
            target=profile,
            before=None,
            after=None,
            outcome="error",
            detail="lock_timeout",
        )
    else:
        _write_audit(
            request, session_id,
            action="lifecycle_up",
            target=profile,
            before=None,
            after=None,
            outcome="error",
            detail=res.get("detail", "")[:200],
        )

    # Step 4: HTTP response.
    # Sanitize response detail fields to ensure the admin secret never leaves via HTTP.
    # This is belt-and-suspenders: the primitive also sanitizes, but a mocked primitive
    # or a future code path could bypass that layer.
    http_status = res["http_status"]

    if res["outcome"] == "applied":
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"ok": True, "profile": profile, "gateway_healthy": True},
        )
    if res["outcome"] == "idempotent":
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ok": True, "idempotent": True, "profile": profile},
        )
    if res["outcome"] == "rejected_mutex":
        running_profile = res.get("running_profile", "unknown")
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "ok": False,
                "error": "mutual_exclusion",
                "running_profile": running_profile,
                "detail": (
                    f"Profile {running_profile!r} is already running; "
                    f"bring it down before starting {profile!r}"
                ),
            },
        )
    if res["outcome"] == "gateway_timeout":
        timeout_secs = res.get("timeout_seconds", 120)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "ok": False,
                "error": "gateway_health_timeout",
                "profile": profile,
                "detail": f"gateway did not become healthy within {timeout_secs}s; profile torn down",
            },
        )
    if res["outcome"] == "lock_timeout":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "ok": False,
                "error": "lifecycle_lock_timeout",
                "detail": "another lifecycle operation is in progress; retry in a moment",
            },
        )
    # compose_error or generic error.
    safe_detail = _sanitize(res.get("detail", ""), secret)
    return JSONResponse(
        status_code=http_status,
        content={
            "ok": False,
            "error": "compose_error",
            "detail": safe_detail[:500],
        },
    )


# ---------------------------------------------------------------------------
# POST /api/v1/profiles/{profile}/down (SPEC-27-P2 section 5.2)
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/profiles/{profile}/down",
    dependencies=[Depends(require_auth)],
)
async def profile_down(request: Request, profile: str) -> JSONResponse:
    """
    Bring the named profile down. Lock acquired to serialize with concurrent up/switch.
    No mutual-exclusion check needed (down cannot cause concurrent-up).
    """
    session_id = get_session_id(request)
    secret = getattr(request.app.state, "secret", "") or ""

    if not validate_profile(profile):
        truncated = profile[:_MAX_INVALID_NAME_AUDIT_LEN]
        _write_audit(
            request, session_id,
            action="lifecycle_down",
            target=truncated,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail="invalid profile name",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_profile",
                "detail": "Profile name must be one of: copilot, claude, codex",
            },
        )

    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, do_down, profile, secret)

    # Audit record BEFORE response.
    if res["outcome"] == "applied":
        _write_audit(
            request, session_id,
            action="lifecycle_down",
            target=profile,
            before=f"{profile}:up",
            after="none",
            outcome="applied",
            detail="",
        )
    elif res["outcome"] == "idempotent":
        _write_audit(
            request, session_id,
            action="lifecycle_down",
            target=profile,
            before="none",
            after="none",
            outcome="applied",
            detail="idempotent_down",
        )
    elif res["outcome"] == "lock_timeout":
        _write_audit(
            request, session_id,
            action="lifecycle_down",
            target=profile,
            before=None,
            after=None,
            outcome="error",
            detail="lock_timeout",
        )
    else:
        _write_audit(
            request, session_id,
            action="lifecycle_down",
            target=profile,
            before=None,
            after=None,
            outcome="error",
            detail=res.get("detail", "")[:200],
        )

    if res["outcome"] in ("applied", "idempotent"):
        idempotent = res["outcome"] == "idempotent"
        body: dict = {"ok": True, "profile": profile}
        if idempotent:
            body["idempotent"] = True
        return JSONResponse(status_code=status.HTTP_200_OK, content=body)

    if res["outcome"] == "lock_timeout":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "ok": False,
                "error": "lifecycle_lock_timeout",
                "detail": "another lifecycle operation is in progress; retry in a moment",
            },
        )
    safe_detail_down = _sanitize(res.get("detail", ""), secret)
    return JSONResponse(
        status_code=res["http_status"],
        content={
            "ok": False,
            "error": "compose_error",
            "detail": safe_detail_down[:500],
        },
    )


# ---------------------------------------------------------------------------
# POST /api/v1/profiles/switch (SPEC-27-P2 section 5.3)
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/profiles/switch",
    dependencies=[Depends(require_auth)],
)
async def profile_switch(request: Request) -> JSONResponse:
    """
    Switch from one profile to another. Down-then-up under one lock acquisition.
    No concurrent-up window: the lock is held for the entire down-verify-up-healthcheck sequence.

    Request body JSON: {"from": "<profile>", "to": "<profile>"}
    """
    session_id = get_session_id(request)
    secret = getattr(request.app.state, "secret", "") or ""

    # Parse body manually to handle the "from" keyword.
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"ok": False, "error": "invalid_body", "detail": "Expected JSON body with 'from' and 'to' keys"},
        )

    from_profile = body.get("from", "")
    to_profile = body.get("to", "")

    # Validate both profiles before acquiring any lock.
    if not validate_profile(from_profile) or not validate_profile(to_profile):
        bad_from = from_profile[:_MAX_INVALID_NAME_AUDIT_LEN] if from_profile else ""
        bad_to = to_profile[:_MAX_INVALID_NAME_AUDIT_LEN] if to_profile else ""
        target_val = f"{bad_from}->{bad_to}"
        _write_audit(
            request, session_id,
            action="lifecycle_switch",
            target=target_val,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail="invalid profile name",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_profile",
                "detail": "Both 'from' and 'to' must be one of: copilot, claude, codex",
            },
        )

    # Idempotent case: switching to the same profile is a no-op.
    if from_profile == to_profile:
        _write_audit(
            request, session_id,
            action="lifecycle_switch",
            target=f"{from_profile}->{to_profile}",
            before=f"{from_profile}:up",
            after=f"{to_profile}:up",
            outcome="applied",
            detail="idempotent_switch",
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ok": True, "idempotent": True, "from": from_profile, "to": to_profile},
        )

    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, do_switch, from_profile, to_profile, secret)

    # Audit record BEFORE response.
    switch_target = f"{from_profile}->{to_profile}"
    if res["outcome"] == "applied":
        from_was_running = res.get("from_was_running", True)
        before_val = f"{from_profile}:up" if from_was_running else "none"
        _write_audit(
            request, session_id,
            action="lifecycle_switch",
            target=switch_target,
            before=before_val,
            after=f"{to_profile}:up:healthy",
            outcome="applied",
            detail="",
        )
    elif res["outcome"] == "rejected_mutex":
        running_profile = res.get("running_profile", "unknown")
        _write_audit(
            request, session_id,
            action="lifecycle_switch",
            target=switch_target,
            before=None,
            after=None,
            outcome="rejected-by-stop-and-flag",
            detail=f"profile {running_profile!r} is running (not from_profile {from_profile!r})",
        )
    elif res["outcome"] == "down_did_not_stop":
        _write_audit(
            request, session_id,
            action="lifecycle_switch",
            target=switch_target,
            before=None,
            after=None,
            outcome="error",
            detail=f"down_did_not_stop_profile:{from_profile}",
        )
    elif res["outcome"] == "gateway_timeout":
        _write_audit(
            request, session_id,
            action="lifecycle_switch",
            target=switch_target,
            before=None,
            after=None,
            outcome="error",
            detail="gateway_health_timeout; to-profile torn down",
        )
    elif res["outcome"] == "lock_timeout":
        _write_audit(
            request, session_id,
            action="lifecycle_switch",
            target=switch_target,
            before=None,
            after=None,
            outcome="error",
            detail="lock_timeout",
        )
    else:
        _write_audit(
            request, session_id,
            action="lifecycle_switch",
            target=switch_target,
            before=None,
            after=None,
            outcome="error",
            detail=res.get("detail", "")[:200],
        )

    # HTTP responses.
    if res["outcome"] == "applied":
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ok": True, "from": from_profile, "to": to_profile, "gateway_healthy": True},
        )
    if res["outcome"] == "rejected_mutex":
        running_profile = res.get("running_profile", "unknown")
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "ok": False,
                "error": "mutual_exclusion",
                "running_profile": running_profile,
                "detail": (
                    f"Profile {running_profile!r} is running (expected {from_profile!r}); "
                    "bring it down first."
                ),
            },
        )
    if res["outcome"] == "down_did_not_stop":
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "ok": False,
                "error": "down_did_not_stop_profile",
                "detail": f"compose down returned exit 0 but {from_profile!r} is still running",
            },
        )
    if res["outcome"] == "gateway_timeout":
        timeout_secs = res.get("timeout_seconds", 120)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "ok": False,
                "error": "gateway_health_timeout",
                "detail": f"gateway did not become healthy within {timeout_secs}s; to-profile torn down",
            },
        )
    if res["outcome"] == "lock_timeout":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "ok": False,
                "error": "lifecycle_lock_timeout",
                "detail": "another lifecycle operation is in progress; retry in a moment",
            },
        )
    safe_detail_sw = _sanitize(res.get("detail", ""), secret)
    return JSONResponse(
        status_code=res["http_status"],
        content={
            "ok": False,
            "error": "compose_error",
            "detail": safe_detail_sw[:500],
        },
    )
