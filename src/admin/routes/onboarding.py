"""
routes/onboarding.py - Guided agent onboarding API.

Endpoints:
  GET  /api/v1/onboarding/{profile}/status  - credential readiness for a profile
  POST /api/v1/onboarding/{profile}/start   - trigger do_up for a ready profile

Security invariants (SPEC-29-P1 sec 5, B8, AC-29-P1-14):
  - Neither endpoint writes to any squid allowlist file.
  - Neither endpoint reads or mounts host ~/.codex.
  - Both require auth + CSRF (same middleware chain as all other portal endpoints).
  - D5.4 isolation invariants are NOT configurable through these endpoints.
  - POST /start reuses the same do_up path as the lifecycle up route, including the
    credential readiness gate. No allowlist write occurs.

Audit convention: POST /start writes to domain="lifecycle" since it triggers a
lifecycle operation. GET /status is read-only and writes no audit record.
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
from src.admin.primitives.credentials import get_credential_status
from src.admin.primitives.lifecycle import (
    do_up,
    validate_profile,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Profile to required credential key(s) mapping (mirrors do_up gate).
# Codex accepts CODEX_API_KEY first, then OPENAI_API_KEY; either satisfies.
_PROFILE_KEY_MAP: dict = {
    "copilot": ("COPILOT_GITHUB_TOKEN",),
    "claude": ("CLAUDE_CODE_OAUTH_TOKEN",),
    "codex": ("CODEX_API_KEY", "OPENAI_API_KEY"),
}

# Human-readable required_key label per profile (AC-29-P1-05/06).
# Codex reports "CODEX_API_KEY or OPENAI_API_KEY" per spec sec 5.5.
_PROFILE_REQUIRED_KEY_LABEL: dict = {
    "copilot": "COPILOT_GITHUB_TOKEN",
    "claude": "CLAUDE_CODE_OAUTH_TOKEN",
    "codex": "CODEX_API_KEY or OPENAI_API_KEY",
}

_MAX_INVALID_NAME_AUDIT_LEN = 64


# ---------------------------------------------------------------------------
# Audit chokepoint (sanitizes ALL fields against admin secret)
# ---------------------------------------------------------------------------

def _sanitize(value, secret: str):
    """Replace the admin secret in a string with [sanitized]."""
    if not secret or not isinstance(value, str):
        return value
    if secret in value:
        print(
            "[AUDIT-SANITIZE] Prevented admin secret from entering an onboarding "
            "audit field.",
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
    """Write one audit record for a lifecycle action triggered from the onboarding route.

    domain is "lifecycle" since these records trace lifecycle operations.
    Logs errors to stderr; does NOT raise (application continues on audit failure).
    """
    audit_path = getattr(request.app.state, "audit_log_path", None)
    if audit_path is None:
        logger.error("audit_log_path not set on app.state; skipping onboarding audit record.")
        return

    secret = getattr(request.app.state, "secret", "") or ""
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
            detail=safe_detail or "",
        )
    except AuditWriteError as exc:
        logger.error("Audit write failed for onboarding action=%s: %s", action, exc)


# ---------------------------------------------------------------------------
# GET /api/v1/onboarding/{profile}/status (SPEC-29-P1 sec 5.5)
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/onboarding/{profile}/status",
    dependencies=[Depends(require_auth)],
)
async def onboarding_status(request: Request, profile: str) -> JSONResponse:
    """
    Return onboarding readiness state for a profile. Read-only; no audit record.

    Response: {profile, credential_present, required_key, ready_to_start}
    For codex: required_key is "CODEX_API_KEY or OPENAI_API_KEY";
               credential_present is true if either key is present.
    """
    if not validate_profile(profile):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_profile",
                "detail": "Profile name must be one of: copilot, claude, codex",
            },
        )

    salt = getattr(request.app.state, "fingerprint_salt", None)
    if salt is None:
        logger.error("fingerprint_salt not set on app.state in onboarding status")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"ok": False, "error": "fingerprint_salt not initialized"},
        )

    required_keys = _PROFILE_KEY_MAP[profile]
    credential_present = any(
        get_credential_status(k, salt, None).present
        for k in required_keys
    )
    required_key_label = _PROFILE_REQUIRED_KEY_LABEL[profile]

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "profile": profile,
            "credential_present": credential_present,
            "required_key": required_key_label,
            "ready_to_start": credential_present,
        },
    )


# ---------------------------------------------------------------------------
# POST /api/v1/onboarding/{profile}/start (SPEC-29-P1 sec 5.5)
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/onboarding/{profile}/start",
    dependencies=[Depends(require_auth)],
)
async def onboarding_start(request: Request, profile: str) -> JSONResponse:
    """
    Trigger do_up for the named profile via the same lifecycle path as the up route.

    Returns the same shape as POST /api/v1/profiles/{profile}/up.
    Auth + CSRF required. No allowlist write. No ~/.codex access.
    """
    session_id = get_session_id(request)
    secret = getattr(request.app.state, "secret", "") or ""

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

    # Write lifecycle_up_intent BEFORE run_in_executor (SPEC-29-P0 / AC-012-5).
    # mint_nonce runs inside do_up under the lifecycle flock; any route-level write
    # before run_in_executor precedes the nonce mint by construction.
    _write_audit(
        request, session_id,
        action="lifecycle_up_intent",
        target=profile,
        before=None,
        after=None,
        outcome="applied",
        detail="start_authorization_minted",
    )

    _salt = getattr(request.app.state, "fingerprint_salt", None) or b""
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, do_up, profile, secret, _salt, None)

    # Audit record BEFORE response. Mirrors the lifecycle up route's audit branches.
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
    elif res["outcome"] == "rejected-by-validation":
        _write_audit(
            request, session_id,
            action="lifecycle_up",
            target=profile,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail=res.get("detail", ""),
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

    # HTTP response (same shape as lifecycle up route).
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
    if res["outcome"] == "rejected-by-validation":
        _detail_rbv = _sanitize(res.get("detail", ""), secret)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "credential_not_present",
                "detail": _detail_rbv[:500],
            },
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
        status_code=res.get("http_status", 500),
        content={
            "ok": False,
            "error": "compose_error",
            "detail": safe_detail[:500],
        },
    )
