"""
routes/portal_config.py - Portal configuration API.

Endpoints:
  GET   /api/v1/portal-config   - return current portal configuration
  PATCH /api/v1/portal-config   - update portal configuration

Security invariants (SPEC-29-P1 sec 6.4, B7, B9):
  - PATCH accepts ONLY {"detection_enabled": <bool>} in P1.
  - Any other key in the request body returns 400 rejected-by-validation
    WITHOUT writing the file (AC-29-P1-10).
  - Non-bool value for detection_enabled also returns 400 (AC-29-P1-10).
  - D5.4 isolation invariants (NET_ADMIN, --privileged, docker.sock,
    concurrent_profiles) are NOT settable through this endpoint (AC-29-P1-15).
    Any attempt returns 400 via the unknown-key check.
  - This endpoint is NOT a security policy control. detection_enabled controls
    observability data collection only; egress controls are unaffected (B7).
  - Auth + CSRF required on all endpoints.

Audit convention: PATCH writes to domain="portal_config". GET is read-only and
writes no audit record.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from src.admin.auth import get_session_id, require_auth
from src.admin.audit import AuditWriteError, write_audit_record
from src.admin.primitives.portal_config import load_portal_config, save_portal_config

logger = logging.getLogger(__name__)

router = APIRouter()

# The only permitted key in P1 (B9 / AC-29-P1-10 / AC-29-P1-15).
# This is a module-level constant; no operator input can extend it.
_PERMITTED_PATCH_KEYS: frozenset = frozenset({"detection_enabled"})


# ---------------------------------------------------------------------------
# Audit chokepoint
# ---------------------------------------------------------------------------

def _sanitize(value, secret: str):
    """Replace the admin secret in a string with [sanitized]."""
    if not secret or not isinstance(value, str):
        return value
    if secret in value:
        print(
            "[AUDIT-SANITIZE] Prevented admin secret from entering a portal_config "
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
    outcome: str,
    detail: str = "",
) -> None:
    """Write one audit record for a portal_config action.

    domain is "portal_config".
    Logs errors to stderr; does NOT raise (application continues on audit failure).
    Catches both AuditWriteError and ValueError (invalid domain) for belt-and-suspenders.
    """
    audit_path = getattr(request.app.state, "audit_log_path", None)
    if audit_path is None:
        logger.error("audit_log_path not set on app.state; skipping portal_config audit.")
        return

    secret = getattr(request.app.state, "secret", "") or ""
    safe_target = _sanitize(target, secret)
    safe_detail = _sanitize(detail, secret)

    try:
        write_audit_record(
            audit_path,
            session_id=session_id,
            domain="portal_config",
            action=action,
            target=safe_target or "",
            before=None,
            after=None,
            outcome=outcome,
            detail=safe_detail or "",
        )
    except (AuditWriteError, ValueError) as exc:
        logger.error("Audit write failed for portal_config action=%s: %s", action, exc)


# ---------------------------------------------------------------------------
# GET /api/v1/portal-config (SPEC-29-P1 sec 6.4)
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/portal-config",
    dependencies=[Depends(require_auth)],
)
async def get_portal_config(request: Request) -> JSONResponse:
    """Return the current portal configuration. Read-only; no audit record."""
    config = load_portal_config()
    return JSONResponse(status_code=status.HTTP_200_OK, content=config)


# ---------------------------------------------------------------------------
# PATCH /api/v1/portal-config (SPEC-29-P1 sec 6.4)
# ---------------------------------------------------------------------------

@router.patch(
    "/api/v1/portal-config",
    dependencies=[Depends(require_auth)],
)
async def patch_portal_config(request: Request) -> JSONResponse:
    """
    Update the portal configuration.

    Accepts ONLY {"detection_enabled": <bool>} in P1.
    Any other key or non-bool value returns 400 WITHOUT writing the file (B9).
    D5.4 isolation invariants are NOT configurable through this endpoint (AC-29-P1-15).
    """
    session_id = get_session_id(request)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"ok": False, "error": "invalid_body", "detail": "Expected JSON body"},
        )

    if not isinstance(body, dict):
        _write_audit(
            request, session_id,
            action="portal_config_patch",
            target="portal-config",
            outcome="rejected-by-validation",
            detail="body must be a JSON object",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_body",
                "detail": "body must be a JSON object",
            },
        )

    # Reject unknown keys before any file I/O (B9 / AC-29-P1-10 / AC-29-P1-15).
    # This also catches any attempt to set D5.4 isolation knobs (net_admin_enabled, etc.).
    unknown_keys = set(body.keys()) - _PERMITTED_PATCH_KEYS
    if unknown_keys:
        detail = (
            f"unknown key(s): {', '.join(sorted(unknown_keys))}. "
            f"Only 'detection_enabled' is permitted in P1."
        )
        _write_audit(
            request, session_id,
            action="portal_config_patch",
            target="portal-config",
            outcome="rejected-by-validation",
            detail=detail,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "rejected-by-validation",
                "detail": detail,
            },
        )

    # Require detection_enabled to be present.
    if "detection_enabled" not in body:
        detail = "body must include 'detection_enabled' key"
        _write_audit(
            request, session_id,
            action="portal_config_patch",
            target="portal-config",
            outcome="rejected-by-validation",
            detail=detail,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"ok": False, "error": "rejected-by-validation", "detail": detail},
        )

    # Require detection_enabled to be a strict bool (not int, not string).
    detection_enabled = body["detection_enabled"]
    if not isinstance(detection_enabled, bool):
        detail = (
            f"'detection_enabled' must be a boolean (true/false), "
            f"got {type(detection_enabled).__name__!r}"
        )
        _write_audit(
            request, session_id,
            action="portal_config_patch",
            target="portal-config",
            outcome="rejected-by-validation",
            detail=detail,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"ok": False, "error": "rejected-by-validation", "detail": detail},
        )

    # Write the config atomically.
    try:
        save_portal_config({"detection_enabled": detection_enabled})
    except Exception as exc:
        logger.error("save_portal_config failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "ok": False,
                "error": "config_write_failed",
                "detail": str(exc)[:200],
            },
        )

    # Write audit record BEFORE returning the HTTP response (applied outcome).
    _write_audit(
        request, session_id,
        action="portal_config_patch",
        target="portal-config",
        outcome="applied",
        detail=f"detection_enabled set to {detection_enabled}",
    )

    # Return updated config.
    updated = load_portal_config()
    return JSONResponse(status_code=status.HTTP_200_OK, content=updated)
