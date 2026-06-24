"""
routes/allowlist.py - FastAPI router for egress allowlist management.

Endpoints:
  GET  /api/v1/allowlist                  - list base + overlay entries
  POST /api/v1/allowlist/entries          - add a host (calls allowlist-local.sh add)
  DELETE /api/v1/allowlist/entries/{host} - remove a host (calls allowlist-local.sh remove)
  POST /api/v1/allowlist/reload           - explicit reload (calls allowlist-local.sh reload)

Security invariants (all inherited from Phase 0):
  - HostValidationMiddleware -> SessionMiddleware -> CSRFMiddleware runs before every route.
  - require_auth dependency enforces authentication on every handler.
  - CSRF tokens are required on POST and DELETE (enforced by CSRFMiddleware in Phase 0).
  - Every mutating call writes an audit record BEFORE returning the HTTP response.
  - Secret sanitization: detail strings are scrubbed before audit write (AC-27-P1-17).
"""

from __future__ import annotations

import logging
import sys
from typing import Annotated, Optional
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.admin.auth import get_session_id, require_auth
from src.admin.audit import AuditWriteError, write_audit_record
from src.admin.primitives.allowlist import (
    is_valid_host,
    run_add,
    run_reload,
    run_remove,
)
from src.admin.primitives.logs import (
    detect_active_gateway,
    read_base_entries,
    read_overlay_entries,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# R-b honest-limit notice included on every non-idempotent successful add.
_RISK_NOTICE = (
    "Each host added widens the egress exfil surface (R-b). "
    "Add the narrowest host that works."
)


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------

class AddEntryRequest(BaseModel):
    host: str


# ---------------------------------------------------------------------------
# Secret sanitization (AC-27-P1-17, SPEC-27-P1 section 6.3)
# ---------------------------------------------------------------------------

def _sanitize_detail(detail: str, secret: str) -> str:
    """
    Ensure the admin secret string does not appear in a detail field before it
    is written to the audit log.

    If the secret is found in detail, replaces detail with a safe substitute and
    logs the sanitization event to stderr. This is an absolute prohibition: a
    detail field that contains the secret MUST NOT reach the audit log.
    """
    if not secret:
        return detail
    if secret in detail:
        print(
            "[AUDIT-SANITIZE] Prevented admin secret from entering audit record detail. "
            "Substituting safe string.",
            file=sys.stderr,
        )
        return "[sanitized: detail contained sensitive data]"
    return detail


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
    Write one audit record. Sanitizes detail against the secret before writing.
    Never raises; logs errors to stderr.
    """
    audit_path = getattr(request.app.state, "audit_log_path", None)
    if audit_path is None:
        logger.error("audit_log_path not set on app.state; skipping audit record.")
        return

    secret = getattr(request.app.state, "secret", "") or ""
    safe_detail = _sanitize_detail(detail, secret)

    try:
        write_audit_record(
            audit_path,
            session_id=session_id,
            domain="allowlist",
            action=action,
            target=target or "",
            before=before,
            after=after,
            outcome=outcome,
            detail=safe_detail,
        )
    except AuditWriteError as exc:
        logger.error("Audit write failed for action=%s: %s", action, exc)


# ---------------------------------------------------------------------------
# GET /api/v1/allowlist - list current allowlist state
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/allowlist",
    dependencies=[Depends(require_auth)],
)
async def list_allowlist(request: Request) -> JSONResponse:
    """
    Return base (locked) entries and overlay (mutable) entries separately.

    Base entries come from src/gateway/squid-allowlist.d/*.conf.
    Overlay entries come from config/allowlist.local.d/overrides.conf (direct read,
    SPEC-27-P1 section 5.1 - the 'list' verb output is prose, not JSON).
    """
    repo_root = None  # primitives derive from their own file location

    try:
        base_entries = read_base_entries(repo_root)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to read base entries: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read base allowlist entries") from exc

    try:
        overlay_entries = read_overlay_entries(repo_root)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to read overlay entries: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read overlay entries") from exc

    active_gateway = detect_active_gateway()

    return JSONResponse(
        status_code=200,
        content={
            "active_gateway": active_gateway,
            "base_entries": base_entries,
            "overlay_entries": overlay_entries,
        },
    )


# ---------------------------------------------------------------------------
# POST /api/v1/allowlist/entries - add a host
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/allowlist/entries",
    dependencies=[Depends(require_auth)],
    status_code=201,
)
async def add_entry(
    request: Request,
    body: AddEntryRequest,
) -> JSONResponse:
    """
    Add a host to the overlay allowlist via allowlist-local.sh add <host>.

    Validates the host with is_valid_host() (double-validation layer, ADR-010 D2.1).
    Writes an audit record for every outcome (success, validation reject, parse reject,
    error) BEFORE returning the HTTP response.

    Returns 201 on new addition, 200 on idempotent (already present).
    Returns 400 on validation failure, 422 on parse-gate failure, 500 on error.
    """
    session_id = get_session_id(request)
    host = body.host

    # Step 1: Python-layer validation (double-validation, ADR-010 D2.1).
    if not is_valid_host(host):
        _write_audit(
            request, session_id,
            action="allowlist_add",
            target=host,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail=f"is_valid_host rejected: {host!r}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid host: {host!r}. Must be a valid SNI FQDN (letters, digits, dots, hyphens only).",
        )

    # Step 2: Call the shell primitive.
    try:
        result = run_add(host)
    except Exception as exc:  # noqa: BLE001
        _write_audit(
            request, session_id,
            action="allowlist_add",
            target=host,
            before=None,
            after=None,
            outcome="error",
            detail=str(exc)[:200],
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Subprocess error calling allowlist-local.sh.",
        ) from exc

    # Step 3: Interpret result and write audit record before response.
    if result.returncode == -1 and "timed out" in result.detail:
        _write_audit(
            request, session_id,
            action="allowlist_add",
            target=host,
            before=None,
            after=None,
            outcome="error",
            detail=result.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="allowlist-local.sh timed out after 30s.",
        )

    if result.ok:
        if result.idempotent:
            _write_audit(
                request, session_id,
                action="allowlist_add",
                target=host,
                before=host,
                after=host,
                outcome="applied",
                detail="idempotent",
            )
            return JSONResponse(
                status_code=200,
                content={"ok": True, "idempotent": True, "host": host},
            )

        _write_audit(
            request, session_id,
            action="allowlist_add",
            target=host,
            before=None,
            after=host,
            outcome="applied",
        )
        return JSONResponse(
            status_code=201,
            content={
                "ok": True,
                "idempotent": False,
                "host": host,
                "risk_notice": _RISK_NOTICE,
            },
        )

    # Non-ok result.
    if result.parse_error is not None:
        sanitized_parse = _sanitize_detail(result.parse_error or "", getattr(request.app.state, "secret", "") or "")
        _write_audit(
            request, session_id,
            action="allowlist_add",
            target=host,
            before=None,
            after=None,
            outcome="rejected-by-parse",
            detail=sanitized_parse[:500],
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "ok": False,
                "error": "parse_gate_failed",
                "detail": sanitized_parse[:500],
            },
        )

    # Generic error.
    _write_audit(
        request, session_id,
        action="allowlist_add",
        target=host,
        before=None,
        after=None,
        outcome="error",
        detail=result.detail[:200],
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="allowlist-local.sh returned a non-zero exit code.",
    )


# ---------------------------------------------------------------------------
# DELETE /api/v1/allowlist/entries/{host} - remove a host
# ---------------------------------------------------------------------------

@router.delete(
    "/api/v1/allowlist/entries/{host:path}",
    dependencies=[Depends(require_auth)],
)
async def remove_entry(
    request: Request,
    host: str,
) -> JSONResponse:
    """
    Remove a host from the overlay allowlist via allowlist-local.sh remove <host>.

    The host path parameter is URL-decoded before validation.
    Writes an audit record for every outcome BEFORE returning the HTTP response.
    """
    session_id = get_session_id(request)
    # URL-decode in case the host was encoded (e.g. dots as %2E, though that is unusual).
    decoded_host = unquote(host)

    # Validate the decoded host.
    if not is_valid_host(decoded_host):
        _write_audit(
            request, session_id,
            action="allowlist_remove",
            target=decoded_host,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail=f"is_valid_host rejected: {decoded_host!r}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid host: {decoded_host!r}.",
        )

    try:
        result = run_remove(decoded_host)
    except Exception as exc:  # noqa: BLE001
        _write_audit(
            request, session_id,
            action="allowlist_remove",
            target=decoded_host,
            before=None,
            after=None,
            outcome="error",
            detail=str(exc)[:200],
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Subprocess error calling allowlist-local.sh.",
        ) from exc

    if result.returncode == -1 and "timed out" in result.detail:
        _write_audit(
            request, session_id,
            action="allowlist_remove",
            target=decoded_host,
            before=None,
            after=None,
            outcome="error",
            detail=result.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="allowlist-local.sh timed out after 30s.",
        )

    if result.ok:
        if result.idempotent:
            _write_audit(
                request, session_id,
                action="allowlist_remove",
                target=decoded_host,
                before=None,
                after=None,
                outcome="applied",
                detail="idempotent_remove",
            )
            return JSONResponse(
                status_code=200,
                content={"ok": True, "idempotent": True, "host": decoded_host},
            )

        _write_audit(
            request, session_id,
            action="allowlist_remove",
            target=decoded_host,
            before=decoded_host,
            after=None,
            outcome="applied",
        )
        return JSONResponse(
            status_code=200,
            content={"ok": True, "idempotent": False, "host": decoded_host},
        )

    _write_audit(
        request, session_id,
        action="allowlist_remove",
        target=decoded_host,
        before=None,
        after=None,
        outcome="error",
        detail=result.detail[:200],
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="allowlist-local.sh returned a non-zero exit code.",
    )


# ---------------------------------------------------------------------------
# POST /api/v1/allowlist/reload - explicit reload
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/allowlist/reload",
    dependencies=[Depends(require_auth)],
)
async def reload_allowlist(request: Request) -> JSONResponse:
    """
    Trigger an explicit reload of the overlay file without adding/removing entries.

    Calls allowlist-local.sh reload. The script runs squid -k parse then SIGHUP.
    Writes an audit record for every outcome BEFORE returning the HTTP response.
    """
    session_id = get_session_id(request)

    try:
        result = run_reload()
    except Exception as exc:  # noqa: BLE001
        _write_audit(
            request, session_id,
            action="allowlist_reload",
            target=None,
            before=None,
            after=None,
            outcome="error",
            detail=str(exc)[:200],
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Subprocess error calling allowlist-local.sh.",
        ) from exc

    if result.returncode == -1 and "timed out" in result.detail:
        _write_audit(
            request, session_id,
            action="allowlist_reload",
            target=None,
            before=None,
            after=None,
            outcome="error",
            detail=result.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="allowlist-local.sh timed out after 30s.",
        )

    if result.ok:
        active_gateway = detect_active_gateway()
        _write_audit(
            request, session_id,
            action="allowlist_reload",
            target=None,
            before=None,
            after=None,
            outcome="applied",
        )
        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
                "gateway": active_gateway,
                "detail": result.detail[:200],
            },
        )

    if result.parse_error is not None:
        sanitized_parse = _sanitize_detail(result.parse_error or "", getattr(request.app.state, "secret", "") or "")
        _write_audit(
            request, session_id,
            action="allowlist_reload",
            target=None,
            before=None,
            after=None,
            outcome="rejected-by-parse",
            detail=sanitized_parse[:500],
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "ok": False,
                "error": "parse_gate_failed",
                "detail": sanitized_parse[:500],
            },
        )

    _write_audit(
        request, session_id,
        action="allowlist_reload",
        target=None,
        before=None,
        after=None,
        outcome="error",
        detail=result.detail[:200],
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="allowlist-local.sh returned a non-zero exit code.",
    )
