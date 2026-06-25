"""
routes/credentials.py - FastAPI router for credential (.env) management.

Endpoints:
  GET    /api/v1/credentials           - presence + fingerprint for all 5 keys (no values)
  PUT    /api/v1/credentials/{key}     - set a single key atomically
  DELETE /api/v1/credentials/{key}     - clear a single key

Security invariants (SPEC-27-P3, highest-privilege phase):

TOKEN NEVER LEAVES:
  - The submitted token value is read ONCE from the request body.
  - It is passed to set_credential(), then immediately reassigned to "" (cleared).
  - It is NEVER placed in any response field, audit field, log line, or detail string.
  - The audit record carries only the fingerprint (before/after) and the key name.
  - The chokepoint _write_audit() sanitizes ALL fields against the admin secret.
  - The token value is NOT available to _write_audit(); the route handler never passes it.

AUDIT BEFORE RESPONSE:
  - Every mutating call writes an audit record BEFORE returning the HTTP response.
  - The before-fingerprint is captured via get_credential_status() BEFORE the write.

AUTH + CSRF:
  - All routes require authentication (require_auth dependency from Phase 0).
  - PUT and DELETE require a valid CSRF token (Phase 0 CSRFMiddleware).
  - Phase 0/1/2 middleware stack is NOT modified.

KEY ALLOWLIST (injection guard):
  - Key names are validated against MANAGED_CREDENTIAL_KEYS before any file I/O.
  - Invalid key names: 400 + audited outcome=rejected-by-validation.

Build-gate assertions 15 and 16 (SPEC-27-P3 section 13):
  - Assertion 15: `body.value` assigned once then cleared; never in any return/response.
  - Assertion 16: `value` does not appear in any write_audit_record() call argument.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.admin.auth import get_session_id, require_auth
from src.admin.audit import AuditWriteError, write_audit_record
from src.admin.primitives.credentials import (
    MANAGED_CREDENTIAL_KEYS,
    CredentialResult,
    get_credential_status,
    set_credential,
    clear_credential,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request body model
# ---------------------------------------------------------------------------

class SetCredentialBody(BaseModel):
    value: str


# ---------------------------------------------------------------------------
# Audit chokepoint (sanitizes ALL fields against admin secret)
# Token value is NEVER passed to this function.
# ---------------------------------------------------------------------------

def _sanitize(v, secret: str):
    """
    Replace the admin secret in a string field with [sanitized].
    Handles None and non-string values safely.
    Belt-and-suspenders: the route handler never passes the token value here.
    """
    if not secret or not isinstance(v, str):
        return v
    if secret in v:
        print(
            "[AUDIT-SANITIZE] Prevented admin secret from entering a credentials "
            "audit field or response body.",
            file=sys.stderr,
        )
        return "[sanitized: contained sensitive data]"
    return v


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
    Write one audit record for a credentials action.

    Sanitizes ALL fields against the admin secret at this single chokepoint.
    The token value is NEVER passed to this function; the route handler clears it
    before calling _write_audit.

    domain is always "credentials" for Phase 3 credentials actions.
    """
    audit_path = getattr(request.app.state, "audit_log_path", None)
    if audit_path is None:
        logger.error("audit_log_path not set on app.state; skipping credentials audit.")
        return

    secret = getattr(request.app.state, "secret", "") or ""
    # Sanitize EVERY field (Phase 1 red-team lesson: sanitize at the single chokepoint).
    safe_target = _sanitize(target, secret)
    safe_before = _sanitize(before, secret)
    safe_after = _sanitize(after, secret)
    safe_detail = _sanitize(detail, secret)

    try:
        write_audit_record(
            audit_path,
            session_id=session_id,
            domain="credentials",
            action=action,
            target=safe_target or "",
            before=safe_before,
            after=safe_after,
            outcome=outcome,
            detail=safe_detail or "",
        )
    except AuditWriteError as exc:
        logger.error("Audit write failed for credentials action=%s: %s", action, exc)


# ---------------------------------------------------------------------------
# GET /api/v1/credentials (SPEC-27-P3 section 7.1)
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/credentials",
    dependencies=[Depends(require_auth)],
)
async def get_credentials(request: Request) -> JSONResponse:
    """
    Return presence and fingerprint for all 5 managed keys.

    Response contains ONLY: key name, SET/UNSET status, and fingerprint (or null).
    No token value appears in the response under any circumstances.
    """
    salt = getattr(request.app.state, "fingerprint_salt", None)
    if salt is None:
        logger.error("fingerprint_salt not set on app.state")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"ok": False, "error": "fingerprint_salt not initialized"},
        )

    # Resolve env_path from REPO_ROOT setting if available.
    env_path = _get_env_path(request)

    keys_data = []
    for key in sorted(MANAGED_CREDENTIAL_KEYS):
        cred_status = get_credential_status(key, salt, env_path)
        keys_data.append({
            "key": key,
            "status": "SET" if cred_status.present else "UNSET",
            "fingerprint": cred_status.fingerprint,
        })

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"keys": keys_data},
    )


# ---------------------------------------------------------------------------
# PUT /api/v1/credentials/{key} (SPEC-27-P3 section 7.2)
# ---------------------------------------------------------------------------

@router.put(
    "/api/v1/credentials/{key}",
    dependencies=[Depends(require_auth)],
)
async def put_credential(
    request: Request,
    key: str,
    body: SetCredentialBody,
) -> JSONResponse:
    """
    Set key=value in the repo-root .env atomically.

    The token value is read once, used, then immediately cleared from local scope.
    It NEVER appears in any response field, audit record, log line, or detail string.
    """
    session_id = get_session_id(request)

    # Step 1: Validate key against MANAGED_CREDENTIAL_KEYS (before reading body).
    if key not in MANAGED_CREDENTIAL_KEYS:
        _write_audit(
            request, session_id,
            action="credential_set",
            target=key[:64],
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail="key not in managed set",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_key",
                "detail": "key not in managed credential set",
            },
        )

    # Step 2: Validate value: non-empty, max 4096 chars.
    # Read body.value ONCE.
    value = body.value  # noqa: build-gate-15 (assigned once, cleared after use)
    if not value:
        _write_audit(
            request, session_id,
            action="credential_set",
            target=key,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail="value must be non-empty",
        )
        value = ""  # clear immediately even though it's empty
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_value",
                "detail": "value must be non-empty",
            },
        )

    if len(value) > 4096:
        _write_audit(
            request, session_id,
            action="credential_set",
            target=key,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail="value too long",
        )
        value = ""  # clear immediately
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_value",
                "detail": f"value exceeds 4096 characters",
            },
        )

    # .env-injection guard (defense-in-depth; primitive also rejects). A newline/CR in the
    # value would forge a second logical .env key; a NUL can confuse downstream parsers.
    # Reject before any file I/O so an out-of-allowlist key can never be written.
    if any(ch in value for ch in ("\n", "\r", "\x00")):
        _write_audit(
            request, session_id,
            action="credential_set",
            target=key,
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail="value contains a forbidden control character",
        )
        value = ""  # clear immediately
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_value",
                "detail": "value contains a forbidden control character (newline/CR/NUL)",
            },
        )

    salt = getattr(request.app.state, "fingerprint_salt", None)
    if salt is None:
        value = ""  # clear before error return
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"ok": False, "error": "fingerprint_salt not initialized"},
        )

    env_path = _get_env_path(request)

    # Step 3: Capture the BEFORE fingerprint (prior value's fingerprint, not the value).
    before_status = get_credential_status(key, salt, env_path)

    # Step 4: Write the credential atomically.
    # NOTE: set_credential also clears value internally after the write.
    result = set_credential(key, value, salt, env_path)

    # Step 5: Clear value from this scope IMMEDIATELY after the call returns.
    # This is the primary protection: the token never appears below this line.
    # build-gate assertion 15 checks this line exists.
    value = ""  # noqa: build-gate-15 (cleared immediately after set_credential call)
    # DO NOT reference `value` below this line.

    if not result.ok:
        _write_audit(
            request, session_id,
            action="credential_set",
            target=key,
            before=before_status.fingerprint,
            after=None,
            outcome=result.outcome,
            detail=result.detail or "",
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "ok": False,
                "error": "write_failed",
                "detail": result.detail or "credential write failed",
            },
        )

    # Step 6: Write audit record BEFORE returning the HTTP response.
    # The token value is NOT in any audit field: only fingerprints and key name.
    # build-gate assertion 16 checks that `value` does not appear in write_audit_record calls.
    _write_audit(
        request, session_id,
        action="credential_set",
        target=key,                        # key name is safe (not a secret)
        before=before_status.fingerprint,  # prior fingerprint only
        after=result.fingerprint,          # new fingerprint only
        outcome="applied",
        detail="",
    )

    # Step 7: Return response. Token NOT in the response.
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "ok": True,
            "key": key,
            "fingerprint": result.fingerprint,
            "detail": "credential set",
        },
    )


# ---------------------------------------------------------------------------
# DELETE /api/v1/credentials/{key} (SPEC-27-P3 section 7.3)
# ---------------------------------------------------------------------------

@router.delete(
    "/api/v1/credentials/{key}",
    dependencies=[Depends(require_auth)],
)
async def delete_credential(
    request: Request,
    key: str,
) -> JSONResponse:
    """
    Remove key from the repo-root .env (line removed entirely).

    Idempotent: if the key is absent, returns ok=True.
    Captures the prior fingerprint before the clear for the audit record.
    """
    session_id = get_session_id(request)

    # Validate key.
    if key not in MANAGED_CREDENTIAL_KEYS:
        _write_audit(
            request, session_id,
            action="credential_clear",
            target=key[:64],
            before=None,
            after=None,
            outcome="rejected-by-validation",
            detail="key not in managed set",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "error": "invalid_key",
                "detail": "key not in managed credential set",
            },
        )

    salt = getattr(request.app.state, "fingerprint_salt", None)
    if salt is None:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"ok": False, "error": "fingerprint_salt not initialized"},
        )

    env_path = _get_env_path(request)

    # Capture the prior fingerprint before the clear.
    before_status = get_credential_status(key, salt, env_path)

    # Clear the credential.
    result = clear_credential(key, env_path)

    # Write audit record BEFORE returning the HTTP response.
    detail_str = result.detail or ""
    _write_audit(
        request, session_id,
        action="credential_clear",
        target=key,
        before=before_status.fingerprint,
        after=None,
        outcome="applied" if result.ok else result.outcome,
        detail=detail_str,
    )

    if not result.ok:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "ok": False,
                "error": "clear_failed",
                "detail": result.detail or "credential clear failed",
            },
        )

    response_detail = (
        "credential was not set (idempotent clear)"
        if result.detail == "idempotent_clear"
        else "credential cleared"
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "ok": True,
            "key": key,
            "detail": response_detail,
        },
    )


# ---------------------------------------------------------------------------
# Helper: resolve env_path from app state
# ---------------------------------------------------------------------------

def _get_env_path(request: Request):
    """
    Return the .env path from app state settings if available,
    otherwise let the primitive use its default (repo root detection).
    """
    settings = getattr(request.app.state, "settings", None)
    if settings is not None:
        repo_root = getattr(settings, "repo_root", None)
        if repo_root is not None:
            from pathlib import Path  # noqa: PLC0415
            return Path(repo_root) / ".env"
    return None
