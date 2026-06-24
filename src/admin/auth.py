"""
auth.py - Shared-secret gate and session management.

Login: POST /api/v1/login, JSON body {"secret": "<value>"}.
Comparison: hmac.compare_digest ONLY. The == operator is NEVER used to compare
the secret or any session credential. The build gate asserts this.

On match:
- Issues a signed session cookie (Starlette SessionMiddleware).
- Returns 200 with {"status": "ok", "csrf_token": "<value>"}.

On mismatch:
- Returns 401 after a short constant-duration sleep to blunt timing channels.
- Never echoes the submitted or stored secret value.

Cookie attributes:
  agentarca_session=<signed>; HttpOnly; SameSite=Strict; Path=/
  (Secure is omitted for MVP; loopback HTTP is acceptable per ADR-010 D4.1.)

Secret handling invariants (spec section 5.3):
- Submitted secret read once, compared once, then out of scope.
- Stored secret lives only in app.state.secret (set at startup, not re-read per request).
- Neither value is logged, placed in an audit record, or returned in a response.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Duration of the constant-time delay on login failure (seconds).
# Blunts timing channels even with hmac.compare_digest already in use.
_FAILURE_DELAY_S = 0.1


class LoginRequest(BaseModel):
    secret: str


async def login_handler(request: Request, body: LoginRequest) -> JSONResponse:
    """
    POST /api/v1/login handler.

    Compares the submitted secret against app.state.secret using
    hmac.compare_digest. Issues a session cookie on success.
    """
    stored = getattr(request.app.state, "secret", "")

    # Constant-time comparison. This is the ONLY place the secret is compared.
    # The == operator is never used for this comparison.
    submitted = body.secret
    match = hmac.compare_digest(
        stored.encode("utf-8"),
        submitted.encode("utf-8"),
    )

    # The submitted value must not be retained; reassign to empty immediately
    # after the comparison so it goes out of scope.
    submitted = ""

    if not match:
        # Fixed-duration delay to blunt timing channels.
        await asyncio.sleep(_FAILURE_DELAY_S)
        # Write an audit record for the failed attempt.
        _audit_login(request, outcome="rejected-by-validation")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )

    # Issue a session.
    # Ensure there is a CSRF token in the session (CSRFMiddleware may have set one,
    # but we create one here if the session was just started).
    from src.admin.middleware.csrf import generate_csrf_token  # noqa: PLC0415
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = generate_csrf_token()

    # Store an opaque session identifier (a hash of a fresh token, not the secret).
    import secrets as _secrets  # noqa: PLC0415
    session_token = _secrets.token_hex(32)
    request.session["session_id"] = hashlib.sha256(session_token.encode()).hexdigest()[:16]
    request.session["authenticated"] = True

    _audit_login(request, outcome="applied")

    csrf_token = request.session["csrf_token"]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "ok", "csrf_token": csrf_token},
    )


async def require_auth(request: Request) -> None:
    """
    FastAPI dependency that enforces authentication.

    Raises HTTP 401 if the request does not carry a valid authenticated session.
    Apply this to any route that requires authentication.
    """
    if not request.session.get("authenticated"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )


def _audit_login(request: Request, outcome: str) -> None:
    """Write an audit record for a login attempt. Never includes the secret."""
    try:
        from src.admin.audit import write_audit_record  # noqa: PLC0415
        audit_path = getattr(request.app.state, "audit_log_path", None)
        if audit_path is None:
            return
        session_id = request.session.get("session_id", "unauthenticated")
        write_audit_record(
            audit_path,
            session_id=session_id,
            domain="skeleton",
            action="login",
            outcome=outcome,
            target="",
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Audit write failed for login event: %s", exc)


def get_session_id(request: Request) -> str:
    """Return the opaque session identifier from the session, or 'unauthenticated'."""
    return request.session.get("session_id", "unauthenticated")
