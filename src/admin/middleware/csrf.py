"""
csrf.py - CSRF middleware for state-changing requests.

State-changing methods: POST, PUT, DELETE, PATCH.
Read-only methods: GET, HEAD, OPTIONS (exempt from CSRF validation).

Token generation: secrets.token_hex(32), once per session, stored in the
signed Starlette session.

Token validation: X-CSRF-Token header, compared via hmac.compare_digest.
On mismatch or absence on a state-changing request: 403.

SameSite=Strict on the session cookie is the first line of defense.
This CSRF token is defense-in-depth (ADR-010 D4.3).
"""

from __future__ import annotations

import hmac
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Methods that require a valid CSRF token.
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Paths exempt from CSRF validation.
# The login endpoint is exempt because it is the endpoint that establishes the session
# and issues the CSRF token; requiring a CSRF token on login itself would be circular.
# AC-27-P0-07 confirms: "Obtain a valid session cookie (log in with correct secret)"
# implies login precedes CSRF token acquisition.
_CSRF_EXEMPT_PATHS = frozenset({"/api/v1/login"})


def generate_csrf_token() -> str:
    """Generate a new CSRF token. Called once on session creation."""
    return secrets.token_hex(32)


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Validate the X-CSRF-Token header on every state-changing request.

    Token is stored in the Starlette session dict under the key "csrf_token".
    If the session has no CSRF token yet, this middleware generates one and
    stores it (the token will be delivered to the client in the login response).
    """

    async def dispatch(self, request: Request, call_next):
        # Ensure the session has a CSRF token (generate on first request).
        if "csrf_token" not in request.session:
            request.session["csrf_token"] = generate_csrf_token()

        if request.method in _STATE_CHANGING_METHODS and request.url.path not in _CSRF_EXEMPT_PATHS:
            session_token = request.session.get("csrf_token", "")
            request_token = request.headers.get("x-csrf-token", "")

            if not session_token or not request_token:
                return Response(
                    "Forbidden: missing CSRF token",
                    status_code=403,
                    media_type="text/plain",
                )

            # Constant-time comparison to prevent timing side-channels.
            if not hmac.compare_digest(session_token, request_token):
                return Response(
                    "Forbidden: invalid CSRF token",
                    status_code=403,
                    media_type="text/plain",
                )

        return await call_next(request)
