"""
health.py - GET /api/v1/health endpoint.

This endpoint:
- Does NOT require authentication (exercises the middleware chain without a session).
- DOES go through HostValidationMiddleware (everything does).
- Returns {"status": "ok", "version": "0.1.0"}.
- Does NOT write an audit record on healthy checks (per spec section 5.6).
- A request with a bad Host header is rejected 403 by HostValidationMiddleware
  before this route handler is reached.

Also exposes POST /api/v1/login via the auth module.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from src.admin.auth import LoginRequest, login_handler

router = APIRouter()

_APP_VERSION = "0.1.0"


@router.get("/api/v1/health")
async def health(request: Request) -> JSONResponse:
    """
    Unauthenticated health probe.

    Also returns the CSRF token from the session if one exists (so the
    frontend can use it for subsequent state-changing requests).
    """
    response_body: dict = {"status": "ok", "version": _APP_VERSION}

    # Include the CSRF token if a session exists (defense-in-depth convenience).
    csrf_token = request.session.get("csrf_token")
    if csrf_token:
        response_body["csrf_token"] = csrf_token

    return JSONResponse(status_code=200, content=response_body)


@router.post("/api/v1/login")
async def login(request: Request, body: LoginRequest) -> JSONResponse:
    """Authenticate with the shared secret and issue a session cookie."""
    return await login_handler(request, body)
