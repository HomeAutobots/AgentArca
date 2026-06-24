"""
routes/logs.py - FastAPI router for read-only logs and observability endpoints.

Endpoints:
  GET /api/v1/logs/audit   - paginated entries from the control-plane audit log
  GET /api/v1/logs/egress  - recent entries from the gateway access.log (best-effort)
  GET /api/v1/logs/health  - container health via docker compose ps

CRITICAL INVARIANT (SPEC-27-P1 section 5.5-5.7, AC-27-P1-13, AC-27-P1-16):
  NO route in this module has a POST, PUT, PATCH, or DELETE method.
  The route enumeration test (AC-27-P1-16) enforces this permanently.
  Violations are caught by the build gate (assertion 6).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from src.admin.auth import require_auth
from src.admin.primitives.logs import (
    detect_active_gateway,
    read_audit_log,
    read_egress_log,
    read_health,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Pagination caps.
_AUDIT_MAX_LIMIT = 500
_AUDIT_DEFAULT_LIMIT = 100
_EGRESS_MAX_LIMIT = 200
_EGRESS_DEFAULT_LIMIT = 50


# ---------------------------------------------------------------------------
# GET /api/v1/logs/audit
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/logs/audit",
    dependencies=[Depends(require_auth)],
)
async def get_audit_log(
    request: Request,
    limit: int = _AUDIT_DEFAULT_LIMIT,
    offset: int = 0,
) -> JSONResponse:
    """
    Return paginated entries from the control-plane audit log.

    The audit log is opened read-only. The no-read-back property of the audit
    log is preserved: the SANDBOX cannot reach this endpoint (ADR-010 D3);
    this endpoint is the intended read path for the authenticated operator.
    """
    # Clamp limit.
    limit = min(max(limit, 1), _AUDIT_MAX_LIMIT)
    offset = max(offset, 0)

    audit_path = getattr(request.app.state, "audit_log_path", None)
    if audit_path is None:
        return JSONResponse(
            status_code=500,
            content={"error": "audit_log_path not configured"},
        )

    result = read_audit_log(Path(audit_path), limit=limit, offset=offset)
    return JSONResponse(status_code=200, content=result)


# ---------------------------------------------------------------------------
# GET /api/v1/logs/egress
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/logs/egress",
    dependencies=[Depends(require_auth)],
)
async def get_egress_log(
    request: Request,
    limit: int = _EGRESS_DEFAULT_LIMIT,
    offset: int = 0,
) -> JSONResponse:
    """
    Return recent entries from the Squid gateway access.log (best-effort).

    If no gateway is running, returns empty list with status="no_gateway_running".
    If docker is unavailable, returns status="docker_not_available".
    Never fails hard; always returns a valid JSON response with a status field.
    """
    limit = min(max(limit, 1), _EGRESS_MAX_LIMIT)
    offset = max(offset, 0)

    gateway = detect_active_gateway()
    result = read_egress_log(gateway=gateway, limit=limit, offset=offset)
    return JSONResponse(status_code=200, content=result)


# ---------------------------------------------------------------------------
# GET /api/v1/logs/health
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/logs/health",
    dependencies=[Depends(require_auth)],
)
async def get_health(request: Request) -> JSONResponse:
    """
    Return health and status of running gateway container(s) via docker compose ps.

    No-write constraint: this endpoint calls no docker compose up/down/restart path.
    If docker is unavailable or no gateway is running, returns empty services list.
    """
    result = read_health()
    return JSONResponse(status_code=200, content=result)
