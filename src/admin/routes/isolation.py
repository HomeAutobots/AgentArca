"""
routes/isolation.py - FastAPI router for isolation posture display and D5.4 validation.

Endpoints:
  GET  /api/v1/isolation           - read-only posture display (no editable fields)
  POST /api/v1/isolation/validate  - NON-MUTATING D5.4 hard-refusal pre-flight check

Security invariants (SPEC-27-P3 section 7.4 and 7.5):

NON-MUTATING GUARANTEE (build-gate assertion 17):
  - This file contains NO subprocess calls.
  - This file contains NO os.replace calls.
  - This file does NOT open any file in write mode.
  - The ONLY write is via write_audit_record() (audit log append, not compose file).

D5.4 HARD REFUSALS:
  - NET_ADMIN, NET_RAW, SYS_ADMIN, --privileged, docker.sock, concurrent_profiles
    are STRUCTURALLY ABSENT from any write surface.
  - Any request containing these returns 400 + audited outcome=rejected-by-stop-and-flag.
  - There is NO code path that would apply these to any container.

READ-ONLY DISPLAY:
  - GET /api/v1/isolation returns posture data only.
  - There is NO PUT, PATCH, or DELETE at any /api/v1/isolation/* path.
  - The response contains no editable field names.
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
from src.admin.primitives.isolation import (
    check_d5_4_hard_refusals,
    read_isolation_posture,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request body model for POST /isolation/validate
# ---------------------------------------------------------------------------

class IsolationValidateBody(BaseModel):
    """
    Body for POST /isolation/validate.

    All fields optional. No field named net_admin, sys_admin, privileged, or
    docker_sock with a validator that accepts truthy values (build-gate assertion 18).
    proposed_caps_add, proposed_flags, proposed_mounts are passed to
    check_d5_4_hard_refusals() which returns rejection reasons for forbidden values.
    concurrent_profiles if true is also a D5.4 hard refusal.
    """
    proposed_caps_add: Optional[list] = None
    proposed_flags: Optional[list] = None
    proposed_mounts: Optional[list] = None
    concurrent_profiles: bool = False


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

def _sanitize(v, secret: str):
    """Belt-and-suspenders secret sanitization."""
    if not secret or not isinstance(v, str):
        return v
    if secret in v:
        print(
            "[AUDIT-SANITIZE] Prevented admin secret from entering an isolation "
            "audit field.",
            file=sys.stderr,
        )
        return "[sanitized: contained sensitive data]"
    return v


def _write_audit(
    request: Request,
    session_id: str,
    action: str,
    target: str,
    outcome: str,
    detail: str = "",
) -> None:
    """Write one audit record for an isolation action."""
    audit_path = getattr(request.app.state, "audit_log_path", None)
    if audit_path is None:
        logger.error("audit_log_path not set on app.state; skipping isolation audit.")
        return

    secret = getattr(request.app.state, "secret", "") or ""
    safe_target = _sanitize(target, secret)
    safe_detail = _sanitize(detail, secret)

    try:
        write_audit_record(
            audit_path,
            session_id=session_id,
            domain="isolation",
            action=action,
            target=safe_target or "",
            before=None,
            after=None,
            outcome=outcome,
            detail=safe_detail or "",
        )
    except AuditWriteError as exc:
        logger.error("Audit write failed for isolation action=%s: %s", action, exc)


# ---------------------------------------------------------------------------
# GET /api/v1/isolation (SPEC-27-P3 section 7.4)
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/isolation",
    dependencies=[Depends(require_auth)],
)
async def get_isolation(request: Request) -> JSONResponse:
    """
    Return the current isolation posture. READ-ONLY. No editable fields.

    D5.4 violations in the current compose config are surfaced in d5_4_violations.
    """
    # Resolve compose path from settings if available.
    compose_path = None
    settings = getattr(request.app.state, "settings", None)
    if settings is not None:
        repo_root = getattr(settings, "repo_root", None)
        if repo_root is not None:
            from pathlib import Path  # noqa: PLC0415
            compose_path = Path(repo_root) / "docker-compose.yml"

    posture = read_isolation_posture(compose_path=compose_path)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "profile": posture.profile,
            "posture": {
                "cap_drop": posture.cap_drop,
                "cap_add": posture.cap_add,
                "no_new_privileges": posture.no_new_privileges,
                "seccomp_profile": posture.seccomp_profile,
                "read_only_rootfs": posture.read_only_rootfs,
                "pids_limit": posture.pids_limit,
                "mem_limit": posture.mem_limit,
                "cpus": posture.cpus,
                "network_mode": posture.network_mode,
                "docker_sock_mounted": posture.docker_sock_mounted,
                "privileged": posture.privileged,
                "gateway_cap_add": posture.gateway_cap_add,
            },
            "d5_4_violations": posture.d5_4_violations,
            "non_editable_notice": (
                "NET_ADMIN, NET_RAW, SYS_ADMIN, --privileged, docker.sock mounts, and "
                "concurrent profiles are hard refusals. They cannot be set via the control plane."
            ),
            "edit_note": (
                "To change isolation knobs, edit docker-compose.yml directly and restart the profile."
            ),
        },
    )


# ---------------------------------------------------------------------------
# POST /api/v1/isolation/validate (SPEC-27-P3 section 7.5)
# NON-MUTATING: no subprocess, no os.replace, no open(..., "w") in this handler.
# Build-gate assertion 17 statically asserts this.
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/isolation/validate",
    dependencies=[Depends(require_auth)],
)
async def isolation_validate(
    request: Request,
    body: IsolationValidateBody,
) -> JSONResponse:
    """
    NON-MUTATING pre-flight check against D5.4 hard-refusal rules.

    No subprocess. No file write. No container modification.
    The only write is the audit record (write_audit_record appends to the audit log).

    Returns 400 with violations list if any D5.4 condition is present.
    Returns 200 with empty violations if no D5.4 condition is found.
    """
    session_id = get_session_id(request)

    # Step 1: Check proposed values against D5.4 rules.
    reasons = check_d5_4_hard_refusals(
        proposed_caps=body.proposed_caps_add,
        proposed_flags=body.proposed_flags,
        proposed_mounts=body.proposed_mounts,
    )

    # Step 2: Check concurrent_profiles leg.
    if body.concurrent_profiles:
        reasons.append(
            "D5.4 hard refusal: concurrent profiles are forbidden (invariant 9)"
        )

    if reasons:
        # Write audit record: rejected-by-stop-and-flag.
        detail_str = "; ".join(reasons[:3])[:500]
        _write_audit(
            request, session_id,
            action="isolation_validate",
            target="proposed_config",
            outcome="rejected-by-stop-and-flag",
            detail=detail_str,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "ok": False,
                "violations": reasons,
                "detail": "proposed configuration contains D5.4 hard-refusal conditions",
            },
        )

    # No violations: write audit record with outcome=applied.
    _write_audit(
        request, session_id,
        action="isolation_validate",
        target="proposed_config",
        outcome="applied",
        detail="validation passed",
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "ok": True,
            "violations": [],
            "detail": "proposed configuration passes D5.4 checks",
        },
    )
