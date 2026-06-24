"""
host_validation.py - Host-header validation middleware.

This is the FIRST middleware that runs on every request (HostValidationMiddleware
is added LAST in the add_middleware() call sequence so Starlette's reverse-order
execution makes it run first).

It enforces:
  - Host header must exactly match {"127.0.0.1:<port>", "localhost:<port>"}
  - If Origin header is present and non-empty, it must match the loopback origin set
  - Returns 403 on ANY mismatch, with no further processing

[::1] is NOT in the allowlist per spec section 5.2 and plan-validator decision 2.
The listener binds IPv4 127.0.0.1 only; if localhost resolves to ::1 on the host,
the TCP connection will not reach the IPv4-bound socket (fails safe).
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class HostValidationMiddleware(BaseHTTPMiddleware):
    """
    Validate the Host header (and optionally Origin) against the loopback allowlist.

    Runs on EVERY request including GET and HEAD. This is the load-bearing
    DNS-rebinding defense (ADR-010 D4.4).
    """

    def __init__(self, app, port: int) -> None:
        super().__init__(app)
        self._allowed_hosts = frozenset(
            {f"127.0.0.1:{port}", f"localhost:{port}"}
        )
        self._allowed_origins = frozenset(
            {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
        )

    async def dispatch(self, request: Request, call_next):
        host_header = request.headers.get("host", "")

        # Primary check: Host header must be in the loopback allowlist.
        if host_header not in self._allowed_hosts:
            return Response(
                "Forbidden: invalid Host header",
                status_code=403,
                media_type="text/plain",
            )

        # Secondary check (defense-in-depth): validate Origin if present.
        origin_header = request.headers.get("origin", "")
        if origin_header:
            if origin_header not in self._allowed_origins:
                return Response(
                    "Forbidden: invalid Origin header",
                    status_code=403,
                    media_type="text/plain",
                )

        return await call_next(request)
