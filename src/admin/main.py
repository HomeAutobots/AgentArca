"""
main.py - Application factory and startup sequence.

create_app() returns a configured FastAPI instance.
run() starts uvicorn. Tests import create_app() directly without starting a server.

Startup sequence (spec section 5.1):
1. Load Settings.
2. Loopback-bind assertion: SystemExit(1) if host not in {"127.0.0.1"} and
   allow_non_loopback is False. NON-LOOPBACK BIND OVERRIDE ACTIVE WARNING if
   allow_non_loopback is True.
3. Read shared secret. SystemExit(1) if neither source yields a value.
4. Load or generate session_secret_key (persisted at ~/.agentarca/session-key, 0600).
5. Assert audit_log_path is not inside a Docker volume path.
6. Register middlewares in REVERSE order so HostValidationMiddleware runs FIRST.
7. Include routers.
8. Log startup info at INFO level (never logs the secret or session key).

Middleware add order (Starlette processes in reverse; last-added runs first):
  add_middleware(CSRFMiddleware)       <- added first, runs third
  add_middleware(SessionMiddleware)    <- added second, runs second
  add_middleware(HostValidationMiddleware) <- added last, runs FIRST
"""

from __future__ import annotations

import logging
import os
import secrets
import stat
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles

from src.admin.audit import assert_audit_path_not_in_volume
from src.admin.config import Settings, load_settings
from src.admin.middleware.csrf import CSRFMiddleware
from src.admin.middleware.host_validation import HostValidationMiddleware
from src.admin.routes.health import router as health_router
from src.admin.routes.allowlist import router as allowlist_router
from src.admin.routes.logs import router as logs_router
from src.admin.routes.lifecycle import router as lifecycle_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

_LOOPBACK_HOSTS = frozenset({"127.0.0.1"})
_SESSION_KEY_PATH = Path("~/.agentarca/session-key").expanduser()


def _load_secret(settings: Settings) -> str:
    """
    Load the shared secret from the configured file or fallback env var.

    Returns the secret string. Never logs or stores it beyond the return value.
    Raises SystemExit(1) if no non-empty secret is found.
    """
    secret_file = settings.secret_file
    if secret_file.exists():
        try:
            _check_mode(secret_file)
            value = secret_file.read_text(encoding="utf-8").strip()
            if value:
                return value
            logger.critical("Secret file %s is empty. Refusing to start.", secret_file)
            sys.exit(1)
        except OSError as exc:
            logger.critical("Cannot read secret file %s: %s. Refusing to start.", secret_file, exc)
            sys.exit(1)

    # Fallback to environment variable.
    env_val = os.environ.get(settings.secret_env_var, "")
    if env_val:
        return env_val

    logger.critical(
        "No shared secret found. Set secret_file (%s) at 0600 or env var %s. "
        "Run build-admin.sh --init to generate one.",
        secret_file,
        settings.secret_env_var,
    )
    sys.exit(1)


def _load_or_generate_session_key() -> str:
    """
    Load the session signing key from ~/.agentarca/session-key,
    generating and persisting it if it does not exist.

    The key is generated with secrets.token_hex(64), written at 0600,
    and never accepted as a CLI argument.
    """
    key_path = _SESSION_KEY_PATH
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        try:
            _check_mode(key_path)
            value = key_path.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError as exc:
            logger.warning("Cannot read session key from %s: %s. Regenerating.", key_path, exc)

    # Generate a new key.
    new_key = secrets.token_hex(64)
    try:
        key_path.write_text(new_key + "\n", encoding="utf-8")
        os.chmod(key_path, 0o600)
        logger.info("Generated new session key at %s (0600).", key_path)
    except OSError as exc:
        logger.warning(
            "Cannot persist session key to %s: %s. Using ephemeral key (sessions will not "
            "survive restart).",
            key_path,
            exc,
        )
    return new_key


def _check_mode(path: Path) -> None:
    """Log a warning if a sensitive file has permissions broader than 0600."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            logger.warning(
                "Sensitive file %s has permissions %o; expected 0600", path, mode
            )
    except OSError:
        pass


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Application factory. Returns a configured FastAPI instance.

    Performs the full startup sequence including the loopback-bind assertion,
    secret loading, session key loading, and audit path assertion.
    """
    if settings is None:
        settings = load_settings()

    # Step 2: Loopback-bind assertion.
    if settings.host not in _LOOPBACK_HOSTS:
        if not settings.allow_non_loopback:
            logger.critical(
                "FATAL: Refusing to bind to non-loopback address %s. "
                "The admin control plane must bind to 127.0.0.1. "
                "Set --allow-non-loopback to override (loudly).",
                settings.host,
            )
            sys.exit(1)
        else:
            logger.warning(
                "NON-LOOPBACK BIND OVERRIDE ACTIVE: binding to %s. "
                "This weakens the agent-unreachability guarantee (ADR-010 D3). "
                "Ensure this is an intentional, reviewed operator decision.",
                settings.host,
            )

    # Step 3: Load the shared secret.
    secret = _load_secret(settings)

    # Step 4: Load or generate the session signing key.
    if settings.session_secret_key:
        session_key = settings.session_secret_key
    else:
        session_key = _load_or_generate_session_key()

    # Step 5: Assert audit path is not inside a Docker volume.
    repo_root = Path(__file__).resolve().parent.parent.parent  # AgentArca/
    assert_audit_path_not_in_volume(settings.audit_log_path, repo_root)

    # Step 5b: Ensure the lifecycle lock file exists on the host filesystem (Phase 2).
    # Import here to avoid circular imports at module level during Phase 0/1-only startup.
    from src.admin.primitives.lifecycle import ensure_lifecycle_lock_file  # noqa: PLC0415
    ensure_lifecycle_lock_file()

    # Log startup info at factory time (AC-27-P0-08: startup log contains bind address).
    # Never log secret or session_key.
    logger.info(
        "Admin listening on %s:%d | audit log: %s",
        settings.host,
        settings.port,
        settings.audit_log_path,
    )

    # Build the application.
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield

    app = FastAPI(
        title="AgentArca Admin",
        version="0.1.0",
        debug=False,
        lifespan=lifespan,
    )

    # Bind secret and audit path to app state (never stored in os.environ).
    app.state.secret = secret
    app.state.audit_log_path = settings.audit_log_path
    app.state.settings = settings

    # Step 6: Register middlewares.
    # Starlette's add_middleware() PREPENDS to user_middleware, so the last call
    # results in index 0 of the list. Starlette builds the stack by wrapping
    # index 0 around index 1, etc., making index 0 the OUTERMOST layer (runs FIRST).
    # Therefore: to make HostValidationMiddleware run FIRST, add it LAST.
    #
    # Desired execution order:   HostValidation -> Session -> CSRF -> Route
    # add_middleware() call order: CSRF first, Session second, HostValidation last.
    #
    # Verified: the built middleware_stack layers (outermost to innermost) are:
    #   ServerErrorMiddleware -> HostValidationMiddleware -> SessionMiddleware
    #   -> CSRFMiddleware -> ExceptionMiddleware -> Route

    # Called first => innermost (runs last in execution order).
    app.add_middleware(CSRFMiddleware)

    # Called second => middle layer.
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_key,
        session_cookie="agentarca_session",
        max_age=settings.session_ttl,
        same_site="strict",
        https_only=False,  # HTTP over loopback; Secure omitted per ADR-010 D4.1.
    )

    # Called last => outermost user middleware (runs FIRST on every incoming request).
    app.add_middleware(HostValidationMiddleware, port=settings.port)

    # Step 7: Include routers.
    # Phase 0 router.
    app.include_router(health_router)
    # Phase 1 routers (mounted behind the same middleware chain; no middleware changes).
    app.include_router(allowlist_router)
    app.include_router(logs_router)
    # Phase 2 router (mounted behind the same middleware chain; no middleware changes).
    app.include_router(lifecycle_router)

    # Serve the static frontend. Mounted AFTER routers so /api/* takes priority.
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


def run(
    host: str | None = None,
    port: int | None = None,
    allow_non_loopback: bool = False,
) -> None:
    """
    Entry point. Loads settings, creates the app, starts uvicorn.
    The host passed to uvicorn is exactly settings.host after the assertion passes.
    """
    settings = load_settings(
        host=host,
        port=port,
        allow_non_loopback=allow_non_loopback,
    )
    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AgentArca admin control plane")
    parser.add_argument("--host", default=None, help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Port (default: 8770)")
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        default=False,
        help="Override loopback-bind assertion (loud WARNING, operator use only)",
    )
    args = parser.parse_args()
    run(
        host=args.host,
        port=args.port,
        allow_non_loopback=args.allow_non_loopback,
    )
