"""
nonce.py - Portal start-authorization nonce primitive (SPEC-29-P0, ADR-012).

Provides mint, consume, and purge operations for the one-time nonces that
authorize gateway container starts. All operations on the nonce directory
happen on the HOST filesystem, outside all Docker volumes.

Security invariants:
  - NONCE_DIR and NONCE_FRESHNESS_WINDOW_SECS are hardcoded. They MUST NOT
    be overridden by environment variable or config at runtime.
  - The token in each nonce file is independently drawn from the OS CSPRNG
    via secrets.token_hex(32) with no external input. It is NOT derived from
    the admin secret, session secret, or any credential (AC-012-3).
  - Nonce files are written mode 0600 before rename (atomic on POSIX).
  - The gateway service receives the nonce directory as a read-only bind-mount
    and cannot write or delete nonce files (EROFS + cap_drop ALL, AC-012-2).
  - Nonces are one-time: consumed after the gateway passes its health gate,
    and purged at portal startup for non-running profiles (AC-012-4).
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants (HARDCODED INVARIANTS - NO ENV/CONFIG OVERRIDE)
# ---------------------------------------------------------------------------

NONCE_DIR = Path("~/.agentarca/start-auth.d").expanduser()
NONCE_FRESHNESS_WINDOW_SECS = 300   # 5 minutes; enforced by gateway entrypoint

# Mirror of lifecycle.ALLOWED_PROFILES. Defined here to avoid a circular import
# (lifecycle.py imports from nonce.py; nonce.py must not import from lifecycle.py).
# These two constants MUST stay in sync.
ALLOWED_PROFILES = frozenset({"copilot", "claude", "codex"})


# ---------------------------------------------------------------------------
# Directory bootstrap
# ---------------------------------------------------------------------------

def _bootstrap_nonce_dir() -> None:
    """
    Create NONCE_DIR at mode 0700 if it does not already exist.

    Called by mint_nonce() (lazy) and purge_stale_nonces() (at portal startup).
    Does NOT chmod an already-existing directory; preserves operator-set
    permissions if they are stricter.
    """
    NONCE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# mint_nonce
# ---------------------------------------------------------------------------

def mint_nonce(profile: str) -> None:
    """
    Write a fresh one-time start-authorization nonce file for the given profile.

    The file is placed at NONCE_DIR / profile. Caller guarantees:
      - profile is in ALLOWED_PROFILES (validated by do_up before this call)
      - the lifecycle flock is held by the calling thread

    File format (3 lines, plain ASCII):
      <64 hex chars>\\n
      <unix timestamp integer seconds UTC>\\n
      <profile name>\\n

    Written via atomic .tmp + chmod 0600 + rename sequence.
    Raises RuntimeError on any OS error.

    INDEPENDENCE INVARIANT (AC-012-3): secrets.token_hex(32) is called with
    ZERO arguments. No admin secret, session key, credential, or external input
    is passed to it. The nonce carries no secret material.
    """
    _bootstrap_nonce_dir()

    token = secrets.token_hex(32)   # 64 lowercase hex chars; 256-bit CSPRNG; no external input
    ts = int(time.time())
    body = f"{token}\n{ts}\n{profile}\n"

    tmp = NONCE_DIR / f"{profile}.tmp"
    nonce_file = NONCE_DIR / profile
    try:
        tmp.write_text(body, encoding="ascii")
        tmp.chmod(0o600)
        tmp.rename(nonce_file)
    except OSError as exc:
        raise RuntimeError(f"mint_nonce: failed to write nonce for {profile!r}: {exc}") from exc


# ---------------------------------------------------------------------------
# consume_nonce
# ---------------------------------------------------------------------------

def consume_nonce(profile: str) -> None:
    """
    Delete the nonce file for the given profile (one-time consumption).

    If the file does not exist (already consumed or never minted), returns
    silently. Any OS error other than FileNotFoundError raises RuntimeError.

    Called:
      - After wait_for_gateway_healthy returns True in do_up (flock held).
      - After successful compose_down in do_down.
      - For the from-profile after successful down in do_switch.
      - For the to-profile after health gate (success or timeout) in do_switch.
    """
    nonce_file = NONCE_DIR / profile
    try:
        nonce_file.unlink()
    except FileNotFoundError:
        pass   # silent: already consumed or never minted
    except OSError as exc:
        raise RuntimeError(f"consume_nonce: failed to delete nonce for {profile!r}: {exc}") from exc


# ---------------------------------------------------------------------------
# purge_stale_nonces
# ---------------------------------------------------------------------------

def purge_stale_nonces(running_profiles: frozenset) -> None:
    """
    Remove nonce files for profiles NOT currently running.

    Called at portal startup to clean up files left by a previous portal crash.
    Only touches files whose names are in ALLOWED_PROFILES; ignores other files.
    Silently skips files that disappear between iterdir() and unlink()
    (concurrent consumption by do_up is benign).

    Args:
        running_profiles: frozenset of profile names currently running,
                          as returned by get_running_profiles().
    """
    _bootstrap_nonce_dir()
    for f in NONCE_DIR.iterdir():
        if f.name in ALLOWED_PROFILES and f.name not in running_profiles:
            try:
                f.unlink()
            except FileNotFoundError:
                pass   # benign: consumed between iterdir and unlink
