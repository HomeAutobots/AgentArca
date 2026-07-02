#!/usr/bin/env python3
"""
_break_glass_up.py -- Guarded break-glass sequence.
Invoked by break-glass-up.sh; NOT called directly by operators.

Acquires ~/.agentarca/lifecycle.lock via Python fcntl.flock (macOS-compatible;
no util-linux flock(1) required). Holds the lock across the entire sequence:
running-state refuse -> audit write -> nonce mint -> docker compose up.

ORDERING INVARIANT (AC-012-5): audit record is written BEFORE the nonce mint
and BEFORE compose. An interruption after the audit write but before the nonce
mint leaves a record but no nonce (fail-closed).
"""
import fcntl
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

ALLOWED_PROFILES = frozenset({"copilot", "claude", "codex"})


def main(profile: str, repo_root_str: str) -> None:
    repo_root = Path(repo_root_str).resolve()
    sys.path.insert(0, str(repo_root))

    # Import the authoritative implementations (B2: no re-implementation).
    from src.admin.primitives.lifecycle import get_running_profiles  # lifecycle.py:176-241
    from src.admin.config import load_settings                        # config.py:42/82-84/104-106

    lock_path = Path("~/.agentarca/lifecycle.lock").expanduser()
    nonce_dir = Path("~/.agentarca/start-auth.d").expanduser()

    # Resolve audit path: same three-layer resolution the console uses.
    # load_settings() honors env AGENTARCA_ADMIN_AUDIT_LOG (config.py:104-106),
    # config-file [admin] audit_log_path key (config.py:82-84), and default
    # ~/.agentarca/admin-audit.jsonl (config.py:42). This is the R3 fix.
    settings = load_settings()
    audit_path = settings.audit_log_path  # type: Path

    # Acquire exclusive lifecycle flock (same lock the console uses at
    # lifecycle.py:138-169 via fcntl.flock). macOS-compatible; no flock(1).
    lock_fd = open(lock_path, "w")
    deadline = time.monotonic() + 30
    acquired = False
    while time.monotonic() < deadline:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            break
        except BlockingIOError:
            time.sleep(0.2)
    if not acquired:
        print("ERROR: could not acquire lifecycle lock within 30s", file=sys.stderr)
        lock_fd.close()
        sys.exit(1)

    try:
        # Running-state refuse (B2 / AC-012-5): calls ACTUAL get_running_profiles().
        # This inherits all match forms and array-format normalization (lifecycle.py:176-241)
        # and the SECURITY NOTE at lifecycle.py:187-190 by construction.
        running = get_running_profiles()
        if running:
            profiles_str = ", ".join(sorted(running))
            print(
                f"ERROR: break-glass refuses to start {profile!r}: "
                f"profiles already running: {profiles_str}",
                file=sys.stderr,
            )
            print(
                "ERROR: Run 'agentarca down' or the portal down route first, "
                "then retry break-glass.",
                file=sys.stderr,
            )
            sys.exit(1)

        # ORDERING INVARIANT (AC-012-5): write audit record BEFORE nonce mint.
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record = {
            "schema_version": "1",
            "timestamp_utc": ts,
            "action": "break_glass_up",
            "domain": "lifecycle",
            "outcome": "applied",
            "target": profile,
            "detail": "break-glass nonce minted",
            "operator_uid": str(os.getuid()),
        }
        with open(audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")

        # Mint nonce AFTER audit record, INSIDE flock.
        nonce_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        token = secrets.token_hex(32)   # 256-bit CSPRNG; no admin-secret input (AC-012-3)
        ts_unix = int(time.time())
        nonce_tmp = nonce_dir / f"{profile}.tmp"
        nonce_file = nonce_dir / profile
        nonce_tmp.write_text(f"{token}\n{ts_unix}\n{profile}\n", encoding="ascii")
        nonce_tmp.chmod(0o600)
        nonce_tmp.rename(nonce_file)

        print(f"[break-glass] Start authorization minted for profile {profile!r}.")
        print("[break-glass] Starting compose profile...")

        # Start compose while lock is still held.
        # cwd=str(repo_root) ensures compose reads docker-compose.yml from the repo root
        # regardless of the operator's working directory (carry-forward N-b).
        result = subprocess.run(
            ["docker", "compose", "--profile", profile, "up", "-d"],
            cwd=str(repo_root),
        )
        if result.returncode != 0:
            print(
                f"ERROR: docker compose up exited {result.returncode}",
                file=sys.stderr,
            )
            sys.exit(result.returncode)

        print("[break-glass] Done. Monitor: agentarca status")
        print(f"[break-glass] This session is logged. Use 'agentarca down {profile}' to stop.")

    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <profile> <repo_root>", file=sys.stderr)
        sys.exit(1)
    if sys.argv[1] not in ALLOWED_PROFILES:
        print(f"ERROR: unknown profile {sys.argv[1]!r}", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
