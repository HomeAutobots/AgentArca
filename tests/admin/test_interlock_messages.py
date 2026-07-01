"""
test_interlock_messages.py - AC-29-P0-25 source-inspection containment check (unmarked, fast).

FRAME: when an unauthorized start is blocked, the fail-closed message must not leave the
operator stuck: BOTH the absent-nonce and expired-nonce branches of the gateway entrypoint
must name the three supported (authorized) restart paths, so the interlock cannot become an
availability foot-gun that pressures an operator into a worse bypass (R-t).

AC-29-P0-25 / AC-012-6: the absent-nonce and expired-nonce entrypoint messages both name:
  - the portal UI
  - `agentarca up`
  - break-glass (break-glass-up.sh)

This is pure source inspection of src/gateway/entrypoint.sh; no Docker required.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ENTRYPOINT = REPO_ROOT / "src" / "gateway" / "entrypoint.sh"

# Tokens every fail-closed guidance message must contain (the three authorized restart paths).
REQUIRED_PATH_TOKENS = ["portal UI", "agentarca up", "break-glass-up.sh"]


def _guidance_after(src: str, fatal_marker: str, window: int = 400) -> str:
    """Return the text immediately following a FATAL marker (the guidance echo lives there)."""
    idx = src.find(fatal_marker)
    assert idx != -1, f"FATAL marker not found in entrypoint.sh: {fatal_marker!r}"
    return src[idx: idx + window]


def test_entrypoint_has_both_failclosed_branches():
    src = ENTRYPOINT.read_text(encoding="utf-8")
    assert "FATAL: start authorization missing" in src, "absent-nonce branch missing"
    assert "FATAL: start authorization expired" in src, "expired-nonce branch missing"


def test_absent_nonce_message_names_all_three_restart_paths():
    """AC-29-P0-25: the absent-nonce FATAL guidance names portal UI, agentarca up, break-glass."""
    src = ENTRYPOINT.read_text(encoding="utf-8")
    guidance = _guidance_after(src, "FATAL: start authorization missing")
    missing = [t for t in REQUIRED_PATH_TOKENS if t not in guidance]
    assert not missing, (
        f"absent-nonce guidance must name all three restart paths; missing: {missing}\n"
        f"guidance seen: {guidance!r}"
    )


def test_expired_nonce_message_names_all_three_restart_paths():
    """AC-29-P0-25: the expired-nonce FATAL guidance names portal UI, agentarca up, break-glass."""
    src = ENTRYPOINT.read_text(encoding="utf-8")
    guidance = _guidance_after(src, "FATAL: start authorization expired")
    missing = [t for t in REQUIRED_PATH_TOKENS if t not in guidance]
    assert not missing, (
        f"expired-nonce guidance must name all three restart paths; missing: {missing}\n"
        f"guidance seen: {guidance!r}"
    )
