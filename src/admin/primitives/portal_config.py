"""
portal_config.py - Read/write portal-config.json (operator preferences).

Security invariants (SPEC-29-P1 sec 3, ADR-012):
  - PORTAL_CONFIG_PATH is on the host filesystem at mode 0600.
  - It is NOT bind-mounted into any container.
  - The only permitted key in P1 is detection_enabled (boolean).
  - Unknown keys in the file are preserved on write (round-trip safe).
  - No security policy is stored here; this is operator UX state only (B9).
"""

from __future__ import annotations

import json
from pathlib import Path

PORTAL_CONFIG_PATH = Path("~/.agentarca/portal-config.json").expanduser()
PORTAL_CONFIG_MODE = 0o600


def load_portal_config() -> dict:
    """Returns the current portal config. Returns defaults if file absent or unreadable."""
    defaults = {"detection_enabled": False}
    try:
        raw = PORTAL_CONFIG_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return defaults
        return {**defaults, **data}   # layer on top of defaults; unknown keys preserved
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return defaults


def save_portal_config(updates: dict) -> None:
    """Merge updates into the existing config and write atomically."""
    PORTAL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    current = load_portal_config()
    merged = {**current, **updates}
    tmp = PORTAL_CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    tmp.chmod(PORTAL_CONFIG_MODE)
    tmp.rename(PORTAL_CONFIG_PATH)
