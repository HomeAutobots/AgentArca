"""
credentials.py - .env atomic write/read primitive.

Implements three operations for the 5 managed credential keys:
  set_credential(key, value, salt, env_path)   - atomic .env write, returns fingerprint
  clear_credential(key, env_path)              - remove key line from .env
  get_credential_status(key, salt, env_path)   - presence + fingerprint, never returns value

Security invariants (SPEC-27-P3, section 5 and plan-validator binding instruction C):
  - MANAGED_CREDENTIAL_KEYS is an exact frozen set. Build gate asserts this.
  - Token value is NEVER returned from any function.
  - Token value is NEVER logged.
  - Fingerprint is HMAC-SHA256(per-install-salt, token.encode('utf-8'))[:16 hex chars].
    No cleartext substring. No unsalted hash. Exact algorithm, no alternatives.
  - .env write is atomic: tempfile in the same dir -> os.chmod(0600) -> os.replace().
  - After use, the value variable is reassigned to "" to remove the reference.

Per-install fingerprint salt:
  - Stored at ~/.agentarca/fingerprint-salt (mode 0600).
  - Created on first run via tempfile + chmod + rename (same atomicity pattern).
  - Loaded once at startup into app.state.fingerprint_salt. NOT an env var.

Key allowlist injection guard:
  - Validated first, before any file I/O or fingerprint computation.
  - Exact case-sensitive match against MANAGED_CREDENTIAL_KEYS.
  - Failure returns rejected-by-validation immediately.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Managed credential key allowlist (injection guard, SPEC-27-P3 section 3)
# Build gate assertion 14 asserts this exact set.
# ---------------------------------------------------------------------------

MANAGED_CREDENTIAL_KEYS = frozenset({
    "COPILOT_GITHUB_TOKEN",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
})

# ---------------------------------------------------------------------------
# Fingerprint salt path (SPEC-27-P3 section 4.2)
# ---------------------------------------------------------------------------

FINGERPRINT_SALT_PATH = Path("~/.agentarca/fingerprint-salt").expanduser()
FINGERPRINT_HEX_PREFIX_LENGTH = 16  # 16 hex chars = 8 bytes of the 32-byte HMAC output

# Maximum allowed token value length (defense-in-depth; no real token is longer).
_MAX_VALUE_LEN = 4096


# ---------------------------------------------------------------------------
# Result types (SPEC-27-P3 section 5.4)
# ---------------------------------------------------------------------------

@dataclass
class CredentialResult:
    ok: bool
    key: str
    outcome: str          # "applied" | "rejected-by-validation" | "error"
    fingerprint: Optional[str]  # HMAC prefix, or None for clear/error
    detail: Optional[str] = None       # human-readable, must not contain the token value


@dataclass
class CredentialStatus:
    key: str
    present: bool
    fingerprint: Optional[str]  # HMAC prefix if present, None if absent


# ---------------------------------------------------------------------------
# Fingerprint algorithm (SPEC-27-P3 section 4.2 - exact algorithm, no alternatives)
# ---------------------------------------------------------------------------

def compute_fingerprint(token_value: str, salt: bytes) -> str:
    """
    Returns the masked fingerprint of token_value using the per-install salt.

    Algorithm: HMAC-SHA256(key=salt, msg=token_value.encode('utf-8'))
    Output: the first FINGERPRINT_HEX_PREFIX_LENGTH hex characters of the digest.

    This is the ONLY permitted fingerprint algorithm (plan-validator binding instruction C).
    No cleartext substring. No unsalted SHA-256. No alternatives.
    """
    digest = hmac.digest(
        key=salt,
        msg=token_value.encode("utf-8"),
        digest=hashlib.sha256,
    )
    return digest.hex()[:FINGERPRINT_HEX_PREFIX_LENGTH]


# ---------------------------------------------------------------------------
# Salt loading / creation (SPEC-27-P3 section 4.2)
# ---------------------------------------------------------------------------

def _load_or_create_salt() -> bytes:
    """
    Loads the per-install fingerprint salt from FINGERPRINT_SALT_PATH (mode 0600).
    Creates a 32-byte random salt on first call if the file does not exist.

    Called once at startup; result cached in app.state.fingerprint_salt.
    Raises SystemExit(1) if the file is unreadable or corrupt.
    """
    path = FINGERPRINT_SALT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        try:
            salt_hex = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.critical("Cannot read fingerprint salt from %s: %s", path, exc)
            raise SystemExit(1) from exc

        if len(salt_hex) != 64:
            logger.critical(
                "Fingerprint salt file %s is corrupt (expected 64 hex chars, got %d). "
                "Delete it to regenerate on next startup.",
                path,
                len(salt_hex),
            )
            raise SystemExit(1)
        try:
            result = bytes.fromhex(salt_hex)
        except ValueError as exc:
            logger.critical(
                "Fingerprint salt file %s contains invalid hex: %s", path, exc
            )
            raise SystemExit(1) from exc

        # Warn if permissions are broader than 0600.
        try:
            mode = oct(os.stat(path).st_mode & 0o777)
            if mode != "0o600":
                logger.warning(
                    "Fingerprint salt file %s has permissions %s; expected 0600",
                    path, mode,
                )
        except OSError:
            pass

        return result

    # First run: generate a 32-byte random salt.
    salt = secrets.token_bytes(32)
    salt_hex = salt.hex()

    # Write atomically: tempfile + chmod 0600 BEFORE rename (SPEC-27-P3 section 4.2 note).
    tmp_path = path.with_suffix(".tmp")
    try:
        tmp_path.write_text(salt_hex, encoding="utf-8")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except OSError as exc:
        logger.critical("Cannot create fingerprint salt file at %s: %s", path, exc)
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise SystemExit(1) from exc

    logger.info("Created fingerprint salt at %s (0600).", path)
    return salt


# ---------------------------------------------------------------------------
# .env path resolution helper
# ---------------------------------------------------------------------------

def _default_env_path() -> Path:
    """Return the default repo-root .env path."""
    # primitives/ -> admin/ -> src/ -> AgentArca/ (repo root)
    return Path(__file__).resolve().parent.parent.parent.parent / ".env"


# ---------------------------------------------------------------------------
# set_credential (SPEC-27-P3 section 5.1)
# ---------------------------------------------------------------------------

def set_credential(
    key: str,
    value: str,
    salt: bytes,
    env_path: Optional[Path] = None,
) -> CredentialResult:
    """
    Set key=value in the repo-root .env file atomically.

    Returns CredentialResult with fingerprint. Never returns the value.
    The caller MUST clear the value variable immediately after this call.

    Pre-conditions:
    - key must be in MANAGED_CREDENTIAL_KEYS (checked here as defense-in-depth;
      primary check is the caller's responsibility).
    - value must be non-empty and at most 4096 bytes after UTF-8 encoding.
    """
    if env_path is None:
        env_path = _default_env_path()

    # Defense-in-depth key validation (primary validation is in the route handler).
    if key not in MANAGED_CREDENTIAL_KEYS:
        return CredentialResult(
            ok=False,
            key=key,
            outcome="rejected-by-validation",
            fingerprint=None,
            detail="key not in managed set",
        )

    # Value length check.
    if not value:
        return CredentialResult(
            ok=False,
            key=key,
            outcome="rejected-by-validation",
            fingerprint=None,
            detail="value must be non-empty",
        )
    try:
        encoded_len = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return CredentialResult(
            ok=False,
            key=key,
            outcome="rejected-by-validation",
            fingerprint=None,
            detail="value is not valid UTF-8",
        )
    if encoded_len > _MAX_VALUE_LEN:
        return CredentialResult(
            ok=False,
            key=key,
            outcome="rejected-by-validation",
            fingerprint=None,
            detail=f"value too long ({encoded_len} bytes; max {_MAX_VALUE_LEN})",
        )

    # .env-injection guard (red-team P3, family 2): the .env file is line-oriented, so a
    # value containing a newline/carriage-return would forge a SECOND logical KEY=VALUE line
    # (e.g. value "x\nEVIL_KEY=y" -> an out-of-allowlist EVIL_KEY that Compose would load).
    # A NUL byte can also truncate/confuse downstream parsers. Reject these control characters
    # BEFORE any file I/O. No real credential token contains them; rejecting (not escaping)
    # keeps the .env writer trivially correct and the one-logical-key invariant structural.
    if any(ch in value for ch in ("\n", "\r", "\x00")):
        value = ""  # clear before error return
        return CredentialResult(
            ok=False,
            key=key,
            outcome="rejected-by-validation",
            fingerprint=None,
            detail="value contains a forbidden control character (newline/CR/NUL)",
        )

    # Compute fingerprint BEFORE we touch the file (so it's done even if write fails).
    fingerprint = compute_fingerprint(value, salt)

    # Read current .env content.
    try:
        if env_path.exists():
            current_lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
        else:
            current_lines = []
    except PermissionError as exc:
        value = ""  # clear before error return
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail="permission denied writing .env",
        )
    except OSError as exc:
        value = ""  # clear before error return
        exc_type = type(exc).__name__
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail=f"{exc_type}: {str(exc)[:100]}",
        )

    # Produce new content: replace or append. Only the target key line is modified.
    key_pattern = re.compile(r"^" + re.escape(key) + r"=.*$")
    new_lines = []
    found = False
    for line in current_lines:
        # Match line without trailing newline for the pattern.
        bare = line.rstrip("\n\r")
        if key_pattern.match(bare):
            new_lines.append(f"{key}={value}\n")
            found = True
        else:
            new_lines.append(line)

    if not found:
        # Append the new key=value line.
        # Ensure the file ends with a newline before appending.
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] = new_lines[-1] + "\n"
        new_lines.append(f"{key}={value}\n")

    new_content = "".join(new_lines)

    # Write atomically: tempfile in same dir -> chmod 0600 -> os.replace.
    env_dir = env_path.parent
    try:
        with tempfile.NamedTemporaryFile(
            dir=env_dir,
            delete=False,
            mode="w",
            suffix=".tmp",
            encoding="utf-8",
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(new_content)
    except FileNotFoundError as exc:
        value = ""  # clear
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail="env directory not found",
        )
    except PermissionError:
        value = ""  # clear
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail="permission denied writing .env",
        )
    except OSError as exc:
        value = ""  # clear
        exc_type = type(exc).__name__
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail=f"{exc_type}: {str(exc)[:100]}",
        )

    try:
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, env_path)
    except OSError as exc:
        value = ""  # clear
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        exc_type = type(exc).__name__
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail=f"{exc_type}: {str(exc)[:100]}",
        )

    # Clear value from local scope (SPEC-27-P3 section 5.1 step 8).
    # Python GC is not reliable for sensitive strings; explicit reassignment
    # removes the reference from this call frame.
    value = ""

    return CredentialResult(
        ok=True,
        key=key,
        outcome="applied",
        fingerprint=fingerprint,
        detail=None,
    )


# ---------------------------------------------------------------------------
# clear_credential (SPEC-27-P3 section 5.2)
# ---------------------------------------------------------------------------

def clear_credential(
    key: str,
    env_path: Optional[Path] = None,
) -> CredentialResult:
    """
    Remove key from the repo-root .env file (or no-op if absent).

    The line is removed entirely (not set to KEY= empty), so Compose interpolation
    resolves to the :- default (unset). Returns ok=True in all cases.
    """
    if env_path is None:
        env_path = _default_env_path()

    # Defense-in-depth key validation.
    if key not in MANAGED_CREDENTIAL_KEYS:
        return CredentialResult(
            ok=False,
            key=key,
            outcome="rejected-by-validation",
            fingerprint=None,
            detail="key not in managed set",
        )

    # If .env does not exist, idempotent success.
    if not env_path.exists():
        return CredentialResult(
            ok=True,
            key=key,
            outcome="applied",
            fingerprint=None,
            detail="idempotent_clear",
        )

    try:
        current_lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    except PermissionError:
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail="permission denied writing .env",
        )
    except OSError as exc:
        exc_type = type(exc).__name__
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail=f"{exc_type}: {str(exc)[:100]}",
        )

    key_pattern = re.compile(r"^" + re.escape(key) + r"=.*$")
    new_lines = []
    found = False
    for line in current_lines:
        bare = line.rstrip("\n\r")
        if key_pattern.match(bare):
            found = True
            # Skip this line (remove it).
        else:
            new_lines.append(line)

    # Idempotent: key was not in the file.
    if not found:
        return CredentialResult(
            ok=True,
            key=key,
            outcome="applied",
            fingerprint=None,
            detail="idempotent_clear",
        )

    new_content = "".join(new_lines)
    env_dir = env_path.parent

    try:
        with tempfile.NamedTemporaryFile(
            dir=env_dir,
            delete=False,
            mode="w",
            suffix=".tmp",
            encoding="utf-8",
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(new_content)
    except OSError as exc:
        exc_type = type(exc).__name__
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail=f"{exc_type}: {str(exc)[:100]}",
        )

    try:
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, env_path)
    except OSError as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        exc_type = type(exc).__name__
        return CredentialResult(
            ok=False,
            key=key,
            outcome="error",
            fingerprint=None,
            detail=f"{exc_type}: {str(exc)[:100]}",
        )

    return CredentialResult(
        ok=True,
        key=key,
        outcome="applied",
        fingerprint=None,
        detail=None,
    )


# ---------------------------------------------------------------------------
# get_credential_status (SPEC-27-P3 section 5.3)
# ---------------------------------------------------------------------------

def get_credential_status(
    key: str,
    salt: bytes,
    env_path: Optional[Path] = None,
) -> CredentialStatus:
    """
    Return presence and fingerprint for key. Never returns the value.

    The captured value is read only to compute the fingerprint and is
    immediately discarded. It is never stored in any field of the return value.
    """
    if env_path is None:
        env_path = _default_env_path()

    if key not in MANAGED_CREDENTIAL_KEYS:
        # Return UNSET for keys not in the managed set (defense-in-depth).
        return CredentialStatus(key=key, present=False, fingerprint=None)

    if not env_path.exists():
        return CredentialStatus(key=key, present=False, fingerprint=None)

    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return CredentialStatus(key=key, present=False, fingerprint=None)

    key_pattern = re.compile(r"^" + re.escape(key) + r"=(.*)$")
    for line in lines:
        m = key_pattern.match(line.rstrip("\n\r"))
        if m:
            captured_value = m.group(1)
            if not captured_value:
                # Key present but empty value: treated as UNSET.
                return CredentialStatus(key=key, present=False, fingerprint=None)
            fingerprint = compute_fingerprint(captured_value, salt)
            # Clear captured value from local scope.
            captured_value = ""
            return CredentialStatus(key=key, present=True, fingerprint=fingerprint)

    return CredentialStatus(key=key, present=False, fingerprint=None)
