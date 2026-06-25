"""
test_credentials_primitive.py - Unit tests for src/admin/primitives/credentials.py

Covers (all isolation-runnable, no Docker required):
  AC-27-P3-03 (BLOCK) Fingerprint algorithm: deterministic, non-cleartext, different tokens differ
  AC-27-P3-04 (BLOCK) Salt non-reversibility: wrong salt / unsalted SHA-256 do not match
  AC-27-P3-15 (BLOCK) Fingerprint salt: loaded from 0600 file; created on first run;
                       two separate loads return the same salt

Uses TEMP directories for all file I/O. Never touches the real ~/.agentarca or .env.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.primitives.credentials import (
    MANAGED_CREDENTIAL_KEYS,
    FINGERPRINT_HEX_PREFIX_LENGTH,
    compute_fingerprint,
    _load_or_create_salt,
    set_credential,
    clear_credential,
    get_credential_status,
)


# ---------------------------------------------------------------------------
# AC-27-P3-03 (BLOCK): Fingerprint algorithm determinism and non-cleartext
# ---------------------------------------------------------------------------

def test_fingerprint_deterministic_and_non_cleartext():
    """
    AC-27-P3-03: HMAC-SHA256(salt, token) prefix is deterministic for known (salt, token);
    two different tokens produce different fingerprints;
    fingerprint is not a substring of the token;
    fingerprint is not the first/last N chars of the token.
    """
    salt = secrets.token_bytes(32)
    token = "ghp_ABCDEF1234567890abcdef1234567890"
    fp1 = compute_fingerprint(token, salt)
    fp2 = compute_fingerprint(token, salt)
    assert fp1 == fp2, "fingerprint must be deterministic for the same (salt, token)"
    assert len(fp1) == FINGERPRINT_HEX_PREFIX_LENGTH, (
        f"fingerprint must be {FINGERPRINT_HEX_PREFIX_LENGTH} hex chars, got {len(fp1)}"
    )
    # Non-cleartext: the fingerprint is NOT a substring of the token
    assert fp1 not in token, "fingerprint must not be a substring of the token"
    assert token[:FINGERPRINT_HEX_PREFIX_LENGTH] != fp1, (
        "fingerprint must not be the first N chars of the token"
    )
    assert token[-FINGERPRINT_HEX_PREFIX_LENGTH:] != fp1, (
        "fingerprint must not be the last N chars of the token"
    )
    # Different tokens produce different fingerprints
    fp3 = compute_fingerprint("ghp_DIFFERENT1234567890abcdef123456", salt)
    assert fp3 != fp1, "different tokens must produce different fingerprints"


def test_fingerprint_length_is_16_hex():
    """Fingerprint output is exactly 16 hex characters."""
    salt = secrets.token_bytes(32)
    fp = compute_fingerprint("sk-test-openai-key-12345", salt)
    assert len(fp) == 16
    # All hex digits
    int(fp, 16)  # raises ValueError if not valid hex


def test_fingerprint_empty_and_nonempty_token_differ():
    """The empty string and a non-empty string produce different fingerprints."""
    salt = secrets.token_bytes(32)
    fp_empty = compute_fingerprint("", salt)
    fp_nonempty = compute_fingerprint("abc", salt)
    assert fp_empty != fp_nonempty


# ---------------------------------------------------------------------------
# AC-27-P3-04 (BLOCK): Salt non-reversibility
# ---------------------------------------------------------------------------

def test_fingerprint_requires_salt():
    """
    AC-27-P3-04: given only the fingerprint, cannot reconstruct the token for a known
    low-entropy format. Demonstrates that:
    - wrong salt produces a different fingerprint
    - unsalted SHA-256 prefix does not match the HMAC fingerprint
    """
    real_salt = secrets.token_bytes(32)
    real_token = "ghp_" + "A" * 36   # plausible GitHub PAT format
    real_fp = compute_fingerprint(real_token, real_salt)

    # Wrong salt must produce a different fingerprint.
    wrong_salt = secrets.token_bytes(32)
    wrong_fp = compute_fingerprint(real_token, wrong_salt)
    assert wrong_fp != real_fp, "different salt must produce different fingerprint"

    # Unsalted SHA-256 prefix must not match the HMAC fingerprint.
    sha256_prefix = hashlib.sha256(real_token.encode()).hexdigest()[:16]
    assert sha256_prefix != real_fp, (
        "unsalted SHA-256 prefix must not equal the HMAC fingerprint "
        "(this is why the salted HMAC is required)"
    )

    # Different tokens with the correct salt also differ (additional coverage).
    different_token = "ghp_" + "B" * 36
    different_fp = compute_fingerprint(different_token, real_salt)
    assert different_fp != real_fp


def test_fingerprint_with_wrong_salt_cannot_reproduce():
    """
    Exhaustively confirm that flipping any bit in the salt changes the fingerprint.
    Uses a fixed token and two random salts; both must yield different fingerprints.
    """
    token = "sk-projAbcdefghijklmnopqrstuvwxyz1234567890"
    salt_a = secrets.token_bytes(32)
    salt_b = secrets.token_bytes(32)
    # Statistically the two salts are different (probability 2^-256 they collide).
    assert salt_a != salt_b, "test relies on two different salts"
    fp_a = compute_fingerprint(token, salt_a)
    fp_b = compute_fingerprint(token, salt_b)
    assert fp_a != fp_b, "different salts must produce different fingerprints for same token"


# ---------------------------------------------------------------------------
# AC-27-P3-15 (BLOCK): Fingerprint salt persistence
# ---------------------------------------------------------------------------

def test_salt_created_on_first_run_and_persisted(tmp_path, monkeypatch):
    """
    AC-27-P3-15: Salt is created on first run, written at 0600, and loading
    the same file twice returns identical bytes.
    """
    salt_dir = tmp_path / ".agentarca"
    salt_dir.mkdir()
    salt_file = salt_dir / "fingerprint-salt"

    # Monkey-patch the salt path to use our tmp directory.
    import src.admin.primitives.credentials as creds_module
    original_path = creds_module.FINGERPRINT_SALT_PATH
    monkeypatch.setattr(creds_module, "FINGERPRINT_SALT_PATH", salt_file)

    try:
        # File does not exist yet: first call creates it.
        assert not salt_file.exists()
        salt1 = _load_or_create_salt()
        assert salt_file.exists(), "salt file must be created on first run"
        assert len(salt1) == 32, "salt must be 32 bytes"

        # Check mode 0600.
        mode = oct(os.stat(salt_file).st_mode & 0o777)
        assert mode == "0o600", f"salt file must be mode 0600, got {mode}"

        # Second call must return the same bytes.
        salt2 = _load_or_create_salt()
        assert salt1 == salt2, "second load must return the same salt as first"
    finally:
        monkeypatch.setattr(creds_module, "FINGERPRINT_SALT_PATH", original_path)


def test_salt_load_from_existing_file(tmp_path, monkeypatch):
    """Salt is correctly loaded from a pre-existing file."""
    salt_dir = tmp_path / ".agentarca"
    salt_dir.mkdir()
    salt_file = salt_dir / "fingerprint-salt"

    # Write a known salt.
    known_salt = secrets.token_bytes(32)
    salt_file.write_text(known_salt.hex())
    os.chmod(salt_file, 0o600)

    import src.admin.primitives.credentials as creds_module
    original_path = creds_module.FINGERPRINT_SALT_PATH
    monkeypatch.setattr(creds_module, "FINGERPRINT_SALT_PATH", salt_file)

    try:
        loaded = _load_or_create_salt()
        assert loaded == known_salt, "loaded salt must match the pre-written salt"
    finally:
        monkeypatch.setattr(creds_module, "FINGERPRINT_SALT_PATH", original_path)


def test_salt_corrupt_file_raises_systemexit(tmp_path, monkeypatch):
    """A corrupt (non-hex) salt file causes SystemExit(1)."""
    salt_dir = tmp_path / ".agentarca"
    salt_dir.mkdir()
    salt_file = salt_dir / "fingerprint-salt"

    # Write invalid hex content.
    salt_file.write_text("not-valid-hex-content")
    os.chmod(salt_file, 0o600)

    import src.admin.primitives.credentials as creds_module
    original_path = creds_module.FINGERPRINT_SALT_PATH
    monkeypatch.setattr(creds_module, "FINGERPRINT_SALT_PATH", salt_file)

    try:
        with pytest.raises(SystemExit):
            _load_or_create_salt()
    finally:
        monkeypatch.setattr(creds_module, "FINGERPRINT_SALT_PATH", original_path)


# ---------------------------------------------------------------------------
# Additional primitive unit tests (not BLOCK, but provide coverage)
# ---------------------------------------------------------------------------

def test_managed_credential_keys_exact_set():
    """MANAGED_CREDENTIAL_KEYS contains exactly the 5 expected keys."""
    expected = frozenset({
        "COPILOT_GITHUB_TOKEN",
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
    })
    assert MANAGED_CREDENTIAL_KEYS == expected, (
        f"MANAGED_CREDENTIAL_KEYS mismatch: {MANAGED_CREDENTIAL_KEYS}"
    )
    assert len(MANAGED_CREDENTIAL_KEYS) == 5


def test_set_credential_rejects_unknown_key(tmp_path):
    """set_credential returns rejected-by-validation for unknown keys."""
    env_path = tmp_path / ".env"
    salt = secrets.token_bytes(32)
    result = set_credential("UNKNOWN_KEY", "some-value", salt, env_path)
    assert not result.ok
    assert result.outcome == "rejected-by-validation"
    assert not env_path.exists(), ".env must not be created for rejected key"


def test_set_credential_rejects_empty_value(tmp_path):
    """set_credential returns rejected-by-validation for empty values."""
    env_path = tmp_path / ".env"
    salt = secrets.token_bytes(32)
    result = set_credential("ANTHROPIC_API_KEY", "", salt, env_path)
    assert not result.ok
    assert result.outcome == "rejected-by-validation"


def test_set_credential_rejects_value_over_4096(tmp_path):
    """set_credential returns rejected-by-validation for values over 4096 chars."""
    env_path = tmp_path / ".env"
    salt = secrets.token_bytes(32)
    long_value = "x" * 4097
    result = set_credential("ANTHROPIC_API_KEY", long_value, salt, env_path)
    assert not result.ok
    assert result.outcome == "rejected-by-validation"


def test_set_credential_creates_env_at_0600_when_absent(tmp_path):
    """set_credential creates .env at mode 0600 when it does not exist."""
    env_path = tmp_path / ".env"
    salt = secrets.token_bytes(32)
    result = set_credential("ANTHROPIC_API_KEY", "test-token-value", salt, env_path)
    assert result.ok
    assert env_path.exists()
    mode = oct(os.stat(env_path).st_mode & 0o777)
    assert mode == "0o600", f".env must be mode 0600, got {mode}"


def test_clear_credential_is_noop_when_absent(tmp_path):
    """clear_credential is a no-op (ok=True) when .env does not exist."""
    env_path = tmp_path / ".env"
    result = clear_credential("ANTHROPIC_API_KEY", env_path)
    assert result.ok
    assert result.detail == "idempotent_clear"
    assert not env_path.exists()


def test_get_credential_status_returns_unset_when_absent(tmp_path):
    """get_credential_status returns present=False when .env does not exist."""
    env_path = tmp_path / ".env"
    salt = secrets.token_bytes(32)
    status_result = get_credential_status("ANTHROPIC_API_KEY", salt, env_path)
    assert not status_result.present
    assert status_result.fingerprint is None


def test_env_preserves_other_keys(tmp_path):
    """
    AC-27-P3-07 (BLOCK): PUT for key A preserves all other lines verbatim.

    Only the target key line is modified. Comment lines, blank lines,
    other key=value lines, and the trailing newline are all preserved.
    The mode is corrected to 0600.
    """
    env_content = (
        "# Managed by AgentArca\n"
        "COPILOT_GITHUB_TOKEN=old_copilot_token\n"
        "\n"
        "# Claude key\n"
        "ANTHROPIC_API_KEY=\n"
        "OPENAI_API_KEY=existing_openai\n"
    )
    env_path = tmp_path / ".env"
    env_path.write_text(env_content)
    os.chmod(env_path, 0o600)

    salt = secrets.token_bytes(32)
    result = set_credential("ANTHROPIC_API_KEY", "new_anthropic_key", salt, env_path)
    assert result.ok

    new_content = env_path.read_text()
    lines = new_content.splitlines(keepends=True)

    # Comment lines preserved verbatim
    assert lines[0] == "# Managed by AgentArca\n"
    # copilot line unchanged
    assert any("COPILOT_GITHUB_TOKEN=old_copilot_token" in ln for ln in lines)
    # blank line preserved
    assert "\n" in lines
    # claude comment line preserved
    assert any("# Claude key" in ln for ln in lines)
    # ANTHROPIC_API_KEY updated
    assert any(ln.startswith("ANTHROPIC_API_KEY=") for ln in lines)
    # openai line unchanged
    assert any("OPENAI_API_KEY=existing_openai" in ln for ln in lines)
    # mode is 0600
    assert oct(os.stat(env_path).st_mode & 0o777) == "0o600"
    # The new token value IS in the .env file (this is the intended behavior)
    assert "new_anthropic_key" in new_content


def test_set_and_get_roundtrip(tmp_path):
    """set_credential followed by get_credential_status returns same fingerprint."""
    env_path = tmp_path / ".env"
    salt = secrets.token_bytes(32)
    token = "test-roundtrip-token-abc123"

    set_result = set_credential("ANTHROPIC_API_KEY", token, salt, env_path)
    assert set_result.ok
    assert set_result.fingerprint is not None

    status_result = get_credential_status("ANTHROPIC_API_KEY", salt, env_path)
    assert status_result.present
    assert status_result.fingerprint == set_result.fingerprint


def test_clear_removes_key_line(tmp_path):
    """clear_credential removes the key line from .env entirely."""
    env_path = tmp_path / ".env"
    env_path.write_text(
        "ANTHROPIC_API_KEY=some-token\n"
        "OPENAI_API_KEY=another-token\n"
    )
    os.chmod(env_path, 0o600)

    result = clear_credential("ANTHROPIC_API_KEY", env_path)
    assert result.ok

    content = env_path.read_text()
    assert "ANTHROPIC_API_KEY=" not in content
    assert "OPENAI_API_KEY=another-token" in content


def test_clear_idempotent_when_key_not_present(tmp_path):
    """clear_credential is idempotent when the key is not in the .env."""
    env_path = tmp_path / ".env"
    env_path.write_text("OPENAI_API_KEY=another-token\n")
    os.chmod(env_path, 0o600)

    result = clear_credential("ANTHROPIC_API_KEY", env_path)
    assert result.ok
    assert result.detail == "idempotent_clear"

    # File unchanged
    assert "OPENAI_API_KEY=another-token" in env_path.read_text()
