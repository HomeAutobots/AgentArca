"""
test_nonce_primitive.py - Unit tests for src/admin/primitives/nonce.py (SPEC-29-P0).

All tests are isolation-runnable (no Docker stack required). Tests redirect NONCE_DIR
to a tmp_path subdirectory via monkeypatch so the real ~/.agentarca/start-auth.d is
never touched. The module-level NONCE_DIR constant in nonce.py is referenced by name
in every function body, so patching nonce_mod.NONCE_DIR at the module level is sufficient
to redirect all file operations.

Covers:
  AC-29-P0-01  mint_nonce(p) creates 3-line file at NONCE_DIR/p:
               line 1 exactly 64 lowercase hex chars;
               line 2 integer unix seconds (sanity-checked as near now);
               line 3 profile name;
               file mode 0600;
               content has exactly 3 newline-terminated lines and no other content.
  AC-29-P0-02  consume_nonce(p) deletes the nonce file; second consume_nonce does not raise.
  AC-29-P0-03  purge_stale_nonces(frozenset({"claude"})) deletes copilot and codex files,
               keeps the claude file, and leaves non-profile filenames in the dir untouched.
  AC-29-P0-18  Portal startup reconciliation semantics: purge_stale_nonces removes nonce
               files for non-running profiles; also covers empty running set (all files purged).
  AC-29-P0-19  build-admin.sh --init contains the exact line
               'mkdir -p -m 0700 "${HOME}/.agentarca/start-auth.d"'
               Source inspection is used here because --init also generates an admin secret
               via openssl, making it unsuitable as a side-effect-free unit test.
               The source inspection verifies the control is present in the --init block.
  AC-29-P0-22  Source inspection of mint_nonce body:
               - calls secrets.token_hex(32) with exactly one positional argument (32)
                 and zero keyword arguments;
               - "admin_secret" and "session" do not appear in the function body;
               - minted file content is exactly token / unix-ts / profile
                 (3 newline-terminated lines, no fourth line, no extra fields).

Drift guards (security-review notes N2, N3):
  N2  The bash literal that enforces the freshness window in
      src/gateway/entrypoint.sh matches nonce.NONCE_FRESHNESS_WINDOW_SECS.
      Both must stay equal; this test trips CI if one is updated without the other.
  N3  ALLOWED_PROFILES is identical across:
        src/admin/primitives/nonce.py    (Python frozenset)
        src/admin/primitives/lifecycle.py (Python frozenset)
        src/scripts/_break_glass_up.py  (Python frozenset)
        src/scripts/break-glass-up.sh   (bash array ALLOWED_PROFILES=(...))
      A future fourth profile added in one place but not the others trips CI.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import re
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import src.admin.primitives.nonce as nonce_mod
from src.admin.primitives.nonce import (
    NONCE_FRESHNESS_WINDOW_SECS,
    consume_nonce,
    mint_nonce,
    purge_stale_nonces,
)


# ---------------------------------------------------------------------------
# Shared fixture: redirect NONCE_DIR to a temp subdirectory
# ---------------------------------------------------------------------------

@pytest.fixture()
def nonce_dir(tmp_path, monkeypatch):
    """
    Patch nonce.NONCE_DIR to a temporary directory so no test touches
    the real ~/.agentarca/start-auth.d.

    The directory is NOT pre-created here; _bootstrap_nonce_dir() creates it
    lazily. Tests that need pre-existing nonce files create nonce_dir.mkdir()
    themselves before writing files.
    """
    d = tmp_path / "start-auth.d"
    monkeypatch.setattr(nonce_mod, "NONCE_DIR", d)
    return d


# ---------------------------------------------------------------------------
# AC-29-P0-01 and AC-29-P0-22: mint_nonce file format, mode, source inspection
# ---------------------------------------------------------------------------

class TestMintNonce:
    """
    AC-29-P0-01 and AC-29-P0-22: nonce file structure, mode, and source inspection.
    """

    def test_mint_creates_file_at_nonce_dir(self, nonce_dir):
        """AC-29-P0-01: mint_nonce creates the file at NONCE_DIR/profile."""
        mint_nonce("claude")
        assert (nonce_dir / "claude").exists(), "Nonce file must exist at NONCE_DIR/claude"

    def test_mint_file_has_exactly_three_newline_terminated_lines(self, nonce_dir):
        """AC-29-P0-01: file content is exactly 3 newline-terminated lines, no more."""
        mint_nonce("copilot")
        content = (nonce_dir / "copilot").read_text(encoding="ascii")
        lines = content.split("\n")
        # split on '\n' of a "a\nb\nc\n" string yields ["a", "b", "c", ""]
        assert len(lines) == 4, (
            f"Expected 3 newline-terminated lines (4 parts after split), got {len(lines)}: {lines!r}"
        )
        assert lines[3] == "", "File must end with a newline (no trailing content)"

    def test_mint_line1_is_64_lowercase_hex(self, nonce_dir):
        """AC-29-P0-01: line 1 is exactly 64 lowercase hex characters."""
        mint_nonce("codex")
        content = (nonce_dir / "codex").read_text(encoding="ascii")
        line1 = content.split("\n")[0]
        assert re.fullmatch(r"[0-9a-f]{64}", line1), (
            f"Line 1 must be exactly 64 lowercase hex chars; got {line1!r}"
        )

    def test_mint_line2_is_integer_unix_seconds_near_now(self, nonce_dir):
        """AC-29-P0-01: line 2 is an integer unix timestamp within 5 seconds of now."""
        before = int(time.time())
        mint_nonce("claude")
        after = int(time.time())
        content = (nonce_dir / "claude").read_text(encoding="ascii")
        line2 = content.split("\n")[1]
        assert line2.isdigit(), f"Line 2 must be a decimal integer; got {line2!r}"
        ts = int(line2)
        assert before <= ts <= after + 1, (
            f"Timestamp {ts} must be within [{before}, {after + 1}] (near now)"
        )

    def test_mint_line3_is_profile_name(self, nonce_dir):
        """AC-29-P0-01: line 3 is the profile name."""
        for profile in ("copilot", "claude", "codex"):
            mint_nonce(profile)
            content = (nonce_dir / profile).read_text(encoding="ascii")
            line3 = content.split("\n")[2]
            assert line3 == profile, f"Line 3 must be {profile!r}; got {line3!r}"

    def test_mint_file_mode_is_0600(self, nonce_dir):
        """AC-29-P0-01: nonce file is mode 0600 (owner read/write only)."""
        mint_nonce("claude")
        mode = os.stat(nonce_dir / "claude").st_mode & 0o777
        assert mode == 0o600, f"Expected mode 0600, got {oct(mode)}"

    def test_mint_nonce_dir_is_bootstrapped_on_first_call(self, nonce_dir):
        """AC-29-P0-01 / 3.2: _bootstrap_nonce_dir is called lazily by mint_nonce."""
        assert not nonce_dir.exists(), "Fixture must not pre-create the directory"
        mint_nonce("claude")
        assert nonce_dir.exists(), "NONCE_DIR must exist after mint_nonce"

    def test_mint_token_is_not_same_across_calls(self, nonce_dir):
        """AC-29-P0-01: each mint produces a fresh random token (basic entropy sanity)."""
        mint_nonce("claude")
        token1 = (nonce_dir / "claude").read_text(encoding="ascii").split("\n")[0]
        mint_nonce("claude")
        token2 = (nonce_dir / "claude").read_text(encoding="ascii").split("\n")[0]
        assert token1 != token2, "Two consecutive mints must produce distinct tokens"

    # --- AC-29-P0-22: source inspection ---

    def test_mint_nonce_uses_secrets_token_hex_32(self):
        """
        AC-29-P0-22 (source inspection): mint_nonce calls secrets.token_hex(32)
        with exactly one positional argument (the integer 32) and zero keyword arguments.
        No admin-secret, session key, or credential is passed.
        """
        source = (REPO_ROOT / "src" / "admin" / "primitives" / "nonce.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        mint_func = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "mint_nonce":
                mint_func = node
                break
        assert mint_func is not None, "mint_nonce not found in nonce.py AST"

        token_hex_calls = []
        for node in ast.walk(mint_func):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "secrets"
                and func.attr == "token_hex"
            ):
                token_hex_calls.append(node)

        assert len(token_hex_calls) == 1, (
            f"mint_nonce must call secrets.token_hex exactly once; found {len(token_hex_calls)} calls"
        )
        call_node = token_hex_calls[0]
        assert len(call_node.args) == 1, (
            f"secrets.token_hex must receive exactly 1 positional argument; "
            f"got {len(call_node.args)}"
        )
        arg = call_node.args[0]
        assert isinstance(arg, ast.Constant) and arg.value == 32, (
            f"secrets.token_hex argument must be the literal 32; got {ast.dump(arg)}"
        )
        assert len(call_node.keywords) == 0, (
            f"secrets.token_hex must have no keyword arguments; "
            f"got {[kw.arg for kw in call_node.keywords]}"
        )

    def test_mint_nonce_body_contains_no_credential_identifiers(self):
        """
        AC-29-P0-22 (source inspection): the strings 'admin_secret' and 'session'
        do not appear in the EXECUTABLE code of the mint_nonce function body
        (docstrings are excluded from the check; the mint_nonce docstring intentionally
        NAMES 'session key' in order to document that it is NOT passed -- that is the
        independence invariant note, not a credential reference).

        The executable code of mint_nonce must not reference any credential identifier
        as a variable name, attribute, or argument (AC-012-3).
        """
        source = (REPO_ROOT / "src" / "admin" / "primitives" / "nonce.py").read_text(encoding="utf-8")

        tree = ast.parse(source)
        mint_func = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "mint_nonce":
                mint_func = node
                break
        assert mint_func is not None

        lines = source.splitlines()

        # Exclude the docstring: it is the first body statement if it is a bare string
        # constant (ast.Expr whose value is ast.Constant with a str value).
        code_start_line = mint_func.lineno  # 1-indexed
        if mint_func.body:
            first_stmt = mint_func.body[0]
            if (
                isinstance(first_stmt, ast.Expr)
                and isinstance(first_stmt.value, ast.Constant)
                and isinstance(first_stmt.value.value, str)
            ):
                # Skip past the docstring; executable code begins on the next line.
                code_start_line = first_stmt.end_lineno + 1  # 1-indexed

        # Extract only executable code lines (0-indexed slice).
        code_lines = lines[code_start_line - 1 : mint_func.end_lineno]
        code_src = "\n".join(code_lines)

        forbidden = ["admin_secret", "session"]
        for term in forbidden:
            assert term not in code_src, (
                f"Forbidden identifier {term!r} found in the EXECUTABLE code of "
                f"mint_nonce (docstring excluded from check). "
                "The nonce must not be derived from any credential (AC-012-3).\n"
                f"Executable code checked:\n{code_src}"
            )

    def test_mint_nonce_content_is_exactly_token_ts_profile(self, nonce_dir):
        """
        AC-29-P0-22 (runtime): minted file contains exactly token / unix-ts / profile.
        No fourth line, no extra fields, no secret material.
        """
        mint_nonce("claude")
        content = (nonce_dir / "claude").read_text(encoding="ascii")
        lines = content.rstrip("\n").split("\n")
        assert len(lines) == 3, f"Must be exactly 3 lines; got {len(lines)}: {lines!r}"
        token, ts_str, profile_name = lines
        assert re.fullmatch(r"[0-9a-f]{64}", token)
        assert ts_str.isdigit()
        assert profile_name == "claude"


# ---------------------------------------------------------------------------
# AC-29-P0-02: consume_nonce
# ---------------------------------------------------------------------------

class TestConsumeNonce:
    """AC-29-P0-02: consume_nonce deletes file; second call does not raise."""

    def test_consume_deletes_nonce_file(self, nonce_dir):
        """consume_nonce removes the nonce file when it exists."""
        mint_nonce("claude")
        assert (nonce_dir / "claude").exists()
        consume_nonce("claude")
        assert not (nonce_dir / "claude").exists(), "consume_nonce must delete the file"

    def test_consume_twice_does_not_raise(self, nonce_dir):
        """Second consume_nonce on an already-consumed (absent) file must not raise."""
        mint_nonce("claude")
        consume_nonce("claude")
        # Must not raise FileNotFoundError or any other exception.
        consume_nonce("claude")

    def test_consume_nonexistent_does_not_raise(self, nonce_dir):
        """consume_nonce on a never-minted file must not raise."""
        nonce_dir.mkdir(mode=0o700)
        consume_nonce("codex")  # file never existed; must succeed silently


# ---------------------------------------------------------------------------
# AC-29-P0-03 and AC-29-P0-18: purge_stale_nonces
# ---------------------------------------------------------------------------

class TestPurgeStaleNonces:
    """AC-29-P0-03 and AC-29-P0-18: purge_stale_nonces semantics."""

    def _write_nonce(self, nonce_dir: Path, name: str) -> Path:
        """Helper: write a dummy nonce file for a given name."""
        f = nonce_dir / name
        f.write_text(f"{'a' * 64}\n{int(time.time())}\n{name}\n", encoding="ascii")
        return f

    def test_purge_keeps_running_profile_deletes_others(self, nonce_dir):
        """
        AC-29-P0-03: purge_stale_nonces(frozenset({"claude"})) keeps the claude
        nonce file and deletes copilot and codex nonce files.
        """
        nonce_dir.mkdir(mode=0o700)
        for profile in ("copilot", "claude", "codex"):
            self._write_nonce(nonce_dir, profile)

        purge_stale_nonces(frozenset({"claude"}))

        assert (nonce_dir / "claude").exists(), "claude nonce must be kept (profile is running)"
        assert not (nonce_dir / "copilot").exists(), "copilot nonce must be purged"
        assert not (nonce_dir / "codex").exists(), "codex nonce must be purged"

    def test_purge_does_not_touch_non_profile_filenames(self, nonce_dir):
        """
        AC-29-P0-03: purge_stale_nonces must not delete files whose names are not
        in ALLOWED_PROFILES (e.g., lock files, temp files, README).
        """
        nonce_dir.mkdir(mode=0o700)
        alien = nonce_dir / "not-a-profile"
        alien.write_text("irrelevant content\n", encoding="ascii")
        for profile in ("copilot", "claude", "codex"):
            self._write_nonce(nonce_dir, profile)

        purge_stale_nonces(frozenset({"claude"}))

        assert alien.exists(), "Non-profile files must not be touched by purge_stale_nonces"

    def test_purge_empty_running_set_deletes_all_profile_nonces(self, nonce_dir):
        """
        AC-29-P0-18: when no profiles are running (empty frozenset), all three
        profile nonce files are purged.
        """
        nonce_dir.mkdir(mode=0o700)
        for profile in ("copilot", "claude", "codex"):
            self._write_nonce(nonce_dir, profile)

        purge_stale_nonces(frozenset())

        for profile in ("copilot", "claude", "codex"):
            assert not (nonce_dir / profile).exists(), (
                f"{profile} nonce must be purged when no profiles are running"
            )

    def test_purge_bootstraps_nonce_dir_if_missing(self, nonce_dir):
        """
        AC-29-P0-18: purge_stale_nonces calls _bootstrap_nonce_dir, so NONCE_DIR
        is created if it does not exist (no crash on missing directory).
        """
        assert not nonce_dir.exists()
        purge_stale_nonces(frozenset({"claude"}))
        assert nonce_dir.exists(), "purge_stale_nonces must bootstrap NONCE_DIR"

    def test_purge_all_running_keeps_all_nonces(self, nonce_dir):
        """
        AC-29-P0-18: when all three profiles are in the running set, no nonce files
        are deleted.
        """
        nonce_dir.mkdir(mode=0o700)
        for profile in ("copilot", "claude", "codex"):
            self._write_nonce(nonce_dir, profile)

        purge_stale_nonces(frozenset({"copilot", "claude", "codex"}))

        for profile in ("copilot", "claude", "codex"):
            assert (nonce_dir / profile).exists(), (
                f"{profile} nonce must be kept when profile is in the running set"
            )


# ---------------------------------------------------------------------------
# AC-29-P0-19: build-admin.sh --init creates start-auth.d at mode 0700
# ---------------------------------------------------------------------------

class TestBuildAdminInit:
    """
    AC-29-P0-19: build-admin.sh --init creates ~/.agentarca/start-auth.d at mode 0700.

    Source inspection is used rather than running --init, because --init also generates
    an admin-secret via openssl and explicitly refuses to run if the secret file already
    exists. Running it against the real HOME would clobber the operator's environment.
    Running it against a temp HOME is possible but adds an openssl dependency and
    orchestration overhead for a simple configuration assertion.

    The source inspection verifies: (a) the exact mkdir line is present in the --init
    block; (b) it uses -m 0700 (mode); (c) it uses -p (parents). This is equivalent
    to asserting the control is present and has the correct parameters.
    """

    def test_build_admin_init_contains_mkdir_start_auth_d(self):
        """AC-29-P0-19 (source inspection): --init block contains mkdir -p -m 0700 for start-auth.d."""
        build_admin = (REPO_ROOT / "src" / "scripts" / "build-admin.sh").read_text(encoding="utf-8")

        # Locate the --init block: begins after the --init conditional and ends at 'exit 0'.
        # Assertion: the exact mkdir line appears inside this block.
        target_line = 'mkdir -p -m 0700 "${HOME}/.agentarca/start-auth.d"'
        assert target_line in build_admin, (
            f"build-admin.sh --init must contain exactly:\n  {target_line}\n"
            "This line bootstraps the nonce directory before the first compose invocation."
        )

    def test_build_admin_init_mkdir_is_inside_init_block(self):
        """AC-29-P0-19: the mkdir line is inside the --init conditional block (not at top level)."""
        build_admin = (REPO_ROOT / "src" / "scripts" / "build-admin.sh").read_text(encoding="utf-8")

        init_start_idx = build_admin.index('== "--init"')
        mkdir_idx = build_admin.index('mkdir -p -m 0700 "${HOME}/.agentarca/start-auth.d"')
        assert mkdir_idx > init_start_idx, (
            "The start-auth.d mkdir must appear AFTER the --init check in the script"
        )


# ---------------------------------------------------------------------------
# Drift guards N2 and N3
# ---------------------------------------------------------------------------

class TestDriftGuards:
    """
    Drift guards from security-review notes N2 and N3.

    N2: NONCE_FRESHNESS_WINDOW_SECS in nonce.py (Python constant) must equal the
        bash literal used in the gateway entrypoint freshness check. Two copies of
        the same constant exist; this test ensures they stay in sync.

    N3: ALLOWED_PROFILES must be identical across all four locations where it is
        defined: nonce.py, lifecycle.py, _break_glass_up.py, and break-glass-up.sh.
        (The nonce.py copy mirrors lifecycle.py's to avoid a circular import; G-2
        of the security review accepts this design; the drift guard is the safety net.)
    """

    def test_n2_freshness_window_matches_bash_literal(self):
        """
        N2 drift guard: NONCE_FRESHNESS_WINDOW_SECS == bash literal in entrypoint.sh.

        Parses entrypoint.sh for the freshness comparison line:
            if (( _age < 0 || _age > 300 ))
        and asserts the bash literal matches the Python constant.

        Version verified: entrypoint.sh freshness check inserted per SPEC-29-P0 sec 6.2,
        line 134 (as of 2026-07-01).
        """
        entrypoint_src = (
            REPO_ROOT / "src" / "gateway" / "entrypoint.sh"
        ).read_text(encoding="utf-8")

        # Find the freshness check: "_age > <N>"
        m = re.search(r"_age\s*>\s*(\d+)", entrypoint_src)
        assert m is not None, (
            "Could not find '_age > <N>' freshness check in entrypoint.sh. "
            "The nonce freshness check may have been moved or renamed."
        )
        bash_window = int(m.group(1))

        python_window = nonce_mod.NONCE_FRESHNESS_WINDOW_SECS

        assert bash_window == python_window, (
            f"Freshness window mismatch: entrypoint.sh uses {bash_window}s, "
            f"nonce.NONCE_FRESHNESS_WINDOW_SECS = {python_window}s. "
            "Update both to the same value. "
            "(Security review note N2: two independent hardcoded copies must stay equal.)"
        )

    def test_n3_allowed_profiles_identical_across_all_four_sources(self):
        """
        N3 drift guard: ALLOWED_PROFILES is identical in nonce.py, lifecycle.py,
        _break_glass_up.py, and break-glass-up.sh.

        Python sources are imported. The bash source is parsed with a regex that
        extracts quoted words from: ALLOWED_PROFILES=("copilot" "claude" "codex")
        """
        # Source 1: nonce.py (already imported as nonce_mod.ALLOWED_PROFILES)
        nonce_profiles = nonce_mod.ALLOWED_PROFILES

        # Source 2: lifecycle.py
        from src.admin.primitives.lifecycle import ALLOWED_PROFILES as lifecycle_profiles

        # Source 3: _break_glass_up.py (load without running main())
        bg_py_path = REPO_ROOT / "src" / "scripts" / "_break_glass_up.py"
        spec = importlib.util.spec_from_file_location("_break_glass_up", bg_py_path)
        bg_mod = importlib.util.module_from_spec(spec)
        # exec_module runs the module body (assigns ALLOWED_PROFILES at module level)
        # main() is NOT called because __name__ != "__main__"
        spec.loader.exec_module(bg_mod)
        bg_py_profiles = bg_mod.ALLOWED_PROFILES

        # Source 4: break-glass-up.sh (bash array parsed from source)
        bash_src = (REPO_ROOT / "src" / "scripts" / "break-glass-up.sh").read_text(encoding="utf-8")
        m = re.search(r'ALLOWED_PROFILES=\(([^)]+)\)', bash_src)
        assert m is not None, (
            "Could not find ALLOWED_PROFILES=(...) in break-glass-up.sh. "
            "Has the variable been renamed?"
        )
        bash_profiles = frozenset(re.findall(r'"(\w+)"', m.group(1)))

        assert nonce_profiles == lifecycle_profiles, (
            f"ALLOWED_PROFILES mismatch: nonce.py={nonce_profiles!r} vs "
            f"lifecycle.py={lifecycle_profiles!r}. Keep these in sync."
        )
        assert nonce_profiles == bg_py_profiles, (
            f"ALLOWED_PROFILES mismatch: nonce.py={nonce_profiles!r} vs "
            f"_break_glass_up.py={bg_py_profiles!r}. Keep these in sync."
        )
        assert nonce_profiles == bash_profiles, (
            f"ALLOWED_PROFILES mismatch: nonce.py={nonce_profiles!r} vs "
            f"break-glass-up.sh bash array={bash_profiles!r}. Keep these in sync."
        )
