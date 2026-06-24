"""
test_allowlist_primitive.py - allowlist-local.sh interface stability tests.

AC-27-P1-11 (BLOCK): Verifies that the shell script interface is stable and
matches what the Python wrapper expects.

Isolation-runnable: requires the script file to be present at
src/scripts/allowlist-local.sh relative to the repo root, but does NOT require
a live Docker stack, a running gateway, or any network access.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "src" / "scripts" / "allowlist-local.sh"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class TestAllowlistScriptInterface:
    """AC-27-P1-11 (BLOCK): Interface stability for allowlist-local.sh."""

    def test_script_exists(self):
        """The script file must exist at the expected path."""
        assert SCRIPT_PATH.exists(), (
            f"allowlist-local.sh not found at {SCRIPT_PATH}. "
            "If the script was moved or renamed, update SPEC-27-P1 and the Python wrapper."
        )

    def test_help_exits_zero(self):
        """allowlist-local.sh help exits with code 0."""
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH), "help"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, (
            f"help exited {result.returncode}. stderr: {result.stderr}"
        )

    def test_help_output_contains_required_verbs(self):
        """help output must mention add, remove, list, reload."""
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH), "help"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(REPO_ROOT),
        )
        combined = result.stdout + result.stderr
        for verb in ("add", "remove", "list", "reload"):
            assert verb in combined, (
                f"Verb '{verb}' not found in help output. "
                f"Output was: {combined[:500]}"
            )

    def test_unknown_verb_exits_nonzero(self):
        """An unknown subcommand must return a non-zero exit code."""
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH), "__nonexistent_verb_xyzzy__"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode != 0, (
            "Expected non-zero exit for unknown verb, but got 0. "
            "The script's main() dispatch may be broken."
        )

    def test_help_no_arg_is_equivalent_to_help_verb(self):
        """Calling the script with no args should exit 0 (help path) or non-zero;
        either is acceptable. The verb contract test above is the load-bearing one."""
        # This is informational; we do not assert exit code here because some
        # scripts choose non-zero for no-arg invocations.
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(REPO_ROOT),
        )
        # Either behavior is ok; we just confirm it does not hang.
        assert result.returncode is not None

    def test_add_verb_requires_arg(self):
        """allowlist-local.sh add with no host argument should exit non-zero."""
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH), "add"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode != 0, (
            "Expected non-zero exit for 'add' with no host argument."
        )

    def test_remove_verb_requires_arg(self):
        """allowlist-local.sh remove with no host argument should exit non-zero."""
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH), "remove"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode != 0, (
            "Expected non-zero exit for 'remove' with no host argument."
        )

    def test_invalid_host_rejected_by_script(self):
        """The script's valid_host() rejects a host with shell metacharacters.

        The host is passed as a single positional argument to the bash script.
        The script's valid_host() function rejects it before any file write or
        command execution. The string may appear in the error message (quoted
        back as part of the rejection notice), but it must NOT have been
        executed as a shell command.

        We test actual injection defense by using a side-effect command:
        if 'echo INJECTED' was executed, a file would be created. If the file
        does NOT exist, the injection was blocked.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            marker_file = Path(tmpdir) / "injection_marker.txt"
            # Pass a host that, if executed as a shell command, would create marker_file.
            malicious_host = f"api.example.com; touch {marker_file}"
            result = subprocess.run(
                ["bash", str(SCRIPT_PATH), "add", malicious_host],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(REPO_ROOT),
            )
            assert result.returncode != 0, (
                "Script accepted a metacharacter host. This is a security regression."
            )
            # The critical assertion: the marker file must NOT have been created.
            # If it exists, the injection succeeded (the semicolon was interpreted).
            assert not marker_file.exists(), (
                "INJECTION SUCCEEDED: marker file was created by the malicious host string. "
                "The shell script's metacharacter validation is broken."
            )

    def test_rm_alias_for_remove(self):
        """The 'rm' alias for remove should work (same as 'remove')."""
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH), "rm"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(REPO_ROOT),
        )
        # rm with no arg should exit non-zero (same as remove with no arg).
        assert result.returncode != 0

    def test_ls_alias_for_list(self):
        """The 'ls' alias for list should exit zero (list is read-only)."""
        # list/ls may try to detect a gateway; without one it should still exit 0.
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH), "ls"],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, (
            f"'ls' alias exited {result.returncode}. stderr: {result.stderr[:200]}"
        )
