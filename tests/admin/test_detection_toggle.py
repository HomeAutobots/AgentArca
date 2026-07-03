"""
test_detection_toggle.py - Acceptance tests for the detection overlay toggle.

Covers:
  AC-29-P1-11  compose_up(profile, overlay_files=["src/detect/docker-compose.detect.yml"])
               builds the correct command list. Assert -f ordering:
               ["docker", "compose", "-f", "src/detect/docker-compose.detect.yml",
                "--profile", "<p>", "up", "-d"] (matches implemented arg order in lifecycle.py).
               subprocess.run is monkeypatched to capture argv.
  AC-29-P1-12  compose_up(profile, overlay_files=["/etc/passwd"]) raises ValueError
               (allowlist validation; exact frozenset membership, not prefix match).
               Also tests a substring-evasion attempt raises ValueError.
  AC-29-P1-09  With detection_enabled=True in portal config (load_portal_config
               monkeypatched), do_up includes the detection overlay -f flag in the
               compose command (subprocess.run argv captured).
  AC-29-P1-13  With detection_enabled=False (default), do_up does NOT include the
               detection overlay -f flag.

Design references: SPEC-29-P1 sec 6.1-6.2, B7; security-review adjudication D.
Security framing: detection toggle is observability infrastructure, NOT a security
boundary. The tests assert cmd structure, not containment efficacy (red-teamer's).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.primitives.lifecycle import compose_up, do_up, PERMITTED_OVERLAYS


# ---------------------------------------------------------------------------
# AC-29-P1-11: compose_up builds the correct command list
# ---------------------------------------------------------------------------

class TestComposeUpCommandUnit:
    """
    AC-29-P1-11: compose_up with the permitted overlay builds the exact expected
    command list. Also verifies baseline (no overlay) command for comparison.

    The expected order (from lifecycle.py:336-367):
      cmd = ["docker", "compose"]
      for f in (overlay_files or []):
          cmd += ["-f", f]
      cmd += ["--profile", profile, "up", "-d"]
    """

    def test_compose_up_no_overlay_builds_baseline_cmd(self):
        """Without overlay, command is [docker, compose, --profile, <p>, up, -d]. AC-29-P1-11 (baseline)."""
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(list(cmd))
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.subprocess.run", side_effect=fake_run):
            compose_up("claude")

        assert len(captured) == 1
        assert captured[0] == ["docker", "compose", "--profile", "claude", "up", "-d"], (
            f"Unexpected baseline command: {captured[0]!r}"
        )

    def test_compose_up_with_detect_overlay_builds_correct_cmd(self):
        """
        With the permitted detection overlay, command includes -f before --profile.
        Expected: [docker, compose, -f, src/detect/docker-compose.detect.yml,
                   --profile, claude, up, -d]. AC-29-P1-11.
        """
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(list(cmd))
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.subprocess.run", side_effect=fake_run):
            compose_up("claude", overlay_files=["src/detect/docker-compose.detect.yml"])

        assert len(captured) == 1
        expected = [
            "docker", "compose",
            "-f", "src/detect/docker-compose.detect.yml",
            "--profile", "claude",
            "up", "-d",
        ]
        assert captured[0] == expected, (
            f"Detection overlay command mismatch.\n"
            f"  Expected: {expected!r}\n"
            f"  Got:      {captured[0]!r}"
        )

    def test_compose_up_overlay_position_before_profile(self):
        """The -f overlay flag appears BEFORE --profile in the command list. AC-29-P1-11."""
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(list(cmd))
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.subprocess.run", side_effect=fake_run):
            compose_up("codex", overlay_files=["src/detect/docker-compose.detect.yml"])

        cmd = captured[0]
        assert "-f" in cmd, "-f flag must be present"
        f_idx = cmd.index("-f")
        profile_idx = cmd.index("--profile")
        assert f_idx < profile_idx, (
            f"Expected -f at index {f_idx} to appear before --profile at index {profile_idx}"
        )

    def test_permitted_overlays_frozenset_contains_detect_path(self):
        """PERMITTED_OVERLAYS contains exactly the detection overlay path. AC-29-P1-11 (allowlist check)."""
        assert "src/detect/docker-compose.detect.yml" in PERMITTED_OVERLAYS, (
            f"Detection overlay path must be in PERMITTED_OVERLAYS; got: {PERMITTED_OVERLAYS!r}"
        )

    # --- AC-29-P1-12: allowlist validation ---

    def test_compose_up_disallowed_path_raises_value_error(self):
        """overlay_files=["/etc/passwd"] raises ValueError. AC-29-P1-12."""
        with pytest.raises(ValueError, match="not in the permitted overlays"):
            compose_up("claude", overlay_files=["/etc/passwd"])

    def test_compose_up_arbitrary_path_raises_value_error(self):
        """overlay_files=["arbitrary/path.yml"] raises ValueError (not in allowlist). AC-29-P1-12."""
        with pytest.raises(ValueError):
            compose_up("claude", overlay_files=["arbitrary/path.yml"])

    def test_compose_up_substring_evasion_raises_value_error(self):
        """
        Substring evasion attempt raises ValueError: exact frozenset membership, not prefix match.
        "src/detect/docker-compose.detect.yml/../../etc/x" is NOT in PERMITTED_OVERLAYS.
        Security-review adjudication D: "the allowlist check is exact set membership
        (f not in PERMITTED_OVERLAYS, line 353), not prefix/substring."
        AC-29-P1-12.
        """
        evasion_path = "src/detect/docker-compose.detect.yml/../../etc/x"
        with pytest.raises(ValueError, match="not in the permitted overlays"), \
             patch("src.admin.primitives.lifecycle.subprocess.run"):
            compose_up("claude", overlay_files=[evasion_path])

    def test_compose_up_path_with_permitted_as_prefix_raises_value_error(self):
        """A string that starts with the permitted path but adds extra chars raises ValueError. AC-29-P1-12."""
        with pytest.raises(ValueError), \
             patch("src.admin.primitives.lifecycle.subprocess.run"):
            compose_up("claude", overlay_files=["src/detect/docker-compose.detect.yml_extra"])

    def test_compose_up_empty_overlay_list_does_not_raise(self):
        """Empty overlay list is valid (equivalent to no overlay). AC-29-P1-12 (inverse guard)."""
        with patch("src.admin.primitives.lifecycle.subprocess.run",
                   return_value=MagicMock(returncode=0)):
            result = compose_up("claude", overlay_files=[])
        # Should not raise; result is the mock.
        assert result is not None

    def test_compose_up_subprocess_not_called_if_allowlist_fails(self):
        """subprocess.run must NOT be called when an overlay path fails the allowlist. AC-29-P1-12."""
        subprocess_called = []

        def fake_run(cmd, **kwargs):
            subprocess_called.append(cmd)
            return MagicMock(returncode=0)

        with pytest.raises(ValueError), \
             patch("src.admin.primitives.lifecycle.subprocess.run", side_effect=fake_run):
            compose_up("claude", overlay_files=["/etc/passwd"])

        assert len(subprocess_called) == 0, (
            "subprocess.run must not be called when allowlist validation fails"
        )


# ---------------------------------------------------------------------------
# AC-29-P1-09 and AC-29-P1-13: detection toggle in do_up
# ---------------------------------------------------------------------------

class TestDetectionToggleInDoUp:
    """
    AC-29-P1-09: With detection_enabled=True (monkeypatched load_portal_config),
    do_up includes the detection overlay -f flag in the compose subprocess command.

    AC-29-P1-13: With detection_enabled=False (default), do_up does NOT include
    the detection overlay -f flag.

    Tests spy on the compose_up function to capture the overlay_files argument
    (spec says "spy on compose_up" as the preferred approach). The subprocess.run
    layer is also mocked to prevent real Docker calls.
    """

    def _run_do_up_capture_compose_args(self, detection_enabled: bool):
        """
        Run do_up with the credential gate passing and all side effects mocked.
        Returns the (profile, overlay_files) tuple passed to compose_up.
        """
        present_cred = MagicMock()
        present_cred.present = True

        compose_up_calls = []

        def spy_compose_up(profile, overlay_files=None, timeout=300):
            compose_up_calls.append((profile, overlay_files))
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=present_cred), \
             patch("src.admin.primitives.lifecycle.mint_nonce"), \
             patch("src.admin.primitives.lifecycle.load_portal_config",
                   return_value={"detection_enabled": detection_enabled}), \
             patch("src.admin.primitives.lifecycle.compose_up", side_effect=spy_compose_up), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True), \
             patch("src.admin.primitives.lifecycle.consume_nonce"):
            result = do_up("claude", secret="test-secret", salt=b"", env_path=None)

        return result, compose_up_calls

    def test_detection_enabled_true_includes_overlay_in_compose_call(self):
        """
        detection_enabled=True: do_up passes overlay_files=["src/detect/docker-compose.detect.yml"]
        to compose_up. AC-29-P1-09.
        """
        result, compose_up_calls = self._run_do_up_capture_compose_args(detection_enabled=True)

        assert result["outcome"] == "applied", (
            f"Expected applied outcome; got {result['outcome']!r}. "
            "Precondition failure: credential gate or compose_up mock not set up correctly."
        )
        assert len(compose_up_calls) == 1, (
            f"compose_up must be called exactly once; got: {compose_up_calls!r}"
        )
        _, overlay_files = compose_up_calls[0]
        assert overlay_files == ["src/detect/docker-compose.detect.yml"], (
            f"With detection_enabled=True, overlay_files must be "
            f"['src/detect/docker-compose.detect.yml']; got: {overlay_files!r}"
        )

    def test_detection_enabled_true_compose_includes_f_flag(self):
        """
        detection_enabled=True: the underlying subprocess command includes
        -f src/detect/docker-compose.detect.yml. AC-29-P1-09 (subprocess-level verification).
        """
        present_cred = MagicMock()
        present_cred.present = True

        captured_cmds = []

        def fake_subprocess_run(cmd, **kwargs):
            captured_cmds.append(list(cmd))
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=present_cred), \
             patch("src.admin.primitives.lifecycle.mint_nonce"), \
             patch("src.admin.primitives.lifecycle.load_portal_config",
                   return_value={"detection_enabled": True}), \
             patch("src.admin.primitives.lifecycle.subprocess.run",
                   side_effect=fake_subprocess_run), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True), \
             patch("src.admin.primitives.lifecycle.consume_nonce"):
            do_up("claude", secret="test-secret", salt=b"", env_path=None)

        # Find the compose up call (not compose down or other subprocess calls).
        compose_up_cmds = [c for c in captured_cmds if "up" in c and "compose" in c]
        assert compose_up_cmds, f"Expected at least one compose up subprocess call; got: {captured_cmds}"
        compose_cmd = compose_up_cmds[0]
        assert "-f" in compose_cmd, (
            f"With detection_enabled=True, -f must appear in compose command; got: {compose_cmd!r}"
        )
        f_idx = compose_cmd.index("-f")
        assert compose_cmd[f_idx + 1] == "src/detect/docker-compose.detect.yml", (
            f"Expected detect overlay after -f; got: {compose_cmd[f_idx + 1]!r}"
        )

    def test_detection_enabled_false_does_not_include_overlay(self):
        """
        detection_enabled=False (default): do_up passes overlay_files=None (no overlay).
        AC-29-P1-13.
        """
        result, compose_up_calls = self._run_do_up_capture_compose_args(detection_enabled=False)

        assert result["outcome"] == "applied"
        assert len(compose_up_calls) == 1
        _, overlay_files = compose_up_calls[0]
        # None or [] both mean no overlay. The implementation passes None when disabled.
        assert not overlay_files, (
            f"With detection_enabled=False, overlay_files must be None or empty; got: {overlay_files!r}"
        )

    def test_detection_enabled_false_compose_excludes_f_flag(self):
        """
        detection_enabled=False: the subprocess command does NOT include -f detect overlay.
        AC-29-P1-13 (subprocess-level verification).
        """
        present_cred = MagicMock()
        present_cred.present = True

        captured_cmds = []

        def fake_subprocess_run(cmd, **kwargs):
            captured_cmds.append(list(cmd))
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=present_cred), \
             patch("src.admin.primitives.lifecycle.mint_nonce"), \
             patch("src.admin.primitives.lifecycle.load_portal_config",
                   return_value={"detection_enabled": False}), \
             patch("src.admin.primitives.lifecycle.subprocess.run",
                   side_effect=fake_subprocess_run), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True), \
             patch("src.admin.primitives.lifecycle.consume_nonce"):
            do_up("claude", secret="test-secret", salt=b"", env_path=None)

        compose_up_cmds = [c for c in captured_cmds if "up" in c and "compose" in c]
        assert compose_up_cmds, f"Expected compose up subprocess call; got: {captured_cmds}"
        compose_cmd = compose_up_cmds[0]
        detect_overlay = "src/detect/docker-compose.detect.yml"
        assert detect_overlay not in compose_cmd, (
            f"With detection_enabled=False, detection overlay must NOT be in command; "
            f"got: {compose_cmd!r}"
        )

    def test_detection_toggle_does_not_affect_returned_outcome(self):
        """
        The detection toggle only affects which overlay is passed; it does not
        change the outcome. Applied is applied regardless of toggle state.
        Confirms B7: toggle does not affect the egress security outcome.
        """
        # Both enabled and disabled should return outcome=applied when everything succeeds.
        result_on, _ = self._run_do_up_capture_compose_args(detection_enabled=True)
        result_off, _ = self._run_do_up_capture_compose_args(detection_enabled=False)

        assert result_on["outcome"] == "applied"
        assert result_off["outcome"] == "applied"
        assert result_on["http_status"] == result_off["http_status"], (
            "Detection toggle must not change the http_status of a successful up"
        )
