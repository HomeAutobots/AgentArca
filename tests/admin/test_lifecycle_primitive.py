"""
test_lifecycle_primitive.py - Isolation-runnable unit tests for lifecycle primitive.

Covers:
  AC-27-P2-02-ir  Mutual-exclusion with mocked get_running_profiles (IR)
  AC-27-P2-03-ir  Up idempotent with mocked state (IR)
  AC-27-P2-09     Switch fail-closed: down returns exit 0 but profile still running (IR)
  AC-27-P2-10     Gateway health timeout leads to teardown (IR)
  AC-27-P2-11     Switch fail-closed: up gateway timeout, to-profile torn down (IR)
  AC-27-P2-14     Primitive unit: allowlist, subprocess list-args, running-state parser

All tests are isolation-runnable (no Docker stack required).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.primitives.lifecycle import (
    ALLOWED_PROFILES,
    LIFECYCLE_LOCK_PATH,
    LifecycleLockError,
    LifecycleStateError,
    _sanitize,
    do_down,
    do_switch,
    do_up,
    get_running_profiles,
    validate_profile,
    wait_for_gateway_healthy,
)


# ---------------------------------------------------------------------------
# AC-27-P2-14: Profile name allowlist (injection guard)
# ---------------------------------------------------------------------------

class TestProfileAllowlist:
    """AC-27-P2-14: ALLOWED_PROFILES is exactly {copilot, claude, codex}."""

    def test_allowed_profiles_exact_set(self):
        assert ALLOWED_PROFILES == frozenset({"copilot", "claude", "codex"})

    def test_allowed_profiles_is_frozenset(self):
        assert isinstance(ALLOWED_PROFILES, frozenset)

    def test_validate_valid_profiles(self):
        for profile in ("copilot", "claude", "codex"):
            assert validate_profile(profile), f"Expected valid: {profile!r}"

    def test_validate_invalid_profiles(self):
        invalid_names = [
            "COPILOT",
            "Copilot",
            "copilot ",
            " copilot",
            "",
            "evil;rm-rf",
            "../../etc/passwd",
            "codex\nextra",
            "copilot--",
            "gpt4",
            "gemini",
        ]
        for name in invalid_names:
            assert not validate_profile(name), f"Expected invalid: {name!r}"

    def test_no_runtime_expansion(self):
        # ALLOWED_PROFILES must not grow at runtime (frozen).
        with pytest.raises((AttributeError, TypeError)):
            ALLOWED_PROFILES.add("gpt5")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# AC-27-P2-14: Running-state parser with fixture data (both JSONL + legacy array)
# ---------------------------------------------------------------------------

class TestGetRunningProfilesParser:
    """
    AC-27-P2-14: get_running_profiles() parses `docker compose ps --format json` (both
    JSONL and legacy array) against the REAL AgentArca topology. AgentArca is a SINGLE
    compose project ("agentarca"); a live profile is identified by its gateway SERVICE
    (gateway-<profile>) / CONTAINER (<profile>-gateway) in State "running" -- NOT by a
    per-project name. These fixtures use the real `docker compose ps` JSON shape captured
    from a live codex stack (Name=codex-gateway, Service=gateway-codex, State=running).

    REGRESSION GUARD: the prior code+fixtures matched `docker compose ls` per-project Name
    (agentarca-<profile>), which never matched the real single "agentarca" project, so a
    running profile read as empty and mutual exclusion was defeated (R-m BLOCK, 2026-06-24).
    """

    def _mock_compose_ps(self, stdout: str, returncode: int = 0):
        """Patch subprocess.run to return the given `docker compose ps` output."""
        mock_result = MagicMock()
        mock_result.returncode = returncode
        mock_result.stdout = stdout
        mock_result.stderr = ""
        return patch(
            "src.admin.primitives.lifecycle.subprocess.run",
            return_value=mock_result,
        )

    @staticmethod
    def _rec(name: str, service: str, state: str = "running",
             status: str = "Up 2 days", health: str = "") -> str:
        """One `docker compose ps --format json` record (real field shape)."""
        return json.dumps({
            "Name": name, "Service": service, "State": state,
            "Status": status, "Health": health,
        })

    # --- JSONL format (Docker Compose 2.21.0+) ---

    def test_jsonl_single_running_profile(self):
        # Real live codex gateway shape.
        stdout = self._rec("codex-gateway", "gateway-codex", "running",
                           "Up 2 days (healthy)", "healthy") + "\n"
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"codex"}

    def test_jsonl_gateway_and_devcontainer_same_profile(self):
        stdout = (
            self._rec("codex-devcontainer", "devcontainer-codex", "running", "Up 2 days") + "\n"
            + self._rec("codex-gateway", "gateway-codex", "running",
                        "Up 2 days (healthy)", "healthy") + "\n"
        )
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"codex"}

    def test_jsonl_exited_gateway_not_running(self):
        stdout = self._rec("codex-gateway", "gateway-codex", "exited",
                           "Exited (0) 1 minute ago") + "\n"
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == set()

    def test_jsonl_copilot_gateway(self):
        stdout = self._rec("copilot-gateway", "gateway-copilot", "running",
                           "Up 5 minutes (healthy)", "healthy") + "\n"
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"copilot"}

    def test_jsonl_container_name_only_match(self):
        # Service field blank, but the canonical <profile>-gateway container name matches.
        stdout = self._rec("claude-gateway", "", "running", "Up 1 hour") + "\n"
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"claude"}

    def test_jsonl_empty_output(self):
        with self._mock_compose_ps(""):
            assert get_running_profiles() == set()

    def test_jsonl_unrelated_containers_ignored(self):
        stdout = (
            self._rec("some-other-container", "web", "running", "Up 3 days") + "\n"
            + self._rec("claude-gateway", "gateway-claude", "running",
                        "Up 2 hours (healthy)", "healthy") + "\n"
        )
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"claude"}

    def test_jsonl_only_running_profile_among_exited_siblings(self):
        stdout = (
            self._rec("copilot-gateway", "gateway-copilot", "exited", "Exited (0)") + "\n"
            + self._rec("claude-gateway", "gateway-claude", "running",
                        "Up 2 hours (healthy)", "healthy") + "\n"
        )
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"claude"}

    # --- Legacy array format (pre-2.21.0) ---

    def test_legacy_array_single_running(self):
        stdout = ("[\n  "
                  + self._rec("codex-gateway", "gateway-codex", "running",
                              "Up 2 days (healthy)", "healthy")
                  + "\n]\n")
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"codex"}

    def test_legacy_array_multiple(self):
        stdout = ("[\n  "
                  + self._rec("copilot-gateway", "gateway-copilot", "exited", "Exited (0)") + ",\n  "
                  + self._rec("claude-gateway", "gateway-claude", "running", "Up 2 hours")
                  + "\n]\n")
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"claude"}

    def test_legacy_array_empty(self):
        with self._mock_compose_ps("[]\n"):
            assert get_running_profiles() == set()

    # --- Error handling ---

    def test_compose_ps_nonzero_raises(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "docker: command not found"
        with patch("src.admin.primitives.lifecycle.subprocess.run", return_value=mock_result):
            with pytest.raises(LifecycleStateError):
                get_running_profiles()

    def test_malformed_json_lines_skipped(self):
        stdout = ("not-json-at-all\n"
                  + self._rec("claude-gateway", "gateway-claude", "running", "Up 2 hours") + "\n")
        with self._mock_compose_ps(stdout):
            assert get_running_profiles() == {"claude"}


# ---------------------------------------------------------------------------
# AC-27-P2-14: subprocess list-args form (not shell string)
# ---------------------------------------------------------------------------

class TestSubprocessListArgs:
    """
    AC-27-P2-14: compose_up, compose_down, and get_running_profiles call
    subprocess.run with a list (not a shell string). shell=False is the default.
    """

    def test_compose_up_uses_list_args(self):
        """compose_up() must call subprocess.run with a list, not a string."""
        from src.admin.primitives.lifecycle import compose_up
        captured_calls = []

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        def capturing_run(cmd, **kwargs):
            captured_calls.append(cmd)
            return mock_result

        with patch("src.admin.primitives.lifecycle.subprocess.run", side_effect=capturing_run):
            compose_up("claude")

        assert len(captured_calls) == 1
        cmd = captured_calls[0]
        assert isinstance(cmd, list), f"subprocess.run must receive a list, got {type(cmd)}"
        assert "docker" in cmd
        assert "compose" in cmd
        assert "--profile" in cmd
        assert "claude" in cmd
        assert "up" in cmd
        assert "-d" in cmd
        # Verify "claude" is only at the expected position (after --profile).
        idx = cmd.index("--profile")
        assert cmd[idx + 1] == "claude"

    def test_compose_down_uses_list_args(self):
        """compose_down() must call subprocess.run with a list, not a string."""
        from src.admin.primitives.lifecycle import compose_down
        captured_calls = []

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        def capturing_run(cmd, **kwargs):
            captured_calls.append(cmd)
            return mock_result

        with patch("src.admin.primitives.lifecycle.subprocess.run", side_effect=capturing_run):
            compose_down("copilot")

        assert len(captured_calls) == 1
        cmd = captured_calls[0]
        assert isinstance(cmd, list)
        assert "docker" in cmd
        assert "compose" in cmd
        assert "--profile" in cmd
        assert "copilot" in cmd
        assert "down" in cmd

    def test_no_shell_equals_true_in_lifecycle(self):
        """
        Assertion: no subprocess call in lifecycle.py passes shell=True.
        This is checked by reading the source and by the build-gate assertion 12.
        Comments include both # lines and docstring content; we detect both.
        """
        lifecycle_src = (REPO_ROOT / "src" / "admin" / "primitives" / "lifecycle.py").read_text()
        # Exclude comment lines (# ...) and docstring lines (inside triple-quote strings).
        # We do this by checking that the line contains shell=True as Python code,
        # not inside a string literal. The build gate grep is more authoritative;
        # this test checks the same property differently.
        bad_lines = [
            line for line in lifecycle_src.splitlines()
            if "shell=True" in line
            and not line.strip().startswith("#")
            and "shell=True" not in line.split("#")[0].strip().lstrip('"\'').lstrip()  # not in a string comment
            # A line is truly suspicious only if shell=True appears as a keyword argument
            # in a function call position (i.e., not inside a string or comment).
            and line.strip().startswith("shell=True")  # bare keyword-only form
        ]
        # More robust: use a simple import check via the build-gate assertion logic.
        # subprocess.run calls with shell=True would appear as: subprocess.run(..., shell=True)
        # or: run(..., shell=True). Check for the keyword argument form, not quoted form.
        import ast
        try:
            tree = ast.parse(lifecycle_src)
            found = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            found.append(f"line {node.lineno}")
            assert not found, f"Found shell=True in subprocess calls in lifecycle.py: {found}"
        except SyntaxError as exc:
            pytest.fail(f"lifecycle.py has a syntax error: {exc}")

    def test_no_docker_exec_in_lifecycle(self):
        """
        Assertion: lifecycle.py does not call docker exec.
        This is the build-gate assertion 11. We use AST to find actual subprocess
        calls containing 'docker exec' rather than string matching in docstrings.
        """
        lifecycle_src = (REPO_ROOT / "src" / "admin" / "primitives" / "lifecycle.py").read_text()
        import ast
        try:
            tree = ast.parse(lifecycle_src)
            found_exec = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Look for subprocess.run(["docker", "exec", ...]) patterns.
                    for arg in ast.walk(node):
                        if isinstance(arg, ast.List):
                            elts = [e.s if isinstance(e, ast.Constant) and isinstance(e.s, str)
                                    else None for e in arg.elts]
                            if "docker" in elts and "exec" in elts:
                                idx_docker = elts.index("docker")
                                idx_exec = elts.index("exec")
                                if idx_exec == idx_docker + 1:
                                    found_exec.append(f"line {node.lineno}")
        except SyntaxError as exc:
            pytest.fail(f"lifecycle.py has a syntax error: {exc}")
        assert not found_exec, (
            f"Found docker exec in subprocess call args in lifecycle.py: {found_exec}"
        )


# ---------------------------------------------------------------------------
# AC-27-P2-02-ir: Mutual-exclusion with mocked get_running_profiles
# ---------------------------------------------------------------------------

class TestMutexMocked:
    """AC-27-P2-02-ir: mutual exclusion with mocked running state."""

    def test_up_refused_when_different_profile_running(self):
        """
        When get_running_profiles returns {"copilot"} and the request is for "claude",
        do_up returns outcome=rejected_mutex, http_status=409, running_profile="copilot".
        No compose_up subprocess should be called.
        """
        compose_up_calls = []
        mock_up_result = MagicMock()
        mock_up_result.returncode = 0

        def fake_compose_up(profile, timeout=300):
            compose_up_calls.append(profile)
            return mock_up_result

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value={"copilot"}), \
             patch("src.admin.primitives.lifecycle.compose_up", side_effect=fake_compose_up):
            result = do_up("claude", secret="test-secret")

        assert result["outcome"] == "rejected_mutex"
        assert result["http_status"] == 409
        assert result["running_profile"] == "copilot"
        assert len(compose_up_calls) == 0, "compose_up must not be called on mutex refusal"

    def test_up_proceeds_when_no_profile_running(self):
        """
        When get_running_profiles returns set() and compose_up + health both succeed,
        do_up returns outcome=applied, http_status=201.
        """
        mock_up_result = MagicMock()
        mock_up_result.returncode = 0

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.compose_up", return_value=mock_up_result), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True):
            result = do_up("claude", secret="test-secret")

        assert result["outcome"] == "applied"
        assert result["http_status"] == 201

    def test_up_idempotent_when_target_already_running(self):
        """
        When get_running_profiles returns {"claude"} and the request is for "claude",
        do_up returns outcome=idempotent, http_status=200.
        No compose_up should be called.
        """
        compose_up_calls = []

        def fake_compose_up(profile, timeout=300):
            compose_up_calls.append(profile)
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value={"claude"}), \
             patch("src.admin.primitives.lifecycle.compose_up", side_effect=fake_compose_up):
            result = do_up("claude", secret="test-secret")

        assert result["outcome"] == "idempotent"
        assert result["http_status"] == 200
        assert len(compose_up_calls) == 0, "compose_up must not be called on idempotent"


# ---------------------------------------------------------------------------
# AC-27-P2-03-ir: Up idempotent
# ---------------------------------------------------------------------------

class TestUpIdempotentMocked:
    """AC-27-P2-03-ir (also part of AC-27-P2-02-ir)."""

    def test_up_idempotent_returns_200(self):
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value={"codex"}):
            result = do_up("codex", secret="")
        assert result["outcome"] == "idempotent"
        assert result["http_status"] == 200
        assert result.get("detail") == "idempotent"


# ---------------------------------------------------------------------------
# AC-27-P2-09: Switch fail-closed on down failure
# ---------------------------------------------------------------------------

class TestSwitchDownFailClosed:
    """
    AC-27-P2-09: if compose down returns exit 0 but get_running_profiles still
    shows the from-profile running, do_switch must NOT call compose_up for the
    to-profile, and must return outcome=down_did_not_stop, http_status=500.
    """

    def test_switch_fail_closed_down_did_not_stop(self):
        """
        Simulate: compose_down returns exit 0, but the from-profile is still
        running on the re-check (profile never actually stopped).
        to-profile compose_up must NOT be called.
        """
        compose_up_calls = []
        mock_down_result = MagicMock()
        mock_down_result.returncode = 0
        mock_down_result.stderr = ""

        def fake_compose_up(profile, timeout=300):
            compose_up_calls.append(profile)
            return MagicMock(returncode=0)

        # get_running_profiles is called twice under the lock:
        # 1. Initial check: {"copilot"} (from-profile is running, no others).
        # 2. Verification after down: {"copilot"} (profile still running, simulating failure).
        get_running_side_effects = [{"copilot"}, {"copilot"}]
        get_running_call_count = [0]

        def fake_get_running():
            idx = get_running_call_count[0]
            get_running_call_count[0] += 1
            return get_running_side_effects[idx] if idx < len(get_running_side_effects) else set()

        with patch("src.admin.primitives.lifecycle.get_running_profiles", side_effect=fake_get_running), \
             patch("src.admin.primitives.lifecycle.compose_down", return_value=mock_down_result), \
             patch("src.admin.primitives.lifecycle.compose_up", side_effect=fake_compose_up):
            result = do_switch("copilot", "claude", secret="test-secret")

        assert result["outcome"] == "down_did_not_stop", (
            f"Expected down_did_not_stop, got {result['outcome']!r}"
        )
        assert result["http_status"] == 500
        assert len(compose_up_calls) == 0, (
            "compose_up for to-profile must NOT be called when down verification fails"
        )

    def test_switch_proceeds_when_down_succeeds(self):
        """
        Simulate: compose_down returns exit 0 and re-check shows from-profile is gone.
        compose_up for to-profile is then called.
        """
        mock_down_result = MagicMock()
        mock_down_result.returncode = 0
        mock_down_result.stderr = ""

        mock_up_result = MagicMock()
        mock_up_result.returncode = 0
        mock_up_result.stderr = ""

        # get_running_profiles calls: initial (copilot running), after down (empty), health check won't call it.
        side_effects = [{"copilot"}, set()]
        call_count = [0]

        def fake_get_running():
            idx = call_count[0]
            call_count[0] += 1
            return side_effects[idx] if idx < len(side_effects) else set()

        with patch("src.admin.primitives.lifecycle.get_running_profiles", side_effect=fake_get_running), \
             patch("src.admin.primitives.lifecycle.compose_down", return_value=mock_down_result), \
             patch("src.admin.primitives.lifecycle.compose_up", return_value=mock_up_result), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True):
            result = do_switch("copilot", "claude", secret="test-secret")

        assert result["outcome"] == "applied"
        assert result["http_status"] == 200


# ---------------------------------------------------------------------------
# AC-27-P2-10: Gateway health timeout leads to teardown
# ---------------------------------------------------------------------------

class TestGatewayHealthTimeout:
    """
    AC-27-P2-10: if wait_for_gateway_healthy returns False, the profile is
    torn down via compose_down, and do_up returns outcome=gateway_timeout, http_status=503.
    """

    def test_up_tears_down_on_health_timeout(self):
        compose_down_calls = []
        mock_up_result = MagicMock()
        mock_up_result.returncode = 0

        def fake_compose_down(profile, timeout=120):
            compose_down_calls.append(profile)
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.compose_up", return_value=mock_up_result), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=False), \
             patch("src.admin.primitives.lifecycle.compose_down", side_effect=fake_compose_down):
            result = do_up("claude", secret="test-secret")

        assert result["outcome"] == "gateway_timeout"
        assert result["http_status"] == 503
        assert "gateway_health_timeout" in result["detail"]
        assert "torn down" in result["detail"]
        assert len(compose_down_calls) == 1, (
            f"compose_down must be called exactly once for teardown; calls: {compose_down_calls}"
        )
        assert compose_down_calls[0] == "claude"

    def test_up_no_teardown_on_healthy(self):
        """On health success, compose_down must NOT be called (no spurious teardown)."""
        compose_down_calls = []

        def fake_compose_down(profile, timeout=120):
            compose_down_calls.append(profile)
            return MagicMock(returncode=0)

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.compose_up", return_value=MagicMock(returncode=0)), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True), \
             patch("src.admin.primitives.lifecycle.compose_down", side_effect=fake_compose_down):
            result = do_up("copilot", secret="test-secret")

        assert result["outcome"] == "applied"
        assert len(compose_down_calls) == 0


# ---------------------------------------------------------------------------
# AC-27-P2-11: Switch fail-closed on up/health failure
# ---------------------------------------------------------------------------

class TestSwitchUpHealthFailClosed:
    """
    AC-27-P2-11: if the gateway health timeout fires for the to-profile during
    switch, the to-profile is torn down and do_switch returns outcome=gateway_timeout.
    Neither profile is left up after this.
    """

    def test_switch_tears_down_to_profile_on_health_timeout(self):
        compose_down_calls = []

        mock_down_result = MagicMock()
        mock_down_result.returncode = 0
        mock_down_result.stderr = ""

        mock_up_result = MagicMock()
        mock_up_result.returncode = 0
        mock_up_result.stderr = ""

        def fake_compose_down(profile, timeout=120):
            compose_down_calls.append(profile)
            return MagicMock(returncode=0)

        # get_running_profiles: initial (copilot running), after down (empty).
        side_effects = [{"copilot"}, set()]
        call_count = [0]

        def fake_get_running():
            idx = call_count[0]
            call_count[0] += 1
            return side_effects[idx] if idx < len(side_effects) else set()

        with patch("src.admin.primitives.lifecycle.get_running_profiles", side_effect=fake_get_running), \
             patch("src.admin.primitives.lifecycle.compose_down", side_effect=fake_compose_down), \
             patch("src.admin.primitives.lifecycle.compose_up", return_value=mock_up_result), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=False):
            result = do_switch("copilot", "claude", secret="test-secret")

        assert result["outcome"] == "gateway_timeout"
        assert result["http_status"] == 503
        # compose_down must be called for: (1) bring down copilot, (2) teardown claude.
        # The first call is copilot down; the second is claude teardown.
        assert len(compose_down_calls) == 2, (
            f"Expected 2 compose_down calls (down copilot + teardown claude), got: {compose_down_calls}"
        )
        assert "copilot" in compose_down_calls
        assert "claude" in compose_down_calls


# ---------------------------------------------------------------------------
# AC-27-P2-10 / AC-27-P2-11: lock released even on exception
# ---------------------------------------------------------------------------

class TestLockRelease:
    """
    The lifecycle_lock context manager must release the lock on any exception,
    including LifecycleLockError and arbitrary RuntimeErrors.
    """

    def test_lock_released_on_exception_in_do_up(self):
        """
        If get_running_profiles raises, do_up catches it and returns an error dict.
        The lock must not remain held (subsequent call to do_up must succeed).
        """
        call_count = [0]

        def fake_get_running():
            call_count[0] += 1
            if call_count[0] == 1:
                raise LifecycleStateError("simulated compose ls failure")
            return set()

        mock_up_result = MagicMock()
        mock_up_result.returncode = 0

        with patch("src.admin.primitives.lifecycle.get_running_profiles", side_effect=fake_get_running), \
             patch("src.admin.primitives.lifecycle.compose_up", return_value=mock_up_result), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True):
            # First call: raises internally, should return error dict.
            result1 = do_up("claude", secret="")
            assert result1["outcome"] == "error"
            # Second call: lock should be available (not permanently held).
            result2 = do_up("claude", secret="")
            # Second call may succeed or fail depending on mocks; the important
            # thing is it does not hang (lock is not permanently held).
            assert result2["http_status"] in (201, 503, 500)


# ---------------------------------------------------------------------------
# AC-27-P2-06b: _sanitize removes admin secret from detail
# ---------------------------------------------------------------------------

class TestSanitize:
    """AC-27-P2-06b: _sanitize replaces the admin secret with a safe string."""

    def test_sanitize_removes_secret(self):
        result = _sanitize("some text with mysecret in it", "mysecret")
        assert "mysecret" not in result
        assert "[sanitized" in result

    def test_sanitize_passthrough_when_no_secret(self):
        result = _sanitize("some text", "")
        assert result == "some text"

    def test_sanitize_passthrough_when_secret_absent(self):
        result = _sanitize("some text about copilot", "mysecret")
        assert result == "some text about copilot"

    def test_sanitize_none_passthrough(self):
        result = _sanitize(None, "mysecret")
        assert result is None

    def test_sanitize_non_string_passthrough(self):
        result = _sanitize(42, "mysecret")
        assert result == 42


# ---------------------------------------------------------------------------
# AC-27-P2-12: lifecycle.lock path assertion
# ---------------------------------------------------------------------------

class TestLifecycleLockPath:
    """AC-27-P2-12: the lifecycle lock file is on the host filesystem."""

    def test_lock_path_is_in_home_dir(self):
        lock_path = LIFECYCLE_LOCK_PATH
        home = Path("~").expanduser()
        # The lock must be under the home directory (host filesystem).
        assert str(lock_path).startswith(str(home)), (
            f"LIFECYCLE_LOCK_PATH {lock_path!r} is not under the home directory {home!r}"
        )

    def test_lock_path_not_in_docker_volume(self):
        lock_path = str(LIFECYCLE_LOCK_PATH)
        # Must not be under /var/lib/docker or any known volume path.
        forbidden_prefixes = ["/var/lib/docker", "/proc", "/sys", "/dev"]
        for prefix in forbidden_prefixes:
            assert not lock_path.startswith(prefix), (
                f"LIFECYCLE_LOCK_PATH {lock_path!r} is under a forbidden path {prefix!r}"
            )

    def test_lock_path_not_under_repo_src(self):
        lock_path = LIFECYCLE_LOCK_PATH
        repo_src = REPO_ROOT / "src"
        try:
            lock_path.relative_to(repo_src)
            pytest.fail(
                f"LIFECYCLE_LOCK_PATH {lock_path!r} is under the repo src/ directory; "
                "it must be on the host filesystem outside the repo."
            )
        except ValueError:
            pass  # Expected: not a sub-path.
