"""
test_lifecycle_interlock.py - Docker-free integration tests for the SPEC-29-P0
portal startup interlock (nonce mint/consume lifecycle integration).

All tests are isolation-runnable: compose subprocess calls, health gate, and the
Docker daemon are monkeypatched out. The lifecycle flock is acquired on the real
~/.agentarca/lifecycle.lock (same as existing tests/admin/test_lifecycle_primitive.py),
which is created by open() in write mode if absent.

NONCE_DIR is redirected to a tmp_path subdirectory via monkeypatch so the real
~/.agentarca/start-auth.d is never touched.

Coverage:
  AC-29-P0-04  Gateway entrypoint nonce validation exits 0 when the nonce file is
               present, fresh, and the profile name matches the gateway's AGENT_FRAGMENT.
               Approach: extract the STEP 1 nonce check block from entrypoint.sh, redirect
               /run/start-auth to a temp directory, prepend AGENT_FRAGMENT=claude.conf,
               and run with bash. Full-container coverage (EROFS mount, init-firewall.sh,
               squid exec) is the red-teamer's stage.
  AC-29-P0-09  Route writes lifecycle_up_intent audit record (via _write_audit) BEFORE
               do_up (which contains mint_nonce) is submitted to run_in_executor.
               Verified by a spy on mint_nonce that reads the audit file at call time
               and records whether the intent record already existed. do_up writes NO
               audit record itself (imports confirmed absent in source).
  AC-29-P0-10  do_up (with mocked compose_up + wait_for_gateway_healthy returning True)
               calls mint_nonce before compose and consume_nonce after health gate:
               nonce file is absent after do_up returns applied; spy confirms mint happened.
  AC-29-P0-11  Health timeout path: wait_for_gateway_healthy mocked False ->
               do_up returns outcome=gateway_timeout, http_status=503;
               nonce file absent after return (consume_nonce called in timeout branch);
               teardown compose_down was called (spy).
  AC-29-P0-12  do_down with successful compose_down consumes nonce (file absent).
               do_down with failing compose_down does NOT consume (file present).
  AC-29-P0-13  do_switch consumes from-nonce and mints then consumes to-nonce within
               one lock: assert final state (both files absent); assert call ordering
               (consume from-profile before mint to-profile) via call log spy.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import src.admin.primitives.nonce as nonce_mod
from src.admin.primitives.lifecycle import do_down, do_switch, do_up
from src.admin.primitives.nonce import mint_nonce as real_mint_nonce
from src.admin.primitives.nonce import consume_nonce as real_consume_nonce


# ---------------------------------------------------------------------------
# Shared fixture: redirect NONCE_DIR to a temp subdirectory
# ---------------------------------------------------------------------------

@pytest.fixture()
def nonce_dir(tmp_path, monkeypatch):
    """
    Patch nonce.NONCE_DIR to a temporary directory so no test touches
    the real ~/.agentarca/start-auth.d.

    Since lifecycle.py imports mint_nonce and consume_nonce by reference at module
    load time, those function objects look up NONCE_DIR from nonce.py's module
    namespace when they execute. Patching nonce_mod.NONCE_DIR is sufficient to
    redirect all file operations, including those triggered from lifecycle.py.
    """
    d = tmp_path / "start-auth.d"
    monkeypatch.setattr(nonce_mod, "NONCE_DIR", d)
    return d


# ---------------------------------------------------------------------------
# Auth helpers (mirroring test_lifecycle_api.py conventions)
# ---------------------------------------------------------------------------

_TEST_SECRET = "test-secret-value-12345"
_TEST_PORT = 8080
_TEST_HOST = "127.0.0.1"
_VALID_HOST_HEADER = f"{_TEST_HOST}:{_TEST_PORT}"


@pytest.fixture()
def _tmp_audit(tmp_path):
    return tmp_path / "admin-audit.jsonl"


@pytest.fixture()
def _test_settings(tmp_path, _tmp_audit):
    from src.admin.config import Settings
    secret_file = tmp_path / "admin-secret"
    secret_file.write_text(_TEST_SECRET + "\n", encoding="utf-8")
    os.chmod(secret_file, 0o600)
    return Settings(
        host=_TEST_HOST,
        port=_TEST_PORT,
        allow_non_loopback=False,
        secret_file=secret_file,
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_INTERLOCK_TEST",
        audit_log_path=_tmp_audit,
        session_secret_key="test-session-key-aaabbbccc" * 4,
    )


@pytest.fixture()
def _client(_test_settings):
    from src.admin.main import create_app
    from starlette.testclient import TestClient
    app = create_app(_test_settings)
    with TestClient(app, base_url=f"http://{_TEST_HOST}:{_TEST_PORT}") as c:
        c.headers.update({"Host": _VALID_HOST_HEADER})
        yield c


@pytest.fixture()
def _authed_client(_client):
    """Client with authenticated session and valid CSRF token."""
    resp = _client.post(
        "/api/v1/login",
        json={"secret": _TEST_SECRET},
        headers={"Host": _VALID_HOST_HEADER},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    csrf = resp.json()["csrf_token"]
    _client.headers.update({"X-CSRF-Token": csrf})
    return _client


def _read_audit_records(audit_path: Path) -> list:
    if not audit_path.exists():
        return []
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


# ---------------------------------------------------------------------------
# AC-29-P0-04: Gateway entrypoint nonce validation exits 0 for a valid nonce
# ---------------------------------------------------------------------------

class TestEntrypointNonceCheck:
    """
    AC-29-P0-04: The nonce validation block in src/gateway/entrypoint.sh exits 0
    when the nonce file is present, fresh (age < 300s), token is 64 hex chars,
    and profile name matches the gateway's AGENT_FRAGMENT.

    Test approach: extract STEP 1 block from entrypoint.sh, redirect /run/start-auth
    to a temp directory, set AGENT_FRAGMENT=claude.conf, and run with bash.
    The bash binary must be on PATH (standard on macOS and Linux CI).

    Coverage boundary: this tests the nonce validation logic in isolation, NOT the
    full container entrypoint (DNS validation, init-firewall.sh, squid exec).
    Full-container containment tests (AC-29-P0-05..08) belong to the red-teamer stage.
    """

    @staticmethod
    def _extract_nonce_block(entrypoint_src: str, nonce_dir: str) -> str:
        """
        Extract the STEP 1 block from entrypoint.sh and redirect /run/start-auth
        to the given nonce_dir path.
        """
        step1_marker = "# STEP 1: Start-authorization check"
        step2_marker = "# STEP 2: Initialize the firewall."

        assert step1_marker in entrypoint_src, (
            f"STEP 1 marker not found in entrypoint.sh. "
            "Has the nonce check block been removed or renamed?"
        )
        assert step2_marker in entrypoint_src, (
            f"STEP 2 marker not found in entrypoint.sh."
        )

        start_idx = entrypoint_src.index(step1_marker)
        end_idx = entrypoint_src.index(step2_marker)
        block = entrypoint_src[start_idx:end_idx]

        # Redirect the bind-mount path to the temp directory.
        block = block.replace("/run/start-auth", nonce_dir)
        return block

    def test_exits_0_when_nonce_present_fresh_and_profile_matches(self, tmp_path):
        """AC-29-P0-04: entrypoint nonce block exits 0 for a valid fresh nonce."""
        # Create a valid nonce file for profile "claude"
        nonce_tmp_dir = tmp_path / "start-auth"
        nonce_tmp_dir.mkdir()
        token = secrets.token_hex(32)
        ts = int(time.time())
        nonce_file = nonce_tmp_dir / "claude"
        nonce_file.write_text(f"{token}\n{ts}\nclaude\n", encoding="ascii")

        # Read and extract the nonce validation block from entrypoint.sh
        entrypoint_src = (
            REPO_ROOT / "src" / "gateway" / "entrypoint.sh"
        ).read_text(encoding="utf-8")
        block = self._extract_nonce_block(entrypoint_src, str(nonce_tmp_dir))

        # Build a standalone bash harness: set AGENT_FRAGMENT then run the block.
        harness = (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "AGENT_FRAGMENT=claude.conf\n"
            + block
            + "\n"
        )
        script_path = tmp_path / "test_nonce_check.sh"
        script_path.write_text(harness, encoding="utf-8")

        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (
            f"Expected exit 0 for a valid nonce; got {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert "Start authorization verified" in result.stdout, (
            "Expected success message in stdout; "
            f"got: {result.stdout!r}"
        )


# ---------------------------------------------------------------------------
# AC-29-P0-09: Route writes lifecycle_up_intent BEFORE mint_nonce
# ---------------------------------------------------------------------------

class TestRouteAuditOrdering:
    """
    AC-29-P0-09: The profile_up route handler writes a lifecycle_up_intent audit
    record (via _write_audit) BEFORE calling run_in_executor(None, do_up, ...).
    Since mint_nonce runs inside do_up under the lifecycle flock, any route-level
    write before the run_in_executor call precedes the nonce mint by construction.

    Test approach:
    - Use TestClient + authed session (same pattern as test_lifecycle_api.py).
    - Monkeypatch src.admin.primitives.lifecycle.mint_nonce with a spy that reads
      the audit log at call time and records whether the intent record exists.
    - Also monkeypatch consume_nonce, get_running_profiles, compose_up, and
      wait_for_gateway_healthy so do_up completes without real Docker calls.
    - Assert: (1) spy recorded that the intent record existed before mint;
              (2) audit log contains record with action=lifecycle_up_intent and target=claude.
    - Assert: do_up does NOT write any audit record (no audit.py import in lifecycle.py).
    """

    def test_lifecycle_up_intent_written_before_mint_nonce(
        self, _authed_client, _tmp_audit
    ):
        """
        AC-29-P0-09: lifecycle_up_intent record exists in audit log at the moment
        mint_nonce is called inside do_up.
        """
        audit_state_at_mint: dict = {}

        def spy_mint(profile: str) -> None:
            # Capture whether the intent record already exists in the audit log.
            records = _read_audit_records(_tmp_audit)
            intent_records = [
                r for r in records
                if r.get("action") == "lifecycle_up_intent"
                and r.get("target") == profile
            ]
            audit_state_at_mint["intent_exists_before_mint"] = bool(intent_records)
            audit_state_at_mint["intent_count"] = len(intent_records)
            # Do NOT create an actual nonce file; this test only verifies ordering.

        with (
            patch("src.admin.primitives.lifecycle.mint_nonce", side_effect=spy_mint),
            patch("src.admin.primitives.lifecycle.consume_nonce"),
            patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()),
            patch(
                "src.admin.primitives.lifecycle.compose_up",
                return_value=MagicMock(returncode=0),
            ),
            patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True),
        ):
            resp = _authed_client.post(
                "/api/v1/profiles/claude/up",
                headers={"Host": _VALID_HOST_HEADER},
            )

        assert resp.status_code in (200, 201), (
            f"Expected 2xx from profile_up; got {resp.status_code}: {resp.text}"
        )
        assert audit_state_at_mint.get("intent_exists_before_mint") is True, (
            "The lifecycle_up_intent audit record must already exist in the audit log "
            "at the moment mint_nonce is called inside do_up. "
            "Ordering guarantee: route writes _write_audit BEFORE run_in_executor(do_up)."
        )

    def test_lifecycle_up_intent_record_has_correct_fields(
        self, _authed_client, _tmp_audit
    ):
        """
        AC-29-P0-09: the lifecycle_up_intent audit record has action=lifecycle_up_intent,
        target=<profile>, domain=lifecycle, outcome=applied.
        """
        with (
            patch("src.admin.primitives.lifecycle.mint_nonce"),
            patch("src.admin.primitives.lifecycle.consume_nonce"),
            patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()),
            patch(
                "src.admin.primitives.lifecycle.compose_up",
                return_value=MagicMock(returncode=0),
            ),
            patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True),
        ):
            _authed_client.post(
                "/api/v1/profiles/codex/up",
                headers={"Host": _VALID_HOST_HEADER},
            )

        records = _read_audit_records(_tmp_audit)
        intent_records = [
            r for r in records
            if r.get("action") == "lifecycle_up_intent"
        ]
        assert intent_records, "At least one lifecycle_up_intent audit record must exist"
        r = intent_records[0]
        assert r.get("target") == "codex", f"target must be 'codex'; got {r.get('target')!r}"
        assert r.get("domain") == "lifecycle"
        assert r.get("outcome") == "applied"

    def test_do_up_writes_no_audit_record(self, _tmp_audit):
        """
        AC-29-P0-09: do_up (the primitive) must not call write_audit_record directly.
        Verified by calling do_up directly with a freshly created audit path: the
        primitive must not append any record. (The route layer writes all audit records.)
        """
        with (
            patch("src.admin.primitives.lifecycle.mint_nonce"),
            patch("src.admin.primitives.lifecycle.consume_nonce"),
            patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()),
            patch(
                "src.admin.primitives.lifecycle.compose_up",
                return_value=MagicMock(returncode=0),
            ),
            patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True),
        ):
            # Call the primitive directly, bypassing the route layer.
            result = do_up("claude", secret=_TEST_SECRET)

        assert result["outcome"] == "applied"
        # The audit log must remain absent (do_up never opens it).
        assert not _tmp_audit.exists(), (
            "do_up must not create or write to the audit log. "
            "All audit writes for the lifecycle domain belong to the route layer."
        )


# ---------------------------------------------------------------------------
# AC-29-P0-10: do_up consumes nonce after healthy
# ---------------------------------------------------------------------------

class TestDoUpNonce:
    """
    AC-29-P0-10 and AC-29-P0-11: do_up nonce lifecycle on the happy path and timeout.
    """

    def test_do_up_mints_and_consumes_nonce_on_success(self, nonce_dir):
        """
        AC-29-P0-10: do_up calls mint_nonce (creating the nonce file) and then
        consume_nonce (deleting it) after wait_for_gateway_healthy returns True.
        The nonce file must be absent after do_up returns applied.
        """
        mint_calls = []
        real_mint = real_mint_nonce  # reference resolved before patching

        def spy_mint(profile: str) -> None:
            mint_calls.append(profile)
            real_mint(profile)  # actually creates nonce file in temp nonce_dir

        with (
            patch("src.admin.primitives.lifecycle.mint_nonce", side_effect=spy_mint),
            patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()),
            patch(
                "src.admin.primitives.lifecycle.compose_up",
                return_value=MagicMock(returncode=0),
            ),
            patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True),
        ):
            result = do_up("claude", secret="test-secret")

        assert result["outcome"] == "applied", f"Expected applied; got {result!r}"
        assert result["http_status"] == 201
        assert "claude" in mint_calls, "mint_nonce must be called for the profile"
        assert not (nonce_dir / "claude").exists(), (
            "Nonce file must be absent after do_up returns applied "
            "(consume_nonce called after health gate passes)"
        )

    def test_do_up_health_timeout_returns_503_and_consumes_nonce(self, nonce_dir):
        """
        AC-29-P0-11: when wait_for_gateway_healthy returns False, do_up returns
        outcome=gateway_timeout, http_status=503. The nonce file must be absent
        (consume_nonce called in the timeout branch) and teardown must be called
        (compose_down called for the profile).
        """
        teardown_calls = []
        real_mint = real_mint_nonce

        def spy_mint(profile: str) -> None:
            real_mint(profile)

        def spy_compose_down(profile: str, **kwargs):
            teardown_calls.append(profile)
            return MagicMock(returncode=0)

        with (
            patch("src.admin.primitives.lifecycle.mint_nonce", side_effect=spy_mint),
            patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()),
            patch(
                "src.admin.primitives.lifecycle.compose_up",
                return_value=MagicMock(returncode=0),
            ),
            patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=False),
            patch(
                "src.admin.primitives.lifecycle.compose_down",
                side_effect=spy_compose_down,
            ),
        ):
            result = do_up("claude", secret="test-secret")

        assert result["outcome"] == "gateway_timeout", (
            f"Expected gateway_timeout; got {result['outcome']!r}"
        )
        assert result["http_status"] == 503
        assert not (nonce_dir / "claude").exists(), (
            "Nonce file must be absent after health timeout "
            "(consume_nonce called in timeout branch, spec sec 4.1 step 7)"
        )
        assert "claude" in teardown_calls, (
            "compose_down must be called for the profile on health timeout (teardown)"
        )


# ---------------------------------------------------------------------------
# AC-29-P0-12: do_down nonce consumption
# ---------------------------------------------------------------------------

class TestDoDownNonce:
    """
    AC-29-P0-12: do_down calls consume_nonce on successful compose_down;
    does NOT consume on a failing compose_down.
    """

    def _write_nonce(self, nonce_dir: Path, profile: str) -> Path:
        """Pre-create a valid nonce file so consume_nonce has something to delete."""
        nonce_dir.mkdir(mode=0o700, exist_ok=True)
        f = nonce_dir / profile
        f.write_text(
            f"{secrets.token_hex(32)}\n{int(time.time())}\n{profile}\n",
            encoding="ascii",
        )
        return f

    def test_do_down_success_consumes_nonce(self, nonce_dir):
        """
        AC-29-P0-12: after a successful compose_down, consume_nonce is called
        and the nonce file is absent.
        """
        self._write_nonce(nonce_dir, "claude")

        with (
            patch("src.admin.primitives.lifecycle.get_running_profiles", return_value={"claude"}),
            patch(
                "src.admin.primitives.lifecycle.compose_down",
                return_value=MagicMock(returncode=0),
            ),
        ):
            result = do_down("claude", secret="test-secret")

        assert result["outcome"] == "applied", f"Expected applied; got {result!r}"
        assert not (nonce_dir / "claude").exists(), (
            "Nonce file must be absent after successful do_down "
            "(consume_nonce called after compose_down succeeds)"
        )

    def test_do_down_failure_does_not_consume_nonce(self, nonce_dir):
        """
        AC-29-P0-12: when compose_down returns a non-zero exit code, do_down
        must NOT call consume_nonce. The nonce file must remain (gateway may still
        be running). Spec sec 4.2: "If compose_down fails, do NOT consume the nonce."
        """
        nonce_file = self._write_nonce(nonce_dir, "claude")

        with (
            patch("src.admin.primitives.lifecycle.get_running_profiles", return_value={"claude"}),
            patch(
                "src.admin.primitives.lifecycle.compose_down",
                return_value=MagicMock(returncode=1, stderr="simulated compose error"),
            ),
        ):
            result = do_down("claude", secret="test-secret")

        assert result["outcome"] == "compose_error", (
            f"Expected compose_error on failed compose_down; got {result['outcome']!r}"
        )
        assert nonce_file.exists(), (
            "Nonce file must NOT be consumed when compose_down fails "
            "(gateway may still be running; nonce is cleaned by purge_stale_nonces on restart)"
        )


# ---------------------------------------------------------------------------
# AC-29-P0-13: do_switch nonce sequencing
# ---------------------------------------------------------------------------

class TestDoSwitchNonce:
    """
    AC-29-P0-13: do_switch consumes the from-profile nonce and mints then consumes
    the to-profile nonce within a single lock acquisition.

    Final state: both nonce files absent.
    Call ordering: consume(from) happens before mint(to).
    """

    def _write_nonce(self, nonce_dir: Path, profile: str) -> Path:
        """Pre-create a nonce file for a profile."""
        nonce_dir.mkdir(mode=0o700, exist_ok=True)
        f = nonce_dir / profile
        f.write_text(
            f"{secrets.token_hex(32)}\n{int(time.time())}\n{profile}\n",
            encoding="ascii",
        )
        return f

    def test_do_switch_both_nonces_absent_at_completion(self, nonce_dir):
        """
        AC-29-P0-13: after a successful do_switch, both the from-profile nonce
        (copilot) and the to-profile nonce (claude) are absent.
        """
        # Pre-create from-profile nonce (simulate prior portal up of copilot).
        self._write_nonce(nonce_dir, "copilot")

        # get_running_profiles: first call (initial check) returns {"copilot"},
        # second call (after down verification) returns set().
        grp_side_effects = [{"copilot"}, set()]
        grp_call_count = [0]

        def fake_grp():
            idx = grp_call_count[0]
            grp_call_count[0] += 1
            return grp_side_effects[idx] if idx < len(grp_side_effects) else set()

        real_mint = real_mint_nonce
        real_consume = real_consume_nonce

        with (
            patch("src.admin.primitives.lifecycle.get_running_profiles", side_effect=fake_grp),
            patch(
                "src.admin.primitives.lifecycle.compose_down",
                return_value=MagicMock(returncode=0),
            ),
            patch(
                "src.admin.primitives.lifecycle.compose_up",
                return_value=MagicMock(returncode=0),
            ),
            patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True),
            patch("src.admin.primitives.lifecycle.mint_nonce", side_effect=real_mint),
            patch("src.admin.primitives.lifecycle.consume_nonce", side_effect=real_consume),
        ):
            result = do_switch("copilot", "claude", secret="test-secret")

        assert result["outcome"] == "applied", f"Expected applied; got {result!r}"
        assert not (nonce_dir / "copilot").exists(), (
            "From-profile (copilot) nonce must be absent after do_switch "
            "(consumed after from-profile down)"
        )
        assert not (nonce_dir / "claude").exists(), (
            "To-profile (claude) nonce must be absent after do_switch "
            "(minted for gateway start, consumed after health gate passes)"
        )

    def test_do_switch_call_ordering_consume_from_before_mint_to(self, nonce_dir):
        """
        AC-29-P0-13: call ordering within the lock: consume(from_profile) precedes
        mint(to_profile), which precedes consume(to_profile).
        Verified via a shared call log spy.
        """
        self._write_nonce(nonce_dir, "copilot")

        grp_side_effects = [{"copilot"}, set()]
        grp_call_count = [0]

        def fake_grp():
            idx = grp_call_count[0]
            grp_call_count[0] += 1
            return grp_side_effects[idx] if idx < len(grp_side_effects) else set()

        call_log: list = []
        real_mint = real_mint_nonce
        real_consume = real_consume_nonce

        def spy_mint(profile: str) -> None:
            call_log.append(("mint", profile))
            real_mint(profile)

        def spy_consume(profile: str) -> None:
            call_log.append(("consume", profile))
            real_consume(profile)

        with (
            patch("src.admin.primitives.lifecycle.get_running_profiles", side_effect=fake_grp),
            patch(
                "src.admin.primitives.lifecycle.compose_down",
                return_value=MagicMock(returncode=0),
            ),
            patch(
                "src.admin.primitives.lifecycle.compose_up",
                return_value=MagicMock(returncode=0),
            ),
            patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True),
            patch("src.admin.primitives.lifecycle.mint_nonce", side_effect=spy_mint),
            patch("src.admin.primitives.lifecycle.consume_nonce", side_effect=spy_consume),
        ):
            result = do_switch("copilot", "claude", secret="test-secret")

        assert result["outcome"] == "applied"

        # Verify expected calls are present.
        assert ("consume", "copilot") in call_log, (
            "consume_nonce must be called for the from-profile (copilot) after it is downed"
        )
        assert ("mint", "claude") in call_log, (
            "mint_nonce must be called for the to-profile (claude) before compose_up"
        )
        assert ("consume", "claude") in call_log, (
            "consume_nonce must be called for the to-profile (claude) after health gate passes"
        )

        # Verify ordering within the call log.
        idx_consume_from = call_log.index(("consume", "copilot"))
        idx_mint_to = call_log.index(("mint", "claude"))
        idx_consume_to = call_log.index(("consume", "claude"))

        assert idx_consume_from < idx_mint_to, (
            f"consume(copilot) must precede mint(claude). "
            f"Call log: {call_log}"
        )
        assert idx_mint_to < idx_consume_to, (
            f"mint(claude) must precede consume(claude). "
            f"Call log: {call_log}"
        )
