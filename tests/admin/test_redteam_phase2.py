"""
test_redteam_phase2.py - Adversarial CONTAINMENT suite for the Phase 2 admin
control plane (profile lifecycle: up / down / switch + mutual exclusion).

Framing (red-teamer role, SPEC-27-P2, R-m / invariant 9):

  ASSUME THE ATTACKER CAN REACH THE API. Auth/CSRF were obtained, or the operator's
  browser is hostile. We do NOT re-test "can the model be tricked" -- Phase 2 has no
  model in the loop; the lifecycle guard is a DETERMINISTIC frozenset allowlist plus a
  flock-serialized check-and-act. We test CONTAINMENT: given a hostile request that
  reaches the lifecycle write surface, can the attacker

    (a) start a SECOND profile and break mutual exclusion (invariant 9 / R-m),
    (b) inject through the {profile} path param into the `docker compose` argv,
    (c) defeat the flock serialization / sneak an up through a held lock,
    (d) exfiltrate the admin secret or tamper / read-back / delete the audit trail,
    (e) coerce a "run both" / concurrent-up state via switch or a UI affordance,
    (f) cause any lifecycle effect before auth / CSRF is enforced?

  Every test asserts an attack FAILS. A failing assertion in this file is a REAL
  boundary FINDING, not a flaky test. If a second profile could start, a metacharacter
  reaches compose, or the secret lands in an audit record, that is CRITICAL: STOP and
  escalate to threat-modeler + security-reviewer; do not paper over it.

This file is DISTINCT from the functional Phase 2 suite (test_lifecycle_api.py,
test_lifecycle_primitive.py, test_lifecycle_mutex.py), which proves the controls are
CONFIGURED correctly. This file proves they CONTAIN an attacker, and carries the
permanent regression guard for the Phase 2 security-review BLOCK (B1): the
get_running_profiles() granularity fix (project name vs service/container) that
previously defeated mutual exclusion.

Non-determinism note: the Phase 2 mutex/injection guard is a DETERMINISTIC frozenset
match (validate_profile) + a POSIX flock, not a model judgement. So each adversarial
input is run as a parametrized battery (every input, every time). The red-teamer
"report attack-success-rate, not one clean run" discipline is honored by the breadth of
the battery AND by TestMutexBypassBattery.test_mutex_attack_success_rate /
TestProfileNameInjectionBattery.test_injection_attack_success_rate, which aggregate the
whole battery and assert a 0% success rate (0 compose_up calls on refuse, 0 hostile
values reaching compose, 0 non-rejections).

Default suite is Docker-free: get_running_profiles / compose_up / compose_down /
wait_for_gateway_healthy and subprocess.run are mocked so a mutex/injection test can
NEVER touch a live Docker stack. Anything that needs a live stack is tagged
@pytest.mark.integration and pytest.fail()s when absent (none are required here; the
live concurrency proof lives in test_lifecycle_mutex.py).
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings  # noqa: E402
from src.admin.main import create_app  # noqa: E402
from src.admin.primitives import lifecycle as lc  # noqa: E402
from src.admin.primitives.lifecycle import (  # noqa: E402
    ALLOWED_PROFILES,
    LifecycleLockError,
    do_down,
    do_switch,
    do_up,
    get_running_profiles,
    validate_profile,
)

TEST_SECRET = "test-secret-value-12345"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"
VALID_HOST_HDR = f"{TEST_HOST}:{TEST_PORT}"

# Where the route reaches the primitives. Mutating-call tripwires patch these names.
_PRIM = "src.admin.primitives.lifecycle"


# ---------------------------------------------------------------------------
# Fixtures (match tests/admin/ style)
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_audit(tmp_path):
    return tmp_path / "admin-audit.jsonl"


@pytest.fixture()
def test_settings(tmp_path, tmp_audit):
    secret_file = tmp_path / "admin-secret"
    secret_file.write_text(TEST_SECRET + "\n", encoding="utf-8")
    os.chmod(secret_file, 0o600)
    return Settings(
        host=TEST_HOST,
        port=TEST_PORT,
        allow_non_loopback=False,
        secret_file=secret_file,
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RT2",
        audit_log_path=tmp_audit,
        session_secret_key="rt2-session-key-aaabbbccc" * 4,
    )


@pytest.fixture()
def client(test_settings):
    from starlette.testclient import TestClient
    app = create_app(test_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HDR})
        yield c


@pytest.fixture()
def authed_client(client):
    """Client with an authenticated session and a valid CSRF token."""
    resp = client.post(
        "/api/v1/login",
        json={"secret": TEST_SECRET},
        headers={"Host": VALID_HOST_HDR},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    csrf = resp.json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": csrf})
    return client


def _audit_lines(audit_path: Path) -> list:
    if not audit_path.exists():
        return []
    out = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def _lifecycle_audit(audit_path: Path) -> list:
    return [r for r in _audit_lines(audit_path) if r.get("domain") == "lifecycle"]


def _ps_record(name: str, service: str, state: str = "running",
               status: str = "Up 2 hours", health: str = "healthy") -> str:
    """One real-shape `docker compose ps --format json` record (single project 'agentarca')."""
    return json.dumps({
        "Name": name, "Service": service, "State": state,
        "Status": status, "Health": health,
    })


class _NeverCalled:
    """A primitive stand-in that records and FAILS if ever invoked.

    Used to prove that a refused/rejected operation never reaches compose_up /
    compose_down (so no second profile can start, and no hostile value reaches the
    `docker compose` argv).
    """

    def __init__(self, label: str = "compose_up"):
        self.label = label
        self.calls: list = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError(
            f"FINDING (CRITICAL): {self.label} was invoked with args={args!r} "
            f"kwargs={kwargs!r}. A refused/hostile lifecycle operation reached the "
            f"compose boundary -- mutual exclusion / injection containment was bypassed "
            f"(R-m / invariant 9). Escalate to threat-modeler + security-reviewer."
        )


# ===========================================================================
# 1. MUTUAL-EXCLUSION BYPASS  (the core Phase 2 attack, R-m / invariant 9)
# ===========================================================================
#
# Containment claim: with one profile already running, EVERY `up <other>` and EVERY
# `switch from=<x> to=<other>` whose running profile is not the from-profile MUST 409
# and MUST NOT call compose_up. We assert the second half with a _NeverCalled tripwire
# on compose_up: a second profile can NEVER be brought up while another is live.
#
# We exercise this both at the primitive layer (do_up / do_switch under the real lock,
# get_running_profiles mocked) and at the route layer (full HTTP stack).


# The detection predicate is fed REAL-shape `docker compose ps` JSON for each case, so
# the test also covers the B1 granularity fix end-to-end: a profile is "running" only
# when its gateway SERVICE (gateway-<p>) / CONTAINER (<p>-gateway) is State=running.
RUNNING_STATE_CASES = [
    # (label, ps_stdout, expected_running_set)
    (
        "codex_gateway_running",
        _ps_record("codex-gateway", "gateway-codex", "running", "Up 2 hours"),
        {"codex"},
    ),
    (
        "codex_gateway_and_devcontainer",
        _ps_record("codex-devcontainer", "devcontainer-codex", "running", "Up 2 days")
        + "\n"
        + _ps_record("codex-gateway", "gateway-codex", "running", "Up 2 hours"),
        {"codex"},
    ),
    (
        "claude_container_name_only",
        _ps_record("claude-gateway", "", "running", "Up 1 hour"),
        {"claude"},
    ),
    (
        "copilot_running",
        _ps_record("copilot-gateway", "gateway-copilot", "running", "Up 5m"),
        {"copilot"},
    ),
]


class TestMutexBypassPrimitive:
    """do_up / do_switch refuse 409 and never call compose_up while another profile runs."""

    @pytest.mark.parametrize(
        "running", [{"codex"}, {"claude"}, {"copilot"}], ids=["codex", "claude", "copilot"]
    )
    def test_up_other_profile_refused_no_compose_up(self, running):
        """With <running> live, an up of any OTHER profile is rejected_mutex and never composes up."""
        spy = _NeverCalled("compose_up")
        running_profile = next(iter(running))
        for target in ALLOWED_PROFILES - running:
            with patch(f"{_PRIM}.get_running_profiles", return_value=set(running)), \
                 patch(f"{_PRIM}.compose_up", side_effect=spy), \
                 patch(f"{_PRIM}.compose_down", side_effect=_NeverCalled("compose_down")), \
                 patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
                res = do_up(target, secret="")
            assert res["outcome"] == "rejected_mutex", (
                f"FINDING (CRITICAL, R-m): up({target!r}) with {running_profile!r} running "
                f"returned {res['outcome']!r}, not rejected_mutex. Mutual exclusion bypassed."
            )
            assert res["http_status"] == 409
            assert res["running_profile"] == running_profile
        assert spy.calls == [], (
            "FINDING (CRITICAL, R-m): compose_up was invoked while another profile was "
            "running. A SECOND profile could start. Escalate."
        )

    @pytest.mark.parametrize("label,stdout,expected", RUNNING_STATE_CASES, ids=[c[0] for c in RUNNING_STATE_CASES])
    def test_up_refused_against_real_ps_json_no_compose_up(self, label, stdout, expected):
        """
        End-to-end through the REAL get_running_profiles parser (B1 fix): feed real-shape
        `docker compose ps` JSON, then attempt to up a DIFFERENT profile. Detection must
        see the running profile (service/container granularity) and refuse; compose_up
        never fires.
        """
        running_profile = next(iter(expected))
        target = next(iter(ALLOWED_PROFILES - expected))
        spy = _NeverCalled("compose_up")

        ps_result = MagicMock()
        ps_result.returncode = 0
        ps_result.stdout = stdout
        ps_result.stderr = ""

        with patch(f"{_PRIM}.subprocess.run", return_value=ps_result), \
             patch(f"{_PRIM}.compose_up", side_effect=spy), \
             patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
            res = do_up(target, secret="")

        assert res["outcome"] == "rejected_mutex", (
            f"FINDING (CRITICAL, B1/R-m): with {label!r} (running profile {running_profile!r}) "
            f"detected from REAL ps JSON, up({target!r}) returned {res['outcome']!r} not "
            f"rejected_mutex. The granularity regression (project vs service/container) is back: "
            f"the running profile was NOT seen, so a second profile could start. Escalate."
        )
        assert res["running_profile"] == running_profile
        assert spy.calls == []

    def test_switch_refused_when_third_profile_running_no_compose(self):
        """
        switch from=A to=B while a THIRD profile C is running must 409 and never call
        compose_down(A) or compose_up(B). (A is not running, C is.)
        """
        up_spy = _NeverCalled("compose_up")
        down_spy = _NeverCalled("compose_down")
        with patch(f"{_PRIM}.get_running_profiles", return_value={"codex"}), \
             patch(f"{_PRIM}.compose_up", side_effect=up_spy), \
             patch(f"{_PRIM}.compose_down", side_effect=down_spy), \
             patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
            res = do_switch("copilot", "claude", secret="")
        assert res["outcome"] == "rejected_mutex", (
            f"FINDING (CRITICAL, R-m): switch(copilot->claude) with codex running returned "
            f"{res['outcome']!r}; a switch ignored a third running profile. Escalate."
        )
        assert res["http_status"] == 409
        assert up_spy.calls == [] and down_spy.calls == []


class TestMutexPredicateTrickery:
    """Try to fool get_running_profiles into NOT seeing a live profile (so an up sneaks through)."""

    def _run_get_running(self, stdout, returncode=0):
        result = MagicMock()
        result.returncode = returncode
        result.stdout = stdout
        result.stderr = ""
        with patch(f"{_PRIM}.subprocess.run", return_value=result):
            return get_running_profiles()

    def test_exited_gateway_does_not_count_as_running(self):
        """A profile whose gateway is 'exited' must NOT be reported running (else a real up is blocked or a stale one passes)."""
        stdout = _ps_record("codex-gateway", "gateway-codex", "exited", "Exited (0) 1m ago")
        assert self._run_get_running(stdout) == set(), (
            "FINDING: an EXITED gateway was counted as running. State misparse (R-m "
            "running-state-misparse): a dead profile would wrongly block / a stale record "
            "could be trusted."
        )

    def test_created_but_not_started_not_running(self):
        stdout = _ps_record("claude-gateway", "gateway-claude", "created", "Created")
        assert self._run_get_running(stdout) == set()

    def test_empty_ps_output_is_empty_set(self):
        assert self._run_get_running("") == set()
        assert self._run_get_running("   \n  \n") == set()

    def test_odd_malformed_lines_skipped_not_crash(self):
        """Malformed JSON lines must be skipped, not crash detection into a fail-open empty set when a real profile is present."""
        stdout = (
            "not-json-at-all\n"
            "{ partial json\n"
            + _ps_record("codex-gateway", "gateway-codex", "running", "Up 1h")
        )
        assert self._run_get_running(stdout) == {"codex"}, (
            "FINDING (CRITICAL, R-m): a malformed line caused the running profile to be "
            "missed -- detection fails OPEN, letting a second profile start. Escalate."
        )

    def test_unrelated_containers_do_not_register_as_profiles(self):
        stdout = (
            _ps_record("postgres", "db", "running", "Up 3 days") + "\n"
            + _ps_record("some-web-app", "web", "running", "Up 1 day") + "\n"
            + _ps_record("redis", "cache", "running", "Up 1 day")
        )
        assert self._run_get_running(stdout) == set(), (
            "FINDING: an unrelated container was misread as a running AgentArca profile."
        )

    def test_b1_project_name_only_record_not_misread_as_running(self):
        """
        B1 REGRESSION GUARD (Phase 2 security-review BLOCK, FIXED 2026-06-24):
        the prior code matched `docker compose ls` per-PROJECT Name ('agentarca') against
        the profile and so NEVER saw the running profile, returning the empty set against
        the real topology and DEFEATING mutual exclusion.

        Here we assert the inverse direction of that bug at the detection layer: a record
        carrying ONLY the project name 'agentarca' (no gateway service/container for any
        profile) must NOT be misread as any specific profile being 'running' -- detection
        is at SERVICE/CONTAINER granularity, never the bare project name. The companion
        positive guard (a real codex gateway IS detected) is
        test_up_refused_against_real_ps_json_no_compose_up above; together they pin the fix.
        """
        # A bare project-name record (what `docker compose ls` would surface). It names no
        # profile gateway, so it must map to NO running profile -- if it mapped to one, a
        # switch/up could be wrongly refused; if the gateway record were ignored (old bug),
        # a real profile would be missed. We assert the project-name noise contributes nothing.
        stdout = _ps_record("agentarca", "agentarca", "running", "Up 2 hours")
        assert self._run_get_running(stdout) == set(), (
            "FINDING (CRITICAL, B1/R-m): a bare project-name 'agentarca' record was mapped "
            "to a running profile (or the matcher is project-granular again). The B1 "
            "granularity fix regressed. Escalate to threat-modeler + security-reviewer."
        )
        # And the canonical real record IS seen, proving the matcher is not vacuous.
        real = _ps_record("codex-gateway", "gateway-codex", "running", "Up 2 hours")
        assert self._run_get_running(real) == {"codex"}, (
            "FINDING (CRITICAL, B1/R-m): the REAL codex gateway record (Name=codex-gateway, "
            "Service=gateway-codex, State=running) was NOT detected as running. This is the "
            "exact B1 BLOCK condition -- a second profile could start. Escalate."
        )


class TestMutexBypassRoute:
    """Full HTTP stack: up of another profile while one runs is 409 and never composes up."""

    @pytest.mark.parametrize("running,target", [
        ("codex", "claude"), ("codex", "copilot"),
        ("claude", "codex"), ("claude", "copilot"),
        ("copilot", "codex"), ("copilot", "claude"),
    ])
    def test_route_up_other_profile_409_no_compose_up(self, authed_client, tmp_audit, running, target):
        spy = _NeverCalled("compose_up")
        with patch(f"{_PRIM}.get_running_profiles", return_value={running}), \
             patch(f"{_PRIM}.compose_up", side_effect=spy), \
             patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
            resp = authed_client.post(
                f"/api/v1/profiles/{target}/up", headers={"Host": VALID_HOST_HDR}
            )
        assert resp.status_code == 409, (
            f"FINDING (CRITICAL, R-m): POST up/{target} with {running} running returned "
            f"{resp.status_code}, not 409. A second profile could start. Body: {resp.text}"
        )
        body = resp.json()
        assert body["error"] == "mutual_exclusion"
        assert body["running_profile"] == running
        assert spy.calls == []
        recs = _lifecycle_audit(tmp_audit)
        assert recs and recs[-1]["outcome"] == "rejected-by-stop-and-flag", (
            "FINDING (R-r): a mutex-refused up was not audited as rejected-by-stop-and-flag."
        )

    def test_mutex_attack_success_rate(self, authed_client):
        """
        Aggregate the whole cross-product of (running, other-up) and report the
        attack-success-rate. Containment requires 0%: 0 non-409 responses, 0 compose_up
        calls. This is the red-teamer "report a rate, not one clean run" assertion.
        """
        successes = []
        total_compose_calls = 0
        pairs = [(r, t) for r in ALLOWED_PROFILES for t in ALLOWED_PROFILES if r != t]
        for running, target in pairs:
            spy = _NeverCalled("compose_up")
            with patch(f"{_PRIM}.get_running_profiles", return_value={running}), \
                 patch(f"{_PRIM}.compose_up", side_effect=spy), \
                 patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
                try:
                    resp = authed_client.post(
                        f"/api/v1/profiles/{target}/up", headers={"Host": VALID_HOST_HDR}
                    )
                    code = resp.status_code
                except AssertionError:
                    successes.append((running, target, "REACHED_COMPOSE_UP"))
                    total_compose_calls += 1
                    continue
            if code != 409:
                successes.append((running, target, f"status={code}"))
            total_compose_calls += len(spy.calls)
        rate = len(successes) / len(pairs)
        assert total_compose_calls == 0, (
            f"FINDING (CRITICAL, R-m): {total_compose_calls} second-profile start(s) reached "
            f"compose_up across the battery. Mutual exclusion is breakable. Offenders: {successes}"
        )
        assert rate == 0.0, (
            f"FINDING (CRITICAL, R-m): mutex-bypass attack-success-rate = {rate:.1%} "
            f"({len(successes)}/{len(pairs)}). Offenders: {successes}"
        )


# ===========================================================================
# 2. PROFILE-NAME INJECTION THROUGH THE PATH PARAM  (R-q / argv injection)
# ===========================================================================
#
# Containment claim: the {profile} path param is validated against the exact frozenset
# BEFORE any lock or subprocess. Every hostile value is rejected 400 and NEVER reaches
# compose_up / compose_down / the lock. We assert the subprocess half with a tripwire on
# compose_up AND on get_running_profiles (the first thing inside the lock): a rejected
# name must not even acquire the lock or query state.

HOSTILE_PROFILES = [
    # --- shell metacharacters / command chaining ---
    ("semicolon_rm", "copilot;rm -rf /"),
    ("pipe_cmd", "codex|id"),
    ("amp_background", "claude&id"),
    ("double_amp", "codex&&id"),
    ("dollar_paren_subst", "codex$(id)"),
    ("backtick_subst", "codex`id`"),
    ("dollar_brace", "codex${IFS}id"),
    ("redirect_out", "codex>/tmp/pwned"),
    ("subshell", "codex(id)"),
    ("logical_or", "codex||id"),
    ("glob_star", "cod*"),
    ("space_arg_split", "codex up"),
    # --- compose-arg / flag injection (leading dash, --) ---
    ("dash_dash", "--"),
    ("dash_f_composefile", "-fdocker-compose.evil.yml"),
    ("dash_f_space", "-f /tmp/evil.yml"),
    ("dash_p_project", "-pother"),
    ("compose_profile_inject", "codex --profile claude"),
    ("flaglike", "--profile=claude"),
    # --- path traversal ---
    ("path_traversal", "../../../etc/passwd"),
    ("dotdot", ".."),
    ("dotdot_profile", "../codex"),
    ("abs_path", "/etc/passwd"),
    ("slash_inside", "codex/claude"),
    # --- service/container names must NOT be accepted as profiles ---
    ("service_gateway_codex", "gateway-codex"),
    ("container_codex_gateway", "codex-gateway"),
    ("service_devcontainer", "devcontainer-codex"),
    ("container_devcontainer", "codex-devcontainer"),
    # --- case / whitespace / unicode / empty / length ---
    ("uppercase", "CODEX"),
    ("titlecase", "Codex"),
    ("trailing_space", "codex "),
    ("leading_space", " codex"),
    ("internal_space", "co dex"),
    ("tab", "codex\t"),
    ("newline", "codex\n"),
    ("crlf_inject", "codex\r\nclaude"),
    ("empty", ""),
    ("only_space", "   "),
    ("unicode_cyrillic", "сodex"),       # cyrillic 'c'
    ("unicode_fullwidth", "ｃodex"),
    ("emoji", "codex\U0001f600"),
    ("very_long", "codex" + "a" * 5000),
    ("null_byte", "codex\x00claude"),
    # --- not-a-profile plausible values ---
    ("plural", "codexes"),
    ("prefix", "codexx"),
    ("near_miss", "codx"),
    ("all", "all"),
    ("star", "*"),
]

# Valid names, to prove the battery is not vacuous (a battery that rejects everything
# proves nothing). These MUST be accepted by validate_profile.
VALID_PROFILES = [("codex", "codex"), ("claude", "claude"), ("copilot", "copilot")]


class TestProfileNameInjectionPrimitive:
    """The frozenset validator rejects every hostile profile and accepts only the three real ones."""

    @pytest.mark.parametrize("label,name", VALID_PROFILES, ids=[p[0] for p in VALID_PROFILES])
    def test_valid_profiles_accepted_not_vacuous(self, label, name):
        assert validate_profile(name) is True, (
            f"Battery sanity FAILED: legit profile {name!r} rejected by validate_profile; "
            f"the rejection battery below would be vacuous."
        )

    @pytest.mark.parametrize("label,name", HOSTILE_PROFILES, ids=[p[0] for p in HOSTILE_PROFILES])
    def test_hostile_profile_rejected_by_validator(self, label, name):
        assert validate_profile(name) is False, (
            f"FINDING (CRITICAL, R-q): validate_profile ACCEPTED hostile profile "
            f"{label!r}={name!r}. This value would flow into the `docker compose --profile "
            f"<name>` argv. Escalate."
        )


class TestProfileNameInjectionRoute:
    """Hostile {profile} path params 400 BEFORE any lock/subprocess; nothing reaches compose."""

    @pytest.mark.parametrize("label,name", HOSTILE_PROFILES, ids=[p[0] for p in HOSTILE_PROFILES])
    def test_up_hostile_profile_400_no_lock_no_compose(self, authed_client, tmp_audit, label, name):
        """
        POST up/<hostile> -> 400, and NEITHER get_running_profiles (the first thing under
        the lock) NOR compose_up is ever called. Proving get_running_profiles is untouched
        proves the lock was never even acquired with the hostile value.
        """
        state_spy = _NeverCalled("get_running_profiles")
        up_spy = _NeverCalled("compose_up")
        # URL-encode nothing: requests/TestClient will percent-encode unsafe chars in the path,
        # which is exactly how a hostile value arrives. null byte/newline are sent via the
        # raw path; TestClient encodes them.
        from urllib.parse import quote
        path = "/api/v1/profiles/" + quote(name, safe="") + "/up"
        with patch(f"{_PRIM}.get_running_profiles", side_effect=state_spy), \
             patch(f"{_PRIM}.compose_up", side_effect=up_spy), \
             patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
            resp = authed_client.request("POST", path, headers={"Host": VALID_HOST_HDR})

        # 400 = handler-level frozenset reject; 404/405 = the encoded value (slash, dot-
        # segment, empty, metachar) no longer matches the /{profile}/up route shape, so the
        # router refuses it before the handler. ALL are containment: the value never reaches
        # the lock/compose (asserted strictly below). A 2xx would be the real finding.
        assert resp.status_code in (400, 404, 405), (
            f"FINDING (R-q): hostile profile {label!r}={name!r} on up returned "
            f"{resp.status_code}; expected 400/404/405 (rejected before effect). A non-reject "
            f"means the value may flow toward compose."
        )
        assert resp.status_code not in (200, 201, 202, 204)
        assert state_spy.calls == [], (
            f"FINDING (CRITICAL, R-q): hostile profile {label!r} reached get_running_profiles "
            f"-- the lock was acquired with an unvalidated value (validation runs AFTER the "
            f"lock instead of before). Escalate."
        )
        assert up_spy.calls == [], (
            f"FINDING (CRITICAL, R-q): hostile profile {label!r} reached compose_up -- it "
            f"would land in the `docker compose --profile <name>` argv. Escalate."
        )

    @pytest.mark.parametrize("label,name", HOSTILE_PROFILES, ids=[p[0] for p in HOSTILE_PROFILES])
    def test_down_hostile_profile_400_no_compose(self, authed_client, label, name):
        down_spy = _NeverCalled("compose_down")
        state_spy = _NeverCalled("get_running_profiles")
        from urllib.parse import quote
        path = "/api/v1/profiles/" + quote(name, safe="") + "/down"
        with patch(f"{_PRIM}.get_running_profiles", side_effect=state_spy), \
             patch(f"{_PRIM}.compose_down", side_effect=down_spy):
            resp = authed_client.request("POST", path, headers={"Host": VALID_HOST_HDR})
        assert resp.status_code in (400, 404, 405)
        assert resp.status_code not in (200, 201, 202, 204)
        assert down_spy.calls == [] and state_spy.calls == [], (
            f"FINDING (CRITICAL, R-q): hostile down profile {label!r} reached the lock/compose."
        )

    @pytest.mark.parametrize("field", ["from", "to"])
    @pytest.mark.parametrize("label,name", [
        ("semicolon_rm", "copilot;rm -rf /"),
        ("dash_f", "-fdocker-compose.evil.yml"),
        ("traversal", "../../../etc/passwd"),
        ("container_name", "codex-gateway"),
        ("uppercase", "CODEX"),
        ("empty", ""),
        ("flag_inject", "codex --profile claude"),
    ], ids=lambda p: p[0] if isinstance(p, tuple) else p)
    def test_switch_hostile_profile_400_no_compose(self, authed_client, field, label, name):
        up_spy = _NeverCalled("compose_up")
        down_spy = _NeverCalled("compose_down")
        state_spy = _NeverCalled("get_running_profiles")
        body = {"from": "codex", "to": "codex"}
        body[field] = name
        # Avoid the from==to idempotent shortcut masking the validation reject.
        if body["from"] == body["to"]:
            body["to" if field == "from" else "from"] = "claude"
        with patch(f"{_PRIM}.get_running_profiles", side_effect=state_spy), \
             patch(f"{_PRIM}.compose_up", side_effect=up_spy), \
             patch(f"{_PRIM}.compose_down", side_effect=down_spy):
            resp = authed_client.post(
                "/api/v1/profiles/switch", json=body, headers={"Host": VALID_HOST_HDR}
            )
        assert resp.status_code == 400, (
            f"FINDING (R-q): switch with hostile {field}={name!r} returned {resp.status_code}, "
            f"not 400. Body: {resp.text}"
        )
        assert up_spy.calls == [] and down_spy.calls == [] and state_spy.calls == [], (
            f"FINDING (CRITICAL, R-q): hostile switch {field}={label!r} reached the lock/compose."
        )

    def test_injection_attack_success_rate(self, authed_client):
        """Aggregate the whole hostile-profile battery across up+down; assert 0% reach compose/lock."""
        successes = []
        reached_boundary = 0
        from urllib.parse import quote
        for label, name in HOSTILE_PROFILES:
            for verb in ("up", "down"):
                spy_state = _NeverCalled("get_running_profiles")
                spy_up = _NeverCalled("compose_up")
                spy_down = _NeverCalled("compose_down")
                path = "/api/v1/profiles/" + quote(name, safe="") + "/" + verb
                with patch(f"{_PRIM}.get_running_profiles", side_effect=spy_state), \
                     patch(f"{_PRIM}.compose_up", side_effect=spy_up), \
                     patch(f"{_PRIM}.compose_down", side_effect=spy_down), \
                     patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
                    try:
                        resp = authed_client.request("POST", path, headers={"Host": VALID_HOST_HDR})
                        code = resp.status_code
                    except AssertionError:
                        successes.append((label, verb, "REACHED_BOUNDARY"))
                        reached_boundary += 1
                        continue
                if code not in (400, 404, 405):
                    successes.append((label, verb, f"status={code}"))
        total = len(HOSTILE_PROFILES) * 2
        rate = len(successes) / total
        assert reached_boundary == 0, (
            f"FINDING (CRITICAL, R-q): {reached_boundary} hostile profile value(s) reached the "
            f"lock/compose boundary. argv injection into `docker compose` is live. {successes}"
        )
        assert rate == 0.0, (
            f"FINDING (R-q): injection attack-success-rate = {rate:.1%} "
            f"({len(successes)}/{total}). Offenders: {successes}"
        )

    def test_compose_argv_never_built_with_hostile_value(self):
        """
        Defense-in-depth at the primitive: even if a hostile value reached compose_up
        (it cannot via the route), the command is a fixed list with the profile as one
        argv element (shell=False) -- it is never concatenated into a shell string. We
        capture the argv compose_up would build and assert the hostile value is a single,
        un-split element (so metacharacters are inert), confirming there is no shell parse.
        """
        captured = {}

        def fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        # We pass a hostile value directly to compose_up to inspect argv construction.
        # (The route never lets this value through; this proves the argv shape if it did.)
        hostile = "codex;rm -rf /"
        with patch(f"{_PRIM}.subprocess.run", side_effect=fake_run):
            lc.compose_up(hostile)
        cmd = captured["cmd"]
        assert isinstance(cmd, list), (
            "FINDING (CRITICAL, R-q): compose_up built a non-list command -- a shell string "
            "would let metacharacters in the profile execute. Escalate."
        )
        assert cmd[:3] == ["docker", "compose", "--profile"], (
            f"FINDING: compose_up argv shape changed: {cmd!r}. Review the wrap boundary."
        )
        # The hostile value occupies exactly ONE argv slot; it is never split on ';' or ' '.
        assert hostile in cmd, (
            f"FINDING (CRITICAL, R-q): the profile value was split/transformed in argv {cmd!r}; "
            f"this implies shell-style parsing of the profile. Escalate."
        )


# ===========================================================================
# 3. FLOCK / CONCURRENCY ABUSE  (defeat serialization, sneak an up through)
# ===========================================================================
#
# Containment claim: the lifecycle_lock is held across the WHOLE check->act->healthcheck
# (not released between compose_up and the health poll); down ALSO takes the lock; and a
# second request cannot proceed while the lock is held -- it bounded-waits and then
# refuses (lock_timeout -> 503), never sneaking a compose_up through.


class TestFlockSerialization:
    """The flock serializes the entire check-act-health window; a contended up refuses, never composes."""

    def test_up_holds_lock_through_healthcheck_not_released_early(self):
        """
        Behavioral: while do_up runs, the lock is held from get_running_profiles through
        wait_for_gateway_healthy. We prove the lock is held during the health poll by
        attempting to acquire it from inside the mocked health poll with LOCK_NB -- it
        must fail (already held by do_up).
        """
        import fcntl

        held_during_health = {"locked": None}

        def probe_health(profile, *a, **k):
            # Try to grab the SAME lock file non-blocking from a second fd; it must be held.
            f = open(lc.LIFECYCLE_LOCK_PATH, "w")
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                held_during_health["locked"] = False  # acquired -> NOT held by do_up (bad)
            except OSError:
                held_during_health["locked"] = True   # could not acquire -> held (good)
            finally:
                f.close()
            return True

        up_result = MagicMock()
        up_result.returncode = 0
        up_result.stdout = ""
        up_result.stderr = ""
        # P1: mock get_credential_status so the credential gate passes.
        mock_cred_status = MagicMock()
        mock_cred_status.present = True
        lc.ensure_lifecycle_lock_file()
        with patch(f"{_PRIM}.get_running_profiles", return_value=set()), \
             patch(f"{_PRIM}.get_credential_status", return_value=mock_cred_status), \
             patch(f"{_PRIM}.compose_up", return_value=up_result), \
             patch(f"{_PRIM}.wait_for_gateway_healthy", side_effect=probe_health):
            res = do_up("codex", secret="")
        assert res["outcome"] == "applied"
        assert held_during_health["locked"] is True, (
            "FINDING (CRITICAL, R-m): the lifecycle lock was NOT held during the gateway "
            "health poll -- it is released between compose_up and the health gate, opening a "
            "concurrent-up window (TOCTOU). Escalate to threat-modeler + security-reviewer."
        )

    def test_down_acquires_the_lock(self):
        """
        do_down must serialize against up/switch by acquiring the same lock. We prove it by
        holding the lock externally and asserting do_down bounded-waits then times out
        (lock_timeout) rather than proceeding to compose_down unserialized.
        """
        import fcntl

        lc.ensure_lifecycle_lock_file()
        down_spy = _NeverCalled("compose_down")
        holder = open(lc.LIFECYCLE_LOCK_PATH, "w")
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        try:
            with patch.dict(os.environ, {"AGENTARCA_ADMIN_LIFECYCLE_LOCK_TIMEOUT": "1"}), \
                 patch(f"{_PRIM}.get_running_profiles", return_value={"codex"}), \
                 patch(f"{_PRIM}.compose_down", side_effect=down_spy):
                res = do_down("codex", secret="")
        finally:
            fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
            holder.close()
        assert res["outcome"] == "lock_timeout", (
            f"FINDING (CRITICAL, R-m): do_down did NOT contend for the lifecycle lock "
            f"(outcome {res['outcome']!r}); it ran unserialized against a held lock. down "
            f"must acquire the same lock as up/switch. Escalate."
        )
        assert down_spy.calls == [], (
            "FINDING (CRITICAL): do_down reached compose_down while the lock was held by "
            "another holder -- serialization broken."
        )

    def test_contended_up_refuses_no_compose_up_sneaks_through(self):
        """
        A second up arriving while the lock is held must bounded-wait and then refuse
        (lock_timeout -> 503), and must NEVER call compose_up. We hold the lock externally,
        run do_up with a short timeout, and assert no compose_up.
        """
        import fcntl

        lc.ensure_lifecycle_lock_file()
        up_spy = _NeverCalled("compose_up")
        state_spy = _NeverCalled("get_running_profiles")
        holder = open(lc.LIFECYCLE_LOCK_PATH, "w")
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        try:
            start = time.monotonic()
            with patch.dict(os.environ, {"AGENTARCA_ADMIN_LIFECYCLE_LOCK_TIMEOUT": "1"}), \
                 patch(f"{_PRIM}.get_running_profiles", side_effect=state_spy), \
                 patch(f"{_PRIM}.compose_up", side_effect=up_spy):
                res = do_up("codex", secret="")
            elapsed = time.monotonic() - start
        finally:
            fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
            holder.close()
        assert res["outcome"] == "lock_timeout", (
            f"FINDING (CRITICAL, R-m): a contended up did NOT block on the held lock "
            f"(outcome {res['outcome']!r}). The flock is not actually serializing -- a "
            f"concurrent up could proceed. Escalate."
        )
        assert res["http_status"] == 503
        # It waited (bounded) rather than returning instantly or hanging forever.
        assert 0.5 <= elapsed <= 30, (
            f"FINDING: contended up returned in {elapsed:.2f}s; expected a bounded wait "
            f"(~timeout) -- neither instant (no real lock) nor unbounded (hang)."
        )
        assert up_spy.calls == [] and state_spy.calls == [], (
            "FINDING (CRITICAL, R-m): a contended up reached state-check/compose_up while the "
            "lock was held by another holder. Serialization bypassed. Escalate."
        )

    def test_lock_uses_flock_not_a_racy_existence_check(self):
        """
        Static: lifecycle_lock must use fcntl.flock (a real kernel advisory lock that the OS
        releases on crash), not a racy os.path.exists / lockfile-create scheme that a SIGKILL
        would leave stale (AC-27-P2-15). A stale-file scheme would let an attacker wedge the
        control plane or, worse, be bypassable.
        """
        src = (REPO_ROOT / "src" / "admin" / "primitives" / "lifecycle.py").read_text(encoding="utf-8")
        assert "fcntl.flock" in src, (
            "FINDING (CRITICAL): lifecycle.py no longer uses fcntl.flock. A non-kernel lock "
            "(existence check / lockfile) is racy and leaks on crash (R-m / AC-27-P2-15)."
        )
        assert "LOCK_EX" in src, "FINDING: lifecycle lock is not exclusive (LOCK_EX missing)."


# ===========================================================================
# 4. AUDIT TAMPER / SECRET EXFIL  (R-r / R-q)
# ===========================================================================
#
# Containment claim: every lifecycle action incl REFUSED is audited; the admin secret
# never lands in an audit record or response body even via odd inputs; no lifecycle
# route reads back / deletes / rotates the audit log.

SECRET_CANARY = "RT-PHASE2-SECRET-CANARY-7a6b5c"


@pytest.fixture()
def canary_settings(tmp_path):
    secret_file = tmp_path / "admin-secret"
    secret_file.write_text(SECRET_CANARY + "\n", encoding="utf-8")
    os.chmod(secret_file, 0o600)
    return Settings(
        host=TEST_HOST, port=TEST_PORT, allow_non_loopback=False, secret_file=secret_file,
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RT2_CANARY",
        audit_log_path=tmp_path / "canary-audit.jsonl",
        session_secret_key="rt2-canary-session-key-aaabbbccc" * 4,
    )


@pytest.fixture()
def canary_client(canary_settings):
    from starlette.testclient import TestClient
    app = create_app(canary_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HDR})
        resp = c.post("/api/v1/login", json={"secret": SECRET_CANARY}, headers={"Host": VALID_HOST_HDR})
        assert resp.status_code == 200
        csrf = resp.json()["csrf_token"]
        c.headers.update({"X-CSRF-Token": csrf})
        yield c, canary_settings.audit_log_path


class TestAuditTamperAndSecretExfil:
    """Refusals are audited; secret never in records/bodies; no lifecycle audit tamper route."""

    def test_mutex_refused_up_is_audited(self, authed_client, tmp_audit):
        before = len(_lifecycle_audit(tmp_audit))
        with patch(f"{_PRIM}.get_running_profiles", return_value={"codex"}), \
             patch(f"{_PRIM}.compose_up", side_effect=_NeverCalled("compose_up")):
            resp = authed_client.post("/api/v1/profiles/claude/up", headers={"Host": VALID_HOST_HDR})
        assert resp.status_code == 409
        recs = _lifecycle_audit(tmp_audit)
        assert len(recs) > before, "FINDING (R-r): a mutex-refused up left no audit trail."
        assert recs[-1]["action"] == "lifecycle_up"
        assert recs[-1]["outcome"] == "rejected-by-stop-and-flag"

    def test_invalid_profile_up_is_audited(self, authed_client, tmp_audit):
        before = len(_lifecycle_audit(tmp_audit))
        resp = authed_client.post("/api/v1/profiles/copilot%3Brm/up", headers={"Host": VALID_HOST_HDR})
        assert resp.status_code in (400, 404)
        if resp.status_code == 400:
            recs = _lifecycle_audit(tmp_audit)
            assert len(recs) > before, "FINDING (R-r): a rejected hostile up left no audit trail."
            assert recs[-1]["outcome"] == "rejected-by-validation"

    @pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH", "POST"])
    @pytest.mark.parametrize("path", [
        "/api/v1/profiles/audit",
        "/api/v1/profiles/audit/delete",
        "/api/v1/profiles/audit/rotate",
        "/api/v1/lifecycle/audit",
        "/api/v1/profiles/codex/audit",
    ])
    def test_no_lifecycle_route_tampers_audit(self, authed_client, method, path):
        """No lifecycle path exposes an audit read-back / delete / rotate surface."""
        resp = authed_client.request(method, path, json={}, headers={"Host": VALID_HOST_HDR})
        assert resp.status_code not in (200, 201, 202, 204), (
            f"FINDING (CRITICAL, R-r): {method} {path} returned {resp.status_code}; a lifecycle "
            f"route reaches the audit log for tamper/rotate/delete. Escalate."
        )
        assert resp.status_code in (400, 401, 403, 404, 405)

    def test_no_lifecycle_route_has_audit_path_in_route_table(self):
        """Route-table enumeration: no lifecycle/profiles route path mentions 'audit'."""
        from fastapi.routing import APIRoute
        import tempfile

        tmp = Path(tempfile.mkdtemp())
        sf = tmp / "admin-secret"
        sf.write_text("rt2-route-enum\n", encoding="utf-8")
        os.chmod(sf, 0o600)
        settings = Settings(
            host="127.0.0.1", port=8080, allow_non_loopback=False, secret_file=sf,
            secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RT2_ENUM",
            audit_log_path=tmp / "audit.jsonl",
            session_secret_key="rt2-route-enum-session-key-aaabbbccc" * 4,
        )
        app = create_app(settings)
        offenders = []
        for route in app.routes:
            if isinstance(route, APIRoute):
                p = str(route.path)
                if ("profiles" in p or "lifecycle" in p) and "audit" in p:
                    offenders.append((p, sorted(route.methods or set())))
        assert not offenders, (
            f"FINDING (CRITICAL, R-r): a lifecycle route exposes an audit surface: {offenders}."
        )

    def test_secret_in_compose_stderr_never_in_audit_or_body(self, canary_client):
        """
        Worst case: compose_up fails and its stderr carries the admin secret. The primitive
        AND the route both sanitize, so the secret reaches neither the audit record nor the
        response body. We mock do_up to return a compose_error whose detail carries the canary.
        """
        client, audit_path = canary_client
        mock_result = {
            "outcome": "compose_error",
            "detail": f"compose failed near token {SECRET_CANARY} oops",
            "http_status": 500,
        }
        with patch("src.admin.routes.lifecycle.do_up", return_value=mock_result):
            resp = client.post("/api/v1/profiles/codex/up", headers={"Host": VALID_HOST_HDR})
        assert resp.status_code == 500
        assert SECRET_CANARY not in resp.text, (
            "FINDING (CRITICAL, R-r): the admin secret leaked through a compose-error response "
            "body. The route-layer sanitizer was bypassed. Escalate."
        )
        content = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        assert SECRET_CANARY not in content, (
            "FINDING (CRITICAL, R-r): the admin secret landed in a lifecycle audit record via "
            "compose-error detail. The single-chokepoint sanitizer was bypassed. Escalate."
        )

    def test_secret_as_profile_path_never_persisted(self, canary_client):
        """
        Submit the secret AS the profile path param. It is rejected (not a valid profile),
        and must not be echoed in the body nor persisted to the audit record (truncated
        target is sanitized at the chokepoint).
        """
        client, audit_path = canary_client
        from urllib.parse import quote
        resp = client.post(
            "/api/v1/profiles/" + quote(SECRET_CANARY, safe="") + "/up",
            headers={"Host": VALID_HOST_HDR},
        )
        assert resp.status_code in (400, 404)
        assert SECRET_CANARY not in resp.text, (
            "FINDING (R-r): the admin secret, submitted as a profile name, was echoed in the "
            "validation-reject response body."
        )
        content = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        assert SECRET_CANARY not in content, (
            "FINDING (CRITICAL, R-r): the admin secret, submitted as a profile name, landed in "
            "the audit TARGET field (durable, log-API-readable). The chokepoint sanitizer must "
            "scrub target. Escalate."
        )

    def test_secret_in_switch_body_never_persisted(self, canary_client):
        """Secret stuffed into switch from/to and odd fields is rejected and never persisted/echoed."""
        client, audit_path = canary_client
        before = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        for body in (
            {"from": SECRET_CANARY, "to": "codex"},
            {"from": "codex", "to": SECRET_CANARY},
            {"from": "codex", "to": "claude", "secret": SECRET_CANARY},
        ):
            resp = client.post("/api/v1/profiles/switch", json=body, headers={"Host": VALID_HOST_HDR})
            assert SECRET_CANARY not in resp.text, (
                f"FINDING (R-r): secret in switch body {set(body)} echoed in response."
            )
        after = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        new_text = after[len(before):]
        assert SECRET_CANARY not in new_text, (
            "FINDING (CRITICAL, R-r): secret in a switch body landed in an audit record."
        )


# ===========================================================================
# 5. NO CONCURRENT-UP AFFORDANCE / SWITCH ABUSE  (invariant 9 / R-m)
# ===========================================================================
#
# Containment claim: switch cannot leave two profiles up; a switch whose down does not
# actually stop from-profile must FAIL-CLOSED (never start to-profile); the UI exposes
# no run-both / force control.


class TestSwitchCannotLeaveTwoUp:
    """Switch fails closed; it never starts to-profile if from-profile did not stop."""

    def test_switch_down_did_not_stop_never_starts_to_profile(self):
        """
        do_switch: compose_down returns exit 0 but get_running_profiles still shows
        from_profile after the down. The sequence MUST fail closed (down_did_not_stop, 500)
        and MUST NEVER call compose_up(to_profile) -- otherwise both would be up.
        """
        up_spy = _NeverCalled("compose_up")
        down_result = MagicMock()
        down_result.returncode = 0
        down_result.stdout = ""
        down_result.stderr = ""

        calls = {"n": 0}

        def fake_get_running():
            # First call (pre-down): from-profile codex is running, no other.
            # Second call (post-down verification): codex STILL running -> down failed.
            calls["n"] += 1
            return {"codex"}

        with patch(f"{_PRIM}.get_running_profiles", side_effect=fake_get_running), \
             patch(f"{_PRIM}.compose_down", return_value=down_result), \
             patch(f"{_PRIM}.compose_up", side_effect=up_spy), \
             patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
            res = do_switch("codex", "claude", secret="")

        assert res["outcome"] == "down_did_not_stop", (
            f"FINDING (CRITICAL, R-m): switch did not fail closed when down left codex "
            f"running (outcome {res['outcome']!r}). It may have started claude on top of "
            f"codex -> TWO profiles up. Escalate."
        )
        assert res["http_status"] == 500
        assert up_spy.calls == [], (
            "FINDING (CRITICAL, R-m): switch called compose_up(to_profile) after the from-"
            "profile failed to stop. Both profiles would be running. Escalate."
        )

    def test_switch_health_fail_tears_down_to_profile(self):
        """
        If to_profile is brought up but never becomes healthy, switch must tear it down
        (gateway_timeout, 503) -- it must not leave a half-up second profile lingering.
        """
        teardown_spy = {"called_with": []}

        down_result = MagicMock()
        down_result.returncode = 0
        down_result.stdout = ""
        down_result.stderr = ""
        up_result = MagicMock()
        up_result.returncode = 0
        up_result.stdout = ""
        up_result.stderr = ""

        calls = {"n": 0}

        def fake_get_running():
            calls["n"] += 1
            # pre-down: codex running; post-down: nothing running (down succeeded).
            return {"codex"} if calls["n"] == 1 else set()

        def fake_teardown(profile, secret):
            teardown_spy["called_with"].append(profile)

        with patch(f"{_PRIM}.get_running_profiles", side_effect=fake_get_running), \
             patch(f"{_PRIM}.get_credential_status", return_value=MagicMock(present=True)), \
             patch(f"{_PRIM}.compose_down", return_value=down_result), \
             patch(f"{_PRIM}.compose_up", return_value=up_result), \
             patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=False), \
             patch(f"{_PRIM}._teardown_profile", side_effect=fake_teardown):
            res = do_switch("codex", "claude", secret="")

        assert res["outcome"] == "gateway_timeout"
        assert res["http_status"] == 503
        assert teardown_spy["called_with"] == ["claude"], (
            "FINDING (CRITICAL, R-m): an unhealthy to-profile was NOT torn down after a "
            "switch health-gate failure; a second, half-up profile would linger. Escalate."
        )

    def test_route_switch_does_not_call_separate_down_then_up(self, authed_client):
        """
        The route must delegate to do_switch (ONE lock acquisition). A route that called
        do_down then do_up separately would have a window between two lock acquisitions in
        which a concurrent up of a third profile could land -> two up.
        """
        seen = {"switch": 0, "down": 0, "up": 0}

        def fake_switch(f, t, s, *args, **kwargs):
            seen["switch"] += 1
            return {"outcome": "applied", "detail": "", "from_was_running": True, "http_status": 200}

        def fake_down(p, s):
            seen["down"] += 1
            return {"outcome": "applied", "detail": "", "http_status": 200}

        def fake_up(p, s, *args, **kwargs):
            seen["up"] += 1
            return {"outcome": "applied", "detail": "", "http_status": 201}

        with patch("src.admin.routes.lifecycle.do_switch", side_effect=fake_switch), \
             patch("src.admin.routes.lifecycle.do_down", side_effect=fake_down), \
             patch("src.admin.routes.lifecycle.do_up", side_effect=fake_up):
            resp = authed_client.post(
                "/api/v1/profiles/switch", json={"from": "codex", "to": "claude"},
                headers={"Host": VALID_HOST_HDR},
            )
        assert resp.status_code == 200
        assert seen == {"switch": 1, "down": 0, "up": 0}, (
            f"FINDING (CRITICAL, R-m): the switch route did not use the single-lock do_switch "
            f"({seen}); a separate down+up opens a concurrent-up window between locks. Escalate."
        )


class TestNoRunBothAffordance:
    """The UI and API expose no run-both / force-start / concurrent control."""

    def test_profiles_js_has_no_run_both_or_force_control(self):
        """Static: profiles.js contains no run-both/force/concurrent affordance in any code path."""
        src = (REPO_ROOT / "src" / "admin" / "static" / "profiles.js").read_text(encoding="utf-8")
        # Strip comments so the audit-doc comments ('NEVER offer run both') aren't false hits.
        code_lines = []
        for ln in src.splitlines():
            stripped = ln.strip()
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                continue
            code_lines.append(ln)
        code = "\n".join(code_lines).lower()
        for token in ("run both", "force start", "force=true", "force: true", "runboth", "force_up", "concurrent"):
            assert token not in code, (
                f"FINDING (CRITICAL, R-m): profiles.js contains a {token!r} affordance in a "
                f"non-comment code path. The UI offers a concurrent/force control. Escalate."
            )

    def test_no_force_query_param_overrides_mutex(self, authed_client):
        """
        An attacker appends ?force=1 / ?override=true to the up endpoint. The route ignores
        unknown query params; mutex must still refuse with a profile running.
        """
        for qs in ("?force=1", "?force=true", "?override=1", "?run_both=1", "?concurrent=1"):
            spy = _NeverCalled("compose_up")
            with patch(f"{_PRIM}.get_running_profiles", return_value={"codex"}), \
                 patch(f"{_PRIM}.compose_up", side_effect=spy), \
                 patch(f"{_PRIM}.wait_for_gateway_healthy", return_value=True):
                resp = authed_client.post(
                    "/api/v1/profiles/claude/up" + qs, headers={"Host": VALID_HOST_HDR}
                )
            assert resp.status_code == 409, (
                f"FINDING (CRITICAL, R-m): query param {qs!r} altered mutex behaviour "
                f"(status {resp.status_code}). A force override exists. Escalate."
            )
            assert spy.calls == []


# ===========================================================================
# 6. AUTH / CSRF BEFORE EFFECT  (AC-27-P2-13)
# ===========================================================================
#
# Containment claim: up/down/switch without auth OR without CSRF are rejected BEFORE any
# lock or subprocess effect. We prove "before any effect" with a tripwire on
# get_running_profiles (the first thing inside the lock) and compose_up.


class TestAuthCsrfBeforeEffect:
    """Unauth / no-CSRF lifecycle calls are rejected before any lock or compose effect."""

    def test_up_without_session_no_lock_no_compose(self, client):
        state_spy = _NeverCalled("get_running_profiles")
        up_spy = _NeverCalled("compose_up")
        health = client.get("/api/v1/health")
        csrf = health.json().get("csrf_token", "")
        with patch(f"{_PRIM}.get_running_profiles", side_effect=state_spy), \
             patch(f"{_PRIM}.compose_up", side_effect=up_spy):
            headers = {"Host": VALID_HOST_HDR}
            if csrf:
                headers["X-CSRF-Token"] = csrf
            resp = client.post("/api/v1/profiles/codex/up", headers=headers)
        assert resp.status_code in (401, 403), (
            f"FINDING: unauthenticated up returned {resp.status_code}; expected 401/403."
        )
        assert state_spy.calls == [] and up_spy.calls == [], (
            "FINDING (CRITICAL): an unauthenticated up reached the lock/compose boundary. "
            "Auth is not enforced before effect (R-m). Escalate."
        )

    def test_up_without_csrf_no_lock_no_compose(self, client):
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET}, headers={"Host": VALID_HOST_HDR})
        assert login.status_code == 200
        state_spy = _NeverCalled("get_running_profiles")
        up_spy = _NeverCalled("compose_up")
        with patch(f"{_PRIM}.get_running_profiles", side_effect=state_spy), \
             patch(f"{_PRIM}.compose_up", side_effect=up_spy):
            resp = client.post("/api/v1/profiles/codex/up", headers={"Host": VALID_HOST_HDR})
        assert resp.status_code == 403, (
            f"FINDING: up without CSRF returned {resp.status_code}; expected 403 (CSRF gate)."
        )
        assert state_spy.calls == [] and up_spy.calls == [], (
            "FINDING (CRITICAL): an up with no CSRF token reached the lock/compose boundary "
            "(R-m). Escalate."
        )

    def test_down_without_csrf_no_compose(self, client):
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET}, headers={"Host": VALID_HOST_HDR})
        assert login.status_code == 200
        down_spy = _NeverCalled("compose_down")
        state_spy = _NeverCalled("get_running_profiles")
        with patch(f"{_PRIM}.get_running_profiles", side_effect=state_spy), \
             patch(f"{_PRIM}.compose_down", side_effect=down_spy):
            resp = client.post("/api/v1/profiles/codex/down", headers={"Host": VALID_HOST_HDR})
        assert resp.status_code == 403
        assert down_spy.calls == [] and state_spy.calls == []

    def test_switch_without_csrf_no_compose(self, client):
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET}, headers={"Host": VALID_HOST_HDR})
        assert login.status_code == 200
        up_spy = _NeverCalled("compose_up")
        down_spy = _NeverCalled("compose_down")
        with patch(f"{_PRIM}.compose_up", side_effect=up_spy), \
             patch(f"{_PRIM}.compose_down", side_effect=down_spy):
            resp = client.post(
                "/api/v1/profiles/switch", json={"from": "codex", "to": "claude"},
                headers={"Host": VALID_HOST_HDR},
            )
        assert resp.status_code == 403, (
            f"FINDING: switch without CSRF returned {resp.status_code}; expected 403."
        )
        assert up_spy.calls == [] and down_spy.calls == []

    def test_forged_host_blocks_up_before_effect(self, client):
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET}, headers={"Host": VALID_HOST_HDR})
        csrf = login.json()["csrf_token"]
        up_spy = _NeverCalled("compose_up")
        state_spy = _NeverCalled("get_running_profiles")
        with patch(f"{_PRIM}.get_running_profiles", side_effect=state_spy), \
             patch(f"{_PRIM}.compose_up", side_effect=up_spy):
            resp = client.post(
                "/api/v1/profiles/codex/up",
                headers={"Host": "evil.attacker.com", "X-CSRF-Token": csrf},
            )
        assert resp.status_code == 403
        assert up_spy.calls == [] and state_spy.calls == [], (
            "FINDING (CRITICAL): a forged-Host up reached the lock/compose boundary; Host "
            "validation does not short-circuit before effect (R-s / R-m). Escalate."
        )
