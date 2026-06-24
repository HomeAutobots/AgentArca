"""
test_redteam_phase1.py - Adversarial CONTAINMENT suite for the Phase 1 admin
control plane (egress allowlist management + read-only logs).

Framing (red-teamer role, SPEC-27-P1, R-q / R-b / R-r):

  ASSUME THE ATTACKER CAN REACH THE API. The operator's browser is hostile, or
  auth was somehow obtained. We do NOT test "can injection be prevented" (it
  cannot). We test CONTAINMENT: given a hostile request that reaches the write
  surface, can the attacker

    (a) widen egress in a way the validation should stop,
    (b) inject through the API into the shell primitive (allowlist-local.sh),
    (c) exfiltrate the admin secret or tamper the audit trail,
    (d) mutate a read-only log surface, or
    (e) bypass the wrap-don't-reimplement boundary so Python writes the overlay /
        calls the proxy / sends a reconfigure signal directly?

  Every test asserts an attack FAILS. A failing assertion in this file is a REAL
  boundary FINDING, not a flaky test. If a hostile metacharacter reaches the shell,
  or a write happens on a rejected input, or the secret lands in an audit record,
  that is a CRITICAL finding to escalate to threat-modeler and security-reviewer.

This file is DISTINCT from the functional Phase 1 suite (test_allowlist_api.py,
test_allowlist_onecodepath.py, test_logs_api.py, test_allowlist_primitive.py),
which proves the controls are CONFIGURED correctly. This file proves they CONTAIN
an attacker: large hostile-input batteries, double-validation proof (API + shell),
audit-tamper / secret-exfil enumeration, read-only-logs immutability, auth/CSRF
gating BEFORE any file/subprocess effect, and a static + behavioral proof of the
wrap boundary.

Coverage map (-> threat reference):
  Class TestShellInjectionBatteryAPI       -> R-b / R-q, AC-27-P1-02 (validation bypass)
  Class TestShellDoubleValidationBehavioral-> ADR-010 D2.1 (the shell's own gate holds)
  Class TestDeletePathParamInjection       -> R-b / R-q (DELETE {host:path} injection)
  Class TestNoWriteOnRejectedInput         -> R-b (rejected add never writes overrides.conf)
  Class TestAuditTamperAndSecretExfil      -> R-r (audit no-tamper; secret never exfil'd)
  Class TestReadOnlyLogsImmutability       -> AC-27-P1-13 / 16 (read-only logs)
  Class TestLogReaderPathTraversal         -> R-r (log readers can't read arbitrary files)
  Class TestAuthCsrfBeforeEffect           -> AC-27-P1-08 (no effect before auth/CSRF)
  Class TestWrapBoundaryCannotBeTricked    -> SPEC-27-P1 s11 assertions 7+8 (wrap boundary)

Non-determinism note: Phase 1's injection guard is a DETERMINISTIC string/regex
validator (is_valid_host) backed by the shell's own valid_host(), not a model
judgement. So each adversarial input is run as a parametrized battery (every input,
every time) rather than a stochastic trial. The red-teamer "report attack-success-
rate, not one clean run" discipline is honored by the breadth of the battery and by
TestShellInjectionBatteryAPI.test_battery_attack_success_rate, which aggregates the
whole battery and asserts a 0% success rate (0 writes, 0 subprocess calls, 0
non-rejections) across all inputs.

Default suite is Docker-free: the subprocess wrapper (run_add / run_remove /
run_reload) is mocked so an injection test can NEVER touch a live gateway, and the
overrides dir is redirected into a temp dir. The single behavioral shell-gate class
runs allowlist-local.sh directly against a temp REPO_ROOT (no Docker, no gateway).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings  # noqa: E402
from src.admin.main import create_app  # noqa: E402
from src.admin.primitives.allowlist import AllowlistResult, is_valid_host  # noqa: E402

TEST_SECRET = "test-secret-value-12345"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"
VALID_HOST_HDR = f"{TEST_HOST}:{TEST_PORT}"
SCRIPT_PATH = REPO_ROOT / "src" / "scripts" / "allowlist-local.sh"


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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RT1",
        audit_log_path=tmp_audit,
        session_secret_key="test-session-key-aaabbbccc" * 4,
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
    resp = client.post("/api/v1/login", json={"secret": TEST_SECRET})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    csrf = resp.json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": csrf})
    return client


def _audit_lines(audit_path: Path) -> list[dict]:
    if not audit_path.exists():
        return []
    out = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def _last_audit(audit_path: Path) -> dict:
    lines = _audit_lines(audit_path)
    assert lines, "Audit log is empty"
    return lines[-1]


class _NeverCalled:
    """A subprocess-wrapper stand-in that records and FAILS if ever invoked.

    Used to prove that a rejected/injection input never reaches the subprocess
    boundary (and therefore never reaches allowlist-local.sh, squid, or SIGHUP).
    """

    def __init__(self, label: str = "subprocess"):
        self.label = label
        self.calls: list = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError(
            f"FINDING (CRITICAL): {self.label} wrapper was invoked with "
            f"args={args!r} kwargs={kwargs!r}. A rejected/hostile input reached "
            f"the shell-primitive boundary -- the API-layer validation gate was "
            f"bypassed (R-b / R-q). Escalate to threat-modeler + security-reviewer."
        )


# ===========================================================================
# THE HOSTILE-HOST BATTERY  (the core Phase 1 attack surface)
# ===========================================================================
#
# Every value here is a host an attacker submits to widen egress or break out of
# the value's intended use as a literal SNI written verbatim into squid.conf and
# passed as a single argv to allowlist-local.sh. Each entry: (label, value).
# Every one MUST be rejected by is_valid_host AND must never reach run_add/run_remove.

HOSTILE_HOSTS = [
    # --- shell metacharacters / command substitution ---
    ("semicolon_cmd", "evil.com; cat /etc/passwd"),
    ("pipe_cmd", "evil.com|id"),
    ("amp_background", "evil.com&id"),
    ("double_amp", "evil.com&&id"),
    ("dollar_paren_subst", "evil.com$(cat /etc/passwd)"),
    ("backtick_subst", "evil.com`id`"),
    ("dollar_brace", "evil.com${IFS}id"),
    ("redirect_out", "evil.com>/tmp/pwned"),
    ("redirect_append", "evil.com>>/tmp/pwned"),
    ("redirect_in", "evil.com</etc/passwd"),
    ("subshell_paren", "evil.com(id)"),
    ("logical_or", "evil.com||id"),
    ("glob_star", "evil*.com"),
    ("glob_question", "evil?.com"),
    ("brace_expansion", "evil{a,b}.com"),
    ("tilde_home", "~/.ssh/id_rsa"),
    ("env_expand", "$HOME.com"),
    ("space_arg_split", "evil.com other.com"),
    ("tab_arg_split", "evil.com\tother.com"),
    # --- newline / CRLF / squid.conf breakout ---
    ("newline_acl_breakout", "a.com\nacl allowed_SNI ssl::server_name evil.com"),
    ("crlf_breakout", "a.com\r\nacl allowed_SNI ssl::server_name evil.com"),
    ("newline_only", "a.com\nevil.com"),
    ("carriage_return", "a.com\revil.com"),
    ("squid_comment_inject", "a.com #all"),
    ("squid_directive_inject", "a.com http_access allow all"),
    ("leading_acl_line", "acl allowed_SNI ssl::server_name evil.com"),
    # --- null byte / control chars ---
    ("null_byte_mid", "a.com\x00.evil.com"),
    ("null_byte_suffix", "a.com\x00"),
    ("bell_char", "a.com\x07"),
    ("vertical_tab", "a.com\x0b.com"),
    ("form_feed", "a.com\x0c.com"),
    # --- wildcards (the leading-dot is the ONLY sanctioned wildcard) ---
    ("star_subdomain", "*.example.com"),
    ("bare_star", "*"),
    ("star_tld", "example.*"),
    ("double_star", "**.example.com"),
    # --- schemes / URLs / userinfo ---
    ("http_scheme", "http://evil.com"),
    ("https_scheme", "https://evil.com"),
    ("scheme_only", "://evil.com"),
    ("userinfo_at", "user@evil.com"),
    ("url_with_path", "evil.com/path"),
    ("url_with_query", "evil.com?x=1"),
    ("url_with_port", "evil.com:8080"),
    ("url_with_frag", "evil.com#frag"),
    # --- path traversal as a host ---
    ("path_traversal", "../../../etc/passwd"),
    ("abs_path", "/etc/passwd"),
    ("dotdot_host", "..evil.com"),
    ("dotdot_mid", "a..com"),
    # --- args injection (leading dash) ---
    ("dash_x", "-x"),
    ("dash_dash", "--"),
    ("dash_dash_help", "--help"),
    ("dash_flag_value", "-rf"),
    ("dash_o_file", "-o/tmp/x"),
    # --- oversize ---
    ("oversize_254", "a" * 250 + ".com"),         # 254 chars > 253 cap
    ("oversize_huge", ("a." * 5000) + "com"),      # ~10k chars
    ("oversize_label_64", ("a" * 1000) + ".com"),
    # --- unicode / IDN homoglyph (must be rejected: ASCII-only grammar) ---
    ("unicode_cyrillic", "exаmple.com"),       # cyrillic 'a'
    ("unicode_fullwidth", "ｅxample.com"),
    ("unicode_combining", "á.com"),
    # NOTE: punycode (xn--...) labels are PURE ASCII and are the INTENDED on-the-wire
    # representation of an IDN. They are legitimately ACCEPTED by the ASCII-only grammar
    # and appear in LEGITIMATE_HOSTS below, NOT here. The homoglyph defense is exactly
    # that a raw-unicode lookalike (unicode_cyrillic above) is rejected while its
    # punycode form is allowed.
    ("emoji", "\U0001f600.com"),
    # --- whitespace / empty / dot edge cases ---
    ("empty", ""),
    ("just_dot", "."),
    ("just_dots", "..."),
    ("trailing_space", "evil.com "),
    ("leading_space", " evil.com"),
    ("internal_space", "ev il.com"),
    ("only_whitespace", "   "),
    ("no_dot_bare_label", "localhost"),
    ("trailing_dot", "evil.com."),
    ("double_leading_dot", "..example.com"),
    ("numeric_tld", "evil.123"),
    ("hyphen_tld", "evil.co-m"),
    ("ip_literal", "192.168.1.1"),
    ("ipv6_literal", "[::1]"),
]

# A couple of these are intentionally VALID-shaped to prove the battery is not
# over-broad (a battery that rejects everything proves nothing). We assert these
# are ACCEPTED, so the rejection assertions on the rest are meaningful.
LEGITIMATE_HOSTS = [
    ("plain_fqdn", "api.example.com"),
    ("leading_dot_wildcard", ".internal.example.com"),
    ("multi_label", "sub.sub.example.co.uk"),
    ("mixed_case", "api.EXAMPLE.com"),
    ("punycode_label", "xn--bcher-kva.example.com"),  # IDN punycode is ASCII -> valid
    ("hyphenated_label", "my-api.example.com"),
]


# ===========================================================================
# 1. VALIDATION-BYPASS / SHELL-INJECTION THROUGH THE API  (R-b / R-q)
# ===========================================================================
#
# Containment claim: every hostile host is REJECTED with 400 at the API layer
# (is_valid_host), the subprocess wrapper run_add is NEVER invoked (so the value
# never reaches allowlist-local.sh / squid / SIGHUP), and the rejection is audited.


class TestShellInjectionBatteryAPI:
    """Every hostile host POSTed to /api/v1/allowlist/entries is rejected with no subprocess effect."""

    @pytest.mark.parametrize("label,host", LEGITIMATE_HOSTS, ids=[h[0] for h in LEGITIMATE_HOSTS])
    def test_legitimate_hosts_are_accepted_battery_is_not_vacuous(self, label, host):
        """Sanity: the legitimate-shaped hosts ARE accepted, so the rejection battery is meaningful."""
        assert is_valid_host(host), (
            f"Battery sanity FAILED: legitimate host {label!r}={host!r} was rejected by "
            f"is_valid_host. If even valid hosts are rejected, the rejection battery below "
            f"proves nothing. Loosen the validator or fix this case."
        )

    @pytest.mark.parametrize("label,host", HOSTILE_HOSTS, ids=[h[0] for h in HOSTILE_HOSTS])
    def test_hostile_host_rejected_400_no_subprocess(self, authed_client, tmp_audit, label, host):
        """
        POST hostile host -> 400, run_add NEVER called (value never reached the shell),
        and a rejected-by-validation audit record is written.
        """
        spy = _NeverCalled("run_add")
        before = len(_audit_lines(tmp_audit))
        with patch("src.admin.routes.allowlist.run_add", side_effect=spy):
            resp = authed_client.post("/api/v1/allowlist/entries", json={"host": host})

        assert resp.status_code == 400, (
            f"FINDING: hostile host {label!r}={host!r} returned {resp.status_code}, not 400. "
            f"Validation-bypass / egress-widening hole (R-b)."
        )
        assert spy.calls == [], (
            f"FINDING (CRITICAL): hostile host {label!r} reached the subprocess wrapper. "
            f"Injection into allowlist-local.sh is possible (R-q)."
        )
        # Rejection must be audited (R-r: an attempted attack is on the record).
        after_lines = _audit_lines(tmp_audit)
        assert len(after_lines) > before, (
            f"FINDING: rejected add of {label!r} was NOT audited. An attempted egress "
            f"widening left no trail (R-r)."
        )
        rec = after_lines[-1]
        assert rec["action"] == "allowlist_add"
        assert rec["outcome"] == "rejected-by-validation", (
            f"FINDING: rejected add of {label!r} recorded with wrong outcome {rec['outcome']!r}."
        )

    @pytest.mark.parametrize("label,host", HOSTILE_HOSTS, ids=[h[0] for h in HOSTILE_HOSTS])
    def test_hostile_host_is_valid_host_layer_rejects(self, label, host):
        """Pure-unit: the API-layer validator itself rejects every hostile host."""
        assert is_valid_host(host) is False, (
            f"FINDING (CRITICAL): is_valid_host ACCEPTED hostile host {label!r}={host!r}. "
            f"The double-validation top layer is broken; this value would be written verbatim "
            f"into squid.conf and passed as argv to the shell (R-q)."
        )

    def test_battery_attack_success_rate(self, authed_client, tmp_audit):
        """
        Aggregate the WHOLE battery and report the attack-success-rate. Containment
        requires a 0% success rate: 0 non-400 responses, 0 subprocess calls, 0 writes.

        This is the red-teamer "report a rate, not a single clean run" assertion: it
        runs every hostile input in one shot and fails loudly with the exact offenders
        if ANY slipped through.
        """
        successes = []  # any input that was NOT contained
        total_subprocess_calls = 0
        for label, host in HOSTILE_HOSTS:
            spy = _NeverCalled("run_add")
            with patch("src.admin.routes.allowlist.run_add", side_effect=spy):
                try:
                    resp = authed_client.post("/api/v1/allowlist/entries", json={"host": host})
                    code = resp.status_code
                except AssertionError:
                    # _NeverCalled fired -> the value reached the shell boundary. Worst case.
                    successes.append((label, "REACHED_SUBPROCESS"))
                    total_subprocess_calls += 1
                    continue
            if code != 400:
                successes.append((label, f"status={code}"))
            total_subprocess_calls += len(spy.calls)

        rate = len(successes) / len(HOSTILE_HOSTS)
        assert total_subprocess_calls == 0, (
            f"FINDING (CRITICAL): {total_subprocess_calls} hostile input(s) reached the "
            f"subprocess wrapper across the battery. Shell injection is live (R-q)."
        )
        assert rate == 0.0, (
            f"FINDING: attack-success-rate = {rate:.1%} ({len(successes)}/{len(HOSTILE_HOSTS)}). "
            f"Validation-bypass containment is NOT total. Offenders: {successes}"
        )


# ===========================================================================
# 2. SHELL DOUBLE-VALIDATION (BEHAVIORAL)  (ADR-010 D2.1)
# ===========================================================================
#
# Containment claim: even if the Python validator were somehow bypassed, the shell
# script's OWN valid_host() is a second gate that holds. We drive allowlist-local.sh
# directly (no Docker, no gateway) against a temp REPO_ROOT and prove that hostile
# inputs are rejected, no overrides.conf is written, and no injected command runs.
#
# This is the "prove the shell's double-validation holds" requirement, behaviorally.


# A focused subset that exercises real shell-dangerous constructs end-to-end through
# the actual script. We keep this list tight (subprocess-per-case is slow) but cover
# the command-execution, file-write, and squid-breakout classes.
SHELL_INJECTION_INPUTS = [
    ("semicolon_cmd", "evil.com; touch INJECTED"),
    ("dollar_paren", "evil.com$(touch INJECTED)"),
    ("backtick", "evil.com`touch INJECTED`"),
    ("pipe", "evil.com|touch INJECTED"),
    ("amp", "evil.com&touch INJECTED"),
    ("redirect", "evil.com>INJECTED"),
    ("newline_breakout", "a.com\nacl allowed_SNI ssl::server_name evil.com"),
    ("glob_star", "*.evil.com"),
    ("dash_x_arginject", "-x"),
    ("dash_dash_arginject", "--"),
    ("null_byte", "a.com\x00.evil.com"),
]


@pytest.fixture()
def shell_repo(tmp_path):
    """
    Build a disposable REPO_ROOT containing only allowlist-local.sh so we can run the
    real script with no Docker and no gateway. detect_gateway() returns "" when no
    container is running, so add/remove operate purely on the local overrides file.
    """
    scripts_dir = tmp_path / "src" / "scripts"
    scripts_dir.mkdir(parents=True)
    (tmp_path / "config" / "allowlist.local.d").mkdir(parents=True)
    script_dst = scripts_dir / "allowlist-local.sh"
    script_dst.write_text(SCRIPT_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(script_dst, 0o755)
    return tmp_path


class TestShellDoubleValidationBehavioral:
    """The shell script's own valid_host() is a real second gate; injection does not execute."""

    def _run(self, shell_repo: Path, verb: str, host: str):
        """
        Run the real script. Returns the CompletedProcess, or None if the OS layer
        refused to spawn the process at all (e.g. an embedded null byte in argv, which
        subprocess rejects with ValueError BEFORE execve). A None return is itself a
        containment outcome: the hostile value never reached the shell -- argv with a
        NUL cannot be passed to a C program, so no exec and no write can occur.
        """
        script = shell_repo / "src" / "scripts" / "allowlist-local.sh"
        env = dict(os.environ)
        env["AGENTARCA_PROFILE"] = ""  # force "no gateway" branch; never touch Docker
        try:
            return subprocess.run(
                ["bash", str(script), verb, host],
                capture_output=True, text=True, timeout=30,
                cwd=str(shell_repo), env=env,
            )
        except ValueError:
            # Embedded null byte (or similar argv that cannot reach execve). The process
            # was never spawned -> no exec, no write. Strongest possible containment.
            return None

    @pytest.mark.parametrize("label,host", SHELL_INJECTION_INPUTS, ids=[h[0] for h in SHELL_INJECTION_INPUTS])
    def test_shell_rejects_injection_no_exec_no_write(self, shell_repo, label, host):
        """
        Drive the real allowlist-local.sh add <hostile>. The hostile input must be
        contained, either by (a) the OS refusing to spawn the process (null byte in
        argv -> ValueError before execve, so _run returns None), or (b) the shell's
        valid_host() rejecting it (non-zero exit). In neither case may the injected side
        effect (INJECTED file) appear, nor may overrides.conf gain the hostile value.
        (overrides.conf is not even created, because ensure_file runs only AFTER
        valid_host passes.)
        """
        overrides = shell_repo / "config" / "allowlist.local.d" / "overrides.conf"
        injected_marker = shell_repo / "INJECTED"

        proc = self._run(shell_repo, "add", host)

        if proc is None:
            # OS refused to spawn (e.g. null byte). The value never reached the shell.
            assert not injected_marker.exists(), (
                f"FINDING (CRITICAL): {label!r} executed a command despite the process "
                f"never being spawned -- impossible unless a write path runs elsewhere."
            )
            assert not overrides.exists(), (
                f"FINDING (CRITICAL): {label!r} mutated overrides.conf though the script "
                f"was never spawned (R-b)."
            )
            return

        assert proc.returncode != 0, (
            f"FINDING (CRITICAL): shell allowlist-local.sh ACCEPTED injection input "
            f"{label!r}={host!r} (exit 0). The shell-layer valid_host() gate is broken; "
            f"this value was written verbatim into squid.conf (R-q)."
        )
        assert not injected_marker.exists(), (
            f"FINDING (CRITICAL): injection input {label!r} EXECUTED a command in the "
            f"shell (the INJECTED marker file was created). Command injection through "
            f"allowlist-local.sh (R-q). Escalate immediately."
        )
        # The hostile value must never appear in the overrides file.
        if overrides.exists():
            content = overrides.read_text(encoding="utf-8")
            # Strip the value down to its first line to detect a breakout that wrote a
            # second acl line.
            assert "evil.com" not in content, (
                f"FINDING (CRITICAL): injection input {label!r} wrote a hostile entry "
                f"('evil.com') into overrides.conf. squid.conf breakout (R-q):\n{content}"
            )

    def test_shell_accepts_legitimate_host_not_vacuous(self, shell_repo):
        """Control: a legitimate host IS accepted and written, so the rejection proofs are meaningful."""
        overrides = shell_repo / "config" / "allowlist.local.d" / "overrides.conf"
        proc = self._run(shell_repo, "add", "api.example.com")
        assert proc.returncode == 0, (
            f"Shell rejected a legitimate host (rc={proc.returncode}); the injection "
            f"rejection battery would be vacuous. stderr={proc.stderr!r}"
        )
        assert overrides.exists()
        content = overrides.read_text(encoding="utf-8")
        assert "acl allowed_SNI ssl::server_name api.example.com" in content


# ===========================================================================
# 3. DELETE {host:path} PARAMETER INJECTION  (R-b / R-q)
# ===========================================================================
#
# Containment claim: the DELETE host path param (which uses {host:path}, so it can
# contain slashes) is URL-decoded then validated. No hostile value reaches run_remove,
# and path-traversal / metacharacters are rejected (400) or routed away (404/405).


DELETE_INJECTION_PATHS = [
    ("encoded_traversal", "/api/v1/allowlist/entries/..%2f..%2fetc%2fpasswd"),
    ("raw_traversal", "/api/v1/allowlist/entries/../../etc/passwd"),
    ("encoded_semicolon", "/api/v1/allowlist/entries/evil.com%3Bid"),
    ("raw_semicolon", "/api/v1/allowlist/entries/evil.com;id"),
    ("encoded_pipe", "/api/v1/allowlist/entries/evil.com%7Cid"),
    ("encoded_dollar", "/api/v1/allowlist/entries/evil.com%24(id)"),
    ("encoded_backtick", "/api/v1/allowlist/entries/evil.com%60id%60"),
    ("encoded_newline_acl", "/api/v1/allowlist/entries/a.com%0aacl"),
    ("encoded_null", "/api/v1/allowlist/entries/a.com%00.evil.com"),
    ("star_wildcard", "/api/v1/allowlist/entries/*.example.com"),
    ("scheme", "/api/v1/allowlist/entries/http://evil.com"),
    ("encoded_space", "/api/v1/allowlist/entries/evil.com%20other.com"),
    ("dash_x", "/api/v1/allowlist/entries/-x"),
    ("ip_literal", "/api/v1/allowlist/entries/192.168.1.1"),
    ("etc_passwd_abs", "/api/v1/allowlist/entries/%2fetc%2fpasswd"),
    ("double_encoded_traversal", "/api/v1/allowlist/entries/%252e%252e%252fetc"),
]

_REJECTED_DELETE_STATUSES = {400, 404, 405}


class TestDeletePathParamInjection:
    """Hostile DELETE host path params never reach run_remove and never widen/leak."""

    @pytest.mark.parametrize("label,path", DELETE_INJECTION_PATHS, ids=[p[0] for p in DELETE_INJECTION_PATHS])
    def test_delete_injection_rejected_no_subprocess(self, authed_client, label, path):
        """
        DELETE with a hostile host path param is rejected (400/404/405 depending on how
        far it gets through routing) and run_remove is NEVER invoked. The critical
        invariant is the subprocess one: no hostile value reaches allowlist-local.sh.
        """
        spy = _NeverCalled("run_remove")
        with patch("src.admin.routes.allowlist.run_remove", side_effect=spy):
            resp = authed_client.delete(path)

        assert resp.status_code in _REJECTED_DELETE_STATUSES, (
            f"FINDING: DELETE injection {label!r} ({path}) returned {resp.status_code}; "
            f"expected one of {_REJECTED_DELETE_STATUSES} (containment). A 200 here would "
            f"mean a hostile host removal/injection succeeded (R-b)."
        )
        assert resp.status_code != 200
        assert spy.calls == [], (
            f"FINDING (CRITICAL): DELETE injection {label!r} reached run_remove. The host "
            f"path param flowed unvalidated into allowlist-local.sh (R-q)."
        )

    def test_delete_legitimate_host_does_reach_remove_not_vacuous(self, authed_client):
        """Control: a legitimate host DELETE DOES reach run_remove, so the battery is meaningful."""
        reached = {"n": 0}

        def ok_remove(host, *a, **k):
            reached["n"] += 1
            assert host == "api.example.com"
            return AllowlistResult(ok=True, idempotent=True, returncode=0, stdout="was not present")

        with patch("src.admin.routes.allowlist.run_remove", side_effect=ok_remove):
            resp = authed_client.delete("/api/v1/allowlist/entries/api.example.com")
        assert resp.status_code == 200
        assert reached["n"] == 1, (
            "Control FAILED: a legitimate DELETE did not reach run_remove; the injection "
            "battery above would be vacuous."
        )


# ===========================================================================
# 4. NO WRITE ON REJECTED INPUT  (R-b)
# ===========================================================================
#
# Containment claim: a rejected add never mutates overrides.conf. We prove this two
# ways: (1) behaviorally through the real shell (rejected add does not even CREATE
# the file), and (2) at the API layer (rejected POST never calls the wrapper, so no
# write path is reachable).


class TestNoWriteOnRejectedInput:
    """A rejected add produces zero mutation of the overlay file."""

    def test_rejected_add_does_not_write_overrides_via_shell(self, tmp_path):
        """
        Run the REAL script with a hostile host against a fresh temp repo. The overrides
        file must not exist afterward (ensure_file runs only after valid_host passes), and
        certainly must not contain the hostile value.
        """
        scripts_dir = tmp_path / "src" / "scripts"
        scripts_dir.mkdir(parents=True)
        (tmp_path / "config" / "allowlist.local.d").mkdir(parents=True)
        script = scripts_dir / "allowlist-local.sh"
        script.write_text(SCRIPT_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(script, 0o755)
        overrides = tmp_path / "config" / "allowlist.local.d" / "overrides.conf"

        env = dict(os.environ)
        env["AGENTARCA_PROFILE"] = ""
        proc = subprocess.run(
            ["bash", str(script), "add", "evil.com; cat /etc/passwd"],
            capture_output=True, text=True, timeout=30, cwd=str(tmp_path), env=env,
        )
        assert proc.returncode != 0
        assert not overrides.exists(), (
            "FINDING: a REJECTED add created/modified overrides.conf. A rejected input "
            "must produce ZERO file mutation (R-b)."
        )

    def test_rejected_add_no_wrapper_call_no_write_path(self, authed_client, tmp_audit):
        """
        At the API layer: a rejected POST never invokes run_add. Since run_add is the
        ONLY path to a write (the wrapper -> allowlist-local.sh -> overrides.conf), no
        write is reachable. We assert the wrapper is never called and the response is 400.
        """
        spy = _NeverCalled("run_add")
        with patch("src.admin.routes.allowlist.run_add", side_effect=spy):
            resp = authed_client.post(
                "/api/v1/allowlist/entries",
                json={"host": "evil.com\nacl allowed_SNI ssl::server_name attacker.com"},
            )
        assert resp.status_code == 400
        assert spy.calls == [], (
            "FINDING (CRITICAL): a rejected add reached run_add. The only write path is "
            "now reachable from a rejected input (R-b)."
        )


# ===========================================================================
# 5. AUDIT TAMPER / SECRET EXFIL  (R-r / R-q)
# ===========================================================================
#
# Containment claim: no allowlist/logs route can read-back, delete, truncate, or
# rotate the audit log; a rejected add is itself audited; the admin secret -- even
# when submitted AS a host or in odd fields -- never lands in an audit record or any
# response body; the secret-sanitization cannot be bypassed.

SECRET_CANARY = "RT-PHASE1-SECRET-CANARY-9f8e7d"


@pytest.fixture()
def canary_settings(tmp_path):
    secret_file = tmp_path / "admin-secret"
    secret_file.write_text(SECRET_CANARY + "\n", encoding="utf-8")
    os.chmod(secret_file, 0o600)
    return Settings(
        host=TEST_HOST,
        port=TEST_PORT,
        allow_non_loopback=False,
        secret_file=secret_file,
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RT_CANARY",
        audit_log_path=tmp_path / "canary-audit.jsonl",
        session_secret_key="canary-rt-session-key-aaabbbccc" * 4,
    )


@pytest.fixture()
def canary_client(canary_settings):
    from starlette.testclient import TestClient
    app = create_app(canary_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HDR})
        resp = c.post("/api/v1/login", json={"secret": SECRET_CANARY})
        assert resp.status_code == 200
        csrf = resp.json()["csrf_token"]
        c.headers.update({"X-CSRF-Token": csrf})
        yield c, canary_settings.audit_log_path


class TestAuditTamperAndSecretExfil:
    """No tamper route; rejections audited; secret never in records or bodies."""

    # Paths an attacker would probe to read or destroy the audit log via the
    # allowlist/logs surfaces.
    AUDIT_TAMPER_PATHS = [
        "/api/v1/logs/audit",
        "/api/v1/logs/audit/truncate",
        "/api/v1/logs/audit/rotate",
        "/api/v1/logs/audit/delete",
        "/api/v1/allowlist/audit",
        "/api/v1/audit",
        "/api/v1/admin-audit.jsonl",
    ]

    @pytest.mark.parametrize("path", AUDIT_TAMPER_PATHS)
    @pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH", "POST"])
    def test_no_route_can_tamper_audit_log(self, authed_client, path, method):
        """
        No mutating method on any audit-ish path may succeed. Acceptable outcomes are
        405 (route exists, method forbidden) or 404 (no such route). A 200/201/204
        would mean the audit log is mutable through the API (R-r CRITICAL).
        """
        resp = authed_client.request(method, path, json={})
        assert resp.status_code not in (200, 201, 202, 204), (
            f"FINDING (CRITICAL): {method} {path} returned {resp.status_code}. The audit "
            f"log is reachable for tamper/rotate/delete through the API (R-r). Escalate."
        )
        assert resp.status_code in (401, 403, 404, 405), (
            f"Unexpected status {resp.status_code} for {method} {path}."
        )

    def test_audit_read_endpoint_cannot_truncate_via_query(self, authed_client, tmp_audit):
        """
        The audit READ endpoint must not expose any parameter that mutates the file.
        We hit it with adversarial query params and assert the file is byte-identical
        before/after (read is pure).
        """
        # Seed a record so there is something to (not) destroy.
        authed_client.post(
            "/api/v1/login", json={"secret": TEST_SECRET}
        )  # writes a login record
        before = tmp_audit.read_bytes() if tmp_audit.exists() else b""
        for qs in (
            "?limit=-1&offset=-1",
            "?limit=0",
            "?limit=999999999",
            "?offset=-999",
            "?truncate=1",
            "?mode=w",
            "?delete=true",
        ):
            resp = authed_client.get("/api/v1/logs/audit" + qs)
            assert resp.status_code == 200
        after = tmp_audit.read_bytes() if tmp_audit.exists() else b""
        assert after == before, (
            "FINDING (CRITICAL): a query parameter on the audit READ endpoint mutated the "
            "audit log file. The read path is not pure (R-r)."
        )

    def test_rejected_add_is_audited(self, authed_client, tmp_audit):
        """A rejected (attack) add is itself recorded as rejected-by-validation."""
        before = len(_audit_lines(tmp_audit))
        resp = authed_client.post(
            "/api/v1/allowlist/entries", json={"host": "evil.com; rm -rf /"}
        )
        assert resp.status_code == 400
        lines = _audit_lines(tmp_audit)
        assert len(lines) > before, (
            "FINDING: a rejected (attack) add was NOT audited (R-r)."
        )
        assert lines[-1]["outcome"] == "rejected-by-validation"
        assert lines[-1]["action"] == "allowlist_add"

    def test_secret_submitted_as_host_detail_field_is_sanitized(self, canary_client):
        """
        The DETAIL half of the sanitizer works: submit the admin secret AS the host. The
        validation-reject path builds detail = f"is_valid_host rejected: {host!r}" (which
        embeds the secret) and routes it through _sanitize_detail before the audit write.
        The audit record's DETAIL field must be the safe substitute, never the secret.

        This passes today and pins the WORKING boundary of the sanitizer, isolating the
        bypass proven by test_secret_in_audit_TARGET_field_FINDING below.
        """
        client, audit_path = canary_client
        resp = client.post("/api/v1/allowlist/entries", json={"host": SECRET_CANARY})
        assert resp.status_code in (400, 422)
        rec = _last_audit(audit_path)
        assert SECRET_CANARY not in (rec.get("detail") or ""), (
            "FINDING (CRITICAL): the admin secret leaked through the audit DETAIL field; "
            "the _sanitize_detail control is broken (R-r). Escalate."
        )
        assert "[sanitized" in (rec.get("detail") or ""), (
            "Expected the sanitized substitute string in the audit detail."
        )

    def test_secret_in_audit_TARGET_field_FINDING(self, canary_client):
        """
        Regression guard (Phase 1 red-team Finding 1, FIXED 2026-06-24): the secret submitted
        as a host must NOT appear anywhere in the audit record -- target/before/after, not just
        detail. _write_audit now sanitizes EVERY field at the single audit-write chokepoint
        (previously only detail was scrubbed, so target=host persisted the secret to the
        durable, GET /api/v1/logs/audit-readable trail). SPEC-27-P1 s6.3 / AC-27-P1-17.
        """
        client, audit_path = canary_client
        resp = client.post("/api/v1/allowlist/entries", json={"host": SECRET_CANARY})
        assert resp.status_code in (400, 422)
        content = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        assert SECRET_CANARY not in content, (
            "FINDING (BLOCK, R-r): the admin secret, submitted as a host, landed in the "
            "audit TARGET field -- the durable audit trail. The sanitizer covers only "
            "'detail', not 'target'. Secret persisted to a durable, log-API-readable sink. "
            "Escalate to threat-modeler + security-reviewer."
        )

    def test_secret_submitted_as_host_not_reflected_in_response_body(self, canary_client):
        """
        Regression guard (Phase 1 red-team Finding 2, FIXED 2026-06-24): the validation-reject
        400 response body must not echo the secret. add_entry/remove_entry now run the reflected
        host through _sanitize_detail() before putting it in the HTTP detail. SPEC-27-P1 s6.3.
        """
        client, _ = canary_client
        resp = client.post("/api/v1/allowlist/entries", json={"host": SECRET_CANARY})
        assert resp.status_code in (400, 422)
        assert SECRET_CANARY not in resp.text, (
            "FINDING: the admin secret, submitted as a host, was echoed back in the "
            "validation-reject response body (R-r, LOW; SPEC-27-P1 s6.3 'nor any response "
            "body'). Sanitize the 400 detail like the parse-error path does."
        )

    def test_secret_in_subprocess_stderr_is_sanitized(self, canary_client):
        """
        The wrap-boundary defense: if the subprocess stderr (parse error) ever contained
        the secret, the sanitizer must scrub it before the audit write and the response.
        We mock run_add to return a parse error carrying the secret canary.
        """
        client, audit_path = canary_client
        mock_result = AllowlistResult(
            ok=False,
            parse_error=f"config did not parse near {SECRET_CANARY}",
            detail="parse_gate_failed",
            returncode=1,
            stderr=f"config did not parse near {SECRET_CANARY}",
        )
        with patch("src.admin.routes.allowlist.run_add", return_value=mock_result):
            resp = client.post("/api/v1/allowlist/entries", json={"host": "api.example.com"})
        assert resp.status_code == 422
        assert SECRET_CANARY not in resp.text, (
            "FINDING (CRITICAL): secret leaked through a parse-error response body (R-r)."
        )
        content = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        assert SECRET_CANARY not in content, (
            "FINDING (CRITICAL): secret leaked into an audit record via parse-error detail; "
            "the sanitizer was bypassed (R-r)."
        )

    def test_secret_in_odd_json_fields_never_persisted(self, canary_client):
        """
        Stuff the secret into extra/odd JSON fields the endpoint does not model. Pydantic
        ignores unknown fields, but we assert defensively that nothing about the request
        causes the secret to be persisted or reflected.
        """
        client, audit_path = canary_client
        before = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        for body in (
            {"host": "api.example.com", "secret": SECRET_CANARY},
            {"host": "api.example.com", "detail": SECRET_CANARY},
            {"host": "api.example.com", "note": SECRET_CANARY},
        ):
            mock_result = AllowlistResult(ok=True, idempotent=False, returncode=0)
            with patch("src.admin.routes.allowlist.run_add", return_value=mock_result):
                resp = client.post("/api/v1/allowlist/entries", json=body)
            assert SECRET_CANARY not in resp.text, (
                f"FINDING (CRITICAL): secret in odd field {set(body) - {'host'}} was "
                f"reflected in the response (R-r)."
            )
        after = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        new_text = after[len(before):]
        assert SECRET_CANARY not in new_text, (
            "FINDING (CRITICAL): secret submitted in an odd JSON field landed in an audit "
            "record (R-r)."
        )


# ===========================================================================
# 6. READ-ONLY LOGS IMMUTABILITY  (AC-27-P1-13 / 16)
# ===========================================================================
#
# Containment claim: every /api/v1/logs/* path rejects POST/PUT/PATCH/DELETE with
# 405; no route table entry has a write method on a logs path; the egress/health
# readers cannot be coerced into a write.


class TestReadOnlyLogsImmutability:
    """Read-only logs reject every write method and expose no write route."""

    LOG_PATHS = [
        "/api/v1/logs/audit",
        "/api/v1/logs/egress",
        "/api/v1/logs/health",
        "/api/v1/logs",
        "/api/v1/logs/",
    ]
    WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]

    @pytest.mark.parametrize("path", LOG_PATHS)
    @pytest.mark.parametrize("method", WRITE_METHODS)
    def test_write_method_on_log_path_never_succeeds(self, authed_client, path, method):
        """No write method on any logs path may return a 2xx. 405 (or 404 for non-routes) only."""
        resp = authed_client.request(method, path, json={})
        assert resp.status_code not in (200, 201, 202, 204), (
            f"FINDING (CRITICAL): {method} {path} returned {resp.status_code}. A read-only "
            f"log surface accepted a write (AC-27-P1-13)."
        )
        assert resp.status_code in (404, 405), (
            f"FINDING: {method} {path} returned {resp.status_code}; expected 405 (or 404). "
            f"An unexpected 2xx/5xx may hide a write path."
        )

    def test_no_write_method_in_route_table_for_logs(self):
        """
        Route-table enumeration: no registered route under /api/v1/logs has a mutating
        method. This is the permanent regression barrier (AC-27-P1-16) -- a future edit
        that adds a write verb to a logs route is caught here.
        """
        from fastapi.routing import APIRoute

        tmp = Path(tempfile.mkdtemp())
        sf = tmp / "admin-secret"
        sf.write_text("route-enum-rt-secret\n", encoding="utf-8")
        os.chmod(sf, 0o600)
        settings = Settings(
            host="127.0.0.1", port=8080, allow_non_loopback=False, secret_file=sf,
            secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RT_ENUM",
            audit_log_path=tmp / "audit.jsonl",
            session_secret_key="route-enum-rt-session-key-aaabbbccc" * 4,
        )
        app = create_app(settings)

        all_routes = []
        for route in app.routes:
            if isinstance(route, APIRoute):
                all_routes.append(route)
            elif hasattr(route, "original_router"):
                for sub in getattr(route.original_router, "routes", []):
                    if isinstance(sub, APIRoute):
                        all_routes.append(sub)

        mutating = {"POST", "PUT", "PATCH", "DELETE"}
        violations = []
        for r in all_routes:
            if str(r.path).startswith("/api/v1/logs"):
                overlap = (r.methods or set()) & mutating
                if overlap:
                    violations.append((str(r.path), sorted(overlap)))
        assert not violations, (
            f"FINDING (CRITICAL): logs route(s) carry mutating methods (AC-27-P1-16): "
            f"{violations}. A write surface exists on read-only logs (R-r)."
        )


# ===========================================================================
# 7. LOG-READER PATH TRAVERSAL / ARBITRARY-FILE READ  (R-r)
# ===========================================================================
#
# Containment claim: no query/path parameter makes a log reader read an arbitrary
# host file, and the egress reader cannot be coerced into executing in a way that
# escapes read-only.


class TestLogReaderPathTraversal:
    """Log readers cannot be steered to an arbitrary file or a write."""

    def test_audit_reader_path_is_fixed_not_attacker_controlled(self, authed_client):
        """
        The audit reader reads app.state.audit_log_path (server-fixed). There is no
        request parameter to point it at /etc/passwd. We probe with traversal-shaped
        query params and assert the response only ever reflects the configured log
        (entries are JSON audit records or empty), never arbitrary file content.
        """
        for qs in (
            "?path=/etc/passwd",
            "?file=../../../../etc/passwd",
            "?audit_log_path=/etc/shadow",
            "?offset=0&limit=100&path=/etc/hosts",
        ):
            resp = authed_client.get("/api/v1/logs/audit" + qs)
            assert resp.status_code == 200
            body = resp.json()
            # The response shape is the audit pagination envelope, never raw file bytes.
            assert set(body.keys()) <= {"total_lines", "offset", "limit", "entries", "error"}, (
                f"FINDING: audit reader returned unexpected keys for {qs!r}: {set(body.keys())}. "
                f"A param may have redirected the read target (R-r)."
            )
            # No /etc/passwd content shape (root:x:0:0) should ever appear.
            assert "root:x:0:0" not in resp.text, (
                f"FINDING (CRITICAL): audit reader returned /etc/passwd content for {qs!r}. "
                f"Arbitrary-file read via the log endpoint (R-r). Escalate."
            )

    def test_egress_reader_uses_pinned_path_not_request_input(self):
        """
        Static containment: read_egress_log derives its file path ONLY from the
        AGENTARCA_ADMIN_ACCESS_LOG_PATH env var or a fixed docker-exec command, never
        from request input. The route handler passes no path through from the request.
        Confirm the route signature exposes no path/file parameter to the client.
        """
        import inspect

        from src.admin.routes import logs as logs_routes

        sig = inspect.signature(logs_routes.get_egress_log)
        client_params = {p for p in sig.parameters if p not in ("request",)}
        # Only pagination params may be client-controlled.
        assert client_params <= {"limit", "offset"}, (
            f"FINDING: the egress endpoint exposes client-controllable parameter(s) "
            f"{client_params - {'limit', 'offset'}} beyond pagination. A path/file param "
            f"would let a caller steer the reader at an arbitrary file (R-r)."
        )

    def test_egress_docker_exec_is_read_only_tail_no_shell(self):
        """
        Static containment: the egress reader's docker-exec command is a fixed argv list
        (no shell string), runs `tail` (read-only), and targets the pinned access.log.
        A shell string or a writing command here would be an escape. We assert the source
        contains the read-only tail invocation and NOT a shell pipe / write redirection.
        """
        src = (REPO_ROOT / "src" / "admin" / "primitives" / "logs.py").read_text(encoding="utf-8")
        # The exec must be an argv list with 'tail' and the pinned access.log.
        assert '"tail", "-n"' in src, (
            "FINDING: egress reader no longer uses the fixed `tail -n` argv. A changed "
            "command could escape read-only (R-r). Review primitives/logs.py."
        )
        assert "/var/log/squid/access.log" in src, (
            "FINDING: egress reader's target path is no longer the pinned access.log."
        )
        # No write verbs / shell redirection in the docker-exec command construction.
        # (Read-only: tail/cat only; never tee, dd, sh -c with redirection, rm, mv.)
        for forbidden in ("tee ", " rm ", " mv ", " dd "):
            assert forbidden not in src, (
                f"FINDING (CRITICAL): egress reader source contains a write-capable token "
                f"{forbidden!r}; the reader may not be read-only (R-r)."
            )


# ===========================================================================
# 8. AUTH / CSRF ON THE WRITE SURFACE  (AC-27-P1-08)
# ===========================================================================
#
# Containment claim: add/remove/reload without auth OR without CSRF are rejected
# BEFORE any file/subprocess effect. We prove the "before any effect" half by
# patching the wrapper with a tripwire that fails if it is ever reached.


class TestAuthCsrfBeforeEffect:
    """Unauth / no-CSRF writes are rejected before run_add/run_remove/run_reload runs."""

    def test_add_without_session_no_subprocess(self, client):
        """Unauthenticated add (no login) is rejected and never reaches run_add."""
        spy = _NeverCalled("run_add")
        # Acquire a CSRF token via health so the request is not merely CSRF-rejected;
        # this isolates the AUTH gate. If health yields no token, the no-CSRF path
        # (403) is also a valid containment outcome.
        health = client.get("/api/v1/health")
        csrf = health.json().get("csrf_token", "")
        with patch("src.admin.routes.allowlist.run_add", side_effect=spy):
            headers = {"X-CSRF-Token": csrf} if csrf else {}
            resp = client.post("/api/v1/allowlist/entries", json={"host": "api.example.com"}, headers=headers)
        assert resp.status_code in (401, 403), (
            f"FINDING: unauthenticated add returned {resp.status_code}; expected 401/403."
        )
        assert spy.calls == [], (
            "FINDING (CRITICAL): an unauthenticated add reached run_add. Auth is not "
            "enforced before the subprocess effect (R-r / R-b)."
        )

    def test_add_without_csrf_no_subprocess(self, client):
        """Authenticated add WITHOUT a CSRF token is 403 and never reaches run_add."""
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET})
        assert login.status_code == 200
        spy = _NeverCalled("run_add")
        with patch("src.admin.routes.allowlist.run_add", side_effect=spy):
            # Deliberately omit X-CSRF-Token.
            resp = client.post("/api/v1/allowlist/entries", json={"host": "api.example.com"})
        assert resp.status_code == 403, (
            f"FINDING: add without CSRF returned {resp.status_code}; expected 403 (CSRF gate)."
        )
        assert spy.calls == [], (
            "FINDING (CRITICAL): an add with no CSRF token reached run_add. CSRF is not "
            "enforced before the subprocess effect (R-r)."
        )

    def test_remove_without_csrf_no_subprocess(self, client):
        """Authenticated DELETE without CSRF is 403 and never reaches run_remove."""
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET})
        assert login.status_code == 200
        spy = _NeverCalled("run_remove")
        with patch("src.admin.routes.allowlist.run_remove", side_effect=spy):
            resp = client.delete("/api/v1/allowlist/entries/api.example.com")
        assert resp.status_code == 403
        assert spy.calls == [], (
            "FINDING (CRITICAL): a DELETE with no CSRF token reached run_remove (R-r)."
        )

    def test_reload_without_csrf_no_subprocess(self, client):
        """Authenticated reload without CSRF is 403 and never reaches run_reload."""
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET})
        assert login.status_code == 200
        spy = _NeverCalled("run_reload")
        with patch("src.admin.routes.allowlist.run_reload", side_effect=spy):
            resp = client.post("/api/v1/allowlist/reload")
        assert resp.status_code == 403
        assert spy.calls == [], (
            "FINDING (CRITICAL): a reload with no CSRF token reached run_reload. The hot-"
            "apply / SIGHUP path is reachable without CSRF (R-q)."
        )

    def test_host_forgery_blocks_add_before_effect(self, client):
        """A forged Host header blocks the add before auth, CSRF, or the subprocess."""
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET})
        csrf = login.json()["csrf_token"]
        spy = _NeverCalled("run_add")
        with patch("src.admin.routes.allowlist.run_add", side_effect=spy):
            resp = client.post(
                "/api/v1/allowlist/entries",
                json={"host": "api.example.com"},
                headers={"Host": "evil.attacker.com", "X-CSRF-Token": csrf},
            )
        assert resp.status_code == 403
        assert spy.calls == [], (
            "FINDING (CRITICAL): a forged-Host add reached run_add. Host validation does "
            "not short-circuit before the subprocess effect (R-s / R-b)."
        )

    def test_rejected_write_leaves_overrides_unchanged_via_shell(self, tmp_path):
        """
        End-to-end no-effect proof: drive the real script directly (the only write path)
        with NO prior successful add. Because the API rejects unauth/no-CSRF before ever
        calling the script, the overlay file is never created. We assert the fresh repo's
        overrides.conf does not exist after an auth-rejected API flow.
        """
        # Build a temp repo and point the wrapper at its script.
        scripts_dir = tmp_path / "src" / "scripts"
        scripts_dir.mkdir(parents=True)
        (tmp_path / "config" / "allowlist.local.d").mkdir(parents=True)
        script = scripts_dir / "allowlist-local.sh"
        script.write_text(SCRIPT_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(script, 0o755)
        overrides = tmp_path / "config" / "allowlist.local.d" / "overrides.conf"

        sf = tmp_path / "admin-secret"
        sf.write_text(TEST_SECRET + "\n", encoding="utf-8")
        os.chmod(sf, 0o600)
        settings = Settings(
            host=TEST_HOST, port=TEST_PORT, allow_non_loopback=False, secret_file=sf,
            secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RT_NOEFFECT",
            audit_log_path=tmp_path / "audit.jsonl",
            session_secret_key="noeffect-rt-session-key-aaabbbccc" * 4,
        )
        from starlette.testclient import TestClient
        import src.admin.primitives.allowlist as prim
        prim._set_script_path_for_testing(script)  # real script, temp repo
        try:
            app = create_app(settings)
            with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
                c.headers.update({"Host": VALID_HOST_HDR})
                # Unauthenticated, no CSRF: must be rejected before any script call.
                r1 = c.post("/api/v1/allowlist/entries", json={"host": "api.example.com"})
                assert r1.status_code in (401, 403)
                # Logged in but NO CSRF token: 403 before any script call.
                c.post("/api/v1/login", json={"secret": TEST_SECRET})
                r2 = c.post("/api/v1/allowlist/entries", json={"host": "api.example.com"})
                assert r2.status_code == 403
            assert not overrides.exists(), (
                "FINDING (CRITICAL): an auth/CSRF-rejected write flow still produced an "
                "overrides.conf. A write happened before the auth/CSRF gate (R-b / R-r)."
            )
        finally:
            # Restore the real script path so we don't leak test state to other tests.
            prim._set_script_path_for_testing(SCRIPT_PATH)


# ===========================================================================
# 9. WRAP-BOUNDARY CANNOT BE TRICKED  (SPEC-27-P1 s11 assertions 7 + 8)
# ===========================================================================
#
# Containment claim: no input path causes the Python to write overrides.conf, call
# the proxy, or send SIGHUP directly. All of that lives in allowlist-local.sh. We
# prove this statically (the wrapper has no such tokens / no file-write / no signal)
# AND behaviorally (run_add is the SOLE subprocess call site, and it shells out to
# the script -- it does not write or signal).


class TestWrapBoundaryCannotBeTricked:
    """The Python wrapper never writes the overlay / calls the proxy / sends a signal."""

    def test_allowlist_py_has_no_overrides_write(self):
        """
        Static: allowlist.py (the wrapper) contains no non-comment reference to
        overrides.conf. Mirrors build-gate assertion 7, kept as a permanent test-level
        regression barrier so a refactor that adds a direct write is caught here too.
        """
        src_lines = (REPO_ROOT / "src" / "admin" / "primitives" / "allowlist.py").read_text(
            encoding="utf-8"
        ).splitlines()
        offenders = [
            (i + 1, ln) for i, ln in enumerate(src_lines)
            if "overrides.conf" in ln and not ln.lstrip().startswith("#")
        ]
        assert not offenders, (
            f"FINDING (CRITICAL): allowlist.py references overrides.conf outside a comment "
            f"-- the wrapper may write the overlay directly, bypassing the script's parse "
            f"gate (R-q). Lines: {offenders}"
        )

    def test_allowlist_py_has_no_proxy_or_signal_call(self):
        """
        Static: allowlist.py contains no non-comment squid / SIGHUP / kill -HUP token.
        Mirrors build-gate assertion 8. A direct proxy reconfigure from Python would
        skip the script's parse-before-HUP fail-safe (R-q.1).
        """
        src_lines = (REPO_ROOT / "src" / "admin" / "primitives" / "allowlist.py").read_text(
            encoding="utf-8"
        ).splitlines()
        offenders = []
        for i, ln in enumerate(src_lines):
            if ln.lstrip().startswith("#"):
                continue
            low = ln.lower()
            if "squid" in low or "sighup" in low or ("kill" in low and "hup" in low):
                offenders.append((i + 1, ln.strip()))
        assert not offenders, (
            f"FINDING (CRITICAL): allowlist.py references squid/SIGHUP/kill -HUP outside a "
            f"comment. The wrapper may reconfigure the proxy directly, skipping the parse "
            f"gate (R-q.1). Lines: {offenders}"
        )

    def test_allowlist_py_only_subprocess_is_the_script(self):
        """
        Static (AST): the ONLY subprocess invocation in allowlist.py runs `bash <script>`.
        No other command (squid, kill, docker exec for reconfigure) is spawned. This
        proves there is no alternate effect path the wrapper could be tricked into.
        """
        import ast

        src = (REPO_ROOT / "src" / "admin" / "primitives" / "allowlist.py").read_text(encoding="utf-8")
        tree = ast.parse(src)

        # Find the literal command list assigned to `cmd` in _run_script: ["bash", str(_SCRIPT_PATH), verb].
        bash_cmd_found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "cmd" and isinstance(node.value, ast.List):
                        elts = node.value.elts
                        if elts and isinstance(elts[0], ast.Constant) and elts[0].value == "bash":
                            bash_cmd_found = True
        assert bash_cmd_found, (
            "FINDING: could not confirm the wrapper's subprocess command is `bash <script>`. "
            "If the command construction changed, the single-code-path / wrap boundary may "
            "be broken -- review primitives/allowlist.py (R-q)."
        )

        # No subprocess call in this module may name squid / kill / docker as the program.
        forbidden_programs = {"squid", "kill", "killall", "pkill"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                is_run = (
                    (isinstance(func, ast.Attribute) and func.attr in {"run", "Popen", "call", "check_output"})
                )
                if not is_run:
                    continue
                if node.args and isinstance(node.args[0], ast.List):
                    first = node.args[0].elts[0] if node.args[0].elts else None
                    if isinstance(first, ast.Constant) and first.value in forbidden_programs:
                        pytest.fail(
                            f"FINDING (CRITICAL): allowlist.py spawns {first.value!r} directly. "
                            f"The wrapper reconfigures the proxy / signals a process itself, "
                            f"bypassing the script's parse gate (R-q)."
                        )

    def test_wrapper_does_not_write_files(self):
        """
        Static (AST): the wrapper module opens no file for writing. The overlay write must
        happen ONLY inside allowlist-local.sh. An open(...,'w'/'a') in the wrapper would be
        a direct-write escape of the wrap boundary.
        """
        import ast

        src = (REPO_ROOT / "src" / "admin" / "primitives" / "allowlist.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        write_opens = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                is_open = (isinstance(func, ast.Name) and func.id == "open") or (
                    isinstance(func, ast.Attribute) and func.attr in {"open", "write_text", "write_bytes"}
                )
                if not is_open:
                    continue
                if isinstance(func, ast.Attribute) and func.attr in {"write_text", "write_bytes"}:
                    write_opens.append(ast.dump(node))
                    continue
                mode_node = node.args[1] if len(node.args) >= 2 else None
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode_node = kw.value
                if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                    if any(c in mode_node.value for c in ("w", "a", "+", "x")):
                        write_opens.append(mode_node.value)
        assert not write_opens, (
            f"FINDING (CRITICAL): the allowlist wrapper opens a file for writing "
            f"({write_opens}). The overlay write must live ONLY in allowlist-local.sh; a "
            f"direct write here bypasses the parse-before-HUP fail-safe (R-q.1)."
        )
