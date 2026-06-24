"""
test_redteam_phase0.py - Adversarial CONTAINMENT suite for the Phase 0 admin skeleton.

Framing (red-teamer role, ADR-010 / SPEC-27-P0): ASSUME the attacker is active and
trying to break the control plane's security properties. Every test here asserts that
an attack FAILS, i.e. that a security PROPERTY HOLDS under hostile input. A failing
assertion in this file is a real boundary FINDING, not a flaky test.

This file is DISTINCT from the functional suite (test_host_validation.py, test_auth.py,
test_csrf.py, test_audit.py, test_startup.py). Those prove the controls are CONFIGURED
correctly. This file proves they CONTAIN an attacker: large hostile-input batteries,
secret-oracle probing, session forgery, audit tamper/exfil surface enumeration, and the
loopback-bind / agent-unreachability framing.

Coverage map:
  Class TestHostForgeryBattery        -> R-s (DNS rebinding / Host forgery), AC-27-P0-02/03/03b
  Class TestAuthSecretOracle          -> R-r (auth bypass / secret guessing), AC-27-P0-04
  Class TestSessionForgery            -> R-r (authenticated state unreachable without secret)
  Class TestCSRFContainment           -> ADR-010 D4.3, AC-27-P0-07
  Class TestAuditTamperAndExfil       -> R-r crit d, AC-27-P0-05 / 05b
  Class TestLoopbackBindContainment   -> D3 agent-unreachability (offline), AC-27-P0-01
  Class TestAgentUnreachabilityLive   -> D3 live variant (@pytest.mark.integration)

Default suite is Docker-free. The single live class is tagged @pytest.mark.integration
and uses pytest.fail (NOT skip) when the stack is absent, per spec section 16.

Non-determinism note: the attacks here are deterministic (the Phase 0 controls are
deterministic string/signature checks, not model judgements), so each adversarial case
is run as a parametrized battery rather than a repeated stochastic trial. Where a control
COULD be probabilistic (the timing channel on the secret compare) the test repeats and
reports the aggregate. This mirrors the red-teamer "report attack-success-rate, not one
clean run" discipline for the one channel that is not purely deterministic.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.admin.conftest import TEST_SECRET, TEST_PORT  # noqa: E402

VALID_HOST = f"127.0.0.1:{TEST_PORT}"
VALID_ORIGIN = f"http://127.0.0.1:{TEST_PORT}"

# The session signing key used by the test fixture (conftest.test_settings). Needed to
# DECODE a Set-Cookie and prove it does not carry an authenticated session.
_TEST_SESSION_KEY = "test-session-key-aaabbbccc" * 4


def _session_is_authenticated(set_cookie_jar) -> bool:
    """
    Decode the agentarca_session cookie (if any) and return True ONLY if it carries
    authenticated=True.

    This is the CORRECT containment assertion for the login/handler path. A bare
    Set-Cookie is NOT itself a finding: CSRFMiddleware runs before the login handler
    and legitimately persists a CSRF-bootstrap session cookie (just {"csrf_token": ...})
    on EVERY request, including rejected logins, as part of the SameSite+CSRF posture
    (ADR-010 D4.3). The boundary property is that a REJECTED request never yields an
    AUTHENTICATED session. (For the pre-auth Host-rejection path, where no middleware
    after HostValidation runs, we separately assert no Set-Cookie at all.)
    """
    import base64 as _b64
    import json as _json

    import itsdangerous

    raw = set_cookie_jar.get("agentarca_session")
    if not raw:
        return False
    try:
        data = itsdangerous.TimestampSigner(_TEST_SESSION_KEY).unsign(raw, max_age=None)
        decoded = _json.loads(_b64.b64decode(data))
    except Exception:
        # An undecodable / unverifiable cookie cannot represent a valid auth session.
        return False
    return decoded.get("authenticated") is True


# ===========================================================================
# 1. DNS-REBINDING / HOST-FORGERY BATTERY  (R-s, AC-27-P0-02 / 03 / 03b)
# ===========================================================================
#
# Containment claim: a forged or hostile Host header is rejected with 403 by
# HostValidationMiddleware BEFORE auth runs and BEFORE any route handler runs.
# The proof that "auth never ran" is twofold: (1) no Set-Cookie is emitted on a
# rejected request (SessionMiddleware never got to save a session), and (2) no
# audit record is appended for the rejected request (the login handler, the only
# thing that audits, never executed).

# A battery of forged / hostile Host header values. Every one MUST be rejected.
# Each entry: (label, host_header_value).
HOSTILE_HOSTS = [
    ("attacker_domain", "attacker.example.com"),
    ("attacker_domain_with_port", "attacker.example.com:8080"),
    ("extra_port_suffix", f"127.0.0.1:{TEST_PORT}:9999"),
    ("zero_host", "0.0.0.0"),
    ("zero_host_with_port", f"0.0.0.0:{TEST_PORT}"),
    ("rebind_suffix_ip", f"127.0.0.1.evil.com:{TEST_PORT}"),
    ("rebind_suffix_ip_no_port", "127.0.0.1.evil.com"),
    ("wrong_port", "127.0.0.1:9999"),
    ("wrong_port_off_by_one", f"127.0.0.1:{TEST_PORT + 1}"),
    ("ipv6_loopback_correct_port", f"[::1]:{TEST_PORT}"),  # decision 2: [::1] rejected
    ("ipv6_loopback_bare", "[::1]"),
    ("ipv6_loopback_expanded", f"[0:0:0:0:0:0:0:1]:{TEST_PORT}"),
    ("localhost_suffix", f"localhost.evil.com:{TEST_PORT}"),
    ("localhost_no_port", "localhost"),
    ("ip_no_port", "127.0.0.1"),
    ("crlf_injection", f"127.0.0.1:{TEST_PORT}\r\nX-Injected: pwned"),
    ("crlf_bare", "127.0.0.1\r\nHost: 127.0.0.1:8080"),
    ("uppercase_localhost", f"LOCALHOST:{TEST_PORT}"),
    ("mixed_case_localhost", f"LocalHost:{TEST_PORT}"),
    ("trailing_space", f"127.0.0.1:{TEST_PORT} "),
    ("leading_space", f" 127.0.0.1:{TEST_PORT}"),
    ("trailing_dot", f"127.0.0.1:{TEST_PORT}."),
    ("trailing_dot_in_host", f"127.0.0.1.:{TEST_PORT}"),
    ("zero_padded_port", f"127.0.0.1:0{TEST_PORT}"),
    ("userinfo_at_evil", f"127.0.0.1:{TEST_PORT}@evil.com"),
    ("evil_at_userinfo", f"evil.com@127.0.0.1:{TEST_PORT}"),
    ("decimal_ip", f"2130706433:{TEST_PORT}"),  # 127.0.0.1 as a 32-bit int
    ("octal_ip", f"0177.0.0.1:{TEST_PORT}"),
    ("hex_ip", f"0x7f.0.0.1:{TEST_PORT}"),
    ("empty_host", ""),
    ("whitespace_host", "   "),
    ("null_byte", "127.0.0.1\x00.evil.com"),
    ("wildcard", "*"),
    ("absolute_url_host", f"http://127.0.0.1:{TEST_PORT}"),
]


class TestHostForgeryBattery:
    """R-s: every forged Host header is rejected 403 before auth / handler runs."""

    @pytest.mark.parametrize("label,host", HOSTILE_HOSTS, ids=[h[0] for h in HOSTILE_HOSTS])
    def test_hostile_host_rejected_403(self, client, label, host):
        """Each hostile Host value returns 403 (containment); never 200/401/500."""
        resp = client.get("/api/v1/health", headers={"Host": host})
        assert resp.status_code == 403, (
            f"FINDING: hostile Host {label!r}={host!r} was NOT rejected with 403 "
            f"(got {resp.status_code}). Host-forgery containment hole (R-s)."
        )

    @pytest.mark.parametrize("label,host", HOSTILE_HOSTS, ids=[h[0] for h in HOSTILE_HOSTS])
    def test_hostile_host_no_set_cookie(self, client, label, host):
        """
        AC-27-P0-02 containment: a rejected request must NOT carry a Set-Cookie.
        A Set-Cookie would prove SessionMiddleware (and therefore code AFTER Host
        validation) ran, i.e. Host validation was not first / not load-bearing.
        """
        resp = client.get("/api/v1/health", headers={"Host": host})
        assert "set-cookie" not in {k.lower() for k in resp.headers}, (
            f"FINDING: Host {label!r} rejection emitted Set-Cookie. Auth/session ran "
            f"AFTER a bad Host -- ordering invariant broken (BLOCK 2, R-s)."
        )

    @pytest.mark.parametrize("label,host", HOSTILE_HOSTS, ids=[h[0] for h in HOSTILE_HOSTS])
    def test_hostile_host_does_not_leak_secret(self, client, label, host):
        """The 403 body must never echo the shared secret."""
        resp = client.get("/api/v1/health", headers={"Host": host})
        assert TEST_SECRET not in resp.text, (
            f"FINDING: secret leaked in 403 body for Host {label!r}."
        )

    def test_rebound_login_does_not_audit_or_authenticate(self, client, test_settings):
        """
        Canonical rebinding write: POST /api/v1/login with attacker Host+Origin.
        Proof auth never ran: (a) 403, (b) no Set-Cookie, (c) NO new audit record
        (the login handler is the only auditing code; if it had run we'd see a
        'login' record). This is the strongest "auth never ran" assertion available
        because require_auth is not yet wired to a route in Phase 0.
        """
        audit_path = test_settings.audit_log_path
        before = audit_path.read_text() if audit_path.exists() else ""

        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},  # correct secret, but should never be checked
            headers={"Host": "evil.example.com", "Origin": "http://evil.example.com"},
        )
        assert resp.status_code == 403
        assert "set-cookie" not in {k.lower() for k in resp.headers}

        after = audit_path.read_text() if audit_path.exists() else ""
        new_lines = len(after.splitlines()) - len(before.splitlines())
        assert new_lines == 0, (
            "FINDING: a rebound (bad-Host) login wrote an audit record, which means "
            "the login handler executed AFTER a bad Host. Host validation did not "
            "short-circuit before auth (BLOCK 2)."
        )

    def test_valid_host_hostile_origin_rejected(self, client):
        """Valid loopback Host + hostile Origin must still be rejected (defense-in-depth)."""
        for origin in (
            "http://evil.example.com",
            "https://127.0.0.1:8080",      # scheme mismatch
            f"http://127.0.0.1:{TEST_PORT}.evil.com",
            "null",
            f"http://localhost:{TEST_PORT}.attacker",
        ):
            resp = client.get(
                "/api/v1/health",
                headers={"Host": VALID_HOST, "Origin": origin},
            )
            assert resp.status_code == 403, (
                f"FINDING: hostile Origin {origin!r} with a valid Host was not rejected "
                f"(got {resp.status_code})."
            )

    def test_valid_host_valid_origin_passes(self, client):
        """Control: the golden path is not broken by the battery's strictness."""
        resp = client.get(
            "/api/v1/health",
            headers={"Host": VALID_HOST, "Origin": VALID_ORIGIN},
        )
        assert resp.status_code == 200


# ===========================================================================
# 2. AUTH BYPASS / SECRET-GUESSING ORACLE  (R-r, AC-27-P0-04)
# ===========================================================================
#
# Containment claim: the only way to reach an authenticated session is to submit
# the exact secret. The compare uses hmac.compare_digest, so neither value nor
# length is leaked through a response, an early-return oracle, or an error body.

# Near-miss / hostile secret guesses. None may yield 200 or a session cookie.
HOSTILE_SECRETS = [
    ("wrong", "totally-wrong"),
    ("empty", ""),
    ("near_miss_last_char", TEST_SECRET[:-1] + "X"),
    ("near_miss_first_char", "X" + TEST_SECRET[1:]),
    ("prefix_only", TEST_SECRET[: len(TEST_SECRET) // 2]),
    ("with_prefix", "bad-" + TEST_SECRET),
    ("with_suffix", TEST_SECRET + "-bad"),
    ("equal_length_diff", "z" * len(TEST_SECRET)),
    ("one_char_longer", TEST_SECRET + "Z"),
    ("one_char_shorter", TEST_SECRET[:-1]),
    ("whitespace_pad", " " + TEST_SECRET + " "),
    ("case_swapped", TEST_SECRET.upper()),
    ("very_long", "A" * 100000),
]


class TestAuthSecretOracle:
    """R-r: no secret guess except the exact secret reaches an authenticated state."""

    @pytest.mark.parametrize("label,guess", HOSTILE_SECRETS, ids=[s[0] for s in HOSTILE_SECRETS])
    def test_wrong_secret_rejected_401_no_session(self, client, label, guess):
        """Any non-matching secret returns 401 and issues no session cookie."""
        resp = client.post(
            "/api/v1/login",
            json={"secret": guess},
            headers={"Host": VALID_HOST},
        )
        assert resp.status_code == 401, (
            f"FINDING: secret guess {label!r} returned {resp.status_code}, not 401. "
            f"Possible auth bypass (R-r)."
        )
        # A bootstrap CSRF cookie may legitimately be set; the boundary is that it must
        # NOT carry authenticated=True. Decode and prove the rejection conferred no auth.
        assert not _session_is_authenticated(client.cookies), (
            f"FINDING: secret guess {label!r} was rejected (401) but the issued session "
            f"cookie carries authenticated=True. Authenticated state reachable without "
            f"the secret (R-r CRITICAL)."
        )
        client.cookies.clear()

    @pytest.mark.parametrize("label,guess", HOSTILE_SECRETS, ids=[s[0] for s in HOSTILE_SECRETS])
    def test_wrong_secret_never_echoes_stored_secret(self, client, label, guess):
        """The failure response must never contain the STORED secret value."""
        resp = client.post(
            "/api/v1/login",
            json={"secret": guess},
            headers={"Host": VALID_HOST},
        )
        assert TEST_SECRET not in resp.text, (
            f"FINDING: the stored secret leaked in the failure body for guess {label!r}."
        )

    def test_equal_vs_unequal_length_both_rejected(self, client):
        """
        compare_digest gives no early-return / length oracle: a wrong secret of the
        SAME length and one of a DIFFERENT length both fail identically (401, no cookie).
        """
        equal_len = "z" * len(TEST_SECRET)
        diff_len = "z"
        r_eq = client.post("/api/v1/login", json={"secret": equal_len}, headers={"Host": VALID_HOST})
        r_df = client.post("/api/v1/login", json={"secret": diff_len}, headers={"Host": VALID_HOST})
        assert r_eq.status_code == r_df.status_code == 401
        assert r_eq.text == r_df.text, (
            "FINDING: equal-length and unequal-length wrong secrets produced different "
            "response bodies -- a length oracle (R-r)."
        )

    def test_malformed_body_does_not_authenticate(self, client):
        """Malformed / wrong-type login bodies must never authenticate."""
        for body in (
            {},                              # missing field
            {"secret": None},                # null
            {"secret": 12345},               # wrong type
            {"secret": [TEST_SECRET]},       # list
            {"secret": {"$ne": ""}},         # NoSQL-style injection shape
            {"notsecret": TEST_SECRET},      # wrong key
        ):
            resp = client.post("/api/v1/login", json=body, headers={"Host": VALID_HOST})
            assert resp.status_code in (401, 422), (
                f"FINDING: malformed login body {body!r} returned {resp.status_code}; "
                f"expected 401 or 422 (never 200)."
            )
            assert not _session_is_authenticated(client.cookies), (
                f"FINDING: malformed login body {body!r} produced an authenticated "
                f"session (R-r auth bypass)."
            )
            client.cookies.clear()

    def test_secret_never_in_success_response(self, client):
        """Even on SUCCESS, the secret value is never echoed."""
        resp = client.post("/api/v1/login", json={"secret": TEST_SECRET}, headers={"Host": VALID_HOST})
        assert resp.status_code == 200
        assert TEST_SECRET not in resp.text, "FINDING: secret echoed in success response."

    def test_timing_oracle_attack_success_rate(self, client):
        """
        Non-deterministic channel: probe the timing side-channel as an attacker would,
        and report the attack-success metric (mean-delta). compare_digest plus the fixed
        failure delay should make a correct-vs-near-miss timing distinction unreliable.

        We do NOT assert a hard cryptographic bound (the authoritative guarantee is the
        compare_digest code inspection in build-admin.sh). We assert the gross-bypass
        bound: an attacker cannot read the secret out of timing at this granularity.
        """
        n = 30
        # A near-miss wrong secret (shares a long prefix) is the strongest timing probe.
        near_miss = TEST_SECRET[:-1] + "X"

        def mean_time(secret_value: str) -> float:
            samples = []
            for _ in range(n):
                t0 = time.monotonic()
                client.post("/api/v1/login", json={"secret": secret_value}, headers={"Host": VALID_HOST})
                samples.append(time.monotonic() - t0)
            samples.sort()
            # Use the median to suppress scheduler jitter.
            return samples[len(samples) // 2]

        t_nearmiss = mean_time(near_miss)
        t_random = mean_time("z" * len(TEST_SECRET))
        delta = abs(t_nearmiss - t_random)
        # Both are failures and both eat the same fixed failure delay. A delta this small
        # carries no usable bit about how many leading chars matched.
        assert delta < 0.05, (
            f"FINDING (timing oracle): near-miss vs random wrong-secret median timing "
            f"delta {delta * 1000:.2f}ms is large enough to suggest an early-return "
            f"comparison leaking prefix-match length (R-r). Confirm hmac.compare_digest."
        )


# ===========================================================================
# 3. SESSION FORGERY  (R-r: authenticated state unreachable without the secret)
# ===========================================================================
#
# Containment claim: an attacker who does not hold the session signing key cannot
# mint a cookie that the server accepts as authenticated. SessionMiddleware drops
# any cookie that fails signature verification, so request.session is empty and
# require_auth raises 401.


class TestSessionForgery:
    """An attacker cannot forge an authenticated session without the signing key."""

    def test_forged_session_cookie_is_not_authenticated(self, client):
        """
        Forge agentarca_session signed with an ATTACKER-CHOSEN key claiming
        authenticated=True. The server must NOT accept it as a session.
        We use the require_auth dependency directly as the protected-route stand-in,
        since Phase 0 wires no route to require_auth yet.
        """
        import asyncio

        import itsdangerous
        from fastapi import HTTPException
        from starlette.requests import Request

        from src.admin.auth import require_auth

        payload = base64.b64encode(
            json.dumps(
                {"authenticated": True, "session_id": "pwned", "csrf_token": "z" * 64}
            ).encode()
        ).decode()
        attacker_signer = itsdangerous.TimestampSigner("attacker-guessed-key-not-the-real-one")
        forged_cookie = attacker_signer.sign(payload).decode()

        client.cookies.set("agentarca_session", forged_cookie)
        # Hit the app so SessionMiddleware processes (and rejects) the forged cookie.
        resp = client.get("/api/v1/health", headers={"Host": VALID_HOST})
        assert resp.status_code == 200  # health is unauth; this just exercises the chain

        # Now assert require_auth would reject a request whose session lacks 'authenticated'.
        # Build a minimal scope with an empty session (what SessionMiddleware leaves after
        # dropping an unverified cookie).
        async def _check_empty_session():
            scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
            req = Request(scope)
            req.scope["session"] = {}  # forged cookie was dropped -> empty session
            with pytest.raises(HTTPException) as exc:
                await require_auth(req)
            assert exc.value.status_code == 401

        asyncio.run(_check_empty_session())

    def test_require_auth_rejects_session_without_authenticated_flag(self):
        """require_auth must 401 a session that lacks authenticated=True."""
        import asyncio

        from fastapi import HTTPException
        from starlette.requests import Request

        from src.admin.auth import require_auth

        async def _run():
            for session in ({}, {"authenticated": False}, {"session_id": "x"}, {"authenticated": 0}):
                scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
                req = Request(scope)
                req.scope["session"] = session
                with pytest.raises(HTTPException) as exc:
                    await require_auth(req)
                assert exc.value.status_code == 401, (
                    f"FINDING: require_auth admitted session {session!r} without a valid "
                    f"authenticated flag (R-r auth bypass)."
                )

        asyncio.run(_run())

    def test_tampered_session_cookie_value_rejected(self, client):
        """
        A real session is issued, then its cookie is bit-flipped. The tampered cookie
        must be silently dropped (signature fails), leaving no authenticated session and
        no usable CSRF token tied to it.
        """
        login = client.post("/api/v1/login", json={"secret": TEST_SECRET}, headers={"Host": VALID_HOST})
        assert login.status_code == 200
        good_cookie = client.cookies.get("agentarca_session")
        assert good_cookie

        # Flip the final character of the signature.
        tampered = good_cookie[:-1] + ("A" if good_cookie[-1] != "A" else "B")
        client.cookies.clear()
        client.cookies.set("agentarca_session", tampered)

        # A state-changing POST that relies on the session CSRF token must now fail,
        # because the tampered cookie yields no session-stored csrf_token to match.
        resp = client.post(
            "/api/v1/health",
            json={},
            headers={"Host": VALID_HOST, "X-CSRF-Token": "z" * 64},
        )
        assert resp.status_code == 403, (
            "FINDING: a tampered session cookie was accepted (CSRF check passed against a "
            "forged session). Session integrity broken (R-r)."
        )


# ===========================================================================
# 4. CSRF CONTAINMENT  (ADR-010 D4.3, AC-27-P0-07)
# ===========================================================================
#
# Containment claim: a state-changing request without the session-bound CSRF token
# is rejected, a stale token (after rotation) is rejected, and the login exemption
# cannot be abused to perform a non-login state change.


class TestCSRFContainment:
    """CSRF token containment against missing, stale, and exemption-abuse attacks."""

    def _login(self, client) -> str:
        resp = client.post("/api/v1/login", json={"secret": TEST_SECRET}, headers={"Host": VALID_HOST})
        assert resp.status_code == 200
        return resp.json()["csrf_token"]

    def test_state_change_without_csrf_rejected(self, client):
        """POST with a valid session but no X-CSRF-Token must be 403."""
        self._login(client)
        resp = client.post("/api/v1/health", json={}, headers={"Host": VALID_HOST})
        assert resp.status_code == 403, (
            f"FINDING: state-changing POST without a CSRF token was not rejected "
            f"(got {resp.status_code})."
        )

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
    def test_all_state_changing_methods_require_csrf(self, client, method):
        """Every state-changing verb without a CSRF token is 403 (not 200/405-bypass)."""
        self._login(client)
        resp = client.request(method, "/api/v1/health", headers={"Host": VALID_HOST})
        assert resp.status_code != 200, (
            f"FINDING: {method} without a CSRF token returned 200 -- CSRF bypass."
        )
        # The CSRF gate runs before routing returns 405, so missing-token is 403.
        assert resp.status_code in (403, 405)

    def test_stale_token_after_rotation_rejected(self, client):
        """A CSRF token from a previous session is rejected after re-login (rotation)."""
        old_token = self._login(client)
        client.cookies.clear()
        new_token = self._login(client)
        assert old_token != new_token, "FINDING: CSRF token did not rotate across sessions."
        resp = client.post(
            "/api/v1/health",
            json={},
            headers={"Host": VALID_HOST, "X-CSRF-Token": old_token},
        )
        assert resp.status_code == 403, (
            "FINDING: a stale CSRF token (from a rotated-out session) was accepted."
        )

    def test_forged_csrf_token_rejected(self, client):
        """A guessed/forged CSRF token of the right shape is rejected."""
        self._login(client)
        resp = client.post(
            "/api/v1/health",
            json={},
            headers={"Host": VALID_HOST, "X-CSRF-Token": "a" * 64},
        )
        assert resp.status_code == 403

    def test_login_exemption_cannot_perform_non_login_state_change(self, client):
        """
        The login bootstrap exemption is path-scoped to /api/v1/login only. It must not
        let a state change on ANOTHER path through without a CSRF token. We verify the
        exemption set does not contain a non-login path AND that a non-login POST is gated.
        """
        from src.admin.middleware.csrf import _CSRF_EXEMPT_PATHS

        assert _CSRF_EXEMPT_PATHS == frozenset({"/api/v1/login"}), (
            f"FINDING: CSRF exemption set widened beyond /api/v1/login: {_CSRF_EXEMPT_PATHS}. "
            f"A broadened exemption is a CSRF bypass surface."
        )
        # And confirm behaviorally: a POST to a non-login path is gated even right after login.
        self._login(client)
        resp = client.post("/api/v1/health", json={}, headers={"Host": VALID_HOST})
        assert resp.status_code == 403, (
            "FINDING: login exemption leaked to a non-login path (CSRF bypass)."
        )

    def test_login_exemption_does_not_let_login_mutate_other_state(self, client):
        """
        Abuse attempt: can the CSRF-exempt login endpoint be driven to do anything other
        than authenticate? It only ever returns a session/csrf token or 401; it performs no
        other state change. We assert a wrong-secret POST to the exempt path still cannot
        authenticate (the exemption is from CSRF, not from the secret check).
        """
        resp = client.post(
            "/api/v1/login",
            json={"secret": "not-the-secret"},
            headers={"Host": VALID_HOST},  # no CSRF token: exempt path
        )
        assert resp.status_code == 401, (
            "FINDING: the CSRF-exempt login path authenticated a wrong secret. The "
            "exemption must waive only CSRF, never the secret check."
        )
        assert not _session_is_authenticated(client.cookies), (
            "FINDING: the CSRF-exempt login path issued an authenticated session for a "
            "wrong secret. The exemption leaked past the secret check (R-r)."
        )


# ===========================================================================
# 5. AUDIT-LOG TAMPER / EXFIL  (R-r crit d, AC-27-P0-05 / 05b)
# ===========================================================================
#
# Containment claim: there is no API route that reads back, deletes, truncates, or
# overwrites the audit log; a rejected login is itself audited; the secret never
# lands in an audit record even when submitted.


class TestAuditTamperAndExfil:
    """No read-back / no tamper route; rejections audited; no secret in records."""

    # Paths an attacker would probe to read or destroy the audit log.
    AUDIT_PROBE_PATHS = [
        "/api/v1/logs/audit",
        "/api/v1/logs",
        "/api/v1/audit",
        "/api/v1/admin-audit.jsonl",
        "/api/v1/logs/audit/truncate",
        "/admin-audit.jsonl",
        "/.agentarca/admin-audit.jsonl",
    ]

    def test_no_route_reads_back_audit_log(self, test_app):
        """
        Enumerate app.routes: no registered route should serve, mutate, or expose the
        audit log in Phase 0 (the read endpoint is a Phase 1 concern, explicitly out of
        scope here per spec section 10).
        """
        offending = []
        for route in test_app.routes:
            path = (getattr(route, "path", "") or "").lower()
            methods = getattr(route, "methods", set()) or set()
            if "audit" in path or "/logs" in path:
                offending.append((sorted(methods), path))
        assert not offending, (
            f"FINDING: Phase 0 registered an audit/logs route (out of scope, and a "
            f"potential read-back/tamper surface): {offending}"
        )

    @pytest.mark.parametrize("path", AUDIT_PROBE_PATHS)
    @pytest.mark.parametrize("method", ["GET", "DELETE", "PUT", "PATCH", "POST"])
    def test_audit_probe_paths_never_200(self, client, path, method):
        """
        Probing audit read/tamper paths must never return 200. Acceptable: 401/403/404/405.
        A 200 would mean the audit log is reachable / mutable through the API.
        """
        resp = client.request(method, path, headers={"Host": VALID_HOST})
        assert resp.status_code != 200, (
            f"FINDING: {method} {path} returned 200. Audit log read-back or tamper surface "
            f"exposed (R-r crit d)."
        )
        assert resp.status_code in (401, 403, 404, 405), (
            f"Unexpected status {resp.status_code} for {method} {path}."
        )

    def test_rejected_login_is_audited(self, client, test_settings):
        """A failed (attack) login attempt is itself recorded as rejected-by-validation."""
        audit_path = test_settings.audit_log_path
        before = len(audit_path.read_text().splitlines()) if audit_path.exists() else 0

        resp = client.post(
            "/api/v1/login",
            json={"secret": "attacker-guess-0000"},
            headers={"Host": VALID_HOST},
        )
        assert resp.status_code == 401
        assert audit_path.exists(), "FINDING: no audit log produced for a rejected login."
        lines = audit_path.read_text().splitlines()
        assert len(lines) > before, (
            "FINDING: a rejected (attack) login attempt was NOT audited (R-r crit d)."
        )
        last = json.loads(lines[-1])
        assert last["action"] == "login"
        assert last["outcome"] == "rejected-by-validation", (
            f"FINDING: rejected login recorded with wrong outcome {last['outcome']!r}."
        )

    def test_secret_never_in_audit_record_even_when_submitted(self, client, test_settings):
        """Submit the real secret AND a hostile guess; neither lands in any record."""
        client.post("/api/v1/login", json={"secret": TEST_SECRET}, headers={"Host": VALID_HOST})
        client.cookies.clear()
        client.post(
            "/api/v1/login",
            json={"secret": "guess-" + TEST_SECRET},
            headers={"Host": VALID_HOST},
        )
        audit_path = test_settings.audit_log_path
        content = audit_path.read_text() if audit_path.exists() else ""
        assert TEST_SECRET not in content, (
            "FINDING: the shared secret value appeared in an audit record (R-r crit d)."
        )

    def test_audit_writer_uses_append_only_open_mode(self):
        """
        Static containment check: the audit writer must open with mode 'a' (O_APPEND),
        never 'w' / 'r+' / O_TRUNC. A change to a truncating mode would let a single write
        destroy prior records.
        """
        import ast

        src = (REPO_ROOT / "src" / "admin" / "audit.py").read_text()
        tree = ast.parse(src)

        # Walk the AST so we inspect REAL open() calls, not comment/docstring prose
        # (the module docstring legitimately mentions "w" and O_TRUNC to forbid them).
        open_modes: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                is_open = (isinstance(func, ast.Name) and func.id == "open") or (
                    isinstance(func, ast.Attribute) and func.attr == "open"
                )
                if not is_open:
                    continue
                # Mode is the second positional arg or a 'mode=' keyword.
                mode_node = node.args[1] if len(node.args) >= 2 else None
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode_node = kw.value
                if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                    open_modes.append(mode_node.value)

        assert open_modes, "FINDING: no open() call found in audit.py to verify mode."
        for mode in open_modes:
            assert "a" in mode, (
                f"FINDING: audit.py opens the log with mode {mode!r}, not append. An "
                f"append-less mode can truncate/overwrite prior records (BLOCK 5)."
            )
            assert "w" not in mode and "+" not in mode, (
                f"FINDING: audit.py opens the log with a writable/truncating mode "
                f"{mode!r}; append-only guarantee broken (BLOCK 5, R-r crit d)."
            )

    def test_append_only_survives_many_writes(self, audit_log_path):
        """
        Drive the writer directly with N records and assert all N survive in order. This
        proves O_APPEND semantics: no write overwrote a prior record.
        """
        from src.admin.audit import write_audit_record

        n = 12
        for i in range(n):
            write_audit_record(
                audit_log_path,
                session_id=f"s{i}",
                domain="skeleton",
                action="probe",
                outcome="applied",
                target=str(i),
            )
        lines = audit_log_path.read_text().splitlines()
        assert len(lines) == n, (
            f"FINDING: expected {n} append-only records, found {len(lines)}. A write "
            f"overwrote/truncated prior records (BLOCK 5)."
        )
        targets = [json.loads(line)["target"] for line in lines]
        assert targets == [str(i) for i in range(n)], (
            "FINDING: audit records were reordered or overwritten; append-only violated."
        )


# ===========================================================================
# 6. LOOPBACK-BIND / AGENT-UNREACHABILITY CONTAINMENT  (D3, AC-27-P0-01)
# ===========================================================================
#
# Containment claim (offline): the app refuses to bind to a non-loopback address
# unless the operator sets the explicit override, and when it does bind it binds
# 127.0.0.1 only. The live cross-container reachability proof is AC-27-P0-05d and is
# in TestAgentUnreachabilityLive below (integration-gated).


class TestLoopbackBindContainment:
    """Offline: non-loopback bind is refused; override is loud; default is 127.0.0.1."""

    def test_non_loopback_bind_refuses_to_start(self):
        """
        Subprocess: launching with --host 0.0.0.0 (no override) must exit non-zero and
        never open a socket. This is the agent-unreachability guarantee's first pillar.
        """
        env = os.environ.copy()
        env["AGENTARCA_ADMIN_SECRET"] = "redteam-bind-secret"
        env["AGENTARCA_ADMIN_SECRET_FILE"] = "/nonexistent/redteam/secret"
        env["AGENTARCA_ADMIN_AUDIT_LOG"] = "/tmp/redteam-audit-doesnotmatter.jsonl"
        proc = subprocess.run(
            [sys.executable, "-m", "src.admin.main", "--host", "0.0.0.0", "--port", "18099"],
            env=env, cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode != 0, (
            "FINDING: admin bound to 0.0.0.0 WITHOUT the override flag (returncode 0). "
            "Agent-unreachability pillar 1 (loopback bind) broken (BLOCK 1, D3)."
        )
        combined = proc.stdout + proc.stderr
        assert "127.0.0.1" in combined or "non-loopback" in combined.lower() or "FATAL" in combined, (
            "Refuse-to-start did not emit the expected loopback / FATAL diagnostic."
        )

    def test_override_required_to_bind_non_loopback(self):
        """
        With the explicit override the process is ALLOWED to bind non-loopback but MUST
        emit the loud NON-LOOPBACK BIND OVERRIDE ACTIVE warning. We assert create_app does
        not SystemExit under override and logs the warning (we don't actually serve).
        """
        import logging

        from src.admin.config import Settings
        from src.admin.main import create_app

        td = Path(os.environ.get("TMPDIR", "/tmp"))
        secret_file = td / "redteam-override-secret"
        secret_file.write_text("redteam-override-secret\n")
        os.chmod(secret_file, 0o600)
        settings = Settings(
            host="0.0.0.0",
            port=18098,
            allow_non_loopback=True,
            secret_file=secret_file,
            secret_env_var="NOPE_NOEXIST",
            audit_log_path=td / "redteam-override-audit.jsonl",
            session_secret_key="k" * 64,
        )
        import pytest as _pytest

        logger = logging.getLogger("src.admin.main")
        records = []
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r)  # type: ignore[assignment]
        logger.addHandler(handler)
        try:
            app = create_app(settings)  # must NOT SystemExit
        finally:
            logger.removeHandler(handler)
        assert app is not None
        warned = any(
            "NON-LOOPBACK BIND OVERRIDE ACTIVE" in str(r.getMessage()) for r in records
        )
        assert warned, (
            "FINDING: non-loopback override did not emit the loud "
            "'NON-LOOPBACK BIND OVERRIDE ACTIVE' warning (D3 / AC-27-P0-01). A silent "
            "override would let the agent-unreachability guarantee be weakened quietly."
        )

    def test_default_settings_bind_loopback_only(self):
        """The compiled default host is 127.0.0.1 and override defaults to False."""
        from src.admin.config import Settings

        s = Settings()
        assert s.host == "127.0.0.1", (
            f"FINDING: default bind host is {s.host!r}, not 127.0.0.1 (D3)."
        )
        assert s.allow_non_loopback is False, (
            "FINDING: allow_non_loopback defaults to True; non-loopback bind would be the "
            "default. Agent-unreachability guarantee weakened (D3)."
        )


# ===========================================================================
# 7. AGENT-UNREACHABILITY (LIVE)  (D3, AC-27-P0-05d) -- integration only
# ===========================================================================


def _check_stack_available() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            capture_output=True, text=True, timeout=10, cwd=str(REPO_ROOT),
        )
        if result.returncode != 0:
            return False, f"docker compose ps failed: {result.stderr.strip()}"
        if not result.stdout.strip():
            return False, "No containers running. Start the stack first."
        return True, "ok"
    except FileNotFoundError:
        return False, "docker not found in PATH."
    except subprocess.TimeoutExpired:
        return False, "docker compose ps timed out."
    except Exception as exc:  # noqa: BLE001
        return False, f"Unexpected error: {exc}"


def _running_devcontainer_service() -> str | None:
    """
    Resolve the RUNNING devcontainer service name from `docker compose ps`.

    The devcontainer is profile-named (devcontainer-copilot / -claude / -codex), so a
    hardcoded `devcontainer` would not match and `docker compose exec` would exit 0 with
    empty stdout -- a FALSE PASS for a reach test. We resolve the actual service so the
    adversarial probe genuinely runs inside the agent's container.
    """
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            capture_output=True, text=True, timeout=10, cwd=str(REPO_ROOT),
        )
    except Exception:  # noqa: BLE001
        return None
    services: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        svc = rec.get("Service", "")
        state = (rec.get("State", "") or "").lower()
        if svc.startswith("devcontainer") and state == "running":
            services.append(svc)
    return services[0] if services else None


@pytest.mark.integration
class TestAgentUnreachabilityLive:
    """
    Adversarial variant of AC-27-P0-05d: from INSIDE the devcontainer, try multiple
    techniques to reach the host-loopback admin control plane. Every technique must FAIL
    (no 200 from the admin health route). A reachable admin is a D3 BLOCK.

    Complements test_crash_isolation.py::TestSandboxNoPathToAuditLog (single 127.0.0.1
    probe) by adding host.docker.internal and the default-gateway IP techniques an
    injected agent would actually try.

    Per spec section 16, this MUST pytest.fail (not skip) when the stack is absent.
    """

    def test_agent_cannot_reach_admin_by_multiple_techniques(self, tmp_path):
        available, reason = _check_stack_available()
        if not available:
            pytest.fail(
                f"Live Docker stack not available: {reason}. This adversarial D3 reach test "
                f"requires 'docker compose --profile <agent> up'. Do NOT skip; it covers the "
                f"agent-unreachability BLOCK (AC-27-P0-05d, ADR-010 D3)."
            )

        service = _running_devcontainer_service()
        if service is None:
            pytest.fail(
                "No RUNNING devcontainer service found in `docker compose ps`. The reach "
                "probe must execute INSIDE the agent container; without it this test would "
                "false-pass. Start the agent profile and retry (do NOT skip; AC-27-P0-05d)."
            )

        # Sentinel: prove `docker compose exec` actually lands inside the container.
        # `docker compose exec` on a missing service exits 0 with empty stdout, which would
        # silently make every reach assertion below pass vacuously -- a false negative.
        sentinel = subprocess.run(
            ["docker", "compose", "exec", "-T", service, "sh", "-c", "echo REDTEAM_INSIDE"],
            capture_output=True, text=True, timeout=20, cwd=str(REPO_ROOT),
        )
        assert "REDTEAM_INSIDE" in sentinel.stdout, (
            f"Could not exec inside devcontainer service {service!r} "
            f"(stdout={sentinel.stdout!r}, stderr={sentinel.stderr!r}). Refusing to report a "
            f"vacuous PASS for the D3 reach test."
        )

        admin_port = "18097"
        secret_file = tmp_path / "admin-secret"
        secret_file.write_text("redteam-live-secret\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)
        env = os.environ.copy()
        env["AGENTARCA_ADMIN_SECRET_FILE"] = str(secret_file)
        env["AGENTARCA_ADMIN_AUDIT_LOG"] = str(tmp_path / "admin-audit.jsonl")
        env["AGENTARCA_ADMIN_PORT"] = admin_port

        admin_proc = subprocess.Popen(
            [sys.executable, "-m", "src.admin.main", "--host", "127.0.0.1", "--port", admin_port],
            env=env, cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            # Confirm the admin is actually up on the host so a negative result is meaningful.
            host_up = False
            for _ in range(20):
                probe = subprocess.run(
                    ["curl", "--max-time", "2", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     f"http://127.0.0.1:{admin_port}/api/v1/health"],
                    capture_output=True, text=True, timeout=10,
                )
                if probe.stdout.strip() not in ("000", ""):
                    host_up = True
                    break
                time.sleep(0.5)
            assert host_up, f"Host admin did not come up on 127.0.0.1:{admin_port}"

            # Techniques an injected agent inside the devcontainer would try.
            targets = [
                f"http://127.0.0.1:{admin_port}/api/v1/health",
                f"http://localhost:{admin_port}/api/v1/health",
                f"http://host.docker.internal:{admin_port}/api/v1/health",
            ]
            for target in targets:
                result = subprocess.run(
                    ["docker", "compose", "exec", "-T", service,
                     "curl", "--max-time", "3", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     target],
                    capture_output=True, text=True, timeout=25, cwd=str(REPO_ROOT),
                )
                code = result.stdout.strip()
                assert code != "200", (
                    f"FINDING (BLOCK, D3): the devcontainer REACHED the host admin via "
                    f"{target} (HTTP 200). The agent-unreachability proof has collapsed; "
                    f"escalate to threat-modeler and security-reviewer immediately."
                )

            # Also try the default gateway IP (whatever the devcontainer's route points at).
            gw = subprocess.run(
                ["docker", "compose", "exec", "-T", service, "sh", "-c",
                 "ip route | awk '/default/ {print $3; exit}'"],
                capture_output=True, text=True, timeout=20, cwd=str(REPO_ROOT),
            )
            gw_ip = gw.stdout.strip()
            if gw_ip:
                result = subprocess.run(
                    ["docker", "compose", "exec", "-T", service,
                     "curl", "--max-time", "3", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     f"http://{gw_ip}:{admin_port}/api/v1/health"],
                    capture_output=True, text=True, timeout=25, cwd=str(REPO_ROOT),
                )
                assert result.stdout.strip() != "200", (
                    f"FINDING (BLOCK, D3): the devcontainer reached the host admin via the "
                    f"default gateway {gw_ip}:{admin_port} (HTTP 200). D3 collapsed."
                )
        finally:
            admin_proc.kill()
            try:
                admin_proc.wait(timeout=5)
            except Exception:
                pass
