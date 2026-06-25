"""
test_redteam_phase3.py - Adversarial CONTAINMENT suite for Phase 3 admin control plane.

Surface under attack: the credentials (.env management) + read-only isolation display,
the HIGHEST-PRIVILEGE admin surface. SPEC-27-P3 + R-r (control-plane compromise, CRITICAL)
+ R-c (readable token).

FRAME (containment, not "the model refused"): ASSUME the attacker has reached the API with
a valid authenticated session + CSRF token (the worst realistic case for the credential
chokepoint). Each test below drives a real attack to its effect boundary and asserts the
boundary HOLDS. A failing assertion is a REAL FINDING, not a flaky test. If an attack
SUCCEEDS (cleartext token leaks, an arbitrary/out-of-allowlist .env key is written, a D5.4
condition is applied, the admin secret leaks, or the read-only surface mutates / reads an
arbitrary file) that is CRITICAL: the test fails loudly with a FINDING message.

Attack families (mapped to the brief):
  1. Credential exfil (R-r/R-c)        -> TestCredentialExfil
  2. .env injection / arbitrary key    -> TestEnvInjection
  3. D5.4 bypass                       -> TestD54Bypass
  4. Audit tamper / secret exfil       -> TestAuditTamperAndSecretExfil
  5. Isolation read coercion           -> TestIsolationReadCoercion
  6. Auth/CSRF before effect           -> TestAuthCsrfBeforeEffect

Non-determinism note (red-team discipline): prompt-injection / fuzz attacks are reported as
attack-success-rate across MANY runs, not a single clean pass. The hostile-input batteries
(TestEnvInjection, TestD54Bypass) iterate large payload corpora and the
test_*_attack_success_rate aggregators assert 0% success across the whole corpus.

Isolation: every test uses a TEMP .env, TEMP audit log, and a TEMP fingerprint-salt path.
NEVER touches the real repo-root .env or the operator's ~/.agentarca. No Docker required;
Docker-needing escape checks are tagged @pytest.mark.integration and pytest.fail when Docker
is absent (so they are never silently skipped into a false RED_TEAMED).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings
from src.admin.main import create_app
from src.admin.primitives.credentials import (
    MANAGED_CREDENTIAL_KEYS,
    compute_fingerprint,
    get_credential_status,
    set_credential,
)

TEST_SECRET = "test-secret-value-RED-TEAM-P3-0xDEADBEEF"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"
VALID_HOST_HEADER = f"{TEST_HOST}:{TEST_PORT}"

# A realistic-looking throwaway canary token. Resembles a GitHub PAT so substring /
# fingerprint-reversal checks are meaningful. NOT a real credential.
CANARY_TOKEN = "ghp_RedTeamCanary3PhaseExfilCANARY0123456789abcd"
# Disjoint substrings that must never surface anywhere but the .env file itself.
CANARY_SUBSTRINGS = [
    CANARY_TOKEN,
    "ghp_RedTeamCanary",
    "CANARY0123456789",
    "Canary3PhaseExfil",
]


# ---------------------------------------------------------------------------
# Fixtures (temp everything; never the real .env / ~/.agentarca)
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_audit(tmp_path):
    return tmp_path / "admin-audit.jsonl"


@pytest.fixture()
def tmp_env_path(tmp_path):
    return tmp_path / ".env"


@pytest.fixture()
def tmp_salt_dir(tmp_path):
    d = tmp_path / ".agentarca"
    d.mkdir()
    return d


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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_REDTEAM_P3",
        audit_log_path=tmp_audit,
        session_secret_key="redteam-p3-session-key-aaabbbccc" * 3,
        repo_root=tmp_path,
    )


def _build_app(test_settings, tmp_salt_dir):
    """Create the app with the salt path redirected to the temp dir."""
    import src.admin.primitives.credentials as creds_module
    orig = creds_module.FINGERPRINT_SALT_PATH
    creds_module.FINGERPRINT_SALT_PATH = tmp_salt_dir / "fingerprint-salt"
    try:
        app = create_app(test_settings)
    except Exception:
        creds_module.FINGERPRINT_SALT_PATH = orig
        raise
    return app, creds_module, orig


@pytest.fixture()
def authed_client(test_settings, tmp_salt_dir):
    """Authenticated client WITH a valid CSRF token (the assume-injection-succeeds case)."""
    from starlette.testclient import TestClient
    app, creds_module, orig = _build_app(test_settings, tmp_salt_dir)
    try:
        with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
            c.headers.update({"Host": VALID_HOST_HEADER})
            login = c.post("/api/v1/login", json={"secret": TEST_SECRET})
            assert login.status_code == 200, f"login failed: {login.text}"
            c.headers.update({"X-CSRF-Token": login.json()["csrf_token"]})
            yield c
    finally:
        creds_module.FINGERPRINT_SALT_PATH = orig


@pytest.fixture()
def authed_no_csrf_client(test_settings, tmp_salt_dir):
    """Authenticated session but NO CSRF token attached (CSRF-bypass attempts)."""
    from starlette.testclient import TestClient
    app, creds_module, orig = _build_app(test_settings, tmp_salt_dir)
    try:
        with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
            c.headers.update({"Host": VALID_HOST_HEADER})
            login = c.post("/api/v1/login", json={"secret": TEST_SECRET})
            assert login.status_code == 200, f"login failed: {login.text}"
            # Deliberately do NOT set X-CSRF-Token.
            yield c
    finally:
        creds_module.FINGERPRINT_SALT_PATH = orig


@pytest.fixture()
def anon_client(test_settings, tmp_salt_dir):
    """Unauthenticated client (no session, no CSRF)."""
    from starlette.testclient import TestClient
    app, creds_module, orig = _build_app(test_settings, tmp_salt_dir)
    try:
        with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
            c.headers.update({"Host": VALID_HOST_HEADER})
            yield c
    finally:
        creds_module.FINGERPRINT_SALT_PATH = orig


def _env_path(test_settings) -> Path:
    return test_settings.repo_root / ".env"


def _assert_no_canary_anywhere(text: str, where: str):
    for sub in CANARY_SUBSTRINGS:
        assert sub not in text, (
            f"FINDING (CRITICAL, R-c/R-r): canary token substring {sub!r} leaked in {where}: "
            f"{text[:500]}"
        )


def _assert_no_secret_anywhere(text: str, where: str):
    assert TEST_SECRET not in text, (
        f"FINDING (CRITICAL, R-r): admin shared secret leaked in {where}: {text[:500]}"
    )


def _put_key(client, key: str, value: str):
    """PUT to /credentials/{key}, tolerating client-side URL rejection.

    Some hostile keys (raw newline, NUL) are refused by the HTTP client before the
    request leaves the process. That is itself containment: the byte never reaches the
    server. Returns (status_code, text) with status_code=None when the client refused.
    """
    import httpx
    try:
        r = client.put(f"/api/v1/credentials/{key}", json={"value": value})
        return r.status_code, r.text
    except httpx.InvalidURL:
        return None, ""  # client refused to transmit -> contained before the server


# ===========================================================================
# Family 1: Credential exfil  (the central P3 attack; R-r / R-c)
# ===========================================================================

class TestCredentialExfil:
    """ASSUME the attacker is authenticated and is trying to read a token back out."""

    def _seed_token(self, client, key="ANTHROPIC_API_KEY", value=CANARY_TOKEN):
        r = client.put(f"/api/v1/credentials/{key}", json={"value": value})
        assert r.status_code == 200, f"seed failed: {r.text}"
        return r

    def test_token_absent_from_every_read_path(
        self, authed_client, test_settings, tmp_audit, capsys, caplog
    ):
        """Hammer GET /credentials, the audit log, and error responses; token never appears."""
        import logging
        caplog.set_level(logging.DEBUG)
        self._seed_token(authed_client)

        # Read path 1: GET /api/v1/credentials (the only sanctioned read).
        get = authed_client.get("/api/v1/credentials")
        assert get.status_code == 200
        _assert_no_canary_anywhere(get.text, "GET /credentials body")
        # Only the fingerprint should be exposed for the SET key.
        seeded = next(k for k in get.json()["keys"] if k["key"] == "ANTHROPIC_API_KEY")
        assert seeded["status"] == "SET"
        assert seeded["fingerprint"] is not None
        _assert_no_canary_anywhere(seeded["fingerprint"], "fingerprint field")

        # Read path 2: the audit log on disk.
        assert tmp_audit.exists()
        _assert_no_canary_anywhere(tmp_audit.read_text(encoding="utf-8"), "audit log")

        # Read path 3: error responses can't be coerced to echo the value.
        for bad in [
            authed_client.put("/api/v1/credentials/ANTHROPIC_API_KEY", json={}),         # missing value
            authed_client.put("/api/v1/credentials/ANTHROPIC_API_KEY", json={"value": ""}),  # empty
            authed_client.put("/api/v1/credentials/NOT_A_KEY", json={"value": "x"}),     # bad key
            authed_client.get("/api/v1/credentials/ANTHROPIC_API_KEY"),                  # GET single (no route)
            authed_client.post("/api/v1/credentials/ANTHROPIC_API_KEY", json={"value": "x"}),  # wrong verb
        ]:
            _assert_no_canary_anywhere(bad.text, f"error response (status {bad.status_code})")

        # Read path 4: nothing printed/logged the value at any point.
        captured = capsys.readouterr()
        for label, stream in (("stdout", captured.out), ("stderr", captured.err), ("logs", caplog.text)):
            _assert_no_canary_anywhere(stream, label)

    def test_fingerprint_is_not_reversible_and_not_a_substring(
        self, authed_client, test_settings, tmp_salt_dir
    ):
        """The fingerprint must not be a substring of the token, and must be unrecoverable
        without the per-install salt (a brute force over short ghp_/sk- tokens must fail)."""
        self._seed_token(authed_client)
        get = authed_client.get("/api/v1/credentials")
        fp = next(k for k in get.json()["keys"] if k["key"] == "ANTHROPIC_API_KEY")["fingerprint"]

        assert fp not in CANARY_TOKEN, (
            "FINDING (CRITICAL, R-c): fingerprint is a substring of the cleartext token"
        )
        assert len(fp) == 16 and int(fp, 16) >= 0  # masked HMAC prefix, valid hex

        # Fingerprint-reversal: without the real salt, no guessed salt reproduces fp for the
        # token, i.e. the displayed fingerprint leaks nothing usable. Try a corpus of plausible
        # attacker-guessed salts; none must match (the real salt is 32 random bytes on disk).
        guessed_salts = [b"", b"0" * 32, b"salt", bytes(32), os.urandom(32), b"agentarca"]
        for gs in guessed_salts:
            assert compute_fingerprint(CANARY_TOKEN, gs) != fp, (
                "FINDING (CRITICAL, R-c): fingerprint reproduced from a guessable salt; "
                "the salt is not providing pre-image protection"
            )

        # And a short-token brute force over the fingerprint without the salt cannot recover
        # the token: distinct candidate tokens hash to distinct values under a wrong salt, and
        # none equals the real (salted) fp by construction. Spot-check a few near-miss tokens.
        for candidate in ["ghp_x", "sk-x", CANARY_TOKEN[:-1], CANARY_TOKEN + "0"]:
            assert compute_fingerprint(candidate, b"wrong-salt") != fp

    def test_admin_secret_submitted_as_value_is_chokepoint_sanitized(
        self, authed_client, test_settings, tmp_audit, capsys
    ):
        """Submit the admin SHARED SECRET as a credential value. It is correctly stored in
        .env (it's just a value to the writer) but must NEVER appear in any response/audit/log:
        the audit chokepoint _sanitize() must catch it everywhere but the .env file."""
        r = authed_client.put(
            "/api/v1/credentials/OPENAI_API_KEY", json={"value": TEST_SECRET}
        )
        assert r.status_code == 200
        # Response body must not echo the secret.
        _assert_no_secret_anywhere(r.text, "PUT response (secret-as-value)")
        # GET must not echo it.
        _assert_no_secret_anywhere(authed_client.get("/api/v1/credentials").text, "GET response")
        # Audit log must not contain it (chokepoint sanitization).
        _assert_no_secret_anywhere(tmp_audit.read_text(encoding="utf-8"), "audit log")
        # The sanitizer fires to stderr; the secret itself must not be in stdout/stderr.
        captured = capsys.readouterr()
        _assert_no_secret_anywhere(captured.out, "stdout")
        _assert_no_secret_anywhere(captured.err, "stderr")

    def test_exfil_attack_success_rate_zero(self, authed_client, test_settings, tmp_audit):
        """Aggregate: across many seed+read cycles with varied tokens and read angles, the
        attack-success-rate (a token substring surfacing in any response or the audit) is 0%."""
        successes = 0
        trials = 0
        keys = sorted(MANAGED_CREDENTIAL_KEYS)
        for i in range(40):
            key = keys[i % len(keys)]
            tok = f"ghp_RedTeamCanary{i:04d}_CANARY0123456789abcd"
            authed_client.put(f"/api/v1/credentials/{key}", json={"value": tok})
            # Try several read angles each iteration.
            bodies = [
                authed_client.get("/api/v1/credentials").text,
                authed_client.put(f"/api/v1/credentials/{key}", json={}).text,
                authed_client.put("/api/v1/credentials/INVALID", json={"value": tok}).text,
                tmp_audit.read_text(encoding="utf-8"),
            ]
            for b in bodies:
                trials += 1
                if tok in b or "CANARY0123456789" in b and tok in b:
                    successes += 1
        rate = successes / trials if trials else 0.0
        assert rate == 0.0, (
            f"FINDING (CRITICAL, R-r/R-c): credential-exfil attack-success-rate = {rate:.2%} "
            f"({successes}/{trials}); a token leaked through a read path."
        )


# ===========================================================================
# Family 2: .env injection / arbitrary-key write
# ===========================================================================

# Hostile KEYS: must all be rejected BEFORE any file I/O (not in the 5-key allowlist).
HOSTILE_KEYS = [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc",
    "EVIL_KEY",
    "anthropic_api_key",          # wrong case -> not in allowlist (case-sensitive)
    "ANTHROPIC_API_KEY ",         # trailing space
    " ANTHROPIC_API_KEY",         # leading space
    "ANTHROPIC_API_KEY=INJECT",   # embedded '='
    "ANTHROPIC_API_KEY\nEVIL=1",  # embedded newline
    "PATH",
    "LD_PRELOAD",
    "A" * 5000,                   # very long
    "ANTHROPIC_API_KEY\x00",      # null byte
    # NOTE: percent-encoded forms that DECODE to a real allowlisted key (e.g.
    # "ANTHROPIC%5fAPI%5fKEY" -> "ANTHROPIC_API_KEY") are intentionally NOT in this list:
    # %5f is just the canonical encoding of '_', so the server correctly routes them to the
    # legitimate key. That is expected behavior, not an allowlist bypass.
]

# Hostile VALUES on a VALID key: must not create a second logical .env key.
HOSTILE_VALUES = [
    "x\nEVIL_KEY=y",
    "x\r\nEVIL_KEY=y",
    "x\nPATH=/attacker/bin",
    "legit\n# comment injection\nROOT_TOKEN=pwned",
    "a\nb\nc\nMULTI=1",
    "val\x00EVIL=1",
    "val\nANOTHER_MANAGED=CODEX_API_KEY=stolen",
]


class TestEnvInjection:
    def test_hostile_keys_rejected_before_file_io(self, authed_client, test_settings):
        """Every hostile key is rejected (400/404/422) and the .env never gains an out-of-
        allowlist key, and no file outside the repo-root .env is written."""
        env_path = _env_path(test_settings)
        repo_root = test_settings.repo_root
        before_snapshot = sorted(p.name for p in repo_root.iterdir())

        for key in HOSTILE_KEYS:
            status_code, text = _put_key(authed_client, key, "attacker")
            if status_code is None:
                continue  # client refused to transmit the key -> contained pre-server
            # Path-segment keys may 404 (no route match) or 400 (validation); never 200.
            assert status_code != 200, (
                f"FINDING (CRITICAL): hostile key {key!r} accepted (200). The 5-key allowlist "
                f"was bypassed."
            )
            assert status_code in (400, 404, 405, 422), (
                f"unexpected status {status_code} for hostile key {key!r}: {text}"
            )

        # .env, if it exists at all, contains only allowlisted keys.
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                k = line.split("=", 1)[0]
                assert k in MANAGED_CREDENTIAL_KEYS, (
                    f"FINDING (CRITICAL): out-of-allowlist key {k!r} written to .env"
                )

        # No new file created outside the repo-root .env (no traversal escape).
        after_snapshot = sorted(p.name for p in repo_root.iterdir())
        new_files = set(after_snapshot) - set(before_snapshot)
        assert new_files <= {".env"}, (
            f"FINDING (CRITICAL): traversal/injection created files outside .env: {new_files}"
        )
        assert not Path("/etc/passwd.agentarca").exists()  # sanity: nothing escaped to /etc

    def test_hostile_value_does_not_create_second_key(self, authed_client, test_settings):
        """A value with a newline must NOT inject a second logical .env key. Either the writer
        escapes/encodes it, or the value stays on one logical KEY= line; either way, no NEW key
        (EVIL_KEY/PATH/ROOT_TOKEN/etc.) and no out-of-allowlist key appears."""
        env_path = _env_path(test_settings)
        for value in HOSTILE_VALUES:
            r = authed_client.put("/api/v1/credentials/CODEX_API_KEY", json={"value": value})
            # Containment is satisfied EITHER by rejecting the control-character value (400)
            # OR by writing it such that it stays one logical key. We assert the structural
            # outcome: no out-of-allowlist key ever appears in .env, regardless of path taken.
            assert r.status_code in (200, 400), f"unexpected status {r.status_code}: {r.text}"
            injected = set()
            if env_path.exists():
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    k = line.split("=", 1)[0].strip()
                    if k not in MANAGED_CREDENTIAL_KEYS:
                        injected.add(k)
            assert not injected, (
                f"FINDING (CRITICAL): value {value!r} injected new .env key(s) {injected}. "
                f"Newline injection created an out-of-allowlist key."
            )

    def test_env_injection_attack_success_rate_zero(self, authed_client, test_settings):
        """Aggregate over the full key+value hostile corpus: 0 successful injections of an
        out-of-allowlist key, reported as attack-success-rate."""
        env_path = _env_path(test_settings)
        forbidden_markers = {"EVIL_KEY", "EVIL", "PATH", "ROOT_TOKEN", "MULTI", "ANOTHER_MANAGED",
                             "LD_PRELOAD"}
        successes = 0
        trials = 0

        for key in HOSTILE_KEYS:
            trials += 1
            status_code, _ = _put_key(authed_client, key, "x")
            if status_code == 200:
                successes += 1
        for value in HOSTILE_VALUES:
            trials += 1
            authed_client.put("/api/v1/credentials/OPENAI_API_KEY", json={"value": value})
            keys_now = set()
            if env_path.exists():
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        keys_now.add(line.split("=", 1)[0].strip())
            if keys_now & forbidden_markers or (keys_now - MANAGED_CREDENTIAL_KEYS):
                successes += 1

        rate = successes / trials if trials else 0.0
        assert rate == 0.0, (
            f"FINDING (CRITICAL): .env-injection attack-success-rate = {rate:.2%} "
            f"({successes}/{trials}); an arbitrary/out-of-allowlist key was written."
        )

    def test_primitive_rejects_unknown_key_before_io(self, tmp_path):
        """Defense-in-depth at the primitive: set_credential with a non-allowlisted key
        returns rejected-by-validation and writes NOTHING."""
        env = tmp_path / ".env"
        res = set_credential("EVIL_KEY", "x", salt=b"0" * 32, env_path=env)
        assert res.outcome == "rejected-by-validation"
        assert not env.exists(), (
            "FINDING (CRITICAL): primitive wrote .env for a non-allowlisted key"
        )


# ===========================================================================
# Family 3: D5.4 bypass  (grant a forbidden capability)
# ===========================================================================

# Each entry is a body for POST /isolation/validate that tries to slip a forbidden condition
# through (incl. alternate casing). All must be REFUSED (400 + rejected-by-stop-and-flag).
D54_HOSTILE_BODIES = [
    {"proposed_caps_add": ["NET_ADMIN"]},
    {"proposed_caps_add": ["net_admin"]},
    {"proposed_caps_add": ["Net_Admin"]},
    {"proposed_caps_add": ["NET_RAW"]},
    {"proposed_caps_add": ["SYS_ADMIN"]},
    {"proposed_caps_add": ["CAP_NET_ADMIN", "NET_ADMIN"]},
    {"proposed_flags": ["--privileged"]},
    {"proposed_flags": ["privileged"]},
    {"proposed_flags": ["--PRIVILEGED"]},
    {"proposed_mounts": ["/var/run/docker.sock:/var/run/docker.sock"]},
    {"proposed_mounts": ["./docker.sock:/x"]},
    {"concurrent_profiles": True},
    {"proposed_caps_add": ["NET_ADMIN"], "proposed_flags": ["--privileged"],
     "concurrent_profiles": True},
]

# Forbidden condition names smuggled as EXTRA fields where there is no such model field;
# they must be ignored by pydantic and have no effect (NOTHING mutates).
D54_SMUGGLED_EXTRA_FIELDS = [
    {"net_admin": True},
    {"sys_admin": True},
    {"privileged": True},
    {"docker_sock": "/var/run/docker.sock"},
    {"NET_ADMIN": True},
    {"cap_add": ["NET_ADMIN"]},          # wrong field name; real field is proposed_caps_add
    {"caps": ["SYS_ADMIN"]},
]


class TestD54Bypass:
    def _read_compose_state(self, test_settings):
        cp = test_settings.repo_root / "docker-compose.yml"
        return cp.read_text(encoding="utf-8") if cp.exists() else None

    def test_forbidden_conditions_refused_and_non_mutating(
        self, authed_client, test_settings, tmp_audit
    ):
        """Every forbidden condition via the validate body is refused (400 +
        rejected-by-stop-and-flag) and nothing mutates."""
        before = self._read_compose_state(test_settings)
        for body in D54_HOSTILE_BODIES:
            r = authed_client.post("/api/v1/isolation/validate", json=body)
            assert r.status_code == 400, (
                f"FINDING (CRITICAL, D5.4): forbidden body {body} returned {r.status_code}, "
                f"not 400: {r.text}"
            )
            data = r.json()
            assert data.get("ok") is False and data.get("violations"), (
                f"FINDING (CRITICAL, D5.4): body {body} not reported as a violation: {data}"
            )
        # Audit recorded rejected-by-stop-and-flag for the refusals.
        audit = tmp_audit.read_text(encoding="utf-8") if tmp_audit.exists() else ""
        assert "rejected-by-stop-and-flag" in audit, (
            "FINDING: D5.4 refusals were not audited as rejected-by-stop-and-flag"
        )
        # Compose file unchanged (validate is non-mutating).
        assert self._read_compose_state(test_settings) == before, (
            "FINDING (CRITICAL): isolation/validate mutated docker-compose.yml"
        )

    def test_smuggled_extra_fields_are_ignored_not_applied(
        self, authed_client, test_settings
    ):
        """Forbidden names smuggled as EXTRA body fields (not real model fields) are ignored:
        the request is treated as an empty/benign proposal (200, no violations), never applied.
        This proves the forbidden names are STRUCTURALLY ABSENT from the write surface."""
        before = self._read_compose_state(test_settings)
        for body in D54_SMUGGLED_EXTRA_FIELDS:
            r = authed_client.post("/api/v1/isolation/validate", json=body)
            # Extra fields ignored by pydantic -> benign empty proposal -> 200 no violations.
            # (A 422 would also be acceptable containment, but never a 200-with-applied-cap.)
            assert r.status_code in (200, 422), (
                f"FINDING: smuggled field body {body} returned {r.status_code}: {r.text}"
            )
            if r.status_code == 200:
                assert r.json().get("violations") == [], (
                    f"unexpected violations for ignored extra-field body {body}: {r.text}"
                )
        assert self._read_compose_state(test_settings) == before, (
            "FINDING (CRITICAL): a smuggled extra field mutated docker-compose.yml"
        )

    def test_forbidden_names_absent_from_request_model(self):
        """The validate body model exposes NO field that could carry a forbidden grant as a
        scalar truthy (net_admin/sys_admin/privileged/docker_sock). Only list/preflight fields
        that are routed through check_d5_4_hard_refusals()."""
        from src.admin.routes.isolation import IsolationValidateBody
        fields = set(IsolationValidateBody.model_fields.keys())
        forbidden_field_names = {"net_admin", "sys_admin", "privileged", "docker_sock",
                                 "cap_add", "caps", "net_raw"}
        leaked = fields & forbidden_field_names
        assert not leaked, (
            f"FINDING (CRITICAL, D5.4): request model exposes forbidden grant field(s) {leaked}"
        )

    def test_d54_bypass_attack_success_rate_zero(self, authed_client, test_settings):
        """Aggregate: across the full forbidden-condition corpus x repeats, 0 are ever
        accepted-as-applied. Reported as attack-success-rate."""
        before = self._read_compose_state(test_settings)
        successes = 0
        trials = 0
        for _ in range(5):  # repeat to surface any non-determinism
            for body in D54_HOSTILE_BODIES:
                trials += 1
                r = authed_client.post("/api/v1/isolation/validate", json=body)
                # Success for the attacker = the forbidden condition was NOT refused.
                if r.status_code != 400 or r.json().get("ok") is True:
                    successes += 1
        rate = successes / trials if trials else 0.0
        assert rate == 0.0, (
            f"FINDING (CRITICAL, D5.4): bypass attack-success-rate = {rate:.2%} "
            f"({successes}/{trials}); a forbidden capability slipped through validate."
        )
        assert self._read_compose_state(test_settings) == before, (
            "FINDING (CRITICAL): repeated validate calls mutated docker-compose.yml"
        )


# ===========================================================================
# Family 4: Audit tamper / secret exfil
# ===========================================================================

class TestAuditTamperAndSecretExfil:
    def test_no_route_reads_or_deletes_audit_log(self, authed_client, test_settings, tmp_audit):
        """No credentials/isolation route reads back, rotates, or deletes the audit log.

        Probe plausible tamper endpoints. None may succeed (200): a 404 (no route), 405
        (verb not allowed), or 400 (the {key} allowlist guard rejecting target="audit") all
        mean the audit log was NOT read back, rotated, or deleted. We additionally seed a
        record first and assert the audit log is intact after the probes (no truncation)."""
        # Seed an audit record so we can prove it survives the tamper probes.
        authed_client.put("/api/v1/credentials/OPENAI_API_KEY", json={"value": CANARY_TOKEN})
        assert tmp_audit.exists()
        before = tmp_audit.read_text(encoding="utf-8")
        assert before.strip(), "expected a seeded audit record"

        for method, path in [
            ("GET", "/api/v1/credentials/audit"),
            ("DELETE", "/api/v1/credentials/audit"),
            ("GET", "/api/v1/isolation/audit"),
            ("DELETE", "/api/v1/audit"),
            ("POST", "/api/v1/audit/clear"),
            ("PUT", "/api/v1/audit"),
        ]:
            r = authed_client.request(method, path, json={})
            assert r.status_code != 200, (
                f"FINDING (CRITICAL, R-r): audit tamper endpoint {method} {path} SUCCEEDED "
                f"(status 200) — the audit log is reachable for read/rotate/delete"
            )
            assert r.status_code in (400, 404, 405, 422), (
                f"unexpected status {r.status_code} for {method} {path}: {r.text}"
            )

        # The audit log must still contain every prior record (no truncation/rotation).
        after = tmp_audit.read_text(encoding="utf-8")
        assert before in after, (
            "FINDING (CRITICAL, R-r): the audit log was truncated/rotated by a tamper probe"
        )

    def test_every_mutation_and_refusal_is_audited_fingerprint_only(
        self, authed_client, test_settings, tmp_audit
    ):
        """A credential set, a credential clear, and a D5.4 refusal each produce an audit
        record carrying FINGERPRINT only (no token, no secret)."""
        authed_client.put("/api/v1/credentials/CLAUDE_CODE_OAUTH_TOKEN", json={"value": CANARY_TOKEN})
        authed_client.delete("/api/v1/credentials/CLAUDE_CODE_OAUTH_TOKEN")
        authed_client.post("/api/v1/isolation/validate", json={"proposed_caps_add": ["NET_ADMIN"]})

        assert tmp_audit.exists()
        lines = [json.loads(l) for l in tmp_audit.read_text(encoding="utf-8").splitlines() if l.strip()]
        actions = {rec["action"] for rec in lines}
        assert {"credential_set", "credential_clear", "isolation_validate"} <= actions, (
            f"FINDING: not all mutations/refusals were audited; saw actions {actions}"
        )
        raw = tmp_audit.read_text(encoding="utf-8")
        _assert_no_canary_anywhere(raw, "audit records")
        _assert_no_secret_anywhere(raw, "audit records")
        # The set record must carry an after-fingerprint (16 hex), not the value.
        set_rec = next(r for r in lines if r["action"] == "credential_set" and r["outcome"] == "applied")
        assert set_rec["after"] and len(set_rec["after"]) == 16
        int(set_rec["after"], 16)

    def test_admin_secret_never_in_any_audit_record(
        self, authed_client, test_settings, tmp_audit
    ):
        """Drive secret-as-value and secret-as-key through every audited path; the secret
        never lands in the audit trail (chokepoint _sanitize)."""
        authed_client.put("/api/v1/credentials/ANTHROPIC_API_KEY", json={"value": TEST_SECRET})
        authed_client.put(f"/api/v1/credentials/{TEST_SECRET}", json={"value": "x"})  # secret as key
        authed_client.post("/api/v1/isolation/validate", json={"proposed_flags": [TEST_SECRET]})
        if tmp_audit.exists():
            _assert_no_secret_anywhere(tmp_audit.read_text(encoding="utf-8"), "audit trail")


# ===========================================================================
# Family 5: Isolation read coercion
# ===========================================================================

class TestIsolationReadCoercion:
    def test_reader_uses_safe_load_no_arbitrary_load(self):
        """Source-level: the isolation primitive uses yaml.safe_load ONLY; never yaml.load
        (object-construction / code-exec risk)."""
        import ast
        src = (REPO_ROOT / "src/admin/primitives/isolation.py").read_text(encoding="utf-8")
        assert "yaml.safe_load" in src
        # Parse the AST so prose mentions of "yaml.load()" in comments/docstrings don't
        # false-positive. Forbid any ACTUAL call to yaml.load / yaml.unsafe_load / yaml.full_load.
        tree = ast.parse(src)
        forbidden_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "yaml"
                    and node.func.attr in {"load", "unsafe_load", "full_load"}
                ):
                    forbidden_calls.append(node.func.attr)
        assert not forbidden_calls, (
            "FINDING (CRITICAL): isolation reader makes an unsafe YAML call "
            f"{forbidden_calls} (code-exec risk); only yaml.safe_load() is permitted"
        )

    def test_malicious_yaml_tags_do_not_execute(self, tmp_path):
        """A compose file carrying a python/object YAML tag must NOT construct an object or
        execute under safe_load: the reader either parse-errors safely or yields plain data."""
        from src.admin.primitives.isolation import read_isolation_posture
        evil = tmp_path / "docker-compose.yml"
        evil.write_text(
            "services:\n"
            "  devcontainer-claude:\n"
            "    cap_add: !!python/object/apply:os.system ['touch /tmp/agentarca_pwned_p3']\n",
            encoding="utf-8",
        )
        sentinel = Path("/tmp/agentarca_pwned_p3")
        if sentinel.exists():
            sentinel.unlink()
        posture = read_isolation_posture(compose_path=evil, profile="claude")
        # safe_load raises on python tags -> reader returns a posture with a parse-error marker.
        assert not sentinel.exists(), (
            "FINDING (CRITICAL): malicious YAML tag executed os.system via the isolation reader"
        )
        assert posture.d5_4_violations, "expected a parse-error marker for the malicious YAML"

    def test_reader_cannot_be_steered_to_arbitrary_file(
        self, authed_client, test_settings
    ):
        """GET /api/v1/isolation takes NO path/param input; there is no way to redirect the
        read to an arbitrary file. Query params are ignored and the fixed compose path is used."""
        # Seed a secret file the attacker would love to read.
        secret_file = test_settings.repo_root / "SECRET_TARGET.txt"
        secret_file.write_text("TOP-SECRET-ISOLATION-TARGET", encoding="utf-8")
        for params in [
            {"path": str(secret_file)},
            {"compose_path": "/etc/passwd"},
            {"file": "../../etc/passwd"},
            {"profile": "../../etc/passwd"},
        ]:
            r = authed_client.get("/api/v1/isolation", params=params)
            assert r.status_code == 200
            assert "TOP-SECRET-ISOLATION-TARGET" not in r.text, (
                f"FINDING (CRITICAL): isolation read was steered to an arbitrary file via {params}"
            )
            assert "root:" not in r.text, (
                f"FINDING (CRITICAL): isolation read leaked /etc/passwd via {params}"
            )

    def test_isolation_paths_reject_mutating_verbs(self, authed_client):
        """GET /isolation and /isolation/validate are read-only-ish; mutating verbs that
        shouldn't be accepted return 405 (or 404). No PUT/PATCH/DELETE writes a posture."""
        for method, path in [
            ("PUT", "/api/v1/isolation"),
            ("PATCH", "/api/v1/isolation"),
            ("DELETE", "/api/v1/isolation"),
            ("PUT", "/api/v1/isolation/validate"),
            ("DELETE", "/api/v1/isolation/validate"),
            ("PATCH", "/api/v1/isolation/validate"),
        ]:
            r = authed_client.request(method, path, json={"x": 1})
            assert r.status_code in (404, 405), (
                f"FINDING (CRITICAL): {method} {path} not rejected (status {r.status_code}); "
                f"a mutating verb reached the read-only isolation surface"
            )


# ===========================================================================
# Family 6: Auth / CSRF before effect
# ===========================================================================

class TestAuthCsrfBeforeEffect:
    def test_unauth_put_delete_rejected_no_file_effect(self, anon_client, test_settings):
        """PUT/DELETE without auth are rejected and produce NO .env effect."""
        env_path = _env_path(test_settings)
        assert not env_path.exists()
        for r in [
            anon_client.put("/api/v1/credentials/ANTHROPIC_API_KEY", json={"value": CANARY_TOKEN}),
            anon_client.delete("/api/v1/credentials/ANTHROPIC_API_KEY"),
            anon_client.post("/api/v1/isolation/validate", json={"proposed_caps_add": ["NET_ADMIN"]}),
        ]:
            assert r.status_code in (401, 403), (
                f"FINDING (CRITICAL): unauthenticated write returned {r.status_code}: {r.text}"
            )
        assert not env_path.exists(), (
            "FINDING (CRITICAL): an unauthenticated request created/modified the .env file"
        )

    def test_authed_no_csrf_put_delete_rejected_no_file_effect(
        self, authed_no_csrf_client, test_settings
    ):
        """Authenticated but missing CSRF token: state-changing requests are rejected (403)
        by CSRF middleware BEFORE any .env write."""
        env_path = _env_path(test_settings)
        assert not env_path.exists()
        put = authed_no_csrf_client.put(
            "/api/v1/credentials/ANTHROPIC_API_KEY", json={"value": CANARY_TOKEN}
        )
        dele = authed_no_csrf_client.delete("/api/v1/credentials/ANTHROPIC_API_KEY")
        for r in (put, dele):
            assert r.status_code == 403, (
                f"FINDING (CRITICAL): CSRF-less write returned {r.status_code}, expected 403: {r.text}"
            )
        assert not env_path.exists(), (
            "FINDING (CRITICAL): a CSRF-less request created/modified the .env file"
        )

    def test_no_canary_in_rejected_request_bodies(self, anon_client, authed_no_csrf_client):
        """Rejected (401/403) requests must not reflect the submitted token back."""
        for client in (anon_client, authed_no_csrf_client):
            r = client.put(
                "/api/v1/credentials/ANTHROPIC_API_KEY", json={"value": CANARY_TOKEN}
            )
            _assert_no_canary_anywhere(r.text, f"rejected request body (status {r.status_code})")


# ===========================================================================
# Container-escape checks (Docker-needing; gated so they cannot silently skip).
# ===========================================================================

class TestContainerEscapeChecks:
    @pytest.mark.integration
    def test_compose_has_no_escape_primitives(self):
        """Static-but-Docker-adjacent: the real compose must not grant docker.sock, privileged,
        or forbidden caps to the devcontainer. Gated as integration; fail (not skip) if the
        compose file is absent so a missing file never yields a false RED_TEAMED."""
        compose = REPO_ROOT / "docker-compose.yml"
        if not compose.exists():
            pytest.fail("docker-compose.yml absent; cannot verify escape primitives (no silent skip)")
        from src.admin.primitives.isolation import read_isolation_posture
        for profile in ("copilot", "claude", "codex"):
            posture = read_isolation_posture(compose_path=compose, profile=profile)
            assert not posture.docker_sock_mounted, (
                f"FINDING (CRITICAL): docker.sock mounted into devcontainer-{profile}"
            )
            assert not posture.privileged, (
                f"FINDING (CRITICAL): devcontainer-{profile} is privileged"
            )
            assert not posture.d5_4_violations, (
                f"FINDING (CRITICAL): D5.4 violations in compose for {profile}: "
                f"{posture.d5_4_violations}"
            )
