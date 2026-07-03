"""
test_readiness_gate.py - Acceptance tests for the P1 credential readiness gate.

Covers:
  AC-29-P1-01  do_up("claude", ...) with CLAUDE_CODE_OAUTH_TOKEN absent returns dict
               http_status=400 outcome=rejected-by-validation; NOT 500; does not raise;
               mint_nonce not called; route writes rejected-by-validation audit with
               target="claude" and HTTP 400.
  AC-29-P1-02  Same for copilot / COPILOT_GITHUB_TOKEN absent.
  AC-29-P1-03  Same for codex when NEITHER CODEX_API_KEY nor OPENAI_API_KEY present.
  AC-29-P1-04  do_up proceeds PAST gate when required managed credential is present:
               claude (CLAUDE_CODE_OAUTH_TOKEN), copilot, codex via CODEX_API_KEY only,
               codex via OPENAI_API_KEY only.

All tests are Docker-free: lifecycle lock, mint_nonce, compose_up, and
wait_for_gateway_healthy are all monkeypatched. Never touches real ~/.agentarca
credentials or audit log.

Design references: SPEC-29-P1 sec 4, B6; security-review adjudication B (proven
end-to-end); round-2 regression guard (B6 was a BLOCK because the 400 contract
was broken by an HTTPException reaching the except Exception -> 500 path).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings
from src.admin.main import create_app
from src.admin.primitives.lifecycle import do_up

TEST_SECRET = "test-secret-value-12345"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"
VALID_HOST_HEADER = f"{TEST_HOST}:{TEST_PORT}"


# ---------------------------------------------------------------------------
# Fixtures
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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RG_TEST",
        audit_log_path=tmp_audit,
        session_secret_key="test-session-key-aaabbbccc" * 4,
    )


@pytest.fixture()
def client(test_settings):
    from starlette.testclient import TestClient
    app = create_app(test_settings)
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HEADER})
        yield c


@pytest.fixture()
def authed_client(client):
    """Authenticated client with CSRF token set."""
    resp = client.post(
        "/api/v1/login",
        json={"secret": TEST_SECRET},
        headers={"Host": VALID_HOST_HEADER},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    csrf = resp.json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": csrf})
    return client


def _read_audit_records(audit_path: Path) -> list:
    if not audit_path.exists():
        return []
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _lifecycle_audit_records(audit_path: Path) -> list:
    return [r for r in _read_audit_records(audit_path) if r.get("domain") == "lifecycle"]


def _make_absent_cred_mock() -> MagicMock:
    m = MagicMock()
    m.present = False
    return m


def _make_present_cred_mock() -> MagicMock:
    m = MagicMock()
    m.present = True
    return m


# ---------------------------------------------------------------------------
# Primitive-level tests: direct calls to do_up() (no HTTP)
# ---------------------------------------------------------------------------

class TestReadinessGatePrimitive:
    """
    Tests the do_up primitive directly, verifying the dict vocabulary and the
    hard contract that the gate returns 400 (never 500) and never raises.
    """

    # --- AC-29-P1-01: claude gate absent ---

    def test_do_up_claude_absent_returns_dict_not_exception(self):
        """Gate MUST return a dict; must NOT raise. AC-29-P1-01."""
        absent = _make_absent_cred_mock()
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=AssertionError("mint_nonce must not be called when credential absent")):
            result = do_up("claude", secret="test-secret", salt=b"", env_path=None)

        assert isinstance(result, dict), "do_up must return a dict on gate failure, not raise"

    def test_do_up_claude_absent_returns_400_not_500(self):
        """Gate returns http_status=400; round-2 regression guard (NOT 500). AC-29-P1-01."""
        absent = _make_absent_cred_mock()
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=AssertionError("mint_nonce must not be called")):
            result = do_up("claude", secret="test-secret", salt=b"", env_path=None)

        assert result["http_status"] == 400, (
            f"Expected http_status=400 from credential gate, got {result['http_status']!r} -- "
            "this is the B6 regression guard: raising HTTPException inside do_up would "
            "have been caught as 500"
        )
        assert result["http_status"] != 500, "Gate must never return 500 (regression guard)"

    def test_do_up_claude_absent_outcome_rejected_by_validation(self):
        """Gate returns outcome=rejected-by-validation. AC-29-P1-01."""
        absent = _make_absent_cred_mock()
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=AssertionError("mint_nonce must not be called")):
            result = do_up("claude", secret="test-secret", salt=b"", env_path=None)

        assert result["outcome"] == "rejected-by-validation"

    def test_do_up_claude_absent_detail_contains_key_name(self):
        """Gate detail names the missing credential key. AC-29-P1-01."""
        absent = _make_absent_cred_mock()
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=AssertionError("mint_nonce must not be called")):
            result = do_up("claude", secret="test-secret", salt=b"", env_path=None)

        assert "CLAUDE_CODE_OAUTH_TOKEN" in result.get("detail", ""), (
            f"Expected CLAUDE_CODE_OAUTH_TOKEN in detail, got: {result.get('detail', '')!r}"
        )

    def test_do_up_claude_absent_mint_nonce_never_called(self):
        """Gate fires BEFORE mint_nonce; nonce must never be minted. AC-29-P1-01."""
        absent = _make_absent_cred_mock()
        mint_calls = []
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=lambda p: mint_calls.append(p)):
            do_up("claude", secret="test-secret", salt=b"", env_path=None)

        assert len(mint_calls) == 0, (
            f"mint_nonce must not be called when credential gate fails; calls: {mint_calls}"
        )

    # --- AC-29-P1-02: copilot gate absent ---

    def test_do_up_copilot_absent_returns_400_not_500(self):
        """Copilot gate returns 400 on absent COPILOT_GITHUB_TOKEN. AC-29-P1-02."""
        absent = _make_absent_cred_mock()
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=AssertionError("mint_nonce must not be called")):
            result = do_up("copilot", secret="test-secret", salt=b"", env_path=None)

        assert result["http_status"] == 400
        assert result["outcome"] == "rejected-by-validation"
        assert "COPILOT_GITHUB_TOKEN" in result.get("detail", ""), (
            f"Detail should name the missing key; got: {result.get('detail', '')!r}"
        )

    # --- AC-29-P1-03: codex gate absent (neither key present) ---

    def test_do_up_codex_both_absent_returns_400(self):
        """Codex gate returns 400 when NEITHER CODEX_API_KEY nor OPENAI_API_KEY present. AC-29-P1-03."""
        absent = _make_absent_cred_mock()
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=AssertionError("mint_nonce must not be called")):
            result = do_up("codex", secret="test-secret", salt=b"", env_path=None)

        assert result["http_status"] == 400
        assert result["outcome"] == "rejected-by-validation"
        # Both keys should be named in the detail (device-auth path not checked per spec sec 5.4)
        detail = result.get("detail", "")
        assert "CODEX_API_KEY" in detail, f"CODEX_API_KEY not in detail: {detail!r}"
        assert "OPENAI_API_KEY" in detail, f"OPENAI_API_KEY not in detail: {detail!r}"

    def test_do_up_codex_both_absent_mint_never_called(self):
        """Codex gate fires before mint_nonce when both keys absent. AC-29-P1-03."""
        absent = _make_absent_cred_mock()
        mint_calls = []
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=lambda p: mint_calls.append(p)):
            do_up("codex", secret="test-secret", salt=b"", env_path=None)

        assert len(mint_calls) == 0

    # --- AC-29-P1-04: gate passes when credential is present ---

    def _do_up_with_present_cred(self, profile, cred_side_effect=None):
        """Helper: run do_up with credential mocked as present; return (result, mint_calls)."""
        mock_compose = MagicMock()
        mock_compose.returncode = 0
        mint_calls = []

        cred_kwargs = (
            {"side_effect": cred_side_effect} if cred_side_effect
            else {"return_value": _make_present_cred_mock()}
        )

        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", **cred_kwargs), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=lambda p: mint_calls.append(p)), \
             patch("src.admin.primitives.lifecycle.load_portal_config",
                   return_value={"detection_enabled": False}), \
             patch("src.admin.primitives.lifecycle.compose_up", return_value=mock_compose), \
             patch("src.admin.primitives.lifecycle.wait_for_gateway_healthy", return_value=True), \
             patch("src.admin.primitives.lifecycle.consume_nonce"):
            result = do_up(profile, secret="test-secret", salt=b"", env_path=None)

        return result, mint_calls

    def test_do_up_claude_present_reaches_mint_and_returns_applied(self):
        """Gate passes for claude when credential present; mint_nonce called; outcome=applied. AC-29-P1-04."""
        result, mint_calls = self._do_up_with_present_cred("claude")
        assert result["outcome"] == "applied", f"Expected applied, got: {result['outcome']!r}"
        assert result["http_status"] != 400
        assert len(mint_calls) == 1 and mint_calls[0] == "claude", (
            f"mint_nonce must be called exactly once with 'claude'; calls: {mint_calls}"
        )

    def test_do_up_copilot_present_reaches_mint(self):
        """Gate passes for copilot when credential present. AC-29-P1-04."""
        result, mint_calls = self._do_up_with_present_cred("copilot")
        assert result["outcome"] == "applied"
        assert len(mint_calls) == 1 and mint_calls[0] == "copilot"

    def test_do_up_codex_via_codex_api_key_passes_gate(self):
        """Codex gate passes when CODEX_API_KEY is present. AC-29-P1-04."""
        # CODEX_API_KEY present, OPENAI_API_KEY absent.
        # _PROFILE_KEY_MAP["codex"] = ("CODEX_API_KEY", "OPENAI_API_KEY"); checks in order.
        def cred_present_for_codex_key(key, salt=b"", env_path=None):
            m = MagicMock()
            m.present = (key == "CODEX_API_KEY")
            return m

        result, mint_calls = self._do_up_with_present_cred(
            "codex", cred_side_effect=cred_present_for_codex_key
        )
        assert result["outcome"] == "applied", (
            f"Expected applied when CODEX_API_KEY present, got: {result['outcome']!r}"
        )
        assert len(mint_calls) == 1 and mint_calls[0] == "codex"

    def test_do_up_codex_via_openai_key_only_passes_gate(self):
        """Codex gate passes when only OPENAI_API_KEY is present (CODEX_API_KEY absent). AC-29-P1-04."""
        # The gate checks CODEX_API_KEY first (False), then OPENAI_API_KEY (True).
        def cred_present_for_openai_key(key, salt=b"", env_path=None):
            m = MagicMock()
            m.present = (key == "OPENAI_API_KEY")
            return m

        result, mint_calls = self._do_up_with_present_cred(
            "codex", cred_side_effect=cred_present_for_openai_key
        )
        assert result["outcome"] == "applied", (
            f"Expected applied when OPENAI_API_KEY present, got: {result['outcome']!r}"
        )
        assert len(mint_calls) == 1 and mint_calls[0] == "codex"


# ---------------------------------------------------------------------------
# Route-level tests: HTTP layer via TestClient (AC-29-P1-01/02/03)
# ---------------------------------------------------------------------------

class TestReadinessGateRoute:
    """
    Verifies the full route path: get_credential_status monkeypatched to present=False,
    HTTP response is 400, and the route writes a rejected-by-validation audit record
    with the correct target after do_up returns the 400 dict.

    The spec's round-2 regression guard: the route must return HTTP 400, never 500.
    This class also verifies mint_nonce is not reached (compose never starts).
    """

    def _post_up_with_absent_cred(self, authed_client, profile):
        """
        POST /api/v1/profiles/{profile}/up with get_credential_status mocked absent.
        Returns HTTP response.
        """
        absent = _make_absent_cred_mock()
        with patch("src.admin.primitives.lifecycle.get_running_profiles", return_value=set()), \
             patch("src.admin.primitives.lifecycle.get_credential_status", return_value=absent), \
             patch("src.admin.primitives.lifecycle.mint_nonce",
                   side_effect=AssertionError("mint_nonce must not be called at gate")), \
             patch("src.admin.primitives.lifecycle.compose_up",
                   side_effect=AssertionError("compose_up must not be called at gate")):
            return authed_client.post(
                f"/api/v1/profiles/{profile}/up",
                headers={"Host": VALID_HOST_HEADER},
            )

    # --- AC-29-P1-01 route: claude ---

    def test_claude_route_absent_returns_http_400_not_500(self, authed_client):
        """Route returns HTTP 400 (not 500) when claude credential absent. AC-29-P1-01."""
        resp = self._post_up_with_absent_cred(authed_client, "claude")
        assert resp.status_code == 400, (
            f"Expected HTTP 400 from credential gate, got {resp.status_code} -- "
            "regression guard: gate must return 400, not allow 500 to escape"
        )
        assert resp.status_code != 500

    def test_claude_route_absent_response_body(self, authed_client):
        """Route response body has error=credential_not_present. AC-29-P1-01."""
        resp = self._post_up_with_absent_cred(authed_client, "claude")
        data = resp.json()
        assert data.get("ok") is False
        assert data.get("error") == "credential_not_present"

    def test_claude_route_absent_writes_rejected_audit_with_target(self, authed_client, tmp_audit):
        """Route writes rejected-by-validation audit with target=claude after gate fires. AC-29-P1-01."""
        self._post_up_with_absent_cred(authed_client, "claude")

        lc_records = _lifecycle_audit_records(tmp_audit)
        rbv = [r for r in lc_records if r.get("outcome") == "rejected-by-validation"
               and r.get("action") == "lifecycle_up"]
        assert rbv, (
            f"Expected a lifecycle_up rejected-by-validation record; got lifecycle records: {lc_records}"
        )
        assert any(r.get("target") == "claude" for r in rbv), (
            f"Expected target='claude' in rejected-by-validation record; got: {rbv}"
        )

    # --- AC-29-P1-02 route: copilot ---

    def test_copilot_route_absent_returns_http_400(self, authed_client):
        """Route returns HTTP 400 when copilot credential absent. AC-29-P1-02."""
        resp = self._post_up_with_absent_cred(authed_client, "copilot")
        assert resp.status_code == 400

    def test_copilot_route_absent_writes_rejected_audit_with_target(self, authed_client, tmp_audit):
        """Route writes rejected-by-validation audit with target=copilot. AC-29-P1-02."""
        self._post_up_with_absent_cred(authed_client, "copilot")

        lc_records = _lifecycle_audit_records(tmp_audit)
        rbv = [r for r in lc_records if r.get("outcome") == "rejected-by-validation"
               and r.get("action") == "lifecycle_up"]
        assert any(r.get("target") == "copilot" for r in rbv), (
            f"Expected target='copilot' in rejected-by-validation record; records: {rbv}"
        )

    # --- AC-29-P1-03 route: codex ---

    def test_codex_route_absent_returns_http_400(self, authed_client):
        """Route returns HTTP 400 when codex credential absent (neither key present). AC-29-P1-03."""
        resp = self._post_up_with_absent_cred(authed_client, "codex")
        assert resp.status_code == 400

    def test_codex_route_absent_writes_rejected_audit_with_target(self, authed_client, tmp_audit):
        """Route writes rejected-by-validation audit with target=codex. AC-29-P1-03."""
        self._post_up_with_absent_cred(authed_client, "codex")

        lc_records = _lifecycle_audit_records(tmp_audit)
        rbv = [r for r in lc_records if r.get("outcome") == "rejected-by-validation"
               and r.get("action") == "lifecycle_up"]
        assert any(r.get("target") == "codex" for r in rbv), (
            f"Expected target='codex' in rejected-by-validation record; records: {rbv}"
        )
