"""
test_redteam_phase4_p1_containment.py - Containment red-team for SPEC-29-P1 (ADR-012).

FRAME: "assume the operator, the browser UI, or an injected agent driving the portal API
is HOSTILE and is trying to widen the egress allowlist, flip a D5.4 isolation invariant,
smuggle an arbitrary key into portal-config.json, or use the detection overlay to suppress
the P0 startup interlock." A PASSING test here means the ATTACK WAS BLOCKED at the boundary.
An assertion failure is a BLOCK-class containment finding (route to threat-modeler +
security-reviewer), NOT something to paper over.

This complements the acceptance suite (test_onboarding.py, test_portal_config.py,
test_detection_toggle.py), which proves the endpoints WORK. Here we prove the endpoints
CANNOT be abused to cross a boundary.

Covers:
  AC-29-P1-14 / N7   Onboarding never widens the allowlist. Drive the entire onboarding
                     surface (status GET + credential PUT + start POST) for ALL THREE
                     profiles with the credential gate forced present, and prove the squid
                     allowlist config directories are BYTE-IDENTICAL before and after
                     (sha256 of every file). Plus a source proof that no onboarding route
                     references any squid/allowlist/local.d/.conf filesystem path.
  AC-29-P1-15 / N10  The four D5.4 isolation invariants (NET_ADMIN/NET_RAW/SYS_ADMIN caps,
                     --privileged, docker.sock mount, concurrent profiles) are not settable
                     through ANY P1 endpoint. A PATCH /portal-config barrage with each knob
                     returns 400, writes NO file, and writes NO applied audit; the config
                     file is still absent after the barrage. Route enumeration confirms the
                     only mutating config surface is PATCH /portal-config (key-allowlisted),
                     and settings.html renders the four knobs display-only (no input/button
                     bound to them). onboarding /start ignores an injected isolation body.
  N8                 An unknown key in PATCH /portal-config ({"firewall_disabled": true})
                     returns 400, does NOT persist, and writes NO applied audit.
  N9                 The detection toggle does NOT bypass the P0 interlock. SOURCE PROOF
                     (chosen over a live bring-up; see the class docstring for why):
                     (a) the detection overlay defines NO gateway-*/devcontainer-* service
                     and overrides no gateway entrypoint/command/volumes, and
                     (b) the interlock nonce check lives in the image-baked
                     src/gateway/entrypoint.sh, independent of any compose -f overlay.

PLACEMENT DECISION (unmarked Python, Docker-FREE, in tests/admin/ next to the other
test_redteam_phase*.py adversarial files):
  Every property here is a deterministic route / filesystem / source-structure fact:
  allowlist-directory byte-equality under a driven onboarding barrage, PATCH key-allowlist
  rejection + no-persist + no-audit, and the structural relationship between the detection
  overlay YAML and the image-baked gateway entrypoint. None of these require a live Docker
  stack, so a live profile bring-up would only add flakiness and cross-test container
  pollution for no additional assurance. The live fail-closed behavior of the interlock is
  already proven by tests/containment/rt29-run-interlock.sh (which builds the gateway image
  fresh and hard-guards that the built entrypoint still contains the nonce check); N9 here
  only needs to prove the detection overlay cannot REMOVE that check, which is a pure
  structural property of two source files plus the do_up compose-command construction
  (the latter already asserted in test_detection_toggle.py: do_up only ADDS a -f overlay).

TEST HYGIENE: real ~/.agentarca/portal-config.json and the real repo-root .env are NEVER
touched. PORTAL_CONFIG_PATH is monkeypatched to tmp_path; the credential PUT env_path is
monkeypatched to a tmp .env; the audit log is the per-test tmp settings path. No container
is started by any test in this file; docker ps is unaffected.

Spec ref: SPEC-29-P1 sec 5-7, sec 10 N7-N10; item-29-P1-security-review.md checks 4, 8, 9, 11.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings
from src.admin.main import create_app

TEST_SECRET = "test-secret-value-12345"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"
VALID_HOST_HEADER = f"{TEST_HOST}:{TEST_PORT}"

# The squid allowlist configuration directories that onboarding MUST NOT widen.
#   1. The per-agent fragments baked into the gateway image (base/copilot/claude/codex).
#   2. The operator-writable local override dir that allowlist-local.sh appends to.
# If onboarding widened egress, a byte would change in ONE of these. We snapshot BOTH.
_ALLOWLIST_DIRS = [
    REPO_ROOT / "src" / "gateway" / "squid-allowlist.d",
    REPO_ROOT / "config" / "allowlist.local.d",
]

# The four D5.4 isolation invariants, expressed as the knob names a hostile caller would
# try to smuggle into PATCH /api/v1/portal-config (SPEC-29-P1 sec 7 / N10).
_ISOLATION_KNOB_BODIES = [
    {"net_admin_enabled": True},          # NET_ADMIN / NET_RAW / SYS_ADMIN cap re-grant
    {"privileged": True},                 # --privileged
    {"docker_sock": "/var/run/docker.sock"},  # docker.sock mount
    {"concurrent_profiles": True},        # concurrent-profile mutual-exclusion break
]

# The two P1 route modules whose handlers must never touch an allowlist path.
_ONBOARDING_ROUTE_SRC = REPO_ROOT / "src" / "admin" / "routes" / "onboarding.py"
_PORTAL_CONFIG_ROUTE_SRC = REPO_ROOT / "src" / "admin" / "routes" / "portal_config.py"
_SETTINGS_HTML = REPO_ROOT / "src" / "admin" / "static" / "settings.html"
_DETECT_OVERLAY = REPO_ROOT / "src" / "detect" / "docker-compose.detect.yml"
_GATEWAY_ENTRYPOINT = REPO_ROOT / "src" / "gateway" / "entrypoint.sh"
_GATEWAY_DOCKERFILE = REPO_ROOT / "src" / "gateway" / "Dockerfile"

# Filesystem-path tokens that indicate an actual allowlist/squid config path (as opposed to
# the word "allowlist" appearing in an invariant-stating docstring). These are hyphenated /
# dotted / slash-bearing tokens that only appear in a real path, never in prose.
_ALLOWLIST_PATH_TOKENS = (
    "squid-allowlist",
    "allowlist.local.d",
    "allowlist-local",
    "/etc/squid",
    "allowlist.d",
    ".conf",
)


# ---------------------------------------------------------------------------
# Fixtures (mirror test_onboarding.py / test_portal_config.py convention)
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_audit(tmp_path):
    return tmp_path / "admin-audit.jsonl"


@pytest.fixture()
def tmp_portal_config_path(tmp_path):
    """Temp path for portal-config.json; the real ~/.agentarca file is never touched."""
    return tmp_path / "portal-config.json"


@pytest.fixture()
def tmp_env_path(tmp_path):
    """Temp .env for the credential PUT path; the real repo-root .env is never touched."""
    return tmp_path / ".env"


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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_RT29P1",
        audit_log_path=tmp_audit,
        session_secret_key="test-session-key-aaabbbccc" * 4,
    )


@pytest.fixture()
def app(test_settings):
    return create_app(test_settings)


@pytest.fixture()
def client(app):
    from starlette.testclient import TestClient
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
        c.headers.update({"Host": VALID_HOST_HEADER})
        yield c


@pytest.fixture()
def authed_client(client):
    """Authenticated client with CSRF token set (a hostile-but-authenticated operator)."""
    resp = client.post(
        "/api/v1/login",
        json={"secret": TEST_SECRET},
        headers={"Host": VALID_HOST_HEADER},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    csrf = resp.json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": csrf})
    return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_tree(root: Path) -> dict:
    """Return {relative_posix_path: sha256_hex} for every file under root (recursive).

    A widened allowlist would change, add, or remove exactly one of these entries.
    """
    result: dict[str, str] = {}
    if not root.exists():
        return result
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            result[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def _snapshot_allowlists() -> dict:
    """Snapshot-hash every allowlist config directory into one dict keyed by dir name."""
    return {str(d): _hash_tree(d) for d in _ALLOWLIST_DIRS}


def _read_audit_records(audit_path: Path) -> list:
    if not audit_path.exists():
        return []
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _string_constants(source_path: Path) -> list[str]:
    """Every string-literal constant in a Python source file (includes docstrings)."""
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append(node.value)
    return out


def _imported_module_names(source_path: Path) -> list[str]:
    """Every module name imported by a Python source file."""
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.append(node.module)
    return names


def _all_route_methods(app) -> list[tuple[str, set]]:
    """
    Return every (path, {methods}) pair registered on the app.

    This app wraps each included router in a hardened `_IncludedRouter` whose real routes
    live under `.original_router.routes` (a defense-in-depth wrapper), so a naive scan of
    app.routes alone misses the API routes. We descend into both.
    """
    pairs: list[tuple[str, set]] = []

    def _collect(routes):
        for r in routes:
            path = getattr(r, "path", None)
            methods = getattr(r, "methods", None)
            if path and methods:
                pairs.append((path, set(methods)))
            orig = getattr(r, "original_router", None)
            if orig is not None and hasattr(orig, "routes"):
                _collect(orig.routes)
            sub = getattr(r, "routes", None)
            if sub and orig is None:
                _collect(sub)

    _collect(app.routes)
    return pairs


# ===========================================================================
# AC-29-P1-14 / N7: Onboarding never widens the allowlist
# ===========================================================================

class TestOnboardingNeverWidensAllowlist:
    """
    AC-29-P1-14 / N7 (ADR-012 B8): the onboarding flow for EVERY profile must never write
    to any squid allowlist file. We assume a hostile operator drives the whole onboarding
    surface hoping a side effect widens egress, and prove the allowlist bytes do not move.
    """

    def test_precondition_allowlist_dirs_exist_and_nonempty(self):
        """Sanity: the dirs we are guarding actually exist and have content to protect."""
        snap = _snapshot_allowlists()
        total_files = sum(len(files) for files in snap.values())
        assert total_files > 0, (
            "No allowlist files found to snapshot; the guard would be vacuous. "
            f"Checked: {[str(d) for d in _ALLOWLIST_DIRS]}"
        )
        # The baked gateway fragments must be present (base + three agents).
        squid_d = _snapshot_allowlists()[str(_ALLOWLIST_DIRS[0])]
        for frag in ("base.conf", "copilot.conf", "claude.conf", "codex.conf"):
            assert frag in squid_d, f"expected baked fragment {frag} in the snapshot"

    def test_full_onboarding_barrage_leaves_allowlist_byte_identical(
        self, authed_client, tmp_env_path
    ):
        """
        Drive status GET + credential PUT + start POST for ALL THREE profiles with the
        credential gate forced present, then assert every allowlist config file is
        byte-identical (same set of files, same sha256). AC-29-P1-14 / N7.

        A PASS = onboarding did NOT widen (or narrow, or touch) the allowlist. Any hash or
        file-set delta is a BLOCK-class finding.
        """
        before = _snapshot_allowlists()

        present = MagicMock()
        present.present = True

        wizard_keys = {
            "copilot": "COPILOT_GITHUB_TOKEN",
            "claude": "CLAUDE_CODE_OAUTH_TOKEN",
            "codex": "OPENAI_API_KEY",
        }
        applied = {"outcome": "applied", "detail": "", "http_status": 201}

        # Route the credential PUT at a throwaway tmp .env, not the real repo-root .env.
        with patch("src.admin.routes.credentials._get_env_path", return_value=tmp_env_path), \
             patch("src.admin.routes.onboarding.get_credential_status", return_value=present), \
             patch("src.admin.routes.onboarding.do_up", return_value=applied):
            for profile, key in wizard_keys.items():
                # (1) status GET (the wizard's poll).
                r_status = authed_client.get(
                    f"/api/v1/onboarding/{profile}/status",
                    headers={"Host": VALID_HOST_HEADER},
                )
                assert r_status.status_code == 200, f"status GET failed for {profile}: {r_status.text}"

                # (2) credential PUT (the wizard's token-set path).
                r_put = authed_client.put(
                    f"/api/v1/credentials/{key}",
                    json={"value": "dummy-token-value-not-a-real-secret"},
                    headers={"Host": VALID_HOST_HEADER},
                )
                assert r_put.status_code == 200, (
                    f"credential PUT for {key} failed ({r_put.status_code}): {r_put.text}"
                )

                # (3) start POST (the wizard's "Start now" button; do_up mocked, Docker-free).
                r_start = authed_client.post(
                    f"/api/v1/onboarding/{profile}/start",
                    headers={"Host": VALID_HOST_HEADER},
                )
                assert r_start.status_code == 201, (
                    f"start POST for {profile} unexpected status: {r_start.status_code}: {r_start.text}"
                )

        after = _snapshot_allowlists()

        assert after == before, (
            "CONTAINMENT FAILURE (BLOCK): onboarding changed the squid allowlist config.\n"
            f"  before: {before}\n"
            f"  after:  {after}\n"
            "The onboarding flow MUST NOT widen (or otherwise modify) any allowlist file "
            "(ADR-012 B8 / AC-29-P1-14). Route to threat-modeler + security-reviewer."
        )

    def test_credential_put_wrote_to_tmp_env_not_allowlist(self, authed_client, tmp_env_path):
        """
        Confirm the credential PUT actually exercised its write path (wrote the tmp .env),
        so the byte-identical allowlist result above is a genuine 'wrote elsewhere, not the
        allowlist' proof and not a no-op that never ran. N7 supporting evidence.
        """
        before = _snapshot_allowlists()
        with patch("src.admin.routes.credentials._get_env_path", return_value=tmp_env_path):
            r = authed_client.put(
                "/api/v1/credentials/OPENAI_API_KEY",
                json={"value": "dummy-token-value-not-a-real-secret"},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert r.status_code == 200, f"credential PUT failed: {r.text}"
        assert tmp_env_path.exists(), "credential PUT should have written the tmp .env"
        env_text = tmp_env_path.read_text(encoding="utf-8")
        assert "OPENAI_API_KEY" in env_text, "the key should be present in the tmp .env"
        # And the allowlist is still untouched.
        assert _snapshot_allowlists() == before, (
            "credential PUT widened the allowlist (BLOCK); it must only write the .env store."
        )

    def test_onboarding_route_source_references_no_allowlist_path(self):
        """
        Source proof (security-review check 4): the onboarding route imports nothing from an
        allowlist/squid module and contains no allowlist/squid filesystem-path string literal.
        The word 'allowlist' may appear in invariant-stating prose, but never as a path token
        (squid-allowlist, allowlist.local.d, allowlist-local, /etc/squid, allowlist.d, .conf).
        AC-29-P1-14 static angle.
        """
        # (a) No import from an allowlist/squid module.
        imports = _imported_module_names(_ONBOARDING_ROUTE_SRC)
        offending_imports = [
            m for m in imports if "allowlist" in m.lower() or "squid" in m.lower()
        ]
        assert not offending_imports, (
            f"onboarding route imports an allowlist/squid module: {offending_imports}. "
            "Onboarding must not have any code path to the egress allowlist (B8)."
        )

        # (b) No allowlist/squid filesystem-path token in any string literal.
        literals = _string_constants(_ONBOARDING_ROUTE_SRC)
        for lit in literals:
            low = lit.lower()
            for token in _ALLOWLIST_PATH_TOKENS:
                assert token not in low, (
                    f"onboarding route source contains allowlist path token {token!r} in a "
                    f"string literal: {lit!r}. This is a potential allowlist-write path (B8)."
                )


# ===========================================================================
# AC-29-P1-15 / N10: D5.4 isolation invariants not settable via any P1 endpoint
# ===========================================================================

class TestIsolationInvariantsNotSettableViaP1:
    """
    AC-29-P1-15 / N10 (ADR-012 D5, R-r criterion c): the four hard-refused D5.4 isolation
    invariants must not be settable through ANY P1 route or UI element. We assume a hostile
    caller who has valid auth+CSRF and tries every knob.
    """

    def test_isolation_knob_patch_barrage_all_rejected_no_write_no_audit(
        self, authed_client, tmp_portal_config_path, tmp_audit
    ):
        """
        PATCH /api/v1/portal-config with each of the four isolation knobs. Each must return
        400, write NO file, and write NO applied audit. After the whole barrage the config
        file is still absent. AC-29-P1-15 / N10.
        """
        assert not tmp_portal_config_path.exists(), "precondition: config file absent"

        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            for body in _ISOLATION_KNOB_BODIES:
                resp = authed_client.patch(
                    "/api/v1/portal-config",
                    json=body,
                    headers={"Host": VALID_HOST_HEADER},
                )
                assert resp.status_code == 400, (
                    f"CONTAINMENT FAILURE (BLOCK): isolation knob {body!r} was NOT rejected "
                    f"(got {resp.status_code}: {resp.text}). D5.4 invariants must be hard-refused."
                )
                # It must NOT have been written to the config file.
                assert not tmp_portal_config_path.exists(), (
                    f"CONTAINMENT FAILURE (BLOCK): isolation knob {body!r} was persisted to "
                    "portal-config.json. The PATCH key allowlist must reject before any file I/O."
                )

        # After the full barrage: file still absent, and NO applied audit for any of them.
        assert not tmp_portal_config_path.exists(), (
            "portal-config.json must remain absent after the isolation-knob barrage"
        )
        records = _read_audit_records(tmp_audit)
        applied = [
            r for r in records
            if r.get("domain") == "portal_config" and r.get("outcome") == "applied"
        ]
        assert not applied, (
            f"CONTAINMENT FAILURE (BLOCK): an isolation-knob PATCH produced an applied audit "
            f"record: {applied}. A rejected knob must never write outcome=applied."
        )
        # And every knob that produced an audit record did so as rejected-by-validation.
        pc_records = [r for r in records if r.get("domain") == "portal_config"]
        for r in pc_records:
            assert r.get("outcome") == "rejected-by-validation", (
                f"unexpected portal_config audit outcome for a rejected knob: {r}"
            )

    def test_isolation_knob_alongside_valid_key_is_rejected_atomically(
        self, authed_client, tmp_portal_config_path
    ):
        """
        A mixed body {detection_enabled + net_admin_enabled} must be rejected WHOLE: the
        unknown-key check fires before any write, so neither the valid nor the invalid key
        is persisted. This blocks a 'ride-along' smuggling of an isolation knob. AC-29-P1-15.
        """
        assert not tmp_portal_config_path.exists()
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.patch(
                "/api/v1/portal-config",
                json={"detection_enabled": True, "net_admin_enabled": True},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400, (
            f"mixed valid+isolation body must be rejected whole; got {resp.status_code}: {resp.text}"
        )
        assert not tmp_portal_config_path.exists(), (
            "a ride-along isolation knob must not cause ANY write, even though "
            "detection_enabled alone would be valid (atomic reject before I/O)."
        )

    def test_only_mutating_p1_config_route_is_key_allowlisted_patch(self, app):
        """
        Route enumeration: the ONLY mutating P1 surface that writes portal state is
        PATCH /api/v1/portal-config, and onboarding exposes only GET status + POST start.
        There is no PUT/POST portal-config route and no isolation-setting route. AC-29-P1-15.
        """
        p1_routes: dict = {}
        for path, methods in _all_route_methods(app):
            if path.startswith("/api/v1/onboarding") or path.startswith("/api/v1/portal-config"):
                mutating = {m for m in methods if m in {"POST", "PUT", "PATCH", "DELETE"}}
                if mutating:
                    p1_routes[path] = p1_routes.get(path, set()) | mutating

        # Exactly two mutating P1 surfaces: onboarding start (POST) and portal-config (PATCH).
        assert p1_routes.get("/api/v1/portal-config") == {"PATCH"}, (
            f"portal-config must expose only PATCH as its mutating method; got {p1_routes}"
        )
        assert p1_routes.get("/api/v1/onboarding/{profile}/start") == {"POST"}, (
            f"onboarding start must be POST-only; got {p1_routes}"
        )
        # No other mutating P1 route may exist (e.g. no PUT/POST that could set an isolation knob).
        assert set(p1_routes.keys()) == {
            "/api/v1/portal-config",
            "/api/v1/onboarding/{profile}/start",
        }, (
            f"unexpected mutating P1 route surface (possible isolation-knob sink): {p1_routes}"
        )

    def test_settings_html_renders_isolation_knobs_display_only(self):
        """
        settings.html source proof (security-review check 11 / adjudication H): the four D5.4
        invariants render inside read-only <div>s with NO <input> or <button> bound to them.
        The only editable control on the page is the detection checkbox. AC-29-P1-15 UI angle.
        """
        html = _SETTINGS_HTML.read_text(encoding="utf-8").lower()

        # The four invariants are described as read-only text.
        for token in ("net_admin", "privileged", "docker.sock", "concurrent profiles"):
            assert token in html, (
                f"settings.html should display the D5.4 invariant {token!r} as read-only text"
            )

        # There must be exactly one editable input, and it is the detection toggle checkbox.
        # A hidden isolation <input> or a <button> wired to a knob would be a UI escape.
        import re
        input_ids = re.findall(r"<input[^>]*\bid=[\"']([^\"']+)[\"']", html)
        assert input_ids == ["detection-toggle"], (
            f"settings.html must have exactly one input (the detection toggle); got {input_ids}. "
            "Any additional input is a potential editable isolation control (AC-29-P1-15)."
        )

        # No button/input carries any isolation-knob name as an id/name/onclick binding.
        for knob in ("net_admin", "net_raw", "sys_admin", "privileged", "docker_sock",
                     "docker-sock", "concurrent_profiles", "concurrent-profiles"):
            # Look for the knob token INSIDE a <button ...> or <input ...> tag.
            for tag_match in re.findall(r"<(?:button|input)\b[^>]*>", html):
                assert knob not in tag_match, (
                    f"settings.html has a control bound to isolation knob {knob!r}: {tag_match!r}. "
                    "Isolation invariants must be display-only (AC-29-P1-15)."
                )

    def test_onboarding_start_ignores_injected_isolation_body(
        self, authed_client, tmp_portal_config_path
    ):
        """
        POST /api/v1/onboarding/{profile}/start takes only the profile path param; it reads
        NO request body. A hostile client that POSTs an isolation-knob body must have that body
        ignored: the start proceeds normally (do_up mocked) and NO portal-config.json is written.
        This proves the onboarding route is not an alternate isolation-knob sink. AC-29-P1-15.
        """
        assert not tmp_portal_config_path.exists()
        applied = {"outcome": "applied", "detail": "", "http_status": 201}
        with patch("src.admin.routes.onboarding.do_up", return_value=applied), \
             patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.post(
                "/api/v1/onboarding/claude/start",
                json={"net_admin_enabled": True, "privileged": True,
                      "docker_sock": "/var/run/docker.sock"},
                headers={"Host": VALID_HOST_HEADER},
            )
        # The injected body is ignored; the start returns its normal 201.
        assert resp.status_code == 201, (
            f"start with an injected isolation body should behave normally (body ignored); "
            f"got {resp.status_code}: {resp.text}"
        )
        # No portal-config write occurred as a side effect of the injected body.
        assert not tmp_portal_config_path.exists(), (
            "an injected isolation body on /start must not cause any portal-config write."
        )


# ===========================================================================
# N8: Unknown key in PATCH /portal-config does not persist
# ===========================================================================

class TestUnknownKeyDoesNotPersist:
    """
    N8 (ADR-012 B9): portal-config.json must not be usable as an arbitrary key-value store
    via the API. An unknown key must be rejected 400 with no file write and no applied audit.
    This overlaps AC-29-P1-10 but asserts the no-persist + no-audit BOUNDARY explicitly.
    """

    def test_unknown_key_rejected_not_persisted_no_applied_audit(
        self, authed_client, tmp_portal_config_path, tmp_audit
    ):
        """PATCH {"firewall_disabled": true} -> 400, no file, no applied audit. N8."""
        assert not tmp_portal_config_path.exists()
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.patch(
                "/api/v1/portal-config",
                json={"firewall_disabled": True},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400, (
            f"CONTAINMENT FAILURE (BLOCK): unknown key firewall_disabled not rejected "
            f"(got {resp.status_code}: {resp.text})."
        )
        assert not tmp_portal_config_path.exists(), (
            "CONTAINMENT FAILURE (BLOCK): unknown key firewall_disabled was persisted to "
            "portal-config.json; the config file must not be an arbitrary key-value store (B9)."
        )
        records = _read_audit_records(tmp_audit)
        applied = [
            r for r in records
            if r.get("domain") == "portal_config" and r.get("outcome") == "applied"
        ]
        assert not applied, (
            f"an unknown-key PATCH must not write an applied audit record; got: {applied}"
        )

    def test_unknown_key_on_preexisting_config_does_not_mutate_it(
        self, authed_client, tmp_portal_config_path
    ):
        """
        If a valid config already exists, an unknown-key PATCH must leave it byte-identical
        (no partial write, no key smuggled in). N8 (no-persist on an existing file).
        """
        # Seed a valid config first.
        tmp_portal_config_path.write_text(
            json.dumps({"detection_enabled": False}, indent=2) + "\n", encoding="utf-8"
        )
        before = tmp_portal_config_path.read_bytes()
        with patch("src.admin.primitives.portal_config.PORTAL_CONFIG_PATH", tmp_portal_config_path):
            resp = authed_client.patch(
                "/api/v1/portal-config",
                json={"arbitrary_attacker_key": "payload"},
                headers={"Host": VALID_HOST_HEADER},
            )
        assert resp.status_code == 400
        assert tmp_portal_config_path.read_bytes() == before, (
            "an unknown-key PATCH must not mutate an existing portal-config.json at all."
        )


# ===========================================================================
# N9: Detection toggle does NOT bypass the P0 startup interlock (source proof)
# ===========================================================================

class TestDetectionToggleDoesNotBypassInterlock:
    """
    N9 (SPEC-29-P1 sec 6.3 / security-review check 9): enabling detection adds a compose
    -f overlay; it must NOT be able to suppress or alter the gateway entrypoint nonce check.

    PROOF CHOICE: source/structure proof, NOT a live bring-up. Rationale is in the module
    docstring: the live fail-closed behavior of the interlock is already covered by
    tests/containment/rt29-run-interlock.sh (fresh image build + stale-image guard), and
    do_up's "only ADDS a -f overlay" behavior is already covered by test_detection_toggle.py.
    What remains for N9 is the purely structural claim that the detection overlay cannot
    REMOVE or OVERRIDE the image-baked interlock. That is decidable from two source files.
    A live gateway bring-up here would add flakiness and cross-test container pollution
    (the suite already carries one restarting-gateway flaky) for zero extra assurance.
    """

    def test_overlay_defines_no_gateway_or_devcontainer_service(self):
        """
        (a) The detection overlay's top-level services are EXACTLY the four detection sinks;
        it defines no gateway-*/devcontainer-* service, so the compose merge cannot override
        any gateway service's entrypoint/command/volumes. N9(a) / security-review check 8.
        """
        data = yaml.safe_load(_DETECT_OVERLAY.read_text(encoding="utf-8"))
        services = data.get("services", {})
        service_keys = set(services.keys())

        expected = {"immudb", "ingest-proxy", "otel-collector", "jaeger"}
        assert service_keys == expected, (
            "CONTAINMENT FAILURE (BLOCK): detection overlay service set changed.\n"
            f"  expected exactly {expected}\n  got {service_keys}\n"
            "A new/renamed service here could override the gateway entrypoint and suppress "
            "the interlock (SPEC-29-P1 sec 6.3)."
        )
        # No service key targets a gateway or devcontainer (belt-and-suspenders).
        for key in service_keys:
            assert not key.startswith("gateway"), f"overlay defines a gateway service: {key!r}"
            assert not key.startswith("devcontainer"), f"overlay defines a devcontainer service: {key!r}"

        # Top-level keys are only services/networks/volumes: no x-anchor or gateway override.
        assert set(data.keys()) <= {"services", "networks", "volumes"}, (
            f"detection overlay has unexpected top-level keys: {set(data.keys())}. "
            "Only services/networks/volumes are permitted; anything else could reach the gateway."
        )

    def test_overlay_does_not_override_gateway_entrypoint_command_or_volumes(self):
        """
        (a, strengthened) None of the four detection services reference the gateway
        entrypoint / init-firewall / the nonce dir. Their own command/entrypoint/volumes stay
        within their own service definition and cannot touch the gateway. N9(a).
        """
        raw = _DETECT_OVERLAY.read_text(encoding="utf-8")
        # The overlay must not reference the gateway entrypoint, its firewall init, or the
        # start-auth nonce mount anywhere (these are the interlock's moving parts).
        for forbidden in ("entrypoint.sh", "init-firewall", "/run/start-auth", "start-auth",
                          "SQUID_AGENT_FRAGMENT"):
            assert forbidden not in raw, (
                f"CONTAINMENT FAILURE (BLOCK): detection overlay references interlock-related "
                f"token {forbidden!r}; the overlay must add observability services only and "
                "never touch the gateway interlock (SPEC-29-P1 sec 6.3)."
            )

    def test_interlock_check_lives_in_image_baked_entrypoint(self):
        """
        (b) The interlock nonce check lives in src/gateway/entrypoint.sh, which is COPYed into
        the gateway image and set as ENTRYPOINT by the Dockerfile. It is therefore image-baked
        and independent of any compose -f overlay: no overlay merge can remove it. N9(b).
        """
        entry = _GATEWAY_ENTRYPOINT.read_text(encoding="utf-8")
        # The fail-closed nonce check and its markers must be present in the entrypoint.
        for marker in (
            "/run/start-auth/",
            "start authorization missing",
            "Start authorization verified",
        ):
            assert marker in entry, (
                f"gateway entrypoint is missing interlock marker {marker!r}; the P0 interlock "
                "must live in the image-baked entrypoint (SPEC-29-P0)."
            )
        # It must fail closed (exit 1) when the nonce is absent.
        assert "exit 1" in entry, "entrypoint must exit 1 (fail closed) on a failed nonce check"

        # The Dockerfile must bake this entrypoint into the image and set it as ENTRYPOINT,
        # so the check cannot be supplied (or withheld) by any compose overlay.
        dockerfile = _GATEWAY_DOCKERFILE.read_text(encoding="utf-8")
        assert "COPY entrypoint.sh /usr/local/bin/entrypoint.sh" in dockerfile, (
            "the gateway Dockerfile must COPY entrypoint.sh into the image (image-baked interlock)"
        )
        assert 'ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]' in dockerfile, (
            "the gateway Dockerfile must set the baked entrypoint as ENTRYPOINT; a compose "
            "overlay must not be able to substitute a different entrypoint for the gateway."
        )

    def test_do_up_only_permitted_overlay_is_the_detection_overlay(self):
        """
        (b, cross-check) The ONLY overlay do_up can ever pass to compose is the detection
        overlay (PERMITTED_OVERLAYS is a one-element frozenset). do_up cannot inject an
        arbitrary compose file that would redefine the gateway. N9(b) supporting.
        """
        from src.admin.primitives.lifecycle import PERMITTED_OVERLAYS
        assert PERMITTED_OVERLAYS == frozenset({"src/detect/docker-compose.detect.yml"}), (
            f"PERMITTED_OVERLAYS must be exactly the detection overlay; got {PERMITTED_OVERLAYS}. "
            "A wider allowlist could let a compose file redefine the gateway and drop the interlock."
        )
