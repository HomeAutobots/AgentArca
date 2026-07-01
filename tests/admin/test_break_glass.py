"""
test_break_glass.py - Containment tests for the SPEC-29-P0 break-glass escape hatch.

FRAME: "assume the operator is hostile or confused and reaches for break-glass to start a
gateway outside the portal." Prove the break-glass guarded sequence CANNOT be used to break
profile mutual exclusion (invariant 9), that every start it authorizes is audited BEFORE the
nonce is minted (AC-012-5), and that a replayed nonce cannot buy a second concurrent profile.

PLACEMENT DECISION (why Python, unmarked / Docker-free):
  The break-glass security core is the ORDERING and MUTUAL-EXCLUSION logic inside the real
  src/scripts/_break_glass_up.py guarded sequence (flock -> running-state refuse -> audit ->
  mint -> compose). That logic is deterministic and does not need a live Docker daemon to
  exercise: we drive the ACTUAL _break_glass_up.main() in-process, monkeypatch the real
  get_running_profiles() to simulate "a profile is running", and intercept the single
  `docker compose up` subprocess so no container is ever started. This makes the tests
  fast and repeatable (prompt-injection is non-deterministic; these run in the default unit
  suite and can be looped cheaply) while exercising the load-bearing code paths verbatim.
  HYGIENE: HOME is redirected to a tmp dir so the lifecycle lock, the nonce dir, and the
  audit trail all land under tmp_path; the real ~/.agentarca is never touched.

Covers:
  AC-29-P0-14 (N4)  break-glass refuses while another profile runs: exits 1, NO audit record,
                    NO nonce minted, NO compose call (real get_running_profiles refuse).
  AC-29-P0-15       break-glass with nothing running writes the break_glass_up audit record
                    BEFORE the nonce file exists, mints a valid nonce, starts compose (order).
  AC-29-P0-21       the break_glass_up record lands at the resolved console audit path and a
                    subsequent GET /api/v1/logs/audit returns it.
  AC-29-P0-23       a replayed / captured nonce cannot start a SECOND concurrent profile: the
                    running-state refuse blocks it even with a valid-looking nonce already at
                    the mount path (combined flock + refuse + freshness + one-time controls).
  AC-29-P0-27       break-glass-up.sh delegates to _break_glass_up.py via the admin venv python;
                    _break_glass_up.py holds fcntl.flock (macOS-safe) across the whole sequence;
                    profile-running -> exit before audit/nonce; nothing-running -> audit+mint+compose.
"""

from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import src.admin.primitives.lifecycle as lifecycle_mod  # noqa: E402

BREAK_GLASS_PY = REPO_ROOT / "src" / "scripts" / "_break_glass_up.py"
BREAK_GLASS_SH = REPO_ROOT / "src" / "scripts" / "break-glass-up.sh"


# ---------------------------------------------------------------------------
# Load the REAL _break_glass_up.py as an importable module (its guarded sequence
# is the code under test; importing it does not run main()).
# ---------------------------------------------------------------------------

def _load_break_glass_module():
    spec = importlib.util.spec_from_file_location("_break_glass_up_under_test", BREAK_GLASS_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def bg(monkeypatch):
    """The real _break_glass_up module, freshly loaded."""
    return _load_break_glass_module()


@pytest.fixture()
def tmp_home(tmp_path, monkeypatch):
    """
    Redirect HOME to a tmp dir so ~/.agentarca/{lifecycle.lock,start-auth.d} and the
    default audit path resolve under tmp_path. Pre-create ~/.agentarca because
    _break_glass_up opens the lock file (open(..., "w")) before creating any dirs.
    """
    home = tmp_path / "home"
    (home / ".agentarca").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    # Make sure no stray config-file layer interferes with audit-path resolution.
    monkeypatch.delenv("AGENTARCA_ADMIN_CONFIG_FILE", raising=False)
    return home


@pytest.fixture()
def audit_path(tmp_home, monkeypatch):
    """Isolated audit trail; _break_glass_up resolves it via load_settings() honoring this env."""
    p = tmp_home / ".agentarca" / "bg-audit.jsonl"
    monkeypatch.setenv("AGENTARCA_ADMIN_AUDIT_LOG", str(p))
    return p


def _nonce_file(tmp_home: Path, profile: str) -> Path:
    return tmp_home / ".agentarca" / "start-auth.d" / profile


def _read_records(p: Path) -> list:
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


class _FakeComposeResult:
    def __init__(self, returncode=0):
        self.returncode = returncode


def _install_fake_compose(monkeypatch, bg, recorder, on_call=None):
    """Replace _break_glass_up's `subprocess` with a fake whose .run records the compose call
    (and optionally runs an on_call hook) instead of touching Docker."""
    def fake_run(cmd, *args, **kwargs):
        recorder.append({"cmd": cmd, "cwd": kwargs.get("cwd")})
        if on_call is not None:
            on_call()
        return _FakeComposeResult(returncode=0)

    fake_sp = types.SimpleNamespace(run=fake_run)
    monkeypatch.setattr(bg, "subprocess", fake_sp)


# ---------------------------------------------------------------------------
# AC-29-P0-14 (N4): refuse while another profile runs
# ---------------------------------------------------------------------------

class TestBreakGlassMutualExclusion:
    def test_refuses_when_a_profile_is_running(self, bg, tmp_home, audit_path, monkeypatch):
        """
        AC-29-P0-14: with a profile already running, break-glass exits 1 and writes NO audit
        record, mints NO nonce, and makes NO compose call. The refuse uses the REAL
        get_running_profiles() (monkeypatched here to simulate a live 'claude').
        """
        monkeypatch.setattr(lifecycle_mod, "get_running_profiles", lambda: {"claude"})
        compose_calls: list = []
        _install_fake_compose(monkeypatch, bg, compose_calls)

        with pytest.raises(SystemExit) as ei:
            bg.main("codex", str(REPO_ROOT))

        assert ei.value.code == 1, "break-glass must exit 1 when a profile is already running"
        # No audit record for the refused start.
        recs = _read_records(audit_path)
        assert not any(r.get("action") == "break_glass_up" for r in recs), (
            "break-glass must NOT write a break_glass_up audit record on a refused start"
        )
        # No nonce minted.
        assert not _nonce_file(tmp_home, "codex").exists(), (
            "break-glass must NOT mint a nonce when it refuses"
        )
        # No compose call.
        assert compose_calls == [], "break-glass must NOT call docker compose on a refused start"


# ---------------------------------------------------------------------------
# AC-29-P0-15: audit written BEFORE nonce; mint valid; start compose
# ---------------------------------------------------------------------------

class TestBreakGlassOrdering:
    def test_audit_before_nonce_then_mint_then_compose(self, bg, tmp_home, audit_path, monkeypatch):
        """
        AC-29-P0-15 / AC-012-5: with nothing running, break-glass writes the break_glass_up
        audit record BEFORE the nonce is minted, then mints a valid nonce, then starts compose.
        Ordering is asserted by a spy on the token mint: at mint time the audit record must
        already exist. At compose time both the audit record and the nonce file must exist.
        """
        monkeypatch.setattr(lifecycle_mod, "get_running_profiles", lambda: set())

        state = {"audit_present_at_mint": None, "nonce_present_at_mint": None}

        # Wrap secrets.token_hex (called immediately before the nonce is written) to snapshot
        # the audit/nonce state at the moment of the mint.
        real_token_hex = bg.secrets.token_hex

        def spy_token_hex(n):
            recs = _read_records(audit_path)
            state["audit_present_at_mint"] = any(r.get("action") == "break_glass_up" for r in recs)
            state["nonce_present_at_mint"] = _nonce_file(tmp_home, "codex").exists()
            return real_token_hex(n)

        monkeypatch.setattr(bg.secrets, "token_hex", spy_token_hex)

        compose_calls: list = []

        def at_compose():
            # At compose time both the audit record and the nonce file must already exist.
            recs = _read_records(audit_path)
            assert any(r.get("action") == "break_glass_up" for r in recs), "audit missing at compose"
            assert _nonce_file(tmp_home, "codex").exists(), "nonce missing at compose"

        _install_fake_compose(monkeypatch, bg, compose_calls, on_call=at_compose)

        bg.main("codex", str(REPO_ROOT))  # returns normally on success

        assert state["audit_present_at_mint"] is True, (
            "the break_glass_up audit record MUST exist before the nonce is minted (AC-012-5)"
        )
        assert state["nonce_present_at_mint"] is False, (
            "the nonce file must NOT exist yet when the mint begins (audit strictly precedes mint)"
        )
        # Nonce minted and well-formed.
        nf = _nonce_file(tmp_home, "codex")
        assert nf.exists(), "break-glass must mint the nonce on the success path"
        lines = nf.read_text(encoding="ascii").splitlines()
        assert len(lines) == 3, f"nonce file must have exactly 3 lines; got {len(lines)}"
        assert len(lines[0]) == 64 and all(c in "0123456789abcdef" for c in lines[0]), (
            "nonce token must be 64 lowercase hex chars"
        )
        assert lines[2] == "codex", "nonce profile line must be the target profile"
        # Compose was started for the target profile.
        assert len(compose_calls) == 1, "break-glass must call docker compose exactly once on success"
        assert compose_calls[0]["cmd"] == ["docker", "compose", "--profile", "codex", "up", "-d"]
        assert compose_calls[0]["cwd"] == str(REPO_ROOT), "compose must run with cwd=repo_root"


# ---------------------------------------------------------------------------
# AC-29-P0-27: two-file delegation + flock held across the whole sequence
# ---------------------------------------------------------------------------

class TestBreakGlassDelegationAndLock:
    def test_wrapper_delegates_to_python_via_venv(self):
        """
        AC-29-P0-27 (structure): break-glass-up.sh execs _break_glass_up.py via the admin venv
        python; it does NOT re-implement the guarded sequence in bash.
        """
        sh = BREAK_GLASS_SH.read_text(encoding="utf-8")
        assert 'VENV_PYTHON="${REPO_ROOT}/.venv-admin/bin/python"' in sh, (
            "wrapper must resolve the admin venv python"
        )
        assert 'exec "${VENV_PYTHON}" "${SCRIPT_DIR}/_break_glass_up.py"' in sh, (
            "wrapper must exec _break_glass_up.py via the venv python (one delegated invocation)"
        )

    def test_python_uses_fcntl_flock_not_util_linux(self):
        """AC-29-P0-27 (macOS-safety): the guarded sequence uses Python fcntl.flock, not flock(1)."""
        py = BREAK_GLASS_PY.read_text(encoding="utf-8")
        assert "import fcntl" in py and "fcntl.flock" in py, "must use Python fcntl.flock"
        # Must not SHELL OUT to the util-linux flock(1) binary (absent on macOS). Comments may
        # legitimately mention flock(1) to explain WHY fcntl is used; forbid only a subprocess
        # invocation whose argv[0] is the flock binary.
        assert '"flock"' not in py and "'flock'" not in py, (
            "must not invoke the util-linux flock(1) binary via subprocess (macOS has no flock(1))"
        )

    def test_lifecycle_lock_is_held_across_the_compose_step(self, bg, tmp_home, audit_path, monkeypatch):
        """
        AC-29-P0-27: the lifecycle flock is held for the ENTIRE refuse->audit->mint->compose
        sequence. Proof: at compose time, an independent open()+flock(LOCK_EX|LOCK_NB) on the
        same ~/.agentarca/lifecycle.lock must FAIL (BlockingIOError) because main() holds it.
        """
        monkeypatch.setattr(lifecycle_mod, "get_running_profiles", lambda: set())
        lock_path = tmp_home / ".agentarca" / "lifecycle.lock"
        held = {"blocked": None}

        def at_compose():
            probe_fd = open(lock_path, "w")
            try:
                fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # If we get here the lock was NOT held by main -> boundary weakened.
                held["blocked"] = False
                fcntl.flock(probe_fd, fcntl.LOCK_UN)
            except BlockingIOError:
                held["blocked"] = True
            finally:
                probe_fd.close()

        compose_calls: list = []
        _install_fake_compose(monkeypatch, bg, compose_calls, on_call=at_compose)

        bg.main("codex", str(REPO_ROOT))

        assert held["blocked"] is True, (
            "the lifecycle lock MUST be held across the compose step; an independent "
            "flock(LOCK_EX|LOCK_NB) on ~/.agentarca/lifecycle.lock must fail during break-glass"
        )


# ---------------------------------------------------------------------------
# AC-29-P0-23: replayed nonce cannot start a second concurrent profile
# ---------------------------------------------------------------------------

class TestBreakGlassReplay:
    def test_replayed_nonce_cannot_start_second_profile(self, bg, tmp_home, audit_path, monkeypatch):
        """
        AC-29-P0-23: an attacker captures a still-valid-looking nonce and drops it at the mount
        path, then reaches for break-glass to bring up a SECOND profile while one is already
        running. The running-state refuse (real get_running_profiles) blocks it regardless of
        the pre-planted nonce: no second profile, no compose call, no audit. This is the
        mutual-exclusion leg of the combined replay defence (freshness + one-time consumption
        are covered at the gateway entrypoint by AC-05/AC-07/AC-26a).
        """
        import time
        # Simulate 'claude' already live (the first, authorized profile).
        monkeypatch.setattr(lifecycle_mod, "get_running_profiles", lambda: {"claude"})

        # Attacker pre-plants a fresh, well-formed nonce for 'codex' at the mount path (a replay
        # of a captured authorization). It looks valid to the entrypoint freshness/token checks.
        nd = tmp_home / ".agentarca" / "start-auth.d"
        nd.mkdir(parents=True, exist_ok=True)
        planted = nd / "codex"
        planted.write_text(f"{'a'*64}\n{int(time.time())}\ncodex\n", encoding="ascii")

        compose_calls: list = []
        _install_fake_compose(monkeypatch, bg, compose_calls)

        with pytest.raises(SystemExit) as ei:
            bg.main("codex", str(REPO_ROOT))

        assert ei.value.code == 1, "break-glass must refuse a second profile while one is running"
        assert compose_calls == [], "no compose call: the replayed nonce cannot start a 2nd profile"
        assert not any(r.get("action") == "break_glass_up" for r in _read_records(audit_path)), (
            "no break_glass_up audit on the refused replay start"
        )
        # The planted nonce is untouched (break-glass never consumed or trusted it); it does not
        # buy a start because mutual exclusion is enforced by the running-state refuse, not by
        # the presence of a file.
        assert planted.exists(), "break-glass does not act on a pre-planted nonce at all"


# ---------------------------------------------------------------------------
# AC-29-P0-21: break_glass_up record retrievable via GET /api/v1/logs/audit
# ---------------------------------------------------------------------------

class TestBreakGlassAuditReadback:
    def test_break_glass_record_returned_by_logs_audit(self, bg, tmp_home, audit_path, monkeypatch):
        """
        AC-29-P0-21: after a break-glass start, the break_glass_up record is appended to the
        resolved console audit path (here isolated via AGENTARCA_ADMIN_AUDIT_LOG), and a
        subsequent GET /api/v1/logs/audit returns it. Proves the console and break-glass share
        one trail (R3 fix) without polluting the real audit log.
        """
        from src.admin.config import Settings
        from src.admin.main import create_app
        from starlette.testclient import TestClient

        # Perform a break-glass start (nothing running) -> writes break_glass_up to audit_path.
        monkeypatch.setattr(lifecycle_mod, "get_running_profiles", lambda: set())
        _install_fake_compose(monkeypatch, bg, [])
        bg.main("codex", str(REPO_ROOT))
        assert any(r.get("action") == "break_glass_up" for r in _read_records(audit_path)), (
            "precondition: break-glass wrote the record"
        )

        # Build a console app whose audit_log_path is the SAME trail and read it back.
        secret = "test-break-glass-secret-123"
        secret_file = tmp_home / ".agentarca" / "admin-secret"
        secret_file.write_text(secret + "\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)
        settings = Settings(
            host="127.0.0.1",
            port=8770,
            allow_non_loopback=False,
            secret_file=secret_file,
            secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_BG",
            audit_log_path=audit_path,
            session_secret_key="bg-session-key-aaabbbccc" * 4,
        )
        app = create_app(settings)
        with TestClient(app, base_url="http://127.0.0.1:8770") as c:
            c.headers.update({"Host": "127.0.0.1:8770"})
            resp = c.post("/api/v1/login", json={"secret": secret}, headers={"Host": "127.0.0.1:8770"})
            assert resp.status_code == 200, f"login failed: {resp.text}"
            c.headers.update({"X-CSRF-Token": resp.json()["csrf_token"]})
            resp = c.get("/api/v1/logs/audit?limit=100", headers={"Host": "127.0.0.1:8770"})
            assert resp.status_code == 200, f"logs/audit failed: {resp.text}"

        body = resp.json()
        entries = body["entries"] if isinstance(body, dict) and "entries" in body else body
        bg_records = [r for r in entries if isinstance(r, dict) and r.get("action") == "break_glass_up"]
        assert bg_records, f"GET /api/v1/logs/audit must return the break_glass_up record; got {body!r}"
        assert bg_records[0].get("target") == "codex", "the returned record must name the target profile"
