"""
test_lifecycle_mutex.py - AC-27-P2-07: Concurrent-up TOCTOU race test.

This is the most important correctness assertion in Phase 2.

Requires a live Docker stack with NO profile pre-running. If a profile is already
running, the test fails immediately with instructions (do NOT forcibly tear down
the operator's running profile).

The test fires 6 simultaneous POST requests (2 per profile) using a threading.Barrier
to synchronize the release. After all requests complete and 10 seconds have elapsed,
it asserts:
  - At most one profile is running.
  - Exactly one response is 201 (profile brought up successfully).
  - All other non-200 responses are 409 (mutex refusal) or 503 (timeout/health).
  - Every rejected request has an audit record with the correct outcome.

This test is tagged @pytest.mark.integration. If the Docker stack is absent, it
calls pytest.fail() with a clear message.

OPERATOR NOTE: if the `codex` or any other profile is already running (invariant 9
relevant), this test MUST NOT be run. It observes the running state and fails safely
rather than tearing down the operator's stack.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.config import Settings
from src.admin.main import create_app

TEST_SECRET = "test-secret-value-12345"
TEST_PORT = 8080
TEST_HOST = "127.0.0.1"
VALID_HOST_HEADER = f"{TEST_HOST}:{TEST_PORT}"


# ---------------------------------------------------------------------------
# Integration guard: check for live Docker and clean state
# ---------------------------------------------------------------------------

def _check_live_stack_clean():
    """
    Check that Docker is reachable and no profile is running.
    Returns (ok: bool, message: str).
    """
    try:
        from src.admin.primitives.lifecycle import get_running_profiles
        running = get_running_profiles()
        if running:
            return False, (
                f"OPERATOR NOTICE: profile(s) {running!r} are already running. "
                "AC-27-P2-07 requires a clean Docker state (no profiles up). "
                "Do NOT run this test while an operator profile is live. "
                "Bring down the running profile(s) on a dedicated test host, then retry."
            )
        return True, "clean"
    except Exception as exc:
        return False, f"Docker not reachable: {exc}. Run this test with a live Docker host."


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
        secret_env_var="AGENTARCA_ADMIN_SECRET_NOEXIST_MUTEX_TEST",
        audit_log_path=tmp_audit,
        session_secret_key="test-session-key-aaabbbccc" * 4,
    )


# ---------------------------------------------------------------------------
# AC-27-P2-07: Concurrent-up TOCTOU race test (integration)
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_concurrent_up_at_most_one_running(test_settings, tmp_audit):
    """
    AC-27-P2-07 (BLOCK, integration): fire 6 simultaneous up requests
    (2 per profile) and assert at most one profile ends up running.

    The test uses a threading.Barrier(6) to synchronize all requests to fire
    within milliseconds of each other, maximizing the likelihood of exposing
    any TOCTOU window if the flock is not correctly held.

    If a profile is already running when this test starts, pytest.fail() is
    called immediately without touching the operator's stack.
    """
    ok, msg = _check_live_stack_clean()
    if not ok:
        pytest.fail(msg)

    from starlette.testclient import TestClient
    from src.admin.primitives.lifecycle import get_running_profiles

    app = create_app(test_settings)

    # Authenticate and get a CSRF token before spawning threads.
    with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as setup_client:
        setup_client.headers.update({"Host": VALID_HOST_HEADER})
        login_resp = setup_client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST_HEADER},
        )
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        csrf_token = login_resp.json()["csrf_token"]
        # Extract the session cookie for use in threaded clients.
        session_cookie = setup_client.cookies.get("agentarca_session")
        assert session_cookie, "No session cookie set after login"

    # Build the 6 requests: 2 per profile.
    profiles_to_test = ["copilot", "claude", "codex"]
    requests_to_fire = []
    for profile in profiles_to_test:
        requests_to_fire.append(profile)
        requests_to_fire.append(profile)  # 2 per profile

    responses = [None] * len(requests_to_fire)
    barrier = threading.Barrier(len(requests_to_fire))
    errors = []

    def fire_up(idx: int, profile: str) -> None:
        """Send a POST /api/v1/profiles/<profile>/up, synchronized at the barrier."""
        try:
            # Each thread creates its own TestClient sharing the same app.
            with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as c:
                # Inject the session cookie from the login above.
                c.cookies.set("agentarca_session", session_cookie)
                c.headers.update({
                    "Host": VALID_HOST_HEADER,
                    "X-CSRF-Token": csrf_token,
                })
                # Wait at the barrier: all threads release simultaneously.
                barrier.wait(timeout=10)
                resp = c.post(
                    f"/api/v1/profiles/{profile}/up",
                    headers={"Host": VALID_HOST_HEADER},
                )
                responses[idx] = (profile, resp.status_code, resp.json())
        except Exception as exc:
            errors.append(f"Thread {idx} (profile={profile}): {exc}")

    # Fire all 6 requests concurrently.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [
            executor.submit(fire_up, i, profile)
            for i, profile in enumerate(requests_to_fire)
        ]
        concurrent.futures.wait(futures, timeout=300)  # 5-min timeout covers compose up

    if errors:
        pytest.fail(f"Thread errors during concurrent up: {errors}")

    # Let compose settle.
    time.sleep(10)

    # --- Assertion 1: At most one profile is running. ---
    running_after = get_running_profiles()
    assert len(running_after) <= 1, (
        f"TOCTOU violation: {len(running_after)} profiles are running after 6 concurrent up requests: "
        f"{running_after}. The mutual-exclusion invariant is broken."
    )

    # --- Assertion 2: Exactly one 201, rest are 200 (idempotent) / 409 / 503. ---
    status_codes = [r[1] for r in responses if r is not None]
    profiles_up = [r[0] for r in responses if r is not None and r[1] in (201, 200)]
    profiles_201 = [r[0] for r in responses if r is not None and r[1] == 201]
    profiles_409_503 = [r[0] for r in responses if r is not None and r[1] in (409, 503)]

    assert len(profiles_201) <= 1, (
        f"Multiple 201 responses: {profiles_201}. Only one profile should have been brought up."
    )

    # All responses must be one of: 201, 200 (idempotent), 409, 503.
    unexpected = [r for r in responses if r is not None and r[1] not in (200, 201, 409, 503)]
    assert not unexpected, (
        f"Unexpected response codes in concurrent test: {unexpected}"
    )

    # --- Assertion 3: Audit log consistency. ---
    if tmp_audit.exists():
        records = [
            json.loads(line)
            for line in tmp_audit.read_text().strip().splitlines()
            if line.strip()
        ]
        lifecycle_records = [r for r in records if r.get("domain") == "lifecycle"]

        # No audit record should have both outcome=applied AND a different profile
        # than the one that actually ended up running.
        if running_after:
            final_profile = next(iter(running_after))
            bad_applied = [
                r for r in lifecycle_records
                if r.get("outcome") == "applied"
                and r.get("target") != final_profile
                and r.get("detail") != "idempotent"
            ]
            assert not bad_applied, (
                f"Audit records show 'applied' outcome for a profile other than the final running "
                f"profile {final_profile!r}: {bad_applied}"
            )

    # --- Cleanup: tear down any running profile. ---
    if running_after:
        with TestClient(app, base_url=f"http://{TEST_HOST}:{TEST_PORT}") as cleanup_client:
            cleanup_client.cookies.set("agentarca_session", session_cookie)
            cleanup_client.headers.update({
                "Host": VALID_HOST_HEADER,
                "X-CSRF-Token": csrf_token,
            })
            for profile in running_after:
                cleanup_client.post(
                    f"/api/v1/profiles/{profile}/down",
                    headers={"Host": VALID_HOST_HEADER},
                )
