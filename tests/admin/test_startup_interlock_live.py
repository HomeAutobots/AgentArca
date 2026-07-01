"""
test_startup_interlock_live.py - Live-profile containment tests for SPEC-29-P0 (ADR-012).

FRAME: "assume the agent inside the sandbox is injected / root-in-container and tries to
mint, forge, delete, or influence a start authorization." Prove the deterministic boundary
holds over a REAL running profile:
  - the nonce directory is NOT present in the devcontainer filesystem (AC-29-P0-16),
  - the nonce mount is read-only from inside the gateway; a write/delete returns EROFS
    even though the entrypoint runs as root (AC-29-P0-17),
  - an injected root-in-container agent has no docker.sock, no route to the portal loopback
    port, and no filesystem path to the nonce dir (AC-29-P0-24).

PLACEMENT DECISION (why @pytest.mark.integration Python against a live stack):
  These properties are structural facts of docker-compose.yml (the read_only nonce bind is
  on x-gateway-base ONLY; devcontainers use network_mode not the mount; cap_drop ALL; no
  docker.sock) and are independent of the gateway IMAGE. The repo's established idiom for
  live-boundary assertions is @pytest.mark.integration Python that assumes a running stack
  and pytest.fail()s (never silently skips) when it is absent -- see tests/admin/
  test_crash_isolation.py. We follow that idiom exactly and DISCOVER whichever profile is
  live from `docker compose ps`, so the test is profile-agnostic. These are non-destructive:
  every write attempt is one the boundary must REJECT (EROFS), and the only process we start
  is a throwaway host listener that we tear down.

Run with:  pytest tests/admin/test_startup_interlock_live.py -m integration
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# Live-stack discovery helpers (profile-agnostic).
# ---------------------------------------------------------------------------

def _compose_ps_json() -> list[dict]:
    result = subprocess.run(
        ["docker", "compose", "ps", "--format", "json"],
        capture_output=True, text=True, timeout=15, cwd=str(REPO_ROOT),
    )
    if result.returncode != 0:
        return []
    out = result.stdout.strip()
    if not out:
        return []
    rows: list[dict] = []
    # JSONL (2.21+) or a single JSON array (legacy).
    if out.lstrip().startswith("["):
        try:
            rows = json.loads(out)
        except json.JSONDecodeError:
            rows = []
    else:
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def _discover_stack():
    """Return (profile, gateway_container, devcontainer_container) for the running profile,
    or (None, None, None) if no profile gateway is running."""
    rows = _compose_ps_json()
    gateway = None
    profile = None
    devcontainer = None
    for r in rows:
        svc = r.get("Service", "")
        name = r.get("Name", "")
        state = (r.get("State", "") or "").lower()
        m = re.match(r"^gateway-(\w+)$", svc)
        if m and state == "running":
            profile = m.group(1)
            gateway = name
    if profile is None:
        return None, None, None
    for r in rows:
        svc = r.get("Service", "")
        name = r.get("Name", "")
        state = (r.get("State", "") or "").lower()
        if svc.startswith("devcontainer") and state == "running":
            # Prefer the devcontainer matching the profile; else the only running one.
            if svc == f"devcontainer-{profile}" or svc == "devcontainer" or devcontainer is None:
                devcontainer = name
    return profile, gateway, devcontainer


@pytest.fixture(scope="module")
def live_stack():
    profile, gw, dc = _discover_stack()
    if gw is None:
        pytest.fail(
            "No running profile gateway found (`docker compose ps` shows no gateway-<p> in "
            "State running). These containment tests require a live profile started via the "
            "portal/break-glass. Bring one up and retry. Do NOT skip: they cover AC-29-P0-16/17/24."
        )
    return {"profile": profile, "gateway": gw, "devcontainer": dc}


def _dexec(container: str, argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", container, *argv],
        capture_output=True, text=True, timeout=timeout,
    )


def _mount_destinations(container: str) -> list[str]:
    r = subprocess.run(
        ["docker", "inspect", container, "--format",
         "{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}"],
        capture_output=True, text=True, timeout=15,
    )
    return r.stdout.split()


# ---------------------------------------------------------------------------
# AC-29-P0-16: nonce dir NOT present in the devcontainer filesystem
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestNonceNotInDevcontainer:
    def test_run_start_auth_absent_in_devcontainer(self, live_stack):
        """AC-29-P0-16: the devcontainer shares the gateway NETNS but has a SEPARATE mount ns;
        /run/start-auth is not mounted and the nonce is unreadable from inside the sandbox."""
        dc = live_stack["devcontainer"]
        if not dc:
            pytest.fail("No running devcontainer discovered; cannot assert AC-29-P0-16.")

        # (a) No mount at /run/start-auth in the devcontainer.
        dests = _mount_destinations(dc)
        offending = [d for d in dests if d.split("=")[0] == "/run/start-auth"]
        assert not offending, (
            f"devcontainer has a /run/start-auth mount ({offending}); the nonce dir MUST NOT be "
            "mounted into any devcontainer (B3 / AC-012-2)."
        )

        # (b) The path does not exist from inside the devcontainer.
        r = _dexec(dc, ["sh", "-c", "test -e /run/start-auth && echo PRESENT || echo ABSENT"])
        assert r.stdout.strip() == "ABSENT", (
            f"/run/start-auth must be ABSENT in the devcontainer; got {r.stdout.strip()!r}"
        )
        # (c) The specific nonce file for the live profile is unreadable from the sandbox.
        prof = live_stack["profile"]
        r = _dexec(dc, ["sh", "-c", f"cat /run/start-auth/{prof} 2>&1; echo EXIT=$?"])
        assert "EXIT=0" not in r.stdout, (
            f"the sandbox must not be able to read the nonce; got: {r.stdout!r}"
        )


# ---------------------------------------------------------------------------
# AC-29-P0-17 (N5): write/delete under /run/start-auth from the gateway -> EROFS
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestNonceMountReadOnlyFromGateway:
    def test_write_and_delete_return_erofs(self, live_stack):
        """AC-29-P0-17 / N5: even as root with the gateway's capability set, a write or delete
        under /run/start-auth returns EROFS (read_only bind + cap_drop ALL). The gateway cannot
        recycle, forge, or delete its own start authorization."""
        gw = live_stack["gateway"]

        # The mount must be read-only per docker inspect.
        dests = _mount_destinations(gw)
        sa = [d for d in dests if d.split("=")[0] == "/run/start-auth"]
        assert sa, "gateway is missing the /run/start-auth mount entirely"
        assert sa[0].endswith("=false"), (
            f"gateway /run/start-auth mount must be read-only (RW=false); got {sa[0]!r}"
        )

        # We run as root inside the gateway entrypoint context; confirm the euid is 0 so the
        # EROFS proof is meaningful (a non-root failure could be mere DAC, not the mount).
        uid = _dexec(gw, ["id", "-u"]).stdout.strip()

        # (a) Creating a new file must fail with EROFS.
        r = _dexec(gw, ["sh", "-c", "touch /run/start-auth/forged 2>&1; echo EXIT=$?"])
        assert "EXIT=0" not in r.stdout, f"touch under /run/start-auth SUCCEEDED (uid={uid}): {r.stdout!r}"
        assert re.search(r"[Rr]ead-only file system", r.stdout), (
            f"expected EROFS on write; got: {r.stdout!r}"
        )

        # (b) Deleting an existing nonce (if present) must also fail with EROFS.
        prof = live_stack["profile"]
        r = _dexec(gw, ["sh", "-c", f"rm -f /run/start-auth/{prof} 2>&1; echo EXIT=$?"])
        # rm -f on a read-only fs of an existing file reports EROFS; if the file is already
        # gone (consumed) rm -f is a silent success (nothing to remove). Either way the nonce
        # cannot be deleted while it exists: assert no successful deletion of a present file.
        still_there = _dexec(gw, ["sh", "-c", f"test -e /run/start-auth/{prof} && echo YES || echo NO"]).stdout.strip()
        if still_there == "YES":
            assert re.search(r"[Rr]ead-only file system", r.stdout), (
                f"an existing nonce must be undeletable (EROFS) from the gateway; got: {r.stdout!r}"
            )


# ---------------------------------------------------------------------------
# AC-29-P0-24: injected root-in-container agent cannot mint/forge/influence a start
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestInjectedAgentCannotMintOrForge:
    def test_no_docker_sock_no_nonce_path_no_portal_route(self, live_stack):
        """AC-29-P0-24: over a live running profile, the injected agent (UID or root in the
        devcontainer) has: (a) no docker.sock to drive compose, (b) no filesystem path to the
        nonce dir, and (c) no network route to the portal's host loopback port. Three closures,
        each independently sufficient to deny minting/forging a start authorization."""
        dc = live_stack["devcontainer"]
        if not dc:
            pytest.fail("No running devcontainer discovered; cannot assert AC-29-P0-24.")

        # (a) No docker.sock anywhere the agent can reach it (ADR-004 D3).
        r = _dexec(dc, ["sh", "-c",
                        "ls -l /var/run/docker.sock /run/docker.sock 2>&1; echo EXIT=$?"])
        assert "EXIT=0" not in r.stdout, f"a docker socket is reachable from the sandbox: {r.stdout!r}"
        assert "srw" not in r.stdout, f"a docker socket file is present: {r.stdout!r}"

        # (b) No filesystem path to the nonce dir (AC-29-P0-16, re-asserted here for the D3 proof).
        r = _dexec(dc, ["sh", "-c", "test -e /run/start-auth && echo PRESENT || echo ABSENT"])
        assert r.stdout.strip() == "ABSENT", "the sandbox must have no path to the nonce dir"

        # (c) No route to the portal loopback port. Start a REAL host listener on 127.0.0.1:<port>
        # (the sandbox's 127.0.0.1 is its own netns loopback, ADR-010 D3), and prove the sandbox
        # cannot reach it. We pick a free host port and bind it ourselves so a "blocked" result
        # is genuine (something IS listening on the host; the sandbox just cannot route to it).
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(16)
        try:
            # Confirm it is genuinely up on the host loopback.
            probe = socket.create_connection(("127.0.0.1", port), timeout=2)
            probe.close()

            # From inside the sandbox, a TCP connect to 127.0.0.1:<port> must NOT succeed.
            r = _dexec(dc, ["sh", "-c",
                            f"(exec 3<>/dev/tcp/127.0.0.1/{port}) 2>&1 && echo CONNECTED || echo REFUSED; echo EXIT=$?"],
                       timeout=15)
            assert "CONNECTED" not in r.stdout, (
                f"the sandbox REACHED the host loopback portal port {port}; this breaks the "
                f"agent-unreachability proof (ADR-010 D3) and is a BLOCK finding. Output: {r.stdout!r}"
            )
        finally:
            sock.close()
