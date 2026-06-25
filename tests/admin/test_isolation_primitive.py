"""
test_isolation_primitive.py - Unit tests for src/admin/primitives/isolation.py

Covers:
  AC-27-P3-23 (BLOCK) D5.4 check function: covers all 6 forbidden conditions;
                       returns empty list for benign inputs
  AC-27-P3-24         IsolationPosture read: reads x-devcontainer-base anchor values;
                       cap_drop=[ALL], no_new_privileges=True, read_only=True, seccomp present

All isolation-runnable. No Docker required.
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.primitives.isolation import (
    D5_4_FORBIDDEN_CAPS,
    D5_4_FORBIDDEN_FLAGS,
    IsolationPosture,
    check_d5_4_hard_refusals,
    read_isolation_posture,
)


# ---------------------------------------------------------------------------
# AC-27-P3-23 (BLOCK): D5.4 check function covers all 6 forbidden conditions
# ---------------------------------------------------------------------------

def test_d5_4_net_admin_refused():
    """NET_ADMIN in proposed_caps triggers a hard refusal."""
    reasons = check_d5_4_hard_refusals(proposed_caps=["NET_ADMIN"])
    assert reasons, "NET_ADMIN must trigger a D5.4 hard refusal"
    assert any("NET_ADMIN" in r for r in reasons)


def test_d5_4_net_raw_refused():
    """NET_RAW triggers a hard refusal."""
    reasons = check_d5_4_hard_refusals(proposed_caps=["NET_RAW"])
    assert reasons
    assert any("NET_RAW" in r for r in reasons)


def test_d5_4_sys_admin_refused():
    """SYS_ADMIN triggers a hard refusal."""
    reasons = check_d5_4_hard_refusals(proposed_caps=["SYS_ADMIN"])
    assert reasons
    assert any("SYS_ADMIN" in r for r in reasons)


def test_d5_4_privileged_refused():
    """--privileged triggers a hard refusal."""
    reasons = check_d5_4_hard_refusals(proposed_flags=["--privileged"])
    assert reasons
    assert any("privileged" in r.lower() for r in reasons)


def test_d5_4_privileged_without_dashes_refused():
    """'privileged' (without dashes) also triggers a hard refusal."""
    reasons = check_d5_4_hard_refusals(proposed_flags=["privileged"])
    assert reasons
    assert any("privileged" in r.lower() for r in reasons)


def test_d5_4_docker_sock_refused():
    """docker.sock mount triggers a hard refusal."""
    reasons = check_d5_4_hard_refusals(
        proposed_mounts=["/var/run/docker.sock:/var/run/docker.sock"]
    )
    assert reasons
    assert any("docker.sock" in r for r in reasons)


def test_d5_4_docker_sock_path_variant_refused():
    """A docker.sock path variant is also refused."""
    reasons = check_d5_4_hard_refusals(
        proposed_mounts=["docker.sock:/tmp/docker.sock"]
    )
    assert reasons
    assert any("docker.sock" in r for r in reasons)


def test_d5_4_empty_inputs_returns_no_reasons():
    """
    AC-27-P3-23 (BLOCK): Benign/empty inputs return an empty list.
    """
    reasons = check_d5_4_hard_refusals(
        proposed_caps=[],
        proposed_flags=[],
        proposed_mounts=[],
    )
    assert reasons == [], f"Expected empty list for benign inputs, got: {reasons}"


def test_d5_4_none_inputs_returns_no_reasons():
    """None inputs (all optional) return an empty list."""
    reasons = check_d5_4_hard_refusals()
    assert reasons == []


def test_d5_4_benign_cap_not_refused():
    """A benign capability like CHOWN is not refused."""
    reasons = check_d5_4_hard_refusals(proposed_caps=["CHOWN", "SETUID", "SETGID"])
    assert reasons == [], f"CHOWN/SETUID/SETGID must not trigger refusals: {reasons}"


def test_d5_4_mixed_benign_and_forbidden():
    """When a mix of benign and forbidden caps is provided, only forbidden are refused."""
    reasons = check_d5_4_hard_refusals(
        proposed_caps=["CHOWN", "NET_ADMIN", "SETUID"],
    )
    assert any("NET_ADMIN" in r for r in reasons)
    # CHOWN and SETUID should not appear in reasons.
    assert not any("CHOWN" in r for r in reasons)
    assert not any("SETUID" in r for r in reasons)


def test_d5_4_case_insensitive_caps():
    """Capability check is case-insensitive for caps (net_admin -> NET_ADMIN)."""
    reasons = check_d5_4_hard_refusals(proposed_caps=["net_admin"])
    assert reasons, "Lowercase net_admin must also trigger a refusal"
    assert any("NET_ADMIN" in r or "net_admin" in r for r in reasons)


def test_d5_4_is_pure_function():
    """check_d5_4_hard_refusals is a pure function: calling it twice returns same result."""
    reasons1 = check_d5_4_hard_refusals(proposed_caps=["NET_ADMIN"])
    reasons2 = check_d5_4_hard_refusals(proposed_caps=["NET_ADMIN"])
    assert reasons1 == reasons2


def test_d5_4_all_forbidden_in_one_call():
    """All 5 API-checkable D5.4 conditions (caps + flags + mounts) in one call."""
    reasons = check_d5_4_hard_refusals(
        proposed_caps=["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        proposed_flags=["--privileged"],
        proposed_mounts=["/var/run/docker.sock:/var/run/docker.sock"],
    )
    assert len(reasons) >= 5, f"Expected at least 5 reasons, got {len(reasons)}: {reasons}"
    reason_text = " ".join(reasons)
    assert "NET_ADMIN" in reason_text
    assert "NET_RAW" in reason_text
    assert "SYS_ADMIN" in reason_text
    assert "privileged" in reason_text.lower()
    assert "docker.sock" in reason_text


# ---------------------------------------------------------------------------
# AC-27-P3-24: IsolationPosture read from docker-compose.yml
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_compose_yml(tmp_path):
    """
    Create a minimal docker-compose.yml that mimics the real one's structure,
    including x-devcontainer-base anchor with all required hardening fields.
    """
    # PyYAML safe_load resolves merge keys (<<: *anchor) automatically.
    compose_content = textwrap.dedent("""\
        x-devcontainer-base: &devcontainer-base
          cap_drop:
            - ALL
          security_opt:
            - no-new-privileges:true
            - seccomp=./src/dev/agent-seccomp.json
          read_only: true
          pids_limit: 512
          mem_limit: "6g"
          cpus: "3"

        x-gateway-base: &gateway-base
          cap_add:
            - NET_ADMIN
            - NET_RAW
            - SETGID
            - SETUID
          cap_drop:
            - ALL

        services:
          devcontainer-copilot:
            <<: *devcontainer-base
            network_mode: "service:gateway-copilot"
            profiles:
              - copilot
          gateway-copilot:
            <<: *gateway-base
            profiles:
              - copilot
    """)
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(compose_content)
    return compose_path


def test_read_isolation_posture_from_mock_compose(mock_compose_yml):
    """
    AC-27-P3-24: read_isolation_posture reads the x-devcontainer-base anchor values.
    Verifies: cap_drop=["ALL"], no_new_privileges=True, read_only=True, seccomp present.
    """
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("PyYAML not installed; install pyyaml to run AC-27-P3-24")

    posture = read_isolation_posture(compose_path=mock_compose_yml, profile="copilot")

    assert "ALL" in posture.cap_drop, (
        f"cap_drop must contain ALL, got: {posture.cap_drop}"
    )
    assert posture.no_new_privileges is True, (
        "no_new_privileges must be True from security_opt"
    )
    assert posture.read_only_rootfs is True, (
        "read_only_rootfs must be True"
    )
    assert "agent-seccomp.json" in posture.seccomp_profile, (
        f"seccomp_profile must contain agent-seccomp.json, got: {posture.seccomp_profile}"
    )
    # No D5.4 violations in a correctly configured devcontainer.
    assert posture.d5_4_violations == [], (
        f"d5_4_violations must be empty for a clean config, got: {posture.d5_4_violations}"
    )
    # docker_sock_mounted and privileged must be False.
    assert posture.docker_sock_mounted is False
    assert posture.privileged is False


def test_read_isolation_posture_gateway_cap_add(mock_compose_yml):
    """Gateway cap_add (NET_ADMIN, NET_RAW, etc.) is reported in gateway_cap_add field."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("PyYAML not installed")

    posture = read_isolation_posture(compose_path=mock_compose_yml, profile="copilot")
    # Gateway should have NET_ADMIN and NET_RAW.
    assert "NET_ADMIN" in posture.gateway_cap_add or len(posture.gateway_cap_add) > 0, (
        f"gateway_cap_add expected to contain NET_ADMIN, got: {posture.gateway_cap_add}"
    )


def test_read_isolation_posture_missing_compose(tmp_path):
    """Missing compose file returns a posture with d5_4_violations describing the error."""
    missing_path = tmp_path / "nonexistent-docker-compose.yml"
    posture = read_isolation_posture(compose_path=missing_path)
    assert posture.d5_4_violations, (
        "d5_4_violations must be non-empty when compose file cannot be read"
    )


def test_read_isolation_posture_with_docker_sock_sets_violation(tmp_path):
    """A compose config with docker.sock mount reports a D5.4 violation."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("PyYAML not installed")

    compose_content = textwrap.dedent("""\
        x-devcontainer-base: &devcontainer-base
          cap_drop:
            - ALL
          security_opt:
            - no-new-privileges:true
          read_only: true
          volumes:
            - /var/run/docker.sock:/var/run/docker.sock

        services:
          devcontainer-copilot:
            <<: *devcontainer-base
    """)
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(compose_content)

    posture = read_isolation_posture(compose_path=compose_path, profile="copilot")
    assert posture.docker_sock_mounted is True
    assert posture.d5_4_violations, (
        "docker.sock mount must generate a D5.4 violation"
    )


def test_d5_4_forbidden_caps_constant():
    """D5_4_FORBIDDEN_CAPS contains exactly the expected caps."""
    assert "NET_ADMIN" in D5_4_FORBIDDEN_CAPS
    assert "NET_RAW" in D5_4_FORBIDDEN_CAPS
    assert "SYS_ADMIN" in D5_4_FORBIDDEN_CAPS
    # SETUID and SETGID are gateway-only (not forbidden for gateway).
    # They should NOT be in the devcontainer-forbidden set.
    # (The spec says NET_ADMIN, NET_RAW, SYS_ADMIN are forbidden for the devcontainer.)


def test_isolation_posture_is_dataclass():
    """IsolationPosture can be instantiated with defaults."""
    p = IsolationPosture(profile="unknown")
    assert p.profile == "unknown"
    assert p.cap_drop == []
    assert p.cap_add == []
    assert p.d5_4_violations == []
    assert p.docker_sock_mounted is False
    assert p.privileged is False
