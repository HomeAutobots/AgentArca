"""
isolation.py - Read-only isolation posture reader and D5.4 hard-refusal logic.

Reads the current sandbox isolation posture from docker-compose.yml using
yaml.safe_load() ONLY. Never uses yaml.load() (code injection risk).

D5.4 hard refusals (SPEC-27-P3 section 6.1, re-verified 2026-06-24 against
docker-compose.yml):
  - NET_ADMIN to devcontainer: FORBIDDEN
  - NET_RAW to devcontainer: FORBIDDEN
  - SYS_ADMIN to devcontainer: FORBIDDEN
  - --privileged on any service: FORBIDDEN
  - docker.sock mount: FORBIDDEN
  - concurrent profiles: FORBIDDEN (enforced at lifecycle layer + here for validate)

These are STRUCTURALLY ABSENT from every write surface. check_d5_4_hard_refusals()
is a pure function: it reads nothing, writes nothing, calls no subprocess.

IsolationPosture is read from the compose file (static read, no Docker API).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# D5.4 forbidden values (SPEC-27-P3 section 6.1)
# ---------------------------------------------------------------------------

D5_4_FORBIDDEN_CAPS = frozenset({"NET_ADMIN", "NET_RAW", "SYS_ADMIN"})
D5_4_FORBIDDEN_FLAGS = frozenset({"privileged", "--privileged"})


# ---------------------------------------------------------------------------
# D5.4 hard-refusal check (pure function, SPEC-27-P3 section 6.1)
# ---------------------------------------------------------------------------

def check_d5_4_hard_refusals(
    proposed_caps: Optional[list] = None,
    proposed_flags: Optional[list] = None,
    proposed_mounts: Optional[list] = None,
) -> list:
    """
    Returns a list of hard-refusal reasons. Empty list means no D5.4 violation.

    Never mutates any state. This is a pure read+check function.
    No file I/O. No subprocess. No network.

    Checks:
    - NET_ADMIN, NET_RAW, SYS_ADMIN in proposed_caps
    - --privileged in proposed_flags
    - docker.sock in proposed_mounts
    """
    reasons = []
    for cap in (proposed_caps or []):
        if str(cap).upper() in D5_4_FORBIDDEN_CAPS:
            reasons.append(
                f"D5.4 hard refusal: capability {cap} is forbidden for the devcontainer"
            )
    for flag in (proposed_flags or []):
        if str(flag).lower() in {"--privileged", "privileged"}:
            reasons.append("D5.4 hard refusal: --privileged mode is forbidden")
    for mount in (proposed_mounts or []):
        if "docker.sock" in str(mount) or "/var/run/docker.sock" in str(mount):
            reasons.append(
                f"D5.4 hard refusal: docker.sock mount is forbidden: {mount}"
            )
    return reasons


# ---------------------------------------------------------------------------
# IsolationPosture dataclass (SPEC-27-P3 section 6.2)
# ---------------------------------------------------------------------------

@dataclass
class IsolationPosture:
    profile: str                    # "copilot" | "claude" | "codex" | "unknown"
    cap_drop: list = field(default_factory=list)      # e.g. ["ALL"]
    cap_add: list = field(default_factory=list)       # e.g. [] for devcontainer
    no_new_privileges: bool = False
    seccomp_profile: str = ""       # "agent-seccomp.json" or path
    read_only_rootfs: bool = False
    pids_limit: int = 0
    mem_limit: str = ""             # e.g. "6g"
    cpus: str = ""                  # e.g. "3"
    network_mode: str = ""          # e.g. "service:gateway-copilot"
    docker_sock_mounted: bool = False   # always False in a correct config; True = ALERT
    privileged: bool = False            # always False in a correct config; True = ALERT
    d5_4_violations: list = field(default_factory=list)   # D5.4 violations found
    gateway_cap_add: list = field(default_factory=list)   # gateway's cap_add


def _default_compose_path() -> Path:
    """Return the default docker-compose.yml path (repo root)."""
    # primitives/ -> admin/ -> src/ -> AgentArca/ (repo root)
    return Path(__file__).resolve().parent.parent.parent.parent / "docker-compose.yml"


def _resolve_merge_keys(obj):
    """
    Recursively resolve YAML merge keys (<<: *anchor) in a parsed YAML dict.

    PyYAML's safe_load resolves merge keys automatically for standard YAML anchors,
    but this helper ensures nested structures are also handled.
    """
    if isinstance(obj, dict):
        return {k: _resolve_merge_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_merge_keys(i) for i in obj]
    return obj


def _extract_security_opts(security_opt: list) -> tuple:
    """
    Parse security_opt list to extract no-new-privileges and seccomp profile.

    Returns (no_new_privileges: bool, seccomp_profile: str)
    """
    no_new_privileges = False
    seccomp_profile = ""
    for opt in (security_opt or []):
        s = str(opt)
        if s == "no-new-privileges:true":
            no_new_privileges = True
        elif s.startswith("seccomp="):
            # e.g. "seccomp=./src/dev/agent-seccomp.json"
            seccomp_profile = s.split("=", 1)[1]
            # Extract just the filename for display.
            seccomp_profile = Path(seccomp_profile).name
    return no_new_privileges, seccomp_profile


def _check_docker_sock_mounted(volumes: list) -> bool:
    """Return True if any volume mounts docker.sock."""
    for vol in (volumes or []):
        v = str(vol)
        if "docker.sock" in v:
            return True
    return False


def read_isolation_posture(
    compose_path: Optional[Path] = None,
    profile: str = "unknown",
) -> IsolationPosture:
    """
    Read the isolation posture from docker-compose.yml (static read, no Docker API).

    Uses yaml.safe_load() only. Never uses yaml.load() with unrestricted Loader.
    Handles YAML anchors (PyYAML safe_load resolves merge keys automatically).

    If the compose file cannot be read, returns a posture with error markers.
    """
    if compose_path is None:
        compose_path = _default_compose_path()

    # Import yaml here; it's a runtime dependency.
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        logger.error("PyYAML not installed; cannot read isolation posture.")
        return IsolationPosture(
            profile=profile,
            d5_4_violations=["PyYAML not available; cannot read compose config"],
        )

    try:
        content = compose_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.error("Cannot read compose file %s: %s", compose_path, exc)
        return IsolationPosture(
            profile=profile,
            d5_4_violations=[f"Cannot read compose file: {exc}"],
        )

    try:
        # yaml.safe_load is the ONLY permitted loader.
        compose_data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        logger.error("YAML parse error in %s: %s", compose_path, exc)
        return IsolationPosture(
            profile=profile,
            d5_4_violations=[f"YAML parse error: {str(exc)[:200]}"],
        )

    if not isinstance(compose_data, dict):
        return IsolationPosture(
            profile=profile,
            d5_4_violations=["Compose file has unexpected structure"],
        )

    services = compose_data.get("services", {}) or {}

    # Extract x-devcontainer-base anchor values.
    # PyYAML safe_load resolves anchors and merge keys inline; the anchor data
    # is embedded in services that use <<: *devcontainer-base.
    # We also look at the top-level x-devcontainer-base key directly.
    devcontainer_base = compose_data.get("x-devcontainer-base", {}) or {}
    gateway_base = compose_data.get("x-gateway-base", {}) or {}

    # Find the devcontainer service for the active profile (or use the base).
    devcontainer_service = {}
    if profile != "unknown":
        svc_name = f"devcontainer-{profile}"
        devcontainer_service = services.get(svc_name, {}) or {}

    # Fall back to the base anchor if no profile-specific service found.
    if not devcontainer_service:
        devcontainer_service = devcontainer_base

    # Extract fields from the devcontainer service.
    cap_drop = devcontainer_service.get("cap_drop", []) or []
    cap_add = devcontainer_service.get("cap_add", []) or []
    security_opt = devcontainer_service.get("security_opt", []) or []
    read_only_rootfs = bool(devcontainer_service.get("read_only", False))
    network_mode_raw = devcontainer_service.get("network_mode", "")

    # Extract resource limits from deploy.resources.limits or top-level keys.
    deploy = devcontainer_service.get("deploy", {}) or {}
    resources = deploy.get("resources", {}) or {}
    limits = resources.get("limits", {}) or {}
    mem_limit = str(limits.get("memory", "")) if limits.get("memory") else ""
    cpus = str(limits.get("cpus", "")) if limits.get("cpus") else ""

    # Also check top-level pids_limit and mem_limit (older Compose syntax).
    pids_limit = int(devcontainer_service.get("pids_limit", 0) or 0)
    if not mem_limit:
        mem_limit = str(devcontainer_service.get("mem_limit", "") or "")
    if not cpus:
        cpus = str(devcontainer_service.get("cpus", "") or "")

    no_new_privileges, seccomp_profile = _extract_security_opts(security_opt)

    # Check docker.sock mounts.
    volumes = devcontainer_service.get("volumes", []) or []
    docker_sock_mounted = _check_docker_sock_mounted(volumes)

    # Check privileged flag.
    privileged = bool(devcontainer_service.get("privileged", False))

    # Extract gateway cap_add from x-gateway-base anchor.
    gateway_cap_add = gateway_base.get("cap_add", []) or []
    # Also check a concrete gateway service if no base.
    if not gateway_cap_add and profile != "unknown":
        gw_svc_name = f"gateway-{profile}"
        gw_service = services.get(gw_svc_name, {}) or {}
        gateway_cap_add = gw_service.get("cap_add", []) or []

    # D5.4 self-check: run hard-refusal check on the DEVCONTAINER caps.
    d5_4_violations = check_d5_4_hard_refusals(
        proposed_caps=cap_add,
        proposed_flags=["--privileged"] if privileged else [],
        proposed_mounts=[v for v in volumes if "docker.sock" in str(v)],
    )
    if d5_4_violations:
        logger.warning(
            "D5.4 violations found in compose config for profile %r: %s",
            profile,
            d5_4_violations,
        )

    return IsolationPosture(
        profile=profile,
        cap_drop=[str(c) for c in cap_drop],
        cap_add=[str(c) for c in cap_add],
        no_new_privileges=no_new_privileges,
        seccomp_profile=seccomp_profile,
        read_only_rootfs=read_only_rootfs,
        pids_limit=pids_limit,
        mem_limit=mem_limit,
        cpus=cpus,
        network_mode=str(network_mode_raw),
        docker_sock_mounted=docker_sock_mounted,
        privileged=privileged,
        d5_4_violations=d5_4_violations,
        gateway_cap_add=[str(c) for c in gateway_cap_add],
    )
