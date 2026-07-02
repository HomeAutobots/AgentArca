# Runbook: Portal Startup Interlock and Break-Glass Override

- Source: ADR-012 D1, D6; SPEC-29-P0 sec 1, 6, 7, 9
- AC: AC-012-1 through AC-012-7, AC-012-6 (documentation deliverable)

---

## Interlock activation: rebuild gateway images after upgrades

The startup interlock lives in `src/gateway/entrypoint.sh` and is copied into the gateway
container image at build time (the `x-gateway-base` anchor in `docker-compose.yml` builds from
`src/gateway/Dockerfile` with context `src/gateway/`). A gateway image built BEFORE SPEC-29-P0
landed has NO nonce check in its entrypoint and will start normally without portal authorization,
even though the source code now contains the check. The rebuilt source does not automatically
update a cached image.

**Operator rule: after pulling a new version of AgentArca, rebuild the gateway images before
relying on the interlock. Until you rebuild, stale images can still be started by raw
`docker compose up`.**

### Build the gateway images

Run this from the repository root:

```
docker compose build gateway-copilot gateway-claude gateway-codex
```

This rebuilds all three gateway services from the current `src/gateway/` source. Docker layer
caching makes subsequent rebuilds fast when only entrypoint.sh has changed. No profile needs to
be running; this command is safe to run at any time.

### Verify the interlock is present in the source

```
grep "start authorization missing" src/gateway/entrypoint.sh
```

Expected output (line 115 or nearby):

```
  echo "[gateway/entrypoint] FATAL: start authorization missing for profile '${_nonce_profile}'." >&2
```

If the grep returns nothing, the source does not contain the interlock. Do not proceed; check
that you are on the correct branch and that the SPEC-29-P0 changes are present.

### Verify the interlock is active in a built image

Run a negative functional test: start the gateway without a portal-minted nonce. The interlock
means it must fail closed (exit 1) and never reach firewall initialization or Squid. This is
the same test the rt29 containment suite runs.

First ensure no valid nonce exists for copilot (the test profile):

```
rm -f "${HOME}/.agentarca/start-auth.d/copilot"
```

Then start just the gateway and check its logs:

```
docker compose --profile copilot up -d gateway-copilot
sleep 8
docker compose logs gateway-copilot
docker compose --profile copilot down
```

Look for this in the logs:

```
[gateway/entrypoint] FATAL: start authorization missing for profile 'copilot'.
```

If you see that line and do NOT see "Initializing firewall" or "Starting Squid", the interlock
is active. If you see "Initializing firewall" without a preceding "Start authorization verified"
line, the image is stale and was built before SPEC-29-P0. Rebuild with the command above.

### Verify after every AgentArca upgrade

The regression discipline is: any pull that touches `src/gateway/entrypoint.sh` or
`src/gateway/Dockerfile` requires a gateway image rebuild before the interlock can be trusted.
CI runs the rt29 containment suite on each build, which includes a hard stale-image guard
(see `tests/containment/rt29-run-interlock.sh`).

---

## What the interlock does and does not protect against

The startup interlock is a boot-time-only gate at the gateway container entrypoint.

**What it enforces:**

- Every gateway container start must be authorized by the portal (`agentarca up <profile>`) or
  the designated break-glass path (`src/scripts/break-glass-up.sh <profile>`). Absence of a
  valid nonce causes the entrypoint to exit 1 before `init-firewall.sh` runs. The egress
  firewall is never initialized and Squid never starts. This is the fail-closed posture for
  unauthorized starts (N1 in SPEC-29-P0 sec 14).
- The nonce must be fresh: it expires 300 seconds after it is minted. A replayed or stale nonce
  is rejected the same way as an absent one (N2).
- The nonce must name the correct profile. A copilot nonce dropped into the claude slot is
  rejected (N3).
- The nonce file is mounted read-only into the gateway container via the `x-gateway-base`
  volumes block. With `cap_drop: [ALL]`, a process inside the gateway cannot write or delete
  the file (EROFS). The gateway cannot forge or recycle its own nonce.

**What it does NOT protect against:**

- A stale un-rebuilt gateway image. If the gateway was built before SPEC-29-P0, its entrypoint
  has no nonce check. `docker compose up` on that image starts Squid normally. This runbook
  section on activation exists specifically because of this gap.
- Runtime re-authorization. The interlock runs once at container startup and does not re-check
  during the container's lifetime (ADR-010 D7.2). This is by design: once Squid is running,
  the nonce file may be deleted without consequence. The boundary is the egress allowlist and
  firewall, not continued nonce presence.
- A host-level operator who writes a nonce file by hand and runs `docker compose up` directly.
  The interlock enforces policy against accidental and unsupported starts; it is not
  tamper-proof against the machine owner. See ADR-012 D4 for the honest trust model.
- A kernel exploit or container escape. The interlock does not add a new isolation tier. A
  kernel-level escape bypasses all userspace controls including this one. See the residual-risk
  register for the accepted kernel 0-day risk.
- Threat models requiring nation-state-level adversaries or production secrets in-container.
  Those workloads need a higher isolation tier (gVisor, microVM, or full VM). This build is
  calibrated for trusted-developer + injected-agent scenarios, not adversarial untrusted code.

---

## When to use break-glass

Break-glass is an emergency operator escape hatch for starting a profile when
the portal process itself is unavailable (crashed, failed to start, or otherwise
broken). It is NOT a normal operation path. Every use is audited.

Use break-glass only when:
1. The portal is not running or cannot be started.
2. You must start a profile immediately (for example, to restore a dev session).
3. You have already tried the normal paths (portal UI, `agentarca up <profile>`).

Do NOT use break-glass as a routine alternative to the portal. Its safety depends
on being a rarely exercised, clearly audited path. If you find yourself reaching
for it regularly, fix the portal.

---

## The command

```
src/scripts/break-glass-up.sh <profile>
```

Where `<profile>` is one of: `copilot`, `claude`, `codex`.

The script must be run from an environment where the admin venv is present
(`.venv-admin/` in the repo root). If the venv is absent, the script exits with
an error. Run `src/scripts/build-admin.sh` (without flags) to create the venv,
or `src/scripts/build-admin.sh --init` if the admin directories and secret also
need to be created first.

---

## What break-glass does (step by step)

The bash wrapper (`break-glass-up.sh`) does minimal work: it validates the
profile name, checks that the admin venv python exists, prints a loud audited-bypass
warning, then hands off to the Python helper (`_break_glass_up.py`). All security-critical
steps run in the Python process:

1. **Acquire lifecycle flock** (`~/.agentarca/lifecycle.lock` via Python `fcntl.flock`).
   Same lock the portal uses. This serializes break-glass with any concurrent portal
   operation. The lock is held for the entire sequence below.

2. **Running-state refuse** (invariant 9 / AC-012-5). Calls the actual
   `get_running_profiles()` from `src/admin/primitives/lifecycle.py` (not a
   re-implementation). If any profile is already running, break-glass exits 1
   immediately with no audit record and no nonce written.

3. **Write audit record** to the resolved console audit path
   (`~/.agentarca/admin-audit.jsonl` by default, or the value set by
   `AGENTARCA_ADMIN_AUDIT_LOG` or the `[admin] audit_log_path` config file key).
   The record is written BEFORE the nonce mint. Fields: `action=break_glass_up`,
   `domain=lifecycle`, `outcome=applied`, `target=<profile>`,
   `detail=break-glass nonce minted`, `operator_uid=<numeric UID>`.

4. **Mint nonce** at `~/.agentarca/start-auth.d/<profile>` (mode 0600). Same 3-line
   format and same independently random `secrets.token_hex(32)` token the portal
   uses. No admin secret is involved in the token (AC-012-3).

5. **Run `docker compose --profile <profile> up -d`** from the repo root.
   The compose invocation uses `cwd=<repo root>` so it works regardless of
   the operator's working directory.

6. **Release flock.** The lock is released in a `finally` block even if compose fails.

The ordering invariant (audit BEFORE mint BEFORE compose) is a hard requirement from
AC-012-5. An interruption after the audit write but before the nonce mint leaves a
record with no nonce: fail-closed, recoverable by retrying.

---

## Two-file design and why

Break-glass is implemented as two files:
- `src/scripts/break-glass-up.sh`: thin bash wrapper (profile validation, venv check,
  loud warning, then `exec` into Python).
- `src/scripts/_break_glass_up.py`: Python helper that owns the guarded sequence.

The split exists because macOS does not ship util-linux `flock(1)`. Python `fcntl.flock`
(stdlib, available on all POSIX platforms including macOS) is used instead. Placing the
flock acquisition and the entire guarded sequence in a single Python process guarantees
the lock is held continuously from step 2 through step 6 with no shell-to-Python handoff
gap.

`break-glass-up.sh` is `chmod 755`. `_break_glass_up.py` is `chmod 644` and is only
ever executed through the venv python, never called directly.

---

## What break-glass protects and what it does not

Break-glass enforces:
- Profile mutual exclusion (the flock + running-state refuse).
- Audit trail (one record per use, same file the portal writes to).
- Nonce freshness (the gateway entrypoint checks the minted nonce the same way
  it would check a portal-minted one; a nonce older than 300 seconds fails).

Break-glass does NOT protect against:
- A determined operator who bypasses it entirely (for example, by writing a nonce
  file by hand and running `docker compose up` directly). The interlock is
  deterministic against accidental and unsupported starts; it is not tamper-proof
  against the host owner. See ADR-012 D4 for the honest trust model.
- A concurrent break-glass invocation that races between the flock release
  and the next invocation's flock acquisition. The lock serializes them; the
  running-state check on the second invocation would see the first profile running
  and refuse.

---

## Use is audited

Every successful break-glass start appends a `break_glass_up` record to the same
audit file the portal writes. This record includes the operator UID. If the portal
is later restored, `GET /api/v1/logs/audit` will return the break-glass record
alongside portal-originated records.

The audit write is the first thing that happens after the running-state check. An
interruption (crash, Ctrl-C) after the audit write but before the nonce mint leaves
a record with no nonce: fail-closed, recoverable by retrying.

---

## Nonce-vs-restart policy

The break-glass script does NOT consume the nonce after `docker compose up`. The
nonce is consumed by the portal when it runs `do_down` or `do_switch` for the
profile. If the portal is still unavailable when you want to stop, run
`docker compose --profile <profile> down` directly; the nonce file persists and
will be purged by `purge_stale_nonces()` the next time the portal starts.

A gateway that crashes after the portal consumes the nonce (the normal portal
path) enters a fail-closed restart loop: it restarts, checks the nonce file,
finds it absent, and exits 1. To recover, run `agentarca up <profile>` (when the
portal is available) or re-run break-glass to mint a fresh nonce.

Do NOT make the nonce indefinitely valid to avoid this restart loop. A reusable or
long-lived nonce re-opens the raw-compose replay path (AC-012-4 stop-and-flag).

---

## Monitoring and stopping

Check status:

```
agentarca status
```

or

```
docker compose ps
```

Stop a profile started by break-glass:

```
agentarca down <profile>
```

or, if the portal is still unavailable:

```
docker compose --profile <profile> down
```
