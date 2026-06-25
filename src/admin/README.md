# AgentArca Admin Console

The admin console is a host-local operator tool for managing the AgentArca sandbox. It runs as a process on your host machine and provides a web UI and JSON API for four control domains: egress allowlist management, log access, profile lifecycle, and credential management.

This document covers what it is, how the security model works, how to set it up, what the endpoints do, and what the residual risks are.

---

## 1. What it is and what it is NOT

**What it is:**

- A FastAPI application that runs on your host at `127.0.0.1:8770` (loopback only).
- An operator console for the sandbox's four control domains, wrapping the same validated primitives (`allowlist-local.sh`, `docker compose up/down`) that the CLI path uses.
- The most privileged process in the system: it can widen the egress allowlist, switch profiles, and write to the repo-root `.env`. Every action it takes is recorded in an append-only audit log.

**What it is NOT:**

- A remote or multi-user tool. It binds loopback-only, serves one operator, and has no remote access mode. A remote mode would require its own threat-model review.
- Part of the sandbox's runtime boundary. The sandbox keeps running if the console crashes. The console is a management surface; it is not a runtime dependency.
- A safe place for the sandboxed agent to reach. The agent cannot see or contact this process. That is a design invariant, not a config option.
- Safe to run inside a sandbox container, on a Compose profile, on `agent-net`, or with any published port. It must always run as a host process, outside every container.

---

## 2. Security model

The loopback bind (`127.0.0.1:8770`) is the primary control. A host-loopback-bound listener is not reachable from a Docker bridge-network container: a container's `127.0.0.1` is its own loopback, not the host's. The sandboxed agent has no route to the host loopback, no `docker.sock`, and the console is not on any Compose network. Three independent facts close the agent-to-console path (ADR-010 D3); any one of them alone is sufficient.

The Host-header check is the load-bearing DNS-rebinding defense. DNS rebinding can trick your browser into issuing requests to `127.0.0.1` while carrying an attacker-controlled `Host` header. The console rejects any request whose `Host` header is not exactly `127.0.0.1:8770` or `localhost:8770`, and rejects any present `Origin` header that does not match `http://127.0.0.1:8770` or `http://localhost:8770`. This check runs on every request, before authentication, as the outermost middleware layer. A rebound request carries the attacker's domain in `Host` and is rejected with 403.

The shared secret is defense-in-depth behind the bind. It gates access so another local process on the same machine cannot trivially drive the console. It is not multi-user authentication and is not the primary boundary; the bind is. The secret is stored in `~/.agentarca/admin-secret` at mode 0600, compared in constant time using `hmac.compare_digest`, and never logged, echoed back, or placed in any audit record.

CSRF tokens protect state-changing requests. Every POST, PUT, and DELETE carries a CSRF token validated server-side, in addition to `SameSite=Strict` on the session cookie.

The audit trail is append-only on the host filesystem. The sandbox has no write path to it. Every state-changing action, every validation rejection, and every stop-and-flag refusal is recorded with timestamp, session ID, domain, action, and outcome. Secret values and token values never appear in audit records.

---

## 3. Setup and first run

**Step 1: generate the admin secret**

Run the init mode of the build script. This creates `~/.agentarca/admin-secret` at mode 0600 using `openssl rand -hex 32`. It also creates `~/.agentarca/` at mode 0700.

```bash
src/scripts/build-admin.sh --init
```

The script will refuse to overwrite an existing secret file. If you need to rotate the secret, delete the file first and re-run `--init`.

Treat `~/.agentarca/admin-secret` as a credential. Do not commit it, log it, or share it.

**Step 2: install dependencies**

The console requires Python 3.10+ and the packages in `requirements-admin.txt`. Install into a virtualenv:

```bash
python3 -m venv .venv-admin
.venv-admin/bin/pip install --require-hashes -r requirements-admin.txt
```

**Step 3: start the console**

```bash
.venv-admin/bin/python -m src.admin.main
```

Defaults: `127.0.0.1:8770`, secret from `~/.agentarca/admin-secret`, audit log at `~/.agentarca/admin-audit.jsonl`.

To override settings with environment variables:

```bash
AGENTARCA_ADMIN_PORT=8771 .venv-admin/bin/python -m src.admin.main
```

All configuration variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `AGENTARCA_ADMIN_HOST` | `127.0.0.1` | Bind address. Must be `127.0.0.1`. Any other value causes a startup failure unless `--allow-non-loopback` is set. |
| `AGENTARCA_ADMIN_PORT` | `8770` | Listen port. Chosen to avoid conflict with Squid (8080). |
| `AGENTARCA_ADMIN_SECRET_FILE` | `~/.agentarca/admin-secret` | Path to the 0600 secret file. |
| `AGENTARCA_ADMIN_SECRET` | (none) | Fallback env var for the secret if the file is absent. |
| `AGENTARCA_ADMIN_AUDIT_LOG` | `~/.agentarca/admin-audit.jsonl` | Append-only audit log path. |
| `AGENTARCA_ADMIN_SESSION_KEY` | (auto-generated) | Session signing key. If not set, a key is generated and persisted at `~/.agentarca/session-key`. |
| `AGENTARCA_ADMIN_SESSION_TTL` | `28800` (8 hours) | Session lifetime in seconds. |

The startup log will print the effective bind address and port. Check for:

```
Admin listening on 127.0.0.1:8770 | audit log: /Users/<you>/.agentarca/admin-audit.jsonl
```

If the startup fails with `FATAL: Refusing to bind to non-loopback address`, the `AGENTARCA_ADMIN_HOST` environment variable is set to a non-loopback value. Fix or unset it.

**Optional: config file**

Settings can also come from `~/.agentarca/admin.conf` (ini format, `[admin]` section). Environment variables override the config file; CLI flags override both.

---

## 4. The four control domains

All endpoints require authentication. Log in first:

```bash
curl -s -X POST http://127.0.0.1:8770/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"secret":"'$(cat ~/.agentarca/admin-secret)'"}'
# Returns: {"status":"ok","csrf_token":"<token>"}
# Sets session cookie: agentarca_session=...
```

Save the session cookie and the CSRF token for subsequent requests. All state-changing requests (POST, PUT, DELETE) require the CSRF token in an `X-CSRF-Token` header.

The health check does not require authentication and can be used to confirm the console is up:

```bash
curl -s http://127.0.0.1:8770/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

### 4a. Egress allowlist

The allowlist domain manages the mutable overlay (`config/allowlist.local.d/overrides.conf`) that the gateway sidecar bind-mounts read-only. Every add and remove goes through `allowlist-local.sh`, which validates the hostname, stages the change, runs `squid -k parse`, and only then applies the change via SIGHUP. A bad overlay is rejected before SIGHUP; if the gateway were to crash, it is fail-closed (no gateway means no egress).

```bash
# List the current allowlist state (base entries + overlay entries)
curl -s http://127.0.0.1:8770/api/v1/allowlist \
  -H "Cookie: agentarca_session=..."

# Add a host to the overlay
curl -s -X POST http://127.0.0.1:8770/api/v1/allowlist/entries \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"host":"registry.internal.example.com"}'
# 201 on new addition, 200 if already present (idempotent)
# Risk notice appears in the response for every new addition (R-b)

# Remove a host from the overlay
curl -s -X DELETE http://127.0.0.1:8770/api/v1/allowlist/entries/registry.internal.example.com \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>"

# Reload without changing entries (re-runs squid -k parse + SIGHUP)
curl -s -X POST http://127.0.0.1:8770/api/v1/allowlist/reload \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>"
```

Hostnames must be valid SNI FQDNs (letters, digits, dots, hyphens). Shell metacharacters and Squid metacharacters are rejected at the Python validation layer before the shell primitive is called.

Every add, remove, and reload is recorded in the audit log with its outcome (applied, rejected-by-validation, rejected-by-parse, error).

### 4b. Logs (read-only)

All three log endpoints are GET-only. There are no write methods on any `/api/v1/logs/*` path. This is enforced at build time by a static assertion.

```bash
# Paginated entries from the admin audit log
curl -s "http://127.0.0.1:8770/api/v1/logs/audit?limit=20&offset=0" \
  -H "Cookie: agentarca_session=..."

# Recent Squid gateway access.log entries (best-effort, empty if no gateway running)
curl -s "http://127.0.0.1:8770/api/v1/logs/egress?limit=50" \
  -H "Cookie: agentarca_session=..."

# Container health via docker compose ps
curl -s http://127.0.0.1:8770/api/v1/logs/health \
  -H "Cookie: agentarca_session=..."
```

The egress log endpoint returns an empty list with `status: "no_gateway_running"` if no gateway is active, rather than failing.

### 4c. Profile lifecycle

The lifecycle domain starts and stops Compose profiles with mutual exclusion enforced. The `up` endpoint will refuse (409 Conflict) if a different profile is already running. Switching profiles does a down-then-up under one lock acquisition so there is no concurrent-up window.

Allowed profiles: `copilot`, `claude`, `codex`.

```bash
# Bring a profile up (health-gates the response; waits up to 120s for the gateway)
curl -s -X POST http://127.0.0.1:8770/api/v1/profiles/claude/up \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>"
# 201 on new start, 200 if already up (idempotent), 409 if a different profile is running

# Bring a profile down
curl -s -X POST http://127.0.0.1:8770/api/v1/profiles/claude/down \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>"

# Switch from one profile to another (atomic down-then-up under one lock)
curl -s -X POST http://127.0.0.1:8770/api/v1/profiles/switch \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"from":"claude","to":"codex"}'
```

Important limit: the flock-based mutual exclusion only governs API-driven operations through this console. If you run `docker compose --profile <agent> up -d` directly from the CLI at the same time as an API-driven operation, the flock is bypassed and concurrent profiles can appear. Use the API or the CLI, not both simultaneously for lifecycle changes.

### 4d. Credentials and isolation (highest privilege)

The credentials domain manages the repo-root `.env` file where agent tokens live. It is write-only and masked: the console can set or clear a key, and it can report whether a key is set along with a salted fingerprint. The token value is never returned to any client, never placed in a response body, never logged, and never placed in an audit record. The audit record carries only the key name and a before/after fingerprint.

Managed credential keys: `COPILOT_GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `CODEX_API_KEY`.

```bash
# Check which keys are set (no values returned, fingerprints only)
curl -s http://127.0.0.1:8770/api/v1/credentials \
  -H "Cookie: agentarca_session=..."
# {"keys":[{"key":"ANTHROPIC_API_KEY","status":"SET","fingerprint":"abc1..."},{"key":"CODEX_API_KEY","status":"UNSET","fingerprint":null},...]}

# Set a token (write-only: the token does not come back)
curl -s -X PUT http://127.0.0.1:8770/api/v1/credentials/ANTHROPIC_API_KEY \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"value":"sk-ant-..."}'
# {"ok":true,"key":"ANTHROPIC_API_KEY","fingerprint":"abc1...","detail":"credential set"}

# Clear a token
curl -s -X DELETE http://127.0.0.1:8770/api/v1/credentials/ANTHROPIC_API_KEY \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>"
```

The isolation domain is read-only. It displays the current isolation posture (cap_drop, no_new_privileges, seccomp profile, resource limits, docker.sock presence, privileged flag) and calls out any D5.4 violations in the active Compose config.

```bash
# Read the current isolation posture
curl -s http://127.0.0.1:8770/api/v1/isolation \
  -H "Cookie: agentarca_session=..."

# Pre-flight check: does a proposed config contain a D5.4 hard refusal?
curl -s -X POST http://127.0.0.1:8770/api/v1/isolation/validate \
  -H "Cookie: agentarca_session=..." \
  -H "X-CSRF-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"proposed_caps_add":["NET_ADMIN"]}'
# 400: {"ok":false,"violations":["D5.4 hard refusal: NET_ADMIN ..."]}
```

The following values are permanently hard-refused by the isolation domain. There is no override. These are not editable fields; the API will never write them to any container config:

- `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN` as capabilities
- `--privileged` flag
- `docker.sock` mounts
- Two profiles running concurrently

To change isolation knobs, edit `docker-compose.yml` directly and restart the profile. The console reflects the current posture; it does not provide a write path to it.

---

## 5. Residual risks

Name them clearly. This console does not eliminate these risks; it names them.

**R-r: whoever controls the console controls the sandbox.**
The console is the most privileged process in the system. Whoever holds the admin secret (or compromises the operator's host session) can widen the egress allowlist to any host, switch profiles, and write tokens to the repo-root `.env`. The primary mitigation is the loopback bind (code-enforced: the console will not start if bound to a non-loopback address without an explicit override flag). The shared secret, CSRF, and Host-header validation are defense-in-depth. The honest limit: a single shared secret is low-assurance. If someone compromises your host session or the secret leaks, they have full sandbox control.

Protect the host machine. Protect `~/.agentarca/admin-secret` at mode 0600. Do not run the console on a machine accessible to untrusted users. Do not expose port 8770 off the host.

**R-q and R-b: every allowlist add widens the exfil surface.**
Adding a host to the allowlist makes that host a standing destination an injected agent can try to exfiltrate to. The console makes every add auditable; it does not make the add safe. Every add is a deliberate operator decision with a residual. Use the narrowest host that works. Remove hosts when you are done with them.

**R-s: DNS rebinding is defended against, not impossible.**
The Host-header validation is a deterministic defense against DNS rebinding (ADR-010 D4.4). It is correctly implemented and tested. The residual is a mis-implementation or a bypass the tests did not cover. Keep port 8770 loopback-only. Do not expose it to any routable interface; if you do, the secret becomes the only barrier between a remote attacker and full sandbox control, which is weak.

**What the console deliberately does not do:**
- No isolation editing: caps, `--privileged`, `docker.sock`, and concurrent profiles are hard-refused. To change these, edit `docker-compose.yml` and go through code review.
- No remote access or multi-user mode: a routable control plane inverts the trust model and requires its own threat-model review (new ADR).
- No enforced second-person approval for allowlist adds: the audit trail is there; a future gate requiring a second confirmation before widening egress is buildable from the audit record but is not in the current build.

---

## 6. File locations

All state files live under `~/.agentarca/`. Nothing under this directory should be committed or shared.

| File | Purpose | Mode |
|------|---------|------|
| `~/.agentarca/admin-secret` | Shared secret (generated by `build-admin.sh --init`) | 0600 |
| `~/.agentarca/session-key` | Session signing key (auto-generated at startup if absent) | 0600 |
| `~/.agentarca/fingerprint-salt` | Salt for credential fingerprinting (auto-generated) | 0600 |
| `~/.agentarca/admin-audit.jsonl` | Append-only audit log | 0600 (written by the console) |
| `~/.agentarca/lifecycle.lock` | Flock file for profile lifecycle mutual exclusion | created by the console |
| `.env` (repo root, next to `docker-compose.yml`) | Agent tokens for Compose interpolation | gitignored |
| `config/allowlist.local.d/overrides.conf` | Mutable egress overlay (gitignored) | written by `allowlist-local.sh` |

**Troubleshooting: console will not start**

- `FATAL: Refusing to bind to non-loopback address`: `AGENTARCA_ADMIN_HOST` is set to a non-loopback value, or the config file has `host =` set to something other than `127.0.0.1`. Fix or unset it.
- `No shared secret found`: `~/.agentarca/admin-secret` does not exist. Run `src/scripts/build-admin.sh --init`.
- `Secret file ... is empty`: the secret file exists but has no content. Delete it and re-run `--init`.
- `403 Forbidden: invalid Host header`: you are reaching the console from a context that sends a different `Host` header (a reverse proxy, a wrong port, or a DNS-rebinding attempt). Use `http://127.0.0.1:8770` or `http://localhost:8770` directly.

**Troubleshooting: lifecycle operations**

- `409 Conflict / mutual_exclusion`: a different profile is already running. Bring it down first with `POST /api/v1/profiles/<name>/down`, or use `POST /api/v1/profiles/switch`.
- `503 / lifecycle_lock_timeout`: another lifecycle operation (started via the API or the CLI) holds the flock. Wait a moment and retry.
- `503 / gateway_health_timeout`: `docker compose up` ran but the gateway did not report healthy within 120 seconds. The profile was torn down to avoid a broken state. Check `docker compose logs gateway-<profile>` for the cause.
