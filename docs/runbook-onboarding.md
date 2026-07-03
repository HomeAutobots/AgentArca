# Runbook: Agent Onboarding, Readiness Gate, and Detection Toggle

This runbook covers the three portal onboarding flows (copilot, claude, codex),
the credential readiness gate, the N2 switch-to-un-onboarded behavior, and the
detection (observability pipeline) toggle.

For the specific codex device-auth limitation, see
`docs/runbook-codex-device-auth.md`.

---

## The credential readiness gate

Starting a profile without its required credential is blocked, not warned about.
The gate runs inside the lifecycle flock, before the startup nonce is minted and
before `docker compose up` is called:

- If the required key is absent from the managed `.env` store, the attempt
  returns HTTP 400 with `outcome: rejected-by-validation`.
- No nonce is minted. No compose call runs. No gateway starts.
- The attempt is written to the audit log at `~/.agentarca/admin-audit.jsonl`.

This applies to every start path: the lifecycle up endpoint, the onboarding
wizard's Start button, and the switch endpoint.

| Profile | Required credential | Keys checked |
|---------|---------------------|--------------|
| copilot | GitHub PAT | `COPILOT_GITHUB_TOKEN` |
| claude | OAuth token | `CLAUDE_CODE_OAUTH_TOKEN` |
| codex | API key | `CODEX_API_KEY` first, then `OPENAI_API_KEY`; either satisfies |

---

## Quick-check: is a profile ready?

```bash
curl -s http://127.0.0.1:8770/api/v1/onboarding/<profile>/status \
  -H "Cookie: agentarca_session=<session>"
```

Response:

```json
{
  "profile": "claude",
  "credential_present": false,
  "required_key": "CLAUDE_CODE_OAUTH_TOKEN",
  "ready_to_start": false
}
```

For codex, `required_key` is `"CODEX_API_KEY or OPENAI_API_KEY"` and
`credential_present` is true if either key is set.

---

## Session setup (required before any state-changing call)

All state-changing endpoints require a session cookie and a CSRF token.

```bash
curl -s -X POST http://127.0.0.1:8770/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"secret":"'"$(cat ~/.agentarca/admin-secret)"'"}'
# Returns: {"status":"ok","csrf_token":"<token>"}
# The response also sets the agentarca_session cookie.
```

Pass the cookie as `-H "Cookie: agentarca_session=<value>"` and the token as
`-H "X-CSRF-Token: <value>"` on every POST, PUT, DELETE, and PATCH.

---

## Flow 1: copilot

**Required credential:** `COPILOT_GITHUB_TOKEN`

1. Go to github.com, then Settings, then Developer settings, then Personal
   access tokens. Generate a token with the `copilot` scope. Copy the token.

2. Set it in the portal. Via the wizard at `/onboarding.html` (Copilot tab):
   paste and click Save token. Via curl:

   ```bash
   curl -s -X PUT http://127.0.0.1:8770/api/v1/credentials/COPILOT_GITHUB_TOKEN \
     -H "Cookie: agentarca_session=<session>" \
     -H "X-CSRF-Token: <csrf>" \
     -H "Content-Type: application/json" \
     -d '{"value":"ghp_..."}'
   ```

3. Confirm readiness:

   ```bash
   curl -s http://127.0.0.1:8770/api/v1/onboarding/copilot/status \
     -H "Cookie: agentarca_session=<session>"
   # Expect: "ready_to_start": true
   ```

4. Start the profile:

   ```bash
   curl -s -X POST http://127.0.0.1:8770/api/v1/profiles/copilot/up \
     -H "Cookie: agentarca_session=<session>" \
     -H "X-CSRF-Token: <csrf>"
   # 201 on first start, 200 if already up, 400 if credential absent
   ```

**What the portal does not do.** The portal does not call github.com to
generate or validate the token. It stores and checks it only.

**Allowlist invariant.** The copilot onboarding flow does not write to any
squid allowlist file. The egress allowlist is not widened by onboarding.

---

## Flow 2: claude

**Required credential:** `CLAUDE_CODE_OAUTH_TOKEN`

Claude requires an OAuth token that you must obtain by running a command in your
host terminal. The portal cannot run this command or open a browser on your
behalf. It shows instructions only.

1. In your host terminal (outside any container), run:

   ```bash
   claude setup-token
   ```

   The command opens a browser for OAuth authentication. When the flow
   completes, it prints `CLAUDE_CODE_OAUTH_TOKEN=<value>` to stdout. It does
   not save the token to any file automatically. The token is valid for one year.

2. Copy the value part of the output (the part after the `=` sign).

3. Set it in the portal. Via the wizard at `/onboarding.html` (Claude tab):
   paste only the value (not the `KEY=` prefix) and click Save token. Via curl:

   ```bash
   curl -s -X PUT http://127.0.0.1:8770/api/v1/credentials/CLAUDE_CODE_OAUTH_TOKEN \
     -H "Cookie: agentarca_session=<session>" \
     -H "X-CSRF-Token: <csrf>" \
     -H "Content-Type: application/json" \
     -d '{"value":"<token-value>"}'
   ```

4. Confirm readiness and start:

   ```bash
   curl -s http://127.0.0.1:8770/api/v1/onboarding/claude/status \
     -H "Cookie: agentarca_session=<session>"
   # Expect: "ready_to_start": true

   curl -s -X POST http://127.0.0.1:8770/api/v1/profiles/claude/up \
     -H "Cookie: agentarca_session=<session>" \
     -H "X-CSRF-Token: <csrf>"
   ```

**Token expiry.** If `claude setup-token` was run more than a year ago or the
token was revoked, the gateway will fail at runtime even though the portal gate
passes (the gate only checks presence, not validity). Repeat this flow to
refresh the token.

**Allowlist invariant.** The claude onboarding flow does not write to any squid
allowlist file.

---

## Flow 3: codex

**Required credential:** `CODEX_API_KEY` or `OPENAI_API_KEY` (either satisfies)

1. Obtain an API key from `platform.openai.com`.

2. Set it in the portal. Via the wizard at `/onboarding.html` (Codex tab):
   paste and click Save token (this sets `OPENAI_API_KEY`). To set
   `CODEX_API_KEY` instead, use the Credentials page or curl:

   ```bash
   curl -s -X PUT http://127.0.0.1:8770/api/v1/credentials/OPENAI_API_KEY \
     -H "Cookie: agentarca_session=<session>" \
     -H "X-CSRF-Token: <csrf>" \
     -H "Content-Type: application/json" \
     -d '{"value":"sk-..."}'
   ```

3. Confirm readiness and start:

   ```bash
   curl -s http://127.0.0.1:8770/api/v1/onboarding/codex/status \
     -H "Cookie: agentarca_session=<session>"
   # Expect: "ready_to_start": true

   curl -s -X POST http://127.0.0.1:8770/api/v1/profiles/codex/up \
     -H "Cookie: agentarca_session=<session>" \
     -H "X-CSRF-Token: <csrf>"
   ```

**Device-auth path.** If you use `codex login --device-auth`, the credential
in `~/.codex/auth.json` on the host is not checked by the portal gate. You must
also set `OPENAI_API_KEY` or `CODEX_API_KEY` in the portal store. See
`docs/runbook-codex-device-auth.md` for the full explanation and workaround.

**Allowlist invariant.** The codex onboarding flow does not write to any squid
allowlist file.

---

## N2: switching to an un-onboarded profile leaves nothing running

Read this before you switch profiles.

When you call `POST /api/v1/profiles/switch`, the portal:

1. Takes down the currently running profile and consumes its nonce.
2. Checks the credential gate for the target profile.
3. If the target credential is absent, returns 400 and stops.

The source profile is already down at this point. Result: nothing is running.

**To avoid this:** check the target profile's readiness before switching.

```bash
# Check first
curl -s http://127.0.0.1:8770/api/v1/onboarding/codex/status \
  -H "Cookie: agentarca_session=<session>"
# Only switch if ready_to_start is true

curl -s -X POST http://127.0.0.1:8770/api/v1/profiles/switch \
  -H "Cookie: agentarca_session=<session>" \
  -H "X-CSRF-Token: <csrf>" \
  -H "Content-Type: application/json" \
  -d '{"from":"claude","to":"codex"}'
```

**Recovery if you end up with nothing running.** Bring up any profile that
already has its credential set:

```bash
curl -s -X POST http://127.0.0.1:8770/api/v1/profiles/claude/up \
  -H "Cookie: agentarca_session=<session>" \
  -H "X-CSRF-Token: <csrf>"
```

This is not a boundary issue. It is an availability trade-off the interlock
makes to stay fail-closed. It is explicitly noted in the security review (N2).

---

## Detection toggle (observability pipeline)

The Settings page at `http://127.0.0.1:8770/settings.html` has one editable
control: the observability pipeline toggle.

**What the toggle does.** When enabled, the compose command includes the
detection overlay:

```
docker compose -f docker-compose.yml -f src/detect/docker-compose.detect.yml --profile <p> up -d
```

The overlay adds four services: immudb, ingest-proxy, otel-collector, jaeger.
It does not modify gateway services, devcontainer services, or any security
configuration. Gateway entrypoint nonce checks run regardless of whether the
overlay is present.

When disabled (default), the overlay is not included.

**This is not a security control.** Disabling the toggle turns off observability
data collection. It does not weaken egress controls, the startup interlock, or
any other security boundary. Egress controls are still enforced. Detection only
controls observability data collection.

The toggle takes effect on the next profile start. Toggling it while a profile
is running does not restart anything. Bring the profile down and back up to
apply the change to a running session.

**Via the API:**

```bash
# Read current config
curl -s http://127.0.0.1:8770/api/v1/portal-config \
  -H "Cookie: agentarca_session=<session>"
# {"detection_enabled": false}

# Enable detection
curl -s -X PATCH http://127.0.0.1:8770/api/v1/portal-config \
  -H "Cookie: agentarca_session=<session>" \
  -H "X-CSRF-Token: <csrf>" \
  -H "Content-Type: application/json" \
  -d '{"detection_enabled": true}'
# Returns: {"detection_enabled": true}

# Disable detection
curl -s -X PATCH http://127.0.0.1:8770/api/v1/portal-config \
  -H "Cookie: agentarca_session=<session>" \
  -H "X-CSRF-Token: <csrf>" \
  -H "Content-Type: application/json" \
  -d '{"detection_enabled": false}'
```

**Permitted keys.** The PATCH endpoint accepts only
`{"detection_enabled": <bool>}`. Any other key in the request body returns 400
and the file is not written. This includes any attempt to pass isolation knobs
like `net_admin_enabled`, `privileged`, or similar. Those are not configurable
through the portal.

**Config file.** `~/.agentarca/portal-config.json`, mode 0600. Operator-private.
Not bind-mounted into any container.

**Audit.** Every PATCH writes a `portal_config_patch` record to the audit log
with `outcome: applied` or `outcome: rejected-by-validation`.
