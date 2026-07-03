# Runbook: Codex Credential Setup and the Device-Auth Limitation

This runbook covers what the portal gates for the codex profile in P1, why
`codex login --device-auth` is not a portal onboarding path and is not gated,
and the manual workaround for operators who use it.

---

## What the P1 readiness gate checks for codex

The portal credential readiness gate for the `codex` profile checks the managed
`.env` store (the repo-root `.env` file) for exactly two keys:

- `CODEX_API_KEY`
- `OPENAI_API_KEY`

Either key present satisfies the gate. The check runs in order: `CODEX_API_KEY`
first, then `OPENAI_API_KEY`. If neither is set, the profile will not start.

The gate runs inside the lifecycle flock, before any nonce is minted and before
`docker compose up` is called. A failed gate returns HTTP 400 with
`outcome: rejected-by-validation`. No gateway starts. The attempt is recorded
in the audit log at `~/.agentarca/admin-audit.jsonl`.

**Scope.** The gate reads only the managed `.env` store via `get_credential_status`
(credentials.py:526-565). It does not check any other file on disk.

---

## Why `codex login --device-auth` is not gated (and why that is intentional)

The `codex login --device-auth` command runs a device-code OAuth flow on the
host and writes credentials to `~/.codex/auth.json` (the CODEX_HOME path).
In P1, the portal does not detect, check, or use this credential. It is not a
portal onboarding path. Three compounding reasons make this the right choice.

**Reason 1: the container's `~/.codex` is a named volume, not the host path.**

The AgentArca sandbox redirects CODEX_HOME to a per-profile named Docker volume,
so the container's `~/.codex` is not the same directory as the host's `~/.codex`.
A credential written by `codex login` to the host's `~/.codex/auth.json` is not
automatically available inside the container. A gate that checks the host file
would pass while the container lacks the credential.

**Reason 2: the portal must not mount or read host `~/.codex`.**

This is named constraint R-c (do-not-mount discipline) from the residual-risk
register, enforced by ADR-003. The portal is a host process. Mounting or reading
host `~/.codex` would create a new path from the portal to agent credential
storage outside the portal's defined credential surface. The portal's credential
surface covers only the five keys in `MANAGED_CREDENTIAL_KEYS`.

**Reason 3: an ambiguous gate is worse than no gate.**

A check that passes on host file presence while the container actually lacks the
credential would cause the readiness gate to report "ready" when the profile
would fail at runtime. That is a harder failure mode to debug than a clear 400
rejection. An honest "not present" is better than a false "ready".

**This is an accepted, named limitation.** It is recorded in SPEC-29-P1 sec 5.4.
No egress control or gateway startup interlock is weakened by this deferral.

---

## Workaround for operators using device-auth

If you authenticate codex via `codex login --device-auth` and also want to
start the codex profile through the portal, set `OPENAI_API_KEY` or
`CODEX_API_KEY` in the managed `.env` store separately. Either key satisfies
the gate. The device-auth credential in `~/.codex/auth.json` can stay on the
host for direct CLI use; the API key in the portal store is only needed to let
the portal's readiness gate pass.

**Option A: via the portal wizard**

1. Open `http://127.0.0.1:8770/onboarding.html` in your browser.
2. Select the Codex tab.
3. Obtain an API key from `platform.openai.com`.
4. Paste it into the `OPENAI_API_KEY` field and click Save token.
5. The status badge turns Ready.

**Option B: via the credentials API**

```bash
# Log in first (if you have no active session)
curl -s -X POST http://127.0.0.1:8770/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"secret":"'"$(cat ~/.agentarca/admin-secret)"'"}'
# Response: {"status":"ok","csrf_token":"<token>"}
# Note the csrf_token value and the Set-Cookie header.

# Set the credential
curl -s -X PUT http://127.0.0.1:8770/api/v1/credentials/OPENAI_API_KEY \
  -H "Cookie: agentarca_session=<your-session-cookie>" \
  -H "X-CSRF-Token: <your-csrf-token>" \
  -H "Content-Type: application/json" \
  -d '{"value":"sk-..."}'
```

---

## Coverage summary

| Situation | Gate behavior |
|-----------|---------------|
| `OPENAI_API_KEY` set in portal `.env` store | Gate passes, profile can start |
| `CODEX_API_KEY` set in portal `.env` store | Gate passes, profile can start |
| Only `~/.codex/auth.json` on host (device-auth, no API key in store) | Gate fails, 400 returned, no profile starts |
| Neither key set, no device-auth file | Gate fails, 400 returned |

**Residual note.** If you have both a device-auth session on the host and an
API key in the portal store, the running container will use whichever credential
the Codex CLI inside the container resolves first (typically the `OPENAI_API_KEY`
environment variable injected at container start). This is standard Codex
behavior and not a portal concern.
