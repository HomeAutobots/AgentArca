# AgentArca

A hardened, multi-agent dev container that runs a coding agent (GitHub Copilot, Claude Code, or OpenAI Codex) locally and contains it behind a deterministic egress boundary. One agent is live per run, selected by a Docker Compose profile.

The design goal is blast-radius containment, not prevention. AgentArca assumes prompt injection will succeed and that the agent is a confused deputy that may be turned against you. It gives the agent maximum autonomy inside the box and puts the load-bearing controls at the wall.

> Meaningfully safer, never safe. Read "What this is and is not safe for" before you rely on it.

## The idea

- **Hard shell, soft interior.** Inside the container the agent runs with little friction. The controls that matter are deterministic and live at the boundary: a network egress allowlist, dropped Linux capabilities, an immutable config surface, and a fail-closed pre-tool hook.
- **The trust boundary is the egress boundary, not the container wall.** The firewall lives in a separate per-profile gateway sidecar. The dev container has no `NET_ADMIN`, so it cannot flush its own containment.
- **Organizing frame: the lethal trifecta + Meta's Rule of Two.** The agent should never have all three of {processes untrusted input, holds sensitive data/access, can communicate externally} live and unsupervised in one path. AgentArca severs the external-communication leg at the boundary.
- **Deterministic boundaries beat probabilistic ones.** Egress allowlists, dropped capabilities, immutable config, and the PreToolUse hook are load-bearing. The agent's own approval prompts are best-effort UX, not the boundary.

## Supported agents

| Profile | Agent | Credential (in repo-root `.env`) |
|---------|-------|----------------------------------|
| `copilot` | GitHub Copilot CLI | `COPILOT_GITHUB_TOKEN` |
| `claude` | Claude Code | `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` |
| `codex` | OpenAI Codex CLI | `OPENAI_API_KEY` or `CODEX_API_KEY` |

Codex also supports ChatGPT-subscription login (`codex login --device-auth`) instead of an API key; on that path no `.env` key is set and the token is minted into the container's token store.

Exactly one profile runs at a time. Profile mutual exclusion is a design invariant: no shared credential, session, or config volume across profiles. This is what keeps inter-agent threats out of scope.

## How it works

- **Per-profile egress gateway (Squid).** Each profile brings up its own gateway sidecar with a deny-by-default allowlist expressed by TLS SNI. It uses peek-and-splice: it observes the real SNI from the ClientHello and either splices the allowlisted connection through untouched or terminates it. There is no CA and no decryption. A separate L3 default-DROP firewall (owner-matched) forces all egress through the gateway, so an agent that ignores `HTTPS_PROXY` still cannot get out.
- **No `NET_ADMIN` in the dev container.** The dev container shares the gateway's network namespace (`network_mode: service:gateway-<agent>`) but holds zero network capabilities, so it cannot alter the firewall.
- **Hardened runc isolation.** `cap_drop: ALL`, `no-new-privileges`, a generated seccomp profile, read-only root filesystem, non-root UID 1000, named-volume workspace, no docker socket.
- **Per-profile credential injection.** Each agent's token comes only from the repo-root `.env` via single-key Compose interpolation, scoped to that profile's service. No `env_file` (it would import every key and bleed tokens across profiles). The token is readable by the agent by necessity; egress is the containment, never file permissions.
- **Immutable boundary config.** The agent's `settings.json` / `config.toml` / `.mcp.json` are mounted read-only (the agent gets EROFS on write), while its token store stays writable in the same directory.
- **Fail-closed PreToolUse hook.** A deterministic hook gates tool calls and defaults to deny/ask. It auto-approves only what it can positively classify as a safe non-boundary edit.
- **Zero MCP by default.** Each MCP server expands all three trifecta legs, so the default is none, in each agent's own schema, with a SHA-256 integrity check.
- **Pull-through caches.** Verdaccio (npm) and devpi (pip) fetch upstream through the gateway under a source-ACL, so the dev container never reaches a registry directly.
- **Detection backstop.** Capture sources feed an external write-only host-side sink. Detection is the last line, not the boundary.

## Quick start

Prerequisites: Docker (Compose v2). Primary target is macOS (Docker Desktop) or Linux. Some test scripts require bash 4+ (`brew install bash` on macOS).

1. Put the token for the agent you want in a **repo-root `.env`** (gitignored). For Claude on a subscription, mint a host token first so the container only ever talks to `api.anthropic.com`:

   ```bash
   # on your host, logged into Claude:
   claude setup-token        # prints sk-ant-oat...
   # then in ./.env :
   CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat...
   ```

   See `.env.example` for all three agents.

2. Bring up one profile:

   ```bash
   docker compose --profile claude up -d        # or: copilot, codex
   docker compose logs -f gateway-claude         # wait for "gateway healthy"
   ```

3. Use the agent inside the container:

   ```bash
   docker exec -it claude-devcontainer claude    # interactive (recommended)
   ```

   Headless note: in non-interactive `-p` mode the fail-closed hook returns "ask" for non-edit tools (which becomes a block, since there is no human to approve), so headless runs are limited to inference and non-boundary edits. Run the agent interactively to do real tool-using work.

## Verify the boundary

```bash
# no NET_ADMIN in the dev container
docker exec claude-devcontainer sh -c 'grep CapEff /proc/self/status'   # 0000000000000000

# blocked host is terminated, allowlisted host routes
docker exec claude-devcontainer sh -c 'curl --max-time 5 https://example.com'      # fails
docker exec claude-devcontainer sh -c 'curl -s -o /dev/null -w "%{http_code}\n" https://api.anthropic.com/v1/messages -X POST -d "{}"'   # 401 (routed)
```

## Allow extra sites while developing

The shipped allowlist (baked into the gateway image) is intentionally locked. To let the active agent reach an extra host while you work — a private registry, an internal API — add it to a **machine-local, gitignored** overlay and hot-apply it. No rebuild, no `docker compose` restart:

```bash
src/scripts/allowlist-local.sh add registry.internal.example.com   # validates, adds, reconfigures live
src/scripts/allowlist-local.sh list                                # show your local additions
src/scripts/allowlist-local.sh remove registry.internal.example.com
```

Your additions live in `config/allowlist.local.d/overrides.conf` (gitignored, so they never ship and never affect anyone else) and are bind-mounted **read-only** into the gateway. That read-only mount is the point: the agent shares the gateway's network namespace but cannot edit the file or reconfigure Squid, and it has no `docker.sock` — so widening egress is always an explicit operator action on the host, never something an injected agent can do.

Be honest with yourself about what each addition costs. AgentArca assumes the agent may be prompt-injected; every host you allow is a standing destination that an injected agent can try to exfiltrate to, and detection of that is weak (the gateway access log is in-container and not a tamper-proof record). Because these additions are local and uncommitted, **no one else reviews them** and they do not show up in any audit trail — the running egress posture can quietly differ from the shipped config. So: add the narrowest host that works (prefer an exact host over a `.example.com` subdomain wildcard), remove hosts when you are done with them, and prefer running unknown hosts through `src/scripts/discover-allowlist.sh` first to see what is actually needed. The ergonomic CLI does not make a wide allowlist safe. See `config/allowlist.local.d/overrides.conf.example` for the file format.

## Tests

Two suites form the regression harness. Re-run them on every upstream agent update, base-image bump, or allowlist change.

```bash
bash tests/acceptance/run-all.sh          # copilot config + boundary (acceptance)
bash tests/acceptance/run-profiles.sh     # per-profile (claude/codex) boundary
bash tests/containment/run-all.sh         # copilot containment (adversarial)
bash tests/containment/rt25-run-profiles.sh   # per-profile containment
```

Containment tests frame everything as "assume injection succeeds; prove the boundary holds." The boundary suites contain 100% of exfil/escape attempts across all three profiles.

Continuous integration runs static security and quality scans on every pull request (shellcheck, hadolint, Compose validation, gitleaks secret scan, Trivy, and the MCP supply-chain gates). The heavier Docker acceptance and containment suites above run on a nightly schedule.

## What this is and is not safe for

Honesty over false security. AgentArca reduces blast radius. It does not make a prompt-injected agent safe, and it does not solve prompt injection (which is unsolved).

**Reasonable for:** a coding agent working on code you do not fully trust to be free of injection, where you want to keep host credentials out and bound what can leave the box. The default hardened runc tier fits a prompt-injected agent running ordinary Node/Python with no production secrets in the container.

**Not appropriate as-is for:**

- Genuinely adversarial untrusted code (active kernel-exploit attempts) without escalating the isolation tier (gVisor, microVM/Kata, or a full VM). runc shares the host kernel.
- Real production secrets inside the container. Keep them out; the agent's own token is the one unavoidable secret and is contained by egress, not by being unreadable. Codex stores its token in plaintext.
- Running two agent profiles at once, or sharing a credential/session volume across profiles. That is out of scope by design.

**Accepted residual risks (named, not solved):**

- **Allowlisted-but-writable-destination exfil.** Anything the agent is allowed to write to (a git push, a telemetry endpoint, a first-party image proxy) is a potential exfil channel the network layer cannot close. This is the single hardest residual; the real control there is policy (human-gated writes), not the firewall.
- **The readable agent token.** The agent must hold its own credential and can read it. Egress is the only containment.
- **Tool-output injection.** Content the agent reads (issues, pages, command output) can carry instructions.
- **Kernel escape at the runc tier.** A kernel 0-day can cross the boundary; escalate the tier for adversarial workloads.
- **Malicious code committed now, run elsewhere later.** The container cannot stop the agent from writing harmful code that executes outside it.
- **Weaker interior gate under Codex.** Codex's pre-tool hook schema is under-documented, so its interior gate is best-effort; the L3 firewall remains the boundary.

## Status

- **Claude Code** is live-verified end to end (auth, inference, and an empirically locked `api.anthropic.com`-only allowlist).
- **Codex** is live-verified end to end on the ChatGPT-subscription path (auth via `codex login --device-auth`, inference, and an empirically locked allowlist). On that path inference routes through `chatgpt.com`, so the lock is `{chatgpt.com, auth.openai.com, api.openai.com}`; the narrow `api.openai.com`-only lock applies to the API-key path.
- **Copilot** is the original reference build: boundary-proven, with live VS Code runtime verification tracked as a documented obligation.

The egress boundary, isolation tier, and config immutability are proven for all three profiles by the credential-independent suites (108 containment attacks across the three profiles, 0 breaches).

## License

No license yet. Add one before sharing.
