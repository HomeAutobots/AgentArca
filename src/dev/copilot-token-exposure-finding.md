# OI-10-A Finding: Copilot Token Exposure Analysis (R-c posture)

- Date: 2026-06-14
- Item: 10 (credential handling build)
- Status: R-c CONFIRMED. Contained by egress (ADR-002), NOT by unreadability.
- Escalation: NOT required. The finding confirms the ADR-003 D3/D7 accepted posture.

## Summary

The Copilot token is irreducibly agent-readable in-container. This is the accepted R-c
posture. The containment is the egress boundary (ADR-002), not file permissions or
environment filtering. This finding does NOT trigger escalation because it exactly
matches the ADR-003 D3/D7 expected outcome.

## Part 1: /proc same-uid token read (HEADLESS DEFAULT path)

**Empirically confirmed 2026-06-14 in the running container (UID 1000, headless default).**

A Python subprocess was started holding a dummy GH_TOKEN value in its environment.
The parent process (also UID 1000) read the subprocess environment via
/proc/[pid]/environ:

```
Started subprocess PID=154 holding dummy GH_TOKEN, running as UID=1000
Read from /proc/154/environ:
  GH_TOKEN = ghu_DUMMY_FAKE_TOKEN_ABCDEF1234567890_demonstration
FINDING: dummy token IS readable via /proc/[pid]/environ same-uid read.
R-c CONFIRMED: a prompt-injected agent can read tokens from sibling process env.
```

The /proc/[pid]/environ file for a process running as UID 1000 is readable by any
other process running as UID 1000 (mode -r--------). hidepid=2 does NOT help here:
it only prevents cross-UID reads. This is the same-UID Copilot case.

**Mechanism:** Any process the Copilot CLI (or the agent host process) spawns inherits
its environment including the token. The agent, running as UID 1000, can read
/proc/[parent-or-sibling-pid]/environ to extract the token. This is the Comment-and-
Control bypass mechanism (Area 3, ADR-003 D5).

## Part 2: Copilot CLI token storage path (HEADLESS DEFAULT path)

The @github/copilot CLI stores its authentication token at:
  - Primary (newer): ~/.config/github-copilot/hosts.json
  - Shape: {"github.com":{"oauth_token":"ghu_...", ...}}
  - Alternate (older): ~/.copilot/hosts.json or ~/.copilot/apps.json

Both paths are inside /home/devuser, which is the agent-home named volume.

Checked in the running container (2026-06-14):
- ~/.config/github-copilot/ does NOT exist (no copilot login run yet)
- ~/.copilot/ does NOT exist (no copilot login run yet)

These paths do not exist yet because no `copilot login` device flow has been run.
Once a user runs `copilot login` inside the container, the token file IS created at
one of these paths, and it IS readable by the agent (UID 1000 owns the files,
UID 1000 is the agent's UID). This is the expected ADR-003 D3 CLI path behavior.

**Mechanism:** The token file at ~/.config/github-copilot/hosts.json is owned by
UID 1000 (devuser) and has permissions 0600 (readable only by the owner). The
agent runs AS UID 1000 and therefore CAN read the file directly. No /proc trick
needed; direct file read suffices.

## Part 3: VS Code FALLBACK model (NOT EXECUTED HEADLESS - documented-not-executed)

**Status: DOCUMENTED-NOT-EXECUTED-HEADLESS. Rationale follows.**

Under the VS Code FALLBACK model (VS Code server attached to the container via
Dev Containers extension), the Copilot Chat extension uses a different token path:

- The GitHub Authentication extension runs as a host-side "ui"-kind extension in
  the LOCAL extension host (on the developer's machine, NOT inside the container).
- The OAuth token lives in host VS Code SecretStorage (Electron safeStorage/OSCrypt,
  encrypted per-platform in ~/.config/Code/User/globalStorage/state.vscdb).
- The token is brokered into the container over the VS Code Remote Development RPC
  protocol when the Chat extension needs it.
- Inside the container the token is present transiently in the extension-host Node.js
  process memory. No primary source confirms the Chat extension writes a cleartext
  token file inside the container.

ADR-003 D3 documents this as "flagged for empirical verification (item 10)" and
explicitly notes: "no primary source confirms the Chat extension writes the OAuth
token to a cleartext file inside the container."

**Why not executed headless:** The VS Code fallback model requires attaching a VS Code
desktop client to the container via the Dev Containers extension. This cannot be
simulated in a headless environment. Running `docker exec` or `docker compose up`
without VS Code does not create the VS Code RPC channel or extension host inside
the container.

**What the finding says about the VS Code path:**
If the fallback model is used, an empirical check would be:
  - printenv | grep -i copilot
  - printenv | grep -i github
  - cat /proc/$(pgrep -n node)/environ | tr '\0' '\n' | grep -i token
  - ls ~/.config/github-copilot/ (if the extension writes a local token file)
This check is documented for any future empirical run of the fallback model.

**Per ADR-003 D3 scoping correction:** The Comment-and-Control env dump of
GITHUB_COPILOT_API_TOKEN was from the GitHub Actions SWE agent (Copilot coding agent
in GitHub Actions), NOT from the interactive Copilot Chat extension in a local dev
container. The named env vars may differ for the local interactive setup. This has NOT
been proven for the local Chat extension path; it remains needs-empirical-verification
IF the fallback model is ever used.

## Conclusion

| Path | Token readable by agent? | Location | Containment |
|------|-------------------------|----------|-------------|
| CLI / headless (the default) | YES (confirmed) | ~/.config/github-copilot/hosts.json (file) OR parent process /proc/pid/environ | Egress boundary (ADR-002) |
| Chat extension / VS Code fallback | LIKELY YES (in memory, in parent-process env) | Host VS Code SecretStorage -> brokered over RPC -> extension-host Node.js process env | DOCUMENTED-NOT-EXECUTED-HEADLESS; containment is egress boundary |

**R-c confirmed:** the token is irreducibly agent-readable in the headless default.
The containment is the ADR-002 egress boundary, NOT unreadability. This is exactly
the ADR-003 D3/D7 accepted posture. Do NOT claim R-c solved.

## Canary placement implication (for item 13)

Per the BUILD_PLAN item 13 RC-3 note: item 13's canary-placement.sh must place
canaries in paths informed by this finding. Specifically:
  - ~/.config/github-copilot/hosts.json (once created by copilot login)
  - ~/.copilot/hosts.json (alternate path)
  - Any path where the CLI stores its token

The auditd `-w <path> -p r -k canary_read` watch should cover these paths so a
canary read (agent reads the token file) fires the detection sink alert.

## Escalation status

NO ESCALATION. The finding confirms R-c as documented (ADR-003 D7, residual-risk-
register). The token is agent-readable and contained by egress. This is the expected
outcome. A cleartext world-readable token file at a fixed path NOT previously
documented would be an escalation trigger; no such finding was made.

## References

- ADR-003 D3 (Copilot token minimization, CLI vs Chat extension paths)
- ADR-003 D5 (/proc/[pid]/environ parent-process read, hidepid=2 same-UID limitation)
- ADR-003 D7 (R-c: egress is the only containment)
- residual-risk-register.md R-c entry (MEDIUM/HIGH, accepted, never solved away)
- Area 3 (host-credential forwarding, headless model, /proc exfil, Copilot token location)
