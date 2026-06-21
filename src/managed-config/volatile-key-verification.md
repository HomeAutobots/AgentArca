# OI-11-F: Volatile Key Re-Verification Table

- Date: 2026-06-14
- VS Code version context: 1.124 (released 2026-06-10)
- Verifier: implementer (item 11)
- Sources: code.visualstudio.com/docs/agents/approvals, code.visualstudio.com/docs/enterprise/ai-settings,
           code.visualstudio.com/docs/agent-customization/hooks, WebFetch 2026-06-14

All keys in `src/managed-config/settings.json` were re-verified. Results below.
Per CLAUDE.md convention: re-verify against current official docs + note date and version.

## Per-key verification table

| Key | Status | Confirmed value / notes | Source + date |
|-----|--------|------------------------|---------------|
| `chat.tools.global.autoApprove` | VERIFIED | Current name. Renamed from `chat.tools.autoApprove` in 1.104; no auto-migration. Set `false` at managed level. | microsoft/vscode #264223, #264753; 2026-06-14 |
| `chat.permissions.default` | VERIFIED | Values: `"default"` / `"bypass"` / `"autopilot"` (lowercase). VS Code 1.124 defaults to `"autopilot"` - this setting corrects that. | code.visualstudio.com/docs/agents/approvals; 2026-06-14 |
| `ChatToolsAutoApprove` (enterprise policy) | VERIFIED | Enterprise policy key. Set to `false`: (a) configures `chat.tools.global.autoApprove` at org level, (b) forces Default Approvals, (c) hides Bypass/Autopilot from picker entirely. V-03. | code.visualstudio.com/docs/enterprise/ai-settings; 2026-06-14 |
| `chat.tools.terminal.autoApproveWorkspaceNpmScripts` | VERIFIED | Experimental; defaults `true`. Set `false`. | VS Code settings search + community issues; 2026-06-14 |
| `task.allowAutomaticTasks` | VERIFIED | Values: `"off"` / `"on"` / `"auto"`. NOT off by default (issue #287073). Set `"off"` explicitly. | microsoft/vscode #287073; 2026-06-14 |
| `chat.agent.maxRequests` | VERIFIED (value volatile) | Setting exists. Current default ~25. We set 25. Re-confirm on exact pinned build. | microsoft/vscode #260814; 2026-06-14 |
| `chat.tools.terminal.autoApprove` | VERIFIED (shape) | Ruleset object (regex `/.../` or command-name -> true/false). `matchCommandLine` supported. Deny-wins. | code.visualstudio.com/docs/agents/approvals; 2026-06-14 |
| `chat.tools.edits.autoApprove` | VERIFIED (shape) | Glob -> boolean; deny-wins; `**/*: true` catch-all overridden by false entries. | code.visualstudio.com/docs/agents/approvals; 2026-06-14 |
| `chat.mcp.discovery.enabled` | UNVERIFIED | Key not found on the approvals page or agent-tools page on 2026-06-13 or 2026-06-14. Carried-from-research-pending-verification (V-18, ADR-005 verification table). Setting defensively to `false` per ADR-006 D7 posture. Item 11 attempted verification; key remains UNVERIFIED. | (not located 2026-06-14) |
| `matchCommandLine: true` + `approve: false` (deny entries) | VERIFIED | Bug #270641 affected `approve: true` + `matchCommandLine: true`. We only use `matchCommandLine: true` on `false` (deny) entries, so unaffected. Re-confirmed 2026-06-14. | microsoft/vscode #270641; 2026-06-14 |
| Hook stdin field names (`session_id`, `hook_event_name`, `tool_name`, `tool_input`) | VERIFIED (CHANGED from research) | Current VS Code docs use snake_case. Research carried camelCase (`sessionId`, `hookEventName`). ADR-007 verification table (2026-06-13) also confirmed snake_case change. Hook script uses defensive both-casings parser. | code.visualstudio.com/docs/agent-customization/hooks; ADR-007; 2026-06-14 |
| `hookSpecificOutput.permissionDecision` schema | VERIFIED | STRING (`"allow"/"deny"/"ask"`) nested under `hookSpecificOutput`. NOT an object. `permissionDecisionReason` is a sibling string field. See permissiondecision-shape-finding.md. | code.visualstudio.com/docs/agent-customization/hooks; 2026-06-14 |
| Hook discovery path (`.github/hooks/*.json`) | VERIFIED | Hook descriptor at `.github/hooks/pretooluse.json` with `{"hooks": {"PreToolUse": [{"type": "command", "command": "..."}]}}`. Type `command` is verified; type `http` is carried-pending-verification per ADR-007 OI-13-C. | code.visualstudio.com/docs/agent-customization/hooks; 2026-06-14 |
| Exit code 2 = hard block | CARRIED | Exit code 2 blocks; `continue: false` stops session. Not independently re-verified on 2026-06-14; carried from ADR-005. Item 18 must re-verify on each VS Code upgrade. | ADR-005 D4; 2026-06-13 |
| `chat.tools.terminal.ignoreDefaultAutoApproveRules` | VERIFIED (NOT set) | We do NOT set this true. Confirmed not present in managed settings. | code.visualstudio.com/docs/agents/approvals; 2026-06-14 |

## Managed settings file path (V-04, item 11 must verify)

The VS Code managed settings layer location for a Linux container is typically
`/etc/vscode/settings.json`. For the docker-based deployment, the correct approach is:

1. Mount `src/managed-config/settings.json` as a read-only bind at `/etc/vscode/settings.json`
   inside the container at container start time.
2. The read-only bind is both the immutability mechanism AND the managed-layer placement.

For VS Code enterprise GPO/MDM deployments, the platform-specific enterprise policy mechanism
deploys `ChatToolsAutoApprove=false` via the policy channel.

**V-04 status:** The exact managed settings file path (`/etc/vscode/settings.json`) is the
commonly cited path for Linux but has NOT been independently confirmed against the actual
pinned VS Code build by running VS Code inside the container. This must be confirmed by
item 18 (regression cadence) on the first actual live VS Code run.

## Regression note (item 18)

Every key in this table is volatile. Item 18 MUST re-verify on each VS Code/Copilot upgrade:
- The `ChatToolsAutoApprove` enterprise policy name may change.
- The `chat.permissions.default` value strings may change.
- The terminal auto-approve ruleset may add or remove built-in entries (issue #286001).
- `chat.mcp.discovery.enabled` may become an official key (check each release).
- The hook stdin field names may revert to camelCase or change further.
- The `permissionDecision` schema may change.
