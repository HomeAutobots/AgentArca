# OI-11-C: permissionDecision Shape Finding (RC-A UPDATED 2026-06-14)

- Date: 2026-06-14
- RC-A update: 2026-06-14 (security-reviewer required change applied)
- Verification sources:
  - code.visualstudio.com/docs/agent-customization/hooks (WebFetch 2026-06-14)
  - docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference (WebFetch 2026-06-14)
  - docs.github.com/en/copilot/tutorials/copilot-cli-hooks (WebFetch 2026-06-14)
  - docs.github.com/en/copilot/how-tos/copilot-sdk/hooks/pre-tool-use (WebFetch 2026-06-14)
- Item: 11 (approval config build)
- AC: AC-11-P03 (stdout invariant)
- Status: CONFIRMED (dual-runtime, RC-A applied)

## Summary (RC-A correction)

The hook is now DUAL-RUNTIME: it targets the @github/copilot CLI as the PRIMARY runtime
(ADR-003 D2 headless default) and VS Code as the FALLBACK runtime. The output format and
input field parsing both handle both runtimes correctly.

## CORRECTED: Discovery path (claim in prior version was WRONG)

PRIOR CLAIM (INCORRECT): the CLI discovers hooks from a different location than VS Code
(claimed "hooks.json" vs ".github/hooks/*.json").

CORRECTED FINDING (2026-06-14, re-verified against current docs):
Both the @github/copilot CLI AND VS Code Copilot discover hooks from
`.github/hooks/*.json` in the repository root. The discovery path does NOT diverge.

What DOES diverge is:
- Input field names (see below)
- Output format wrapper (see below)

The pretooluse.json hook descriptor is correct and needs no change for either runtime.

Source: docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference
(2026-06-14): "Repository-level hook files: .github/hooks/*.json in the repository root."

## Confirmed output schema: DUAL-FORMAT (RC-A, 2026-06-14)

The hook now emits ONE JSON object that both runtimes can read:

```json
{
  "permissionDecision": "allow|deny|ask",
  "permissionDecisionReason": "reason string",
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow|deny|ask",
    "permissionDecisionReason": "reason string"
  }
}
```

- The @github/copilot CLI reads `.permissionDecision` at the TOP LEVEL (flat fields).
- VS Code reads `.hookSpecificOutput.permissionDecision` (wrapper fields).
- Both return the same non-null string for every decision.
- `permissionDecisionReason` is present on every path (not just deny).
- `jq '.permissionDecision'` AND `jq '.hookSpecificOutput.permissionDecision'` both return
  the same non-null string for every hook output. The --self-test asserts this explicitly
  on every decision path (Section 3: dual-readable assertions).

Source for CLI flat format:
docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference (2026-06-14):
preToolUse decision control output: `{"permissionDecision": "allow|deny|ask", "permissionDecisionReason": "string"}`

Source for VS Code wrapper format:
code.visualstudio.com/docs/agent-customization/hooks (2026-06-14):
`{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow|deny|ask", ...}}`

## Confirmed input schemas: BOTH RUNTIMES

### VS Code runtime input (snake_case)

```json
{
  "session_id": "string",
  "hook_event_name": "PreToolUse",
  "tool_name": "string",
  "tool_input": { "command": "...", "path": "..." },
  "tool_use_id": "string",
  "timestamp": "ISO 8601 string",
  "cwd": "string"
}
```

Command extraction: `.tool_input.command`
Path extraction: `.tool_input.path`

### @github/copilot CLI input (camelCase)

```json
{
  "sessionId": "string",
  "toolName": "string",
  "toolArgs": { "command": "...", "path": "..." },
  "timestamp": 1718323200,
  "cwd": "string"
}
```

Command extraction: `.toolArgs.command`
Path extraction: `.toolArgs.path`

NOTE: `toolArgs` is typed as `unknown` in the CLI TypeScript schema. In some CLI versions
it may arrive as a nested object (standard form) or as a JSON-encoded string (double-encoded
form). The hook handles both via a defensive double-decode path.

### Hook tool name mapping (confirmed 2026-06-14)

| Category | VS Code tool names | CLI tool names |
|----------|--------------------|----------------|
| Terminal / shell | `run_in_terminal`, `terminal`, `shell` | `bash`, `powershell` |
| File edit / create | `str_replace_editor`, `edit_file`, `write_file` | `edit`, `create` |
| File read (no write path, treated as unknown->ask) | (various) | `view`, `glob`, `grep` |
| Other (treated as unknown->ask) | (various) | `web_fetch`, `ask_user`, `task` |

Source: docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference
(2026-06-14, tool names table).

## Fail-closed invariants (unchanged, confirmed RC-A preserves them)

- `allow`: ONLY for a recognized file-edit tool (VS Code: str_replace_editor/edit_file/write_file;
  CLI: edit/create) with a non-empty parseable path that does not match the boundary-config set.
- `ask`: recognized terminal tool whose command passes deny checks; OR unrecognized tool;
  OR recognized edit tool with empty/unparseable path; OR boundary-config path.
- `deny`: dangerous primitive matched; OR empty command; OR jq missing; OR malformed JSON;
  OR any crash/trap. permissionDecisionReason is ALWAYS present.

No new allow path was introduced by RC-A. The only allow path remains: recognized-edit-tool
+ non-empty parseable path + non-boundary path.

## Verification chain

1. WebFetch to `code.visualstudio.com/docs/agent-customization/hooks` (2026-06-14):
   - Input stdin: snake_case (`session_id`, `hook_event_name`, `tool_name`, `tool_input`)
   - Output stdout: hookSpecificOutput wrapper with string permissionDecision
   - Hook discovery: `.github/hooks/*.json`

2. WebFetch to `docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference` (2026-06-14):
   - Input stdin camelCase: `sessionId`, `toolName`, `toolArgs`
   - toolArgs.command = shell command string (bash tool)
   - toolArgs.path = file path (edit/create tools)
   - Output stdout: flat top-level `permissionDecision` + `permissionDecisionReason`
   - Hook discovery: `.github/hooks/*.json` (SAME as VS Code - no divergence)
   - "ask" on preToolUse is treated as "deny" by the CLI in non-interactive mode

3. --self-test (`pretooluse.sh --self-test`) confirmed 37/37 PASS (2026-06-14):
   - Section 1: all existing VS Code-format assertions pass (11 tests)
   - Section 2: all new CLI-format assertions pass (7 tests): git push -> ask
     (discriminated, not empty-command), sudo rm -rf / -> deny, base64 pipe -> deny,
     edit boundary -> ask, edit normal -> allow, create normal -> allow,
     edit missing path -> ask
   - Section 3: all dual-output-readable assertions pass (10 tests): for every
     decision path, both jq '.permissionDecision' and
     jq '.hookSpecificOutput.permissionDecision' return the same non-null string.

## AC-11-P03 status

PASS (RC-A applied). The hook emits exactly one JSON object per invocation with both
`.permissionDecision` (top-level, CLI) and `.hookSpecificOutput.permissionDecision`
(wrapper, VS Code) as STRING values matching the confirmed dual-runtime schema.
The `--self-test` asserts this on every invocation path including all CLI-format inputs.

## Item 13 handoff (RC-4, OI-11-B-confirmed-fields, updated for RC-A)

The confirmed field names for the live hook stdin (OI-11-B-confirmed-fields):

- VS Code primary form (snake_case, ADR-007, current docs): `session_id`, `hook_event_name`,
  `tool_name`, `tool_input`
- CLI primary form (camelCase, cli-hooks-reference, 2026-06-14): `sessionId`, `toolName`,
  `toolArgs`
- Defensive parser: `.session_id // .sessionId` for session id; `.tool_name // .toolName`
  for tool name; command from `.tool_input.command // .toolArgs.command`; path from
  `.tool_input.path // .toolArgs.path`.

Item 13 MUST consume `session_id` as the primary join key per OI-11-B-confirmed-fields.
The log line emitted by `pretooluse.sh log_attempt` uses `sessionId` as the JSON key in
the log output (historical compatibility with SPEC-07 log format), sourced from whichever
input field was non-empty.

Under the CLI runtime, `parsed_command` in the log line now contains the REAL command
string extracted from `toolArgs.command` (not empty as it was pre-RC-A). Item 13 D7
correlation log join and alert rules will see the actual command.

CLI `sessionId` field name for item 13: the log line key is `sessionId` (unchanged);
the value is extracted from `.session_id // .sessionId` in the hook's defensive parser,
so the log line's sessionId is correct under both runtimes.
