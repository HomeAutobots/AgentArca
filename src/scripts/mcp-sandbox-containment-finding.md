# MCP Sandbox Containment Finding (OI-12-E)

- Date: 2026-06-14
- Item: 12 (MCP posture build)
- Source: SPEC-06 section 7 (the three sandbox-auto-approve conditions), ADR-006 D6 Review note,
  plan/BUILD_PLAN.md OI-12-E, plan/validation/SPEC-06-validation.md section 2.

---

## Shipped Default: Interaction is LATENT

The shipped default is ZERO MCP servers (mcp.json servers object is `{}`). No sandboxed VS Code
stdio server exists in the shipped state. The sandbox-auto-approve interaction described in SPEC-06
section 7 is therefore NOT TRIGGERED by the shipped artifact. There is nothing to test.

This finding documents:
1. That the interaction is latent in the shipped state.
2. What must be proven before the VS Code stdio sandbox path may ever be enabled.
3. What was done to check, and what requires a VS Code runtime / live token to complete.

---

## The Three Conditions (ADR-006 D6 Review note; all MANDATORY before any sandboxed server may be added)

### Condition (a): PreToolUse hook MUST fire for sandboxed-server tool calls

FINDING: REQUIRES-VS-CODE-RUNTIME. CANNOT BE EMPIRICALLY CONFIRMED IN THIS HEADLESS ENVIRONMENT.

The headless production runtime is the `@github/copilot` CLI. The VS Code stdio sandbox
(`sandboxEnabled: true`) is a VS Code extension runtime feature. The sandbox does not exist
headlessly. Therefore:

- There is no sandboxed server in the shipped state (zero-server default).
- The VS Code extension runtime is not available in this headless CLI environment.
- Running a sandboxed server, triggering a tool call from it, and observing the hook log
  requires the VS Code extension host to be running.

CONDITIONAL GATE (from ADR-006 D6 and SPEC-06 section 7):
A sandboxed VS Code stdio server is NOT PERMITTED to be added to this deployment until
condition (a) is empirically confirmed: invoke a sandboxed server's tool call, check the
hook log at `$HOOK_LOG_SINK`, and verify the PreToolUse hook entry IS present for that call.
If the hook log shows NO entry for the sandboxed-server tool call, the VS Code sandbox path
is BLOCKED for this deployment until a VS Code release restores that behavior.

CLI alternative check (no-token lightweight): The `@github/copilot` CLI supports a
`mcp.json` configuration (via `~/.copilot/config.json` or equivalent). Configuring a trivial
local stdio server (e.g. `{"type":"stdio","command":"echo","args":["hello"]}`) in the CLI's
MCP config and observing whether the CLI's hook mechanism gates the server at registration
or at tool invocation would be a partial check. However:
- This does NOT test the VS Code sandbox's specific auto-approve interaction.
- This requires `@github/copilot` CLI to be present in the container (it is, per item 09).
- This DOES NOT require a live Copilot token for hook observation, only for actual agent use.

The lightweight CLI MCP registration check was NOT performed because:
1. The task instruction says do NOT trigger another Copilot device-flow/token.
2. Observing whether the hook fires for a CLI-registered MCP server at session start
   is a partial proxy for the VS Code sandbox condition, not the full test.
3. Fabricating a "hook fires" result would violate the honesty requirement.

RESULT: REQUIRES-VS-CODE-RUNTIME. Marked as a tracked test obligation for the first live
VS Code runtime session. The VS Code sandbox path is BLOCKED until confirmed.

### Condition (b): Egress scoped by BOTH in-sandbox network.allowedDomains AND ADR-002 gateway

FINDING: POLICY-VERIFIED, NOT EMPIRICALLY TESTED (no sandboxed server exists).

The ADR-002 egress gateway (item 08, SECURITY_REVIEWED) is the authoritative egress boundary
and is live. The design is correct:
- The `network.allowedDomains` in the `sandbox` object is a best-effort in-editor filter.
- The ADR-002 L3 default-DROP + L7 allowlist at the gateway sidecar is the authoritative boundary.
- Both would need to be present when a sandboxed server is added.

Since no sandboxed server exists in the shipped state, the dual-scoping test (RT-MCP-01(a))
is a RED-TEAM obligation for item 16, not a build-time test.

### Condition (c): Prefer Docker MCP Gateway for write-credential or private-data servers

FINDING: POLICY-ONLY (no server has been added to evaluate).

The policy is stated in SPEC-06 section 7 condition (c): if a server requires a write
credential or touches private/sensitive data, use the Docker MCP Gateway (not the VS Code
stdio sandbox). This is a gate criterion, not an empirical test. It applies to any future
server that clears the four-condition gate in SPEC-06 section 3.

---

## What a Valid Condition (a) Test Looks Like (procedure for when VS Code runtime is available)

When the VS Code extension host is available, perform this test BEFORE adding any sandboxed server:

1. Add a test-only sandboxed stdio server entry to a COPY of mcp.json (NOT the shipped default):
   ```json
   {
     "servers": {
       "sandbox-test": {
         "type": "stdio",
         "command": "/usr/local/bin/test-mcp-echo-server",
         "sandboxEnabled": true
       }
     }
   }
   ```

2. Start a VS Code session with this test config active (bypassing the `chattr +i` immutable
   bit on the mcp.json copy for this test only).

3. Trigger a tool call from `sandbox-test`.

4. Check the hook log: `grep -i "sandbox-test" $HOOK_LOG_SINK` or examine the raw log.

5. PASS: the hook log entry for the sandboxed-server tool call IS present. The PreToolUse hook
   ran BEFORE the tool call completed, with a non-empty session ID and tool name.

6. FAIL: the hook log shows NO entry for the sandboxed-server tool call. The VS Code sandbox
   path is BLOCKED. Escalate to ADR-006 D6 and the spec-writer before adding any sandboxed server.

After a PASS on condition (a), conditions (b) and (c) must also be confirmed (see above).

---

## PreToolUse Hook Behavior for MCP Tool Calls (CLI runtime, from docs)

From item 11's security review (plan/validation/item-11-security-review.md) and current
Copilot CLI documentation (2026-06-14):

The PreToolUse hook fires before every tool invocation in the `@github/copilot` CLI runtime.
SPEC-05 section 7 documents the `mcp.*` ASK pattern in the hook's ask-set, which gates
MCP server STARTS (not just tool calls from already-running servers). Item 11's hook script
(src/.github/hooks/pretooluse.sh line 469) returns `ask` on any tool name matching `mcp*`.

Whether the PreToolUse hook fires specifically for tool calls FROM a VS Code sandboxed server
(where the in-editor confirmation is auto-approved by the sandbox) is the unresolved question.
The hook's documented behavior is "fires before every tool invocation regardless of session
permission level" (SPEC-06 section 7 condition (a)). But this is the CLAIMED behavior; it is
not confirmed for the sandboxed-auto-approve path specifically.

IMPORTANT: "ask" in the CLI runtime is treated as "deny" in non-interactive (headless) mode
per item 11's security review note. This is fail-closed-safe. Even if the hook fires and
returns "ask", the CLI will block the tool call in non-interactive mode. An MCP server start
or MCP tool call in headless mode therefore requires explicit human approval.

---

## Summary

| Condition | Status | Notes |
|-----------|--------|-------|
| (a) PreToolUse hook fires for sandboxed calls | REQUIRES-VS-CODE-RUNTIME, UNTESTED | CONDITIONAL GATE: sandbox NOT permitted until confirmed |
| (b) Dual egress scoping (in-sandbox + ADR-002 gateway) | POLICY-VERIFIED, UNTESTED | Tested by RT-MCP-01(a) at item 16 |
| (c) Prefer gateway for write-cred/private-data servers | POLICY-ONLY | Applies to future gate decisions |
| Shipped default: interaction triggered? | NO (zero servers) | Latent; not activated in shipped state |

The VS Code stdio sandbox path is BLOCKED until condition (a) is empirically confirmed
on the pinned VS Code build. This is the ADR-006 D6 conditional gate.
