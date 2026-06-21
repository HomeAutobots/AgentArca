#!/usr/bin/env bash
# src/.github/hooks/pretooluse.sh
#
# PreToolUse hook for the @github/copilot CLI (production default, ADR-003 D2)
# and VS Code Copilot agent mode (fallback runtime).
# Source of truth: ADR-005 D4, SPEC-05 section 7.
#
# DUAL-RUNTIME OUTPUT (OI-11-C, RC-A, verified 2026-06-14):
#   The @github/copilot CLI reads permissionDecision at the TOP LEVEL (flat).
#   VS Code reads permissionDecision inside hookSpecificOutput wrapper.
#   We emit BOTH in the same JSON object so each runtime reads its own field
#   and ignores the extra fields:
#
#   stdout:
#   {
#     "permissionDecision": "allow|deny|ask",
#     "permissionDecisionReason": "...",
#     "hookSpecificOutput": {
#       "hookEventName": "PreToolUse",
#       "permissionDecision": "allow|deny|ask",
#       "permissionDecisionReason": "..."
#     }
#   }
#
#   CLI reads: .permissionDecision (top-level)
#   VS Code reads: .hookSpecificOutput.permissionDecision
#   Both return the same non-null string.
#   Source: docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference
#           code.visualstudio.com/docs/agent-customization/hooks (verified 2026-06-14)
#
# DUAL-RUNTIME INPUT (RC-A, verified 2026-06-14):
#   CLI sends: { toolName, toolArgs: {command|path|...}, sessionId, timestamp, cwd }
#   VS Code sends: { tool_name, tool_input: {command|path|...}, session_id, ... }
#
#   Confirmed CLI tool names (docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference):
#     Terminal/shell: "bash", "powershell"
#     File edit: "edit", "create"
#     File read: "view", "glob", "grep"
#     Other: "web_fetch", "ask_user", "task"
#
#   toolArgs field names (confirmed from multiple sources 2026-06-14):
#     bash tool: toolArgs.command (the shell command string)
#     edit/create tool: toolArgs.path (the file path)
#     NOTE: toolArgs may arrive as a nested object or a JSON-encoded string
#     depending on the CLI version; we handle both via double-decode below.
#
#   VS Code tool names (code.visualstudio.com/docs/agent-customization/hooks):
#     Terminal/shell: "run_in_terminal", "terminal", "shell"
#     File edit: "str_replace_editor", "edit_file", "write_file"
#
# FAIL-CLOSED INVARIANTS (every path resolves to one of these):
#   allow  - ONLY for recognized file-edit tool with non-empty path not matching boundary patterns.
#   ask    - recognized terminal tool with command that passes deny checks; OR unknown tool;
#            OR recognized edit tool with empty/unparseable path.
#   deny   - dangerous primitive detected; OR any hook error/crash/parse failure.
#
# STDOUT INVARIANT (D-8): emit EXACTLY ONE JSON object on stdout per invocation.
# All diagnostics go to stderr or the log sink. A stray stdout line corrupts the parser.
#
# EXIT CODES: 0 = decision returned in JSON; 2 = hard block.
# IMMUTABILITY: this file MUST be in a read-only mount (or chattr +i host-side) and
#   excluded from agent edits (**/.github/hooks/** deny glob in managed settings).
#   In-container chattr +i cannot run (cap_drop:ALL removes CAP_LINUX_IMMUTABLE; item 10).
#   Primary immutability: the deny-glob + managed-level config + read-only mount.

set -euo pipefail

# ============================================================
# DUAL-FORMAT OUTPUT HELPER
# Emits one JSON object readable by BOTH runtimes.
# CLI reads .permissionDecision (top-level).
# VS Code reads .hookSpecificOutput.permissionDecision.
# Both fields carry the same value.
# Usage: emit_decision "allow|deny|ask" "reason-string"
emit_decision() {
  local decision="$1"
  local reason="$2"
  printf '{"permissionDecision":"%s","permissionDecisionReason":"%s","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' \
    "$decision" "$reason" "$decision" "$reason"
}

# ============================================================
# BUILD SELF-TEST (V-21 and V-15 hard build gate, OI-11-A/B/C, RC-A)
# Invoke with: pretooluse.sh --self-test
# Runs synthetic stdin through the hook parser and asserts behavior.
# The build MUST run this and FAIL if any assertion fails.
# ============================================================
if [ "${1:-}" = "--self-test" ]; then
  SELF_TEST_FAILURES=0

  echo "[self-test] === pretooluse.sh --self-test START ===" >&2
  echo "[self-test] VS Code terminal tool names: run_in_terminal, terminal, shell" >&2
  echo "[self-test] VS Code edit tool names:     str_replace_editor, edit_file, write_file" >&2
  echo "[self-test] CLI terminal tool names:     bash, powershell" >&2
  echo "[self-test] CLI edit tool names:         edit, create" >&2
  echo "[self-test] CLI stdin command field:     .toolArgs.command (bash tool)" >&2
  echo "[self-test] CLI stdin path field:        .toolArgs.path (edit/create tool)" >&2
  echo "[self-test] VS Code stdin command field: .tool_input.command" >&2
  echo "[self-test] VS Code stdin path field:    .tool_input.path" >&2
  echo "[self-test] Output shape (RC-A dual-format):" >&2
  echo "[self-test]   top-level .permissionDecision (CLI reads this)" >&2
  echo "[self-test]   .hookSpecificOutput.permissionDecision (VS Code reads this)" >&2
  echo "[self-test]   both must be the same non-null string" >&2

  # Require jq for self-test
  if ! command -v jq &>/dev/null; then
    echo "[self-test] FAIL: jq not found; all parse tests skipped" >&2
    exit 1
  fi

  # _assert_decision: checks .hookSpecificOutput.permissionDecision (VS Code path)
  _assert_decision() {
    local label="$1"
    local stdin_json="$2"
    local expected_decision="$3"
    local actual_output
    actual_output=$(echo "$stdin_json" | "$0" 2>/dev/null)
    local actual_decision
    actual_decision=$(echo "$actual_output" | jq -r '.hookSpecificOutput.permissionDecision // "MISSING"' 2>/dev/null || echo "PARSE_ERROR")
    if [ "$actual_decision" = "$expected_decision" ]; then
      echo "[self-test] PASS: $label -> decision=$actual_decision" >&2
    else
      echo "[self-test] FAIL: $label -> expected=$expected_decision got=$actual_decision (raw: $actual_output)" >&2
      SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
    fi
  }

  # _assert_dual_readable: checks BOTH .permissionDecision (CLI) AND
  # .hookSpecificOutput.permissionDecision (VS Code) are the same non-null string.
  # This is the RC-A regression test: if CLI top-level is missing, hard-fail.
  _assert_dual_readable() {
    local label="$1"
    local stdin_json="$2"
    local actual_output
    actual_output=$(echo "$stdin_json" | "$0" 2>/dev/null)

    # CLI path: top-level .permissionDecision
    local cli_decision
    cli_decision=$(echo "$actual_output" | jq -r '.permissionDecision // "MISSING"' 2>/dev/null || echo "PARSE_ERROR")

    # VS Code path: .hookSpecificOutput.permissionDecision
    local vsc_decision
    vsc_decision=$(echo "$actual_output" | jq -r '.hookSpecificOutput.permissionDecision // "MISSING"' 2>/dev/null || echo "PARSE_ERROR")

    local failed=0
    if [ "$cli_decision" = "MISSING" ] || [ "$cli_decision" = "PARSE_ERROR" ] || [ "$cli_decision" = "null" ]; then
      echo "[self-test] FAIL: $label -> CLI top-level .permissionDecision is '$cli_decision' (MISSING - the RC-A regression)" >&2
      SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
      failed=1
    fi
    if [ "$vsc_decision" = "MISSING" ] || [ "$vsc_decision" = "PARSE_ERROR" ] || [ "$vsc_decision" = "null" ]; then
      echo "[self-test] FAIL: $label -> VS Code .hookSpecificOutput.permissionDecision is '$vsc_decision' (MISSING)" >&2
      SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
      failed=1
    fi
    if [ "$failed" -eq 0 ] && [ "$cli_decision" != "$vsc_decision" ]; then
      echo "[self-test] FAIL: $label -> CLI decision '$cli_decision' != VS Code decision '$vsc_decision' (mismatch)" >&2
      SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
      failed=1
    fi
    if [ "$failed" -eq 0 ]; then
      echo "[self-test] PASS: $label -> CLI='$cli_decision' VSCode='$vsc_decision' (both match, both non-null)" >&2
    fi
  }

  _assert_session_id_nonempty() {
    local label="$1"
    local stdin_json="$2"
    # Run hook and capture log line from the log sink
    local tmp_log
    tmp_log=$(mktemp /tmp/hook-selftest-XXXXXX.log)
    HOOK_LOG_SINK="$tmp_log" bash "$0" <<< "$stdin_json" >/dev/null 2>/dev/null || true
    # Read the last log line and check sessionId field
    local session_id_val
    session_id_val=$(tail -1 "$tmp_log" 2>/dev/null | jq -r '.sessionId // "unknown"' 2>/dev/null || echo "unknown")
    rm -f "$tmp_log"
    if [ "$session_id_val" = "unknown" ] || [ -z "$session_id_val" ]; then
      echo "[self-test] FAIL: $label -> session_id parsed as '$session_id_val' (expected non-empty, non-unknown)" >&2
      SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
    else
      echo "[self-test] PASS: $label -> session_id='$session_id_val' (non-empty, non-unknown)" >&2
    fi
  }

  _assert_stdout_shape() {
    local label="$1"
    local stdin_json="$2"
    local actual_output
    actual_output=$(echo "$stdin_json" | "$0" 2>/dev/null)
    # Assert: exactly one JSON object, has hookSpecificOutput.permissionDecision as a STRING
    # and top-level permissionDecision as a STRING (dual-format, RC-A)
    local line_count
    line_count=$(echo "$actual_output" | wc -l | tr -d ' ')
    local vsc_pd_type
    vsc_pd_type=$(echo "$actual_output" | jq -r '.hookSpecificOutput.permissionDecision | type' 2>/dev/null || echo "error")
    local cli_pd_type
    cli_pd_type=$(echo "$actual_output" | jq -r '.permissionDecision | type' 2>/dev/null || echo "error")
    if [ "$line_count" -eq 1 ] && [ "$vsc_pd_type" = "string" ] && [ "$cli_pd_type" = "string" ]; then
      echo "[self-test] PASS: $label -> stdout=1 line, VS Code pd type=$vsc_pd_type, CLI pd type=$cli_pd_type" >&2
    else
      echo "[self-test] FAIL: $label -> stdout=$line_count lines, VS Code pd type=$vsc_pd_type, CLI pd type=$cli_pd_type (expected 1 line, both string)" >&2
      SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
    fi
  }

  # ============================================================
  # SECTION 1: EXISTING VS CODE FORMAT ASSERTIONS (must keep passing)
  # ============================================================

  # --- OI-11-A: tool-name gate (V-21) ---
  echo "[self-test] --- OI-11-A: unknown tool returns ask ---" >&2
  _assert_decision "unknown-tool" \
    '{"session_id":"t1","hook_event_name":"PreToolUse","tool_name":"executeCommand","tool_input":{"command":"ls"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}' \
    "ask"

  # --- OI-11-B: snake_case session_id (primary form, from ADR-007 + VS Code docs) ---
  echo "[self-test] --- OI-11-B snake_case: session_id='test-snake-id' ---" >&2
  _assert_session_id_nonempty "snake_case-session_id" \
    '{"session_id":"test-snake-id","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"ls"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'

  # --- OI-11-B: camelCase sessionId (fallback form, defensive parser) ---
  echo "[self-test] --- OI-11-B camelCase: sessionId='test-camel-id' ---" >&2
  _assert_session_id_nonempty "camelCase-sessionId" \
    '{"sessionId":"test-camel-id","hookEventName":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"ls"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'

  # --- OI-11-C / RC-A: stdout shape (STRING in BOTH hookSpecificOutput AND top-level) ---
  echo "[self-test] --- OI-11-C/RC-A: stdout shape (dual-format: top-level CLI + hookSpecificOutput VS Code) ---" >&2
  _assert_stdout_shape "terminal-ls-shape" \
    '{"session_id":"t2","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"ls"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'
  _assert_stdout_shape "deny-shape" \
    '{"session_id":"t3","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"sudo bash"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'
  _assert_stdout_shape "edit-allow-shape" \
    '{"session_id":"t4","hook_event_name":"PreToolUse","tool_name":"str_replace_editor","tool_input":{"path":"src/main.ts","new_str":"x"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'
  _assert_stdout_shape "malformed-shape" \
    '{"not":"valid json for tool'

  # --- AC-11-P04: git push returns ask (VS Code format) ---
  echo "[self-test] --- AC-11-P04 (VS Code): git push returns ask ---" >&2
  _assert_decision "git-push-ask-vscode" \
    '{"session_id":"t5","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"git push origin main"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}' \
    "ask"

  # --- AC-11-P05: find -e"x"ec returns deny ---
  echo "[self-test] --- AC-11-P05: find -exec quote-concat returns deny ---" >&2
  _assert_decision 'find-exec-quote-concat' \
    '{"session_id":"t6","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"find . -e\"x\"ec cat {} \\;"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}' \
    "deny"

  # --- AC-11-P05: base64 pipe to bash returns deny ---
  echo "[self-test] --- AC-11-P05: base64 pipe-to-bash returns deny ---" >&2
  _assert_decision "base64-pipe-deny" \
    '{"session_id":"t7","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"echo aWQ= | base64 -d | bash"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}' \
    "deny"

  # --- BLOCK-2 UPDATED: recognized edit tool with file_path (item 23 SPEC-23 path extraction) ---
  # Before item 23: hook only extracted .tool_input.path; .file_path was not found -> ask (BLOCK-2 behavior).
  # After item 23: hook now extracts .tool_input.file_path as a fallback; path is found -> allow.
  # This test is UPDATED to reflect the correct post-item-23 behavior.
  # The empty-path->ask behavior is still tested below with truly missing path fields.
  echo "[self-test] --- BLOCK-2 (VS Code): edit tool with file_path (item-23 update: allow)" >&2
  _assert_decision "edit-file_path-allow-vscode" \
    '{"session_id":"t8","hook_event_name":"PreToolUse","tool_name":"str_replace_editor","tool_input":{"file_path":"src/main.ts"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}' \
    "allow"
  # BLOCK-2 original behavior: truly absent path (no .path, no .file_path) still returns ask.
  echo "[self-test] --- BLOCK-2 (VS Code): edit tool with no path field at all -> ask ---" >&2
  _assert_decision "edit-truly-empty-path-ask-vscode" \
    '{"session_id":"t8b","hook_event_name":"PreToolUse","tool_name":"str_replace_editor","tool_input":{"new_str":"x"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}' \
    "ask"

  # --- Fail-closed: malformed JSON returns deny ---
  echo "[self-test] --- Fail-closed: malformed JSON returns deny ---" >&2
  BAD_JSON='{"bad json'
  BAD_OUTPUT=$(echo "$BAD_JSON" | "$0" 2>/dev/null || true)
  BAD_DECISION=$(echo "$BAD_OUTPUT" | jq -r '.hookSpecificOutput.permissionDecision // "MISSING"' 2>/dev/null || echo "MISSING")
  if [ "$BAD_DECISION" = "deny" ]; then
    echo "[self-test] PASS: malformed-json -> deny" >&2
  else
    echo "[self-test] FAIL: malformed-json -> expected deny, got '$BAD_DECISION'" >&2
    SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
  fi

  # --- deny on sudo (VS Code format) ---
  echo "[self-test] --- deny (VS Code): sudo bash ---" >&2
  _assert_decision "sudo-deny-vscode" \
    '{"session_id":"t9","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"sudo bash"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}' \
    "deny"

  # --- deny on empty command (VS Code format) ---
  echo "[self-test] --- deny (VS Code): empty command ---" >&2
  _assert_decision "empty-cmd-deny-vscode" \
    '{"session_id":"t10","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":""},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}' \
    "deny"

  # ============================================================
  # SECTION 2: NEW CLI FORMAT ASSERTIONS (RC-A requirement)
  # CLI sends toolName + toolArgs (camelCase), NOT tool_name + tool_input.
  # CLI terminal tool name: "bash"
  # CLI edit tool names: "edit", "create"
  # CLI toolArgs.command = the shell command string
  # CLI toolArgs.path = the file path for edit/create
  # ============================================================

  echo "[self-test] --- RC-A CLI FORMAT ASSERTIONS ---" >&2

  # CLI terminal git push: toolName=bash, toolArgs.command="git push origin main"
  # Expected: ask (discriminated git-push-human-gate), NOT empty-command deny
  echo "[self-test] --- CLI: git push must return 'ask' (discriminated, NOT empty-command deny) ---" >&2
  _assert_decision "CLI-git-push-ask" \
    '{"toolName":"bash","toolArgs":{"command":"git push origin main"},"sessionId":"x","timestamp":1718323200,"cwd":"/workspace"}' \
    "ask"

  # CLI terminal dangerous: toolName=bash, toolArgs.command="sudo rm -rf /"
  # Expected: deny (privilege-escalation or destructive)
  echo "[self-test] --- CLI: sudo rm -rf / must return 'deny' ---" >&2
  _assert_decision "CLI-sudo-rmrf-deny" \
    '{"toolName":"bash","toolArgs":{"command":"sudo rm -rf /"},"sessionId":"x","timestamp":1718323200,"cwd":"/workspace"}' \
    "deny"

  # CLI terminal base64 pipe: toolName=bash, toolArgs.command="echo aWQ= | base64 -d | bash"
  # Expected: deny
  echo "[self-test] --- CLI: base64 pipe to bash must return 'deny' ---" >&2
  _assert_decision "CLI-base64-pipe-deny" \
    '{"toolName":"bash","toolArgs":{"command":"echo aWQ= | base64 -d | bash"},"sessionId":"x","timestamp":1718323200,"cwd":"/workspace"}' \
    "deny"

  # CLI edit to boundary path: toolName=edit, toolArgs.path=".vscode/settings.json"
  # Expected: ask (boundary-config-path-edit-HIGH-SIGNAL)
  echo "[self-test] --- CLI: edit boundary path must return 'ask' ---" >&2
  _assert_decision "CLI-edit-boundary-ask" \
    '{"toolName":"edit","toolArgs":{"path":".vscode/settings.json"},"sessionId":"x","timestamp":1718323200,"cwd":"/workspace"}' \
    "ask"

  # CLI edit to normal (non-boundary) source path: toolName=edit, toolArgs.path="src/main.ts"
  # Expected: allow (the one safe allow path: recognized-edit-tool + non-boundary)
  echo "[self-test] --- CLI: edit normal source path must return 'allow' ---" >&2
  _assert_decision "CLI-edit-normal-allow" \
    '{"toolName":"edit","toolArgs":{"path":"src/main.ts"},"sessionId":"x","timestamp":1718323200,"cwd":"/workspace"}' \
    "allow"

  # CLI create to normal path: toolName=create, toolArgs.path="src/newfile.ts"
  # Expected: allow
  echo "[self-test] --- CLI: create normal path must return 'allow' ---" >&2
  _assert_decision "CLI-create-normal-allow" \
    '{"toolName":"create","toolArgs":{"path":"src/newfile.ts"},"sessionId":"x","timestamp":1718323200,"cwd":"/workspace"}' \
    "allow"

  # CLI edit with empty/missing path: toolName=edit, toolArgs={} (no path field)
  # Expected: ask (edit-path-unparseable-fail-closed-HIGH-SIGNAL)
  echo "[self-test] --- CLI: edit with missing path must return 'ask' ---" >&2
  _assert_decision "CLI-edit-missing-path-ask" \
    '{"toolName":"edit","toolArgs":{},"sessionId":"x","timestamp":1718323200,"cwd":"/workspace"}' \
    "ask"

  # ============================================================
  # SECTION 3: DUAL-OUTPUT READABLE BY BOTH RUNTIMES (RC-A requirement)
  # For every decision, assert BOTH .permissionDecision (top-level, CLI)
  # AND .hookSpecificOutput.permissionDecision (VS Code wrapper) are
  # the same non-null string. Hard-fail if the CLI top-level field is missing.
  # ============================================================

  echo "[self-test] --- RC-A DUAL-OUTPUT READABLE ASSERTIONS ---" >&2
  echo "[self-test] (Checks that CLI top-level .permissionDecision is present on every path)" >&2

  _assert_dual_readable "dual-vscode-terminal-ls" \
    '{"session_id":"dr1","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"ls"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'

  _assert_dual_readable "dual-vscode-sudo-deny" \
    '{"session_id":"dr2","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"sudo bash"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'

  _assert_dual_readable "dual-vscode-git-push-ask" \
    '{"session_id":"dr3","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"git push origin main"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'

  _assert_dual_readable "dual-vscode-edit-allow" \
    '{"session_id":"dr4","hook_event_name":"PreToolUse","tool_name":"str_replace_editor","tool_input":{"path":"src/main.ts"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'

  _assert_dual_readable "dual-vscode-boundary-ask" \
    '{"session_id":"dr5","hook_event_name":"PreToolUse","tool_name":"str_replace_editor","tool_input":{"path":".vscode/settings.json"},"timestamp":"2026-06-14T00:00:00Z","cwd":"/workspace"}'

  _assert_dual_readable "dual-cli-bash-git-push" \
    '{"toolName":"bash","toolArgs":{"command":"git push origin main"},"sessionId":"dr6","timestamp":1718323200,"cwd":"/workspace"}'

  _assert_dual_readable "dual-cli-bash-sudo-deny" \
    '{"toolName":"bash","toolArgs":{"command":"sudo rm -rf /"},"sessionId":"dr7","timestamp":1718323200,"cwd":"/workspace"}'

  _assert_dual_readable "dual-cli-edit-allow" \
    '{"toolName":"edit","toolArgs":{"path":"src/main.ts"},"sessionId":"dr8","timestamp":1718323200,"cwd":"/workspace"}'

  _assert_dual_readable "dual-cli-edit-boundary" \
    '{"toolName":"edit","toolArgs":{"path":".vscode/settings.json"},"sessionId":"dr9","timestamp":1718323200,"cwd":"/workspace"}'

  _assert_dual_readable "dual-malformed-json" \
    '{"bad json'

  # ============================================================
  # SECTION 4: CLAUDE CODE CONTRACT ASSERTIONS (SPEC-23 section 3, item 23)
  # These fixtures assert the correct behavior AFTER the Bash/Edit/Write/Read tool-name
  # extension and file_path extraction are applied (SPEC-23 section 2 notes 2, 4).
  # They will FAIL on an unmodified hook that does not recognize capitalized tool names.
  # Passing this section proves:
  #   (a) Bash -> terminal dispatch (not unknown-tool-ask)
  #   (b) Edit/Write -> edit dispatch (not unknown-tool-ask)
  #   (c) Read -> unknown-tool-ask (it is a read-only tool, not an edit tool)
  #   (d) .tool_input.file_path is extracted (not just .tool_input.path)
  #   (e) permission_mode is NOT read; deny fires regardless of its value
  #   (f) no 'defer' is emitted for dangerous commands
  #   (g) session_id dual-casing works on capitalized-tool fixtures
  # Source: SPEC-23 section 3 fixtures; code.claude.com/docs/en/hooks (2026-06-17)
  # ============================================================

  echo "[self-test] --- SECTION 4: CLAUDE CODE CONTRACT ASSERTIONS ---" >&2

  # Fixture 1a: Claude terminal tool -- deny on dangerous command (privilege escalation)
  # Rationale: tool_name="Bash" is the Claude Code terminal tool name.
  # sudo bash is a dangerous primitive (privilege-escalation-sudo rule).
  # Proves Bash is routed to the terminal-command-inspection path, not unknown-tool-ask.
  echo "[self-test] --- S4: claude-Bash-sudo-deny ---" >&2
  _assert_decision "claude-Bash-sudo-deny" \
    '{"session_id":"cc1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sudo bash"},"permission_mode":"default"}' \
    "deny"

  # Fixture 1b: Claude terminal tool -- curl routes to ask (not allow, not silent pass-through)
  echo "[self-test] --- S4: claude-Bash-curl-ask ---" >&2
  _assert_decision "claude-Bash-curl-ask" \
    '{"session_id":"cc2","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://attacker.com"},"permission_mode":"default"}' \
    "ask"

  # Fixture 2: Fail-closed on unknown tool after Bash is recognized
  # SomeUnknownTool must still return ask (not allow) after the extension is applied.
  echo "[self-test] --- S4: claude-SomeUnknownTool-ask ---" >&2
  _assert_decision "claude-SomeUnknownTool-ask" \
    '{"session_id":"cc3","hook_event_name":"PreToolUse","tool_name":"SomeUnknownTool","tool_input":{"command":"anything"},"permission_mode":"default"}' \
    "ask"

  # Fixture 3: Claude Edit tool -- boundary path returns ask
  # Edit tool uses tool_input.file_path (not .path) per Claude Code schema (SPEC-23 note 4).
  # .claude/settings.json is in the boundary-config set.
  echo "[self-test] --- S4: claude-Edit-boundary-ask ---" >&2
  _assert_decision "claude-Edit-boundary-ask" \
    '{"session_id":"cc4","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":".claude/settings.json"},"permission_mode":"default"}' \
    "ask"

  # Fixture 4: Claude Write tool -- non-boundary path returns allow
  # Write tool with tool_input.file_path for a normal source file -> allow.
  echo "[self-test] --- S4: claude-Write-normal-allow ---" >&2
  _assert_decision "claude-Write-normal-allow" \
    '{"session_id":"cc5","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"src/main.ts"},"permission_mode":"default"}' \
    "allow"

  # Fixture 5: Claude Read tool -- returns ask (it is a read-only tool, not an edit tool)
  # Read is NOT in the edit-tool set. It hits the unknown-tool->ask path.
  # This is correct fail-closed behavior for unclassified tools.
  echo "[self-test] --- S4: claude-Read-ask ---" >&2
  _assert_decision "claude-Read-ask" \
    '{"session_id":"cc6","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"src/main.ts"},"permission_mode":"default"}' \
    "ask"

  # Fixture 6: permission_mode fixtures -- deny is independent of permission_mode value.
  # The hook does NOT read permission_mode at all. These prove deny fires regardless.
  # All three dangerous-mode values must produce the same deny as "default".
  echo "[self-test] --- S4: claude-Bash-bypassPermissions-deny ---" >&2
  _assert_decision "claude-Bash-bypassPermissions-deny" \
    '{"session_id":"cc7","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sudo bash"},"permission_mode":"bypassPermissions"}' \
    "deny"
  echo "[self-test] --- S4: claude-Bash-dontAsk-deny ---" >&2
  _assert_decision "claude-Bash-dontAsk-deny" \
    '{"session_id":"cc8","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sudo bash"},"permission_mode":"dontAsk"}' \
    "deny"
  echo "[self-test] --- S4: claude-Bash-auto-deny ---" >&2
  _assert_decision "claude-Bash-auto-deny" \
    '{"session_id":"cc9","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sudo bash"},"permission_mode":"auto"}' \
    "deny"

  # Fixture 7: No-defer contract -- dangerous fixture never returns defer.
  # The hook returns allow/ask/deny only; 'defer' must never appear for dangerous commands.
  # The _assert_decision check above for bypassPermissions already covers this (if "defer" were
  # returned, expected="deny" != actual="defer" -> FAIL). Belt-and-suspenders explicit check:
  echo "[self-test] --- S4: claude-no-defer (explicit string-equality check) ---" >&2
  CC_DEFER_CHECK=$(echo '{"session_id":"cc10","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sudo bash"},"permission_mode":"bypassPermissions"}' | "$0" 2>/dev/null)
  CC_DEFER_DECISION=$(echo "$CC_DEFER_CHECK" | jq -r '.hookSpecificOutput.permissionDecision // "MISSING"' 2>/dev/null || echo "PARSE_ERROR")
  if [ "$CC_DEFER_DECISION" = "defer" ]; then
    echo "[self-test] FAIL: claude-no-defer -> hook returned 'defer' for dangerous command (NEVER allowed per SPEC-23 section 3 fixture 7)" >&2
    SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
  else
    echo "[self-test] PASS: claude-no-defer -> decision='$CC_DEFER_DECISION' (not defer)" >&2
  fi

  # Fixture 8: session_id dual-casing on a capitalized-tool fixture.
  # Verifies the dual-casing parser still works after the tool-name extension.
  echo "[self-test] --- S4: claude-Bash-snake-session_id ---" >&2
  _assert_session_id_nonempty "claude-Bash-snake-session_id" \
    '{"session_id":"test-claude-snake","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm test"},"permission_mode":"default"}'
  echo "[self-test] --- S4: claude-Bash-camel-sessionId ---" >&2
  _assert_session_id_nonempty "claude-Bash-camel-sessionId" \
    '{"sessionId":"test-claude-camel","hookEventName":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm test"},"permission_mode":"default"}'

  # Bonus: verify .tool_input.file_path extraction directly (Edit tool with file_path, non-boundary)
  echo "[self-test] --- S4: claude-Edit-file_path-extraction-allow ---" >&2
  _assert_decision "claude-Edit-file_path-extraction-allow" \
    '{"session_id":"cc11","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"src/components/Button.tsx"},"permission_mode":"default"}' \
    "allow"

  # Bonus: Copilot VS Code hook regression -- verify Section 1 Copilot paths still work
  # (existing run_in_terminal and str_replace_editor tool names must not be broken by the extension)
  echo "[self-test] --- S4 regression: Copilot VS Code paths unchanged ---" >&2
  _assert_decision "regression-vscode-terminal-sudo-deny" \
    '{"session_id":"rr1","hook_event_name":"PreToolUse","tool_name":"run_in_terminal","tool_input":{"command":"sudo bash"},"permission_mode":"default"}' \
    "deny"
  _assert_decision "regression-vscode-edit-allow" \
    '{"session_id":"rr2","hook_event_name":"PreToolUse","tool_name":"str_replace_editor","tool_input":{"path":"src/main.ts"},"permission_mode":"default"}' \
    "allow"
  _assert_decision "regression-vscode-boundary-ask" \
    '{"session_id":"rr3","hook_event_name":"PreToolUse","tool_name":"str_replace_editor","tool_input":{"path":".vscode/settings.json"},"permission_mode":"default"}' \
    "ask"

  echo "[self-test] --- SECTION 4 COMPLETE ---" >&2

  echo "[self-test] === pretooluse.sh --self-test END: failures=$SELF_TEST_FAILURES ===" >&2
  if [ "$SELF_TEST_FAILURES" -gt 0 ]; then
    echo "[self-test] BUILD GATE FAILED: $SELF_TEST_FAILURES assertion(s) failed." >&2
    exit 1
  fi
  echo "[self-test] BUILD GATE PASSED." >&2
  exit 0
fi

# ============================================================
# DETECTION SINK (external, item 13)
# Log BEFORE making the decision; logging failure does not fail-open the decision.
# Item 13 sets the actual LOG_SINK path/URL to the external sink.
LOG_SINK="${HOOK_LOG_SINK:-/var/log/copilot-hook/decisions.log}"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

log_attempt() {
  local decision="$1"
  local tool_name_arg="$2"
  local parsed_cmd="$3"
  local session_id_arg="$4"
  local log_line
  # log_attempt writes ONLY to the log sink (not stdout). D-8 invariant: no stdout output here.
  # If printf -v log_line fails, log_attempt exits non-zero, set -e trips, trap fires with deny.
  # This is intentional fail-closed behavior (D-7 note).
  # || true guards ONLY on I/O side effects (mkdir, printf >>, curl), NOT on log_line construction.
  #
  # ITEM 13 ENRICHED LOG LINE (SPEC-07 section 2a):
  # Emits the SPEC-07 enriched format with source, hook_event_name, tool_use_id, reason fields.
  # SESSION_ID FIELD AUTHORITY (OI-11-B-confirmed-fields, item 13 RC-4):
  #   Log key: "sessionId" (camelCase, historical compatibility with SPEC-07 log format).
  #   Value sourced from: .session_id // .sessionId (defensive dual-casing parser).
  #   Do NOT re-derive the casing; this traces to OI-11-B-confirmed-fields artifact.
  log_line=$(printf '{"source":"pretooluse_hook","timestamp":"%s","sessionId":"%s","hook_event_name":"PreToolUse","tool_name":"%s","tool_use_id":"%s","parsed_command":"%s","decision":"%s","reason":"%s"}\n' \
    "$TIMESTAMP" "$session_id_arg" "$tool_name_arg" "${TOOL_USE_ID:-unknown}" "$parsed_cmd" "$decision" "${REASON:-unknown}")
  # ITEM 13: HTTP sink support (AC-13-N06, SPEC-07 section 2a forward mechanism).
  # If HOOK_LOG_SINK is an HTTP URL, POST the log line via curl (command-type forwarder).
  # OI-13-C: command-type is the verified mechanism (http-type not confirmed in docs as of 2026-06-14).
  # Logging failure MUST NOT fail-open the decision: curl uses || true.
  if [[ "${LOG_SINK:-}" == http://* ]] || [[ "${LOG_SINK:-}" == https://* ]]; then
    curl -sf -X POST "${LOG_SINK}" \
      -H "Content-Type: application/json" \
      -d "${log_line}" \
      --max-time 5 \
      >/dev/null 2>&1 || true
    # Also write to local fallback (defense-in-depth forensics; not the trustworthy sink).
    local local_fallback="/tmp/copilot-hook/decisions.log"
    mkdir -p "$(dirname "$local_fallback")" 2>/dev/null || true
    printf '%s\n' "$log_line" >> "$local_fallback" 2>/dev/null || true
  else
    # Local file sink (item 11 default / fallback path).
    mkdir -p "$(dirname "$LOG_SINK")" 2>/dev/null || true
    printf '%s\n' "$log_line" >> "$LOG_SINK" 2>/dev/null || true
  fi
}

# ============================================================
# DEFAULT DECISION: deny (fail-closed)
DECISION="deny"
REASON="default-deny-fail-closed"

# ============================================================
# CLEANUP / FAIL-CLOSED TRAP
# If the script exits unexpectedly (non-zero), output deny on stdout (exactly one JSON object)
# and exit 0 so the runtime reads the decision rather than getting an unhandled crash.
# Uses dual-format so both CLI and VS Code receive the deny.
cleanup() {
  local exit_code=$?
  if [ "$exit_code" -ne 0 ]; then
    # D-8: exactly one JSON object on stdout. RC-A dual-format: top-level for CLI, wrapper for VS Code.
    printf '{"permissionDecision":"deny","permissionDecisionReason":"hook-error-fail-closed","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"hook-error-fail-closed"}}\n'
    exit 0
  fi
}
trap cleanup EXIT

# ============================================================
# READ STDIN (the tool call JSON)
INPUT=$(cat)

# Parse tool_name and session_id from the JSON.
# jq is required; if missing, fail closed.
if ! command -v jq &>/dev/null; then
  REASON="jq-missing-fail-closed"
  log_attempt "deny" "unknown" "jq-missing" "unknown"
  emit_decision "deny" "$REASON"
  exit 0
fi

# Validate JSON before parsing (AC-16 / fail-closed on malformed JSON).
# If the input is not valid JSON, return deny immediately (not ask).
if ! echo "$INPUT" | jq '.' >/dev/null 2>&1; then
  REASON="malformed-json-input-fail-closed"
  log_attempt "deny" "unknown" "MALFORMED-JSON" "unknown"
  emit_decision "deny" "$REASON"
  exit 0
fi

# ============================================================
# DUAL-RUNTIME INPUT PARSING (RC-A)
#
# VS Code sends: tool_name, tool_input (snake_case)
# CLI sends:     toolName, toolArgs (camelCase)
#
# Top-level tool identifier: .tool_name (VS Code) // .toolName (CLI)
# session id: .session_id (VS Code primary) // .sessionId (CLI fallback)
#
# Command (terminal tools):
#   VS Code: .tool_input.command
#   CLI:     .toolArgs.command (toolArgs may be a nested object OR a JSON-encoded string)
#
# Path (edit tools):
#   VS Code: .tool_input.path
#   CLI:     .toolArgs.path (same note: may be object or JSON string)
#
# Defensive strategy for toolArgs: attempt to read .toolArgs.command directly first
# (handles toolArgs as a nested object). If empty, attempt to parse .toolArgs as a
# JSON string and then read .command from the parsed result. This covers both forms
# observed in the wild (object form and double-encoded string form).
# OI-11-B defensive both-casings parser:
# VS Code docs (2026-06-14): live stdin uses snake_case (session_id, hook_event_name, tool_name, tool_input).
# SPEC-05 carried camelCase (sessionId, hookEventName). The // operator handles both.
# tool_name is the same in both schemas (snake_case per VS Code; camelCase toolName per CLI).
# We parse .tool_name first (VS Code form), then .toolName (CLI form), as the defensive fallback.
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // .toolName // "unknown"' 2>/dev/null || echo "parse-error")

# session_id: snake_case (VS Code primary) with camelCase fallback (CLI / older builds).
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // .sessionId // "unknown"' 2>/dev/null || echo "parse-error")

# tool_use_id: the D7 correlation key linking hook log to OTel span gen_ai.tool.call.id.
# VS Code sends tool_use_id (snake_case). CLI may not send this field.
TOOL_USE_ID=$(echo "$INPUT" | jq -r '.tool_use_id // "unknown"' 2>/dev/null || echo "unknown")

# COMMAND extraction (RC-A dual-runtime):
#   Primary: .tool_input.command (VS Code snake_case)
#   Fallback 1: .toolArgs.command when toolArgs is a nested object (CLI standard form)
#   Fallback 2: parse .toolArgs as a JSON string, then read .command (CLI string-encoded form)
# The jq // "" chains ensure an empty string (not null) on miss.
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // .toolArgs.command // ""' 2>/dev/null || echo "")

# If COMMAND is still empty and .toolArgs is present as a JSON-encoded string, try double-decode.
# This handles the form: {"toolArgs": "{\"command\":\"git push\"}"}
if [ -z "$COMMAND" ]; then
  TOOLARGS_RAW=$(echo "$INPUT" | jq -r '.toolArgs // ""' 2>/dev/null || echo "")
  if [ -n "$TOOLARGS_RAW" ] && echo "$TOOLARGS_RAW" | jq '.' >/dev/null 2>&1; then
    COMMAND=$(echo "$TOOLARGS_RAW" | jq -r '.command // ""' 2>/dev/null || echo "")
  fi
fi

# TOOL_INPUT_PATH extraction (RC-A dual-runtime + SPEC-23 Claude Code extension):
#   Primary 1: .tool_input.path (VS Code snake_case + CLI Copilot)
#   Primary 2: .tool_input.file_path (Claude Code edit tools: Edit/Write use file_path not path)
#              Source: SPEC-23 section 2 note 4; code.claude.com/docs/en/hooks (2026-06-17)
#   Fallback 1: .toolArgs.path when toolArgs is a nested object (CLI Copilot standard form)
#   Fallback 2: parse .toolArgs as a JSON string, then read .path (CLI string-encoded form)
TOOL_INPUT_PATH=$(echo "$INPUT" | jq -r '.tool_input.path // .tool_input.file_path // .toolArgs.path // ""' 2>/dev/null || echo "")

# If TOOL_INPUT_PATH is still empty and .toolArgs is present as a string, try double-decode.
if [ -z "$TOOL_INPUT_PATH" ]; then
  TOOLARGS_RAW=$(echo "$INPUT" | jq -r '.toolArgs // ""' 2>/dev/null || echo "")
  if [ -n "$TOOLARGS_RAW" ] && echo "$TOOLARGS_RAW" | jq '.' >/dev/null 2>&1; then
    TOOL_INPUT_PATH=$(echo "$TOOLARGS_RAW" | jq -r '.path // ""' 2>/dev/null || echo "")
  fi
fi

# ============================================================
# HANDLE RECOGNIZED FILE-EDIT TOOLS (BLOCK-2 fix)
# VS Code edit tool names (V-15, OI-11-A confirmed): str_replace_editor, edit_file, write_file
# CLI Copilot edit tool names (docs.github.com, 2026-06-14): edit, create
# (CLI "view", "glob", "grep" are read-only; no write path; treated as unknown-tool->ask below)
# Claude Code edit tool names (SPEC-23 section 2, code.claude.com/docs/en/hooks 2026-06-17):
#   Edit, Write  (capitalized; these are write operations)
#   Read is NOT in this set (it is a read-only tool; treated as unknown-tool->ask per SPEC-23 fixture 5)
# EXTENSION: Bash is Claude Code's terminal tool (handled in the terminal dispatch below)

if [ "$TOOL_NAME" = "str_replace_editor" ] || [ "$TOOL_NAME" = "edit_file" ] || \
   [ "$TOOL_NAME" = "write_file" ] || \
   [ "$TOOL_NAME" = "edit" ] || [ "$TOOL_NAME" = "create" ] || \
   [ "$TOOL_NAME" = "Edit" ] || [ "$TOOL_NAME" = "Write" ]; then

  # BLOCK-2 fix: if TOOL_INPUT_PATH is empty or unparseable, fail closed to ask (not allow).
  # An empty path means the field name is wrong (.tool_input.path vs .tool_input.file_path etc.)
  # or the input is malformed. We cannot verify it is safe, so we must ask.
  if [ -z "$TOOL_INPUT_PATH" ]; then
    DECISION="ask"
    REASON="edit-path-unparseable-fail-closed-HIGH-SIGNAL"
    log_attempt "$DECISION" "$TOOL_NAME" "UNPARSEABLE-PATH" "$SESSION_ID"
    emit_decision "$DECISION" "$REASON"
    exit 0
  fi

  # Path is present: check if it matches the canonical boundary-config set (section 5).
  # If so, force ask. The edits glob is the primary control; this is the backstop.
  BOUNDARY_EDIT=0
  for boundary_pattern in \
    "\.vscode/" "\.devcontainer/" "\.git/hooks/" "\.github/hooks/" \
    "\.claude/" "mcp\.json" "\.env" "AGENTS\.md" "copilot-instructions\.md" \
    "\.agent\.md"; do
    if echo "$TOOL_INPUT_PATH" | grep -qE "$boundary_pattern"; then
      BOUNDARY_EDIT=1
      break
    fi
  done

  if [ "$BOUNDARY_EDIT" -eq 1 ]; then
    DECISION="ask"
    REASON="boundary-config-path-edit-HIGH-SIGNAL"
    log_attempt "$DECISION" "$TOOL_NAME" "$TOOL_INPUT_PATH" "$SESSION_ID"
    emit_decision "$DECISION" "$REASON"
    exit 0
  fi

  # Non-boundary file edit with a parseable path: allow (edits glob is the primary control).
  DECISION="allow"
  REASON="file-edit-non-boundary"
  log_attempt "$DECISION" "$TOOL_NAME" "$TOOL_INPUT_PATH" "$SESSION_ID"
  emit_decision "$DECISION" "$REASON"
  exit 0
fi

# ============================================================
# TERMINAL TOOL DISPATCH (BLOCK-1 fix)
# BLOCK-1 fix: unrecognized tool names return ASK (not allow).
# If V-21 is wrong and the pinned build sends a different tool name, returning allow here
# would make the entire hook a silent no-op. Returning ask puts a human in the loop.
#
# VS Code terminal tool names: run_in_terminal, terminal, shell
# CLI Copilot terminal tool names: bash, powershell
# Claude Code terminal tool name: Bash (capitalized, SPEC-23 section 2 note 2)
#   Source: code.claude.com/docs/en/hooks (fetched 2026-06-17)
# (CLI read-only tools view/glob/grep/web_fetch/ask_user/task fall through to unknown-tool ask)
# (Claude Code Read is a read-only tool and falls through to unknown-tool->ask per SPEC-23 fixture 5)

if [ "$TOOL_NAME" != "run_in_terminal" ] && [ "$TOOL_NAME" != "terminal" ] && \
   [ "$TOOL_NAME" != "shell" ] && \
   [ "$TOOL_NAME" != "bash" ] && [ "$TOOL_NAME" != "powershell" ] && \
   [ "$TOOL_NAME" != "Bash" ]; then
  # Unknown tool: ask (not allow). Human gate for unrecognized tools.
  DECISION="ask"
  REASON="unknown-tool-human-gate"
  log_attempt "$DECISION" "$TOOL_NAME" "unknown-tool" "$SESSION_ID"
  emit_decision "$DECISION" "$REASON"
  exit 0
fi

# No command: deny (fail-closed on empty input)
if [ -z "$COMMAND" ]; then
  DECISION="deny"
  REASON="empty-command-fail-closed"
  log_attempt "$DECISION" "$TOOL_NAME" "empty" "$SESSION_ID"
  emit_decision "$DECISION" "$REASON"
  exit 0
fi

# ============================================================
# DANGEROUS PRIMITIVE SET: DENY unconditionally.
# Patterns are checked against the FULL command string (not just the leading word),
# so quote-concatenation variants are caught.
#
# D-6 fix: single grep engine (ERE via grep -qE) for all pattern matching.
# Do NOT use dual PCRE+ERE fallback: if a pattern fails to compile in ERE,
# grep exits non-zero, set -e trips, the cleanup trap fires with deny. Fail-closed.
# All patterns below are ERE-expressible; no PCRE extensions used.
# Do NOT add 2>/dev/null to the grep call itself: pattern-compile errors must fail closed.
#
# D-4 / BLOCK-3 coverage note (honest scope):
# The hook deterministically catches: quote-concatenated find-exec, base64/hex decode
# piped to interpreter, bare shell invocations, inline-interpreter with -c/-e, eval/source,
# xargs, destructive commands, privilege escalation, network tools, git push, and
# terminal-touches-boundary-path. Novel wrappers not listed here are handled by the
# section-4 deny-by-default allowlist (unrecognized commands require human approval)
# and by ADR-002 L3 egress default-DROP for any network-reaching attempt.

deny_if_matches() {
  local pattern="$1"
  local reason="$2"
  # grep -qE: exits 0=match, 1=no-match, 2+=error. Error trips set -e -> deny. Fail-closed.
  if echo "$COMMAND" | grep -qE "$pattern"; then
    DECISION="deny"
    REASON="$reason"
    log_attempt "$DECISION" "$TOOL_NAME" "$COMMAND" "$SESSION_ID"
    emit_decision "$DECISION" "$REASON"
    exit 0
  fi
}

ask_if_matches() {
  local pattern="$1"
  local reason="$2"
  if echo "$COMMAND" | grep -qE "$pattern"; then
    DECISION="ask"
    REASON="$reason"
    log_attempt "$DECISION" "$TOOL_NAME" "$COMMAND" "$SESSION_ID"
    emit_decision "$DECISION" "$REASON"
    exit 0
  fi
}

# --- DENY: destructive / irreversible ---
# ERE: [[:space:]] inside bracket expression is correct POSIX ERE.
deny_if_matches '(^|[;&|][[:space:]]*)rm[[:space:]]' "destructive-rm"
deny_if_matches '(^|[;&|][[:space:]]*)rmdir[[:space:]]' "destructive-rmdir"
deny_if_matches '(^|[;&|][[:space:]]*)del[[:space:]]' "destructive-del"
deny_if_matches '(^|[;&|][[:space:]]*)dd[[:space:]]' "destructive-dd"
deny_if_matches '(^|[;&|][[:space:]]*)mkfs[[:space:]]' "destructive-mkfs"
deny_if_matches '(^|[;&|][[:space:]]*)chmod[[:space:]]' "permission-change"
deny_if_matches '(^|[;&|][[:space:]]*)chown[[:space:]]' "ownership-change"
deny_if_matches '(^|[;&|][[:space:]]*)kill[[:space:]]' "process-kill"
deny_if_matches '(^|[;&|][[:space:]]*)killall[[:space:]]' "process-killall"
deny_if_matches '(^|[;&|][[:space:]]*)sudo[[:space:]]' "privilege-escalation-sudo"
deny_if_matches '(^|[;&|][[:space:]]*)su[[:space:]]' "privilege-escalation-su"
deny_if_matches '(^|[;&|][[:space:]]*)doas[[:space:]]' "privilege-escalation-doas"

# --- DENY: inline interpreter / wrapper class (bypass set, D-4 coverage) ---
# Matches the base form AND quote-concatenation variants because we inspect the raw string.
deny_if_matches '(^|[;&|][[:space:]]*)python[0-9.]*[[:space:]]+-[^[:space:]]*c' "inline-interpreter-python"
deny_if_matches '(^|[;&|][[:space:]]*)node[[:space:]]+-[^[:space:]]*e' "inline-interpreter-node"
deny_if_matches '(^|[;&|][[:space:]]*)ruby[[:space:]]+-[^[:space:]]*e' "inline-interpreter-ruby"
deny_if_matches '(^|[;&|][[:space:]]*)perl[[:space:]]+-[^[:space:]]*e' "inline-interpreter-perl"
deny_if_matches '(^|[;&|][[:space:]]*)bash[[:space:]]+-[^[:space:]]*c' "shell-inline-bash-c"
deny_if_matches '(^|[;&|][[:space:]]*)sh[[:space:]]+-[^[:space:]]*c' "shell-inline-sh-c"
deny_if_matches '(^|[;&|][[:space:]]*)zsh[[:space:]]+-[^[:space:]]*c' "shell-inline-zsh-c"
deny_if_matches '(^|[;&|][[:space:]]*)ksh[[:space:]]+-[^[:space:]]*c' "shell-inline-ksh-c"
deny_if_matches '(^|[;&|][[:space:]]*)dash[[:space:]]+-[^[:space:]]*c' "shell-inline-dash-c"
deny_if_matches '(^|[;&|][[:space:]]*)eval[[:space:]]' "eval"
deny_if_matches '(^|[;&|][[:space:]]*)source[[:space:]]' "source"
deny_if_matches '(^|[;&|][[:space:]]*)xargs[[:space:]]' "xargs-wrapper"

# --- DENY: bare shell invocation at pipeline position (D-4, BLOCK-3 base64-pipe case) ---
# "echo <b64> | base64 -d | bash" reaches bash with NO -c flag.
# The -c patterns above catch "bash -c"; this catches bare "| bash", "; bash", "$(... | bash)".
deny_if_matches '(^|[|;&][[:space:]]*)bash([[:space:]]|$)' "bare-shell-bash"
deny_if_matches '(^|[|;&][[:space:]]*)sh([[:space:]]|$)' "bare-shell-sh"
deny_if_matches '(^|[|;&][[:space:]]*)zsh([[:space:]]|$)' "bare-shell-zsh"
deny_if_matches '(^|[|;&][[:space:]]*)dash([[:space:]]|$)' "bare-shell-dash"

# --- DENY: base64/hex/xxd decode as part of a pipeline (D-4 coverage) ---
deny_if_matches 'base64[[:space:]]+(--decode|-d)' "base64-decode-pipeline"
deny_if_matches 'xxd[[:space:]]+-r' "xxd-reverse-pipeline"
deny_if_matches 'openssl[[:space:]]+base64' "openssl-base64-pipeline"

# --- DENY: find with exec (D-5 fix + catches quote-concatenation: find -e"x"ec) ---
# The allowlist regex matches "find -exec" as a string; an injected agent uses find -e"x"ec.
# We normalize by stripping quotes, then check with a correct ERE bracket expression.
COMMAND_NORMALIZED=$(echo "$COMMAND" | tr -d '"'"'" | tr -s ' ')
# grep -qE on COMMAND_NORMALIZED; a pattern-compile error exits non-zero -> deny (fail-closed).
if echo "$COMMAND_NORMALIZED" | grep -qE '(^|[[:space:];&|])find[[:space:]].*-e(x)?ec(dir)?[[:space:]]'; then
  DECISION="deny"
  REASON="find-exec-including-quote-concat-bypass"
  log_attempt "$DECISION" "$TOOL_NAME" "$COMMAND" "$SESSION_ID"
  emit_decision "$DECISION" "$REASON"
  exit 0
fi

# --- DENY: env wrapper (env VAR=val cmd - injects environment to bypass detection) ---
deny_if_matches '(^|[;&|][[:space:]]*)env[[:space:]]+[A-Za-z_]' "env-wrapper"

# --- ASK: git push and git write operations ---
ask_if_matches '(^|[;&|][[:space:]]*)git[[:space:]]+push[[:space:]]' "git-push-human-gate"
ask_if_matches '(^|[;&|][[:space:]]*)git[[:space:]]+(reset[[:space:]]+--hard|clean[[:space:]]|remote[[:space:]]+(add|set-url|remove))' "git-destructive-human-gate"

# --- ASK: network tools (egress is the catch-all; ask here for human-loop awareness) ---
ask_if_matches '(^|[;&|][[:space:]]*)curl[[:space:]]' "network-tool-curl"
ask_if_matches '(^|[;&|][[:space:]]*)wget[[:space:]]' "network-tool-wget"
ask_if_matches '(^|[;&|][[:space:]]*)nc[[:space:]]' "network-tool-nc"
ask_if_matches '(^|[;&|][[:space:]]*)telnet[[:space:]]' "network-tool-telnet"
ask_if_matches '(^|[;&|][[:space:]]*)ncat[[:space:]]' "network-tool-ncat"
ask_if_matches '(^|[;&|][[:space:]]*)netcat[[:space:]]' "network-tool-netcat"
ask_if_matches '(^|[;&|][[:space:]]*)ssh[[:space:]]' "ssh-human-gate"
ask_if_matches '(^|[;&|][[:space:]]*)scp[[:space:]]' "scp-human-gate"
ask_if_matches '(^|[;&|][[:space:]]*)sftp[[:space:]]' "sftp-human-gate"
ask_if_matches '(^|[;&|][[:space:]]*)rsync[[:space:]]' "rsync-human-gate"
ask_if_matches '(^|[;&|][[:space:]]*)npm[[:space:]]+publish[[:space:]]' "npm-publish-human-gate"

# --- ASK: MCP server starts ---
ask_if_matches '(^|[;&|][[:space:]]*)mcp[[:space:]]' "mcp-server-start-human-gate"

# --- ASK: boundary-config path touches via terminal (belt-and-suspenders, canonical set) ---
if echo "$COMMAND" | grep -qE '(\.vscode|\.devcontainer|\.git/hooks|\.github/hooks|\.claude|mcp\.json|AGENTS\.md|copilot-instructions|\.agent\.md)'; then
  DECISION="ask"
  REASON="terminal-touches-boundary-path-HIGH-SIGNAL"
  log_attempt "$DECISION" "$TOOL_NAME" "$COMMAND" "$SESSION_ID"
  emit_decision "$DECISION" "$REASON"
  exit 0
fi

# ============================================================
# TERMINAL FALLTHROUGH (BLOCK-3 fix)
# A recognized terminal tool with a command that passed all deny/ask checks above.
#
# Return ASK (not allow). This is the fail-closed default for the terminal path.
# Rationale: the section-4 allowlist is deny-by-default for unrecognized commands;
# the VS Code approval UI will handle the final allow/deny for commands already on the
# section-4 allow set. The hook returning "ask" for unclassified commands is correct:
# it puts a human in the loop for anything not positively categorized above.
DECISION="ask"
REASON="hook-terminal-fallthrough-to-human-gate"
log_attempt "$DECISION" "$TOOL_NAME" "$COMMAND" "$SESSION_ID"
emit_decision "$DECISION" "$REASON"
exit 0
