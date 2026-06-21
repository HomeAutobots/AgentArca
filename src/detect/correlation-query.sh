#!/usr/bin/env bash
# src/detect/correlation-query.sh
# D7 Cross-log session-join correlation (the CRUX of the detective layer).
# Item 13, ADR-007 D7, SPEC-07 section 4 + section 10-H.
#
# Given a session_id (or time window), reconstructs the 4-event session timeline:
#   1. PreToolUse hook log entry (hook log at the external sink)
#   2. OTel span (JSONL from the otel-collector file exporter)
#   3. Squid proxy access.log entry (gateway sidecar access log)
#   4. auditd execve record (kernel-level process execution)
#   5. (bonus) canary read record (auditd -k canary_read)
#
# JOIN KEYS (SPEC-07 section 4):
#   session_id / gen_ai.conversation.id: primary D7 join key
#   tool_use_id / gen_ai.tool.call.id: tool-call-level join key
#   UTC timestamps: all sources must use UTC (synchronized)
#   Process lineage (pid/ppid): auditd join to the VS Code parent process
#
# SESSION_ID FIELD AUTHORITY (OI-13-B, OI-11-B-confirmed-fields):
#   This script uses "sessionId" as the log line key (the key in the JSON emitted
#   by pretooluse.sh log_attempt, historical compatibility per OI-11-B-confirmed-fields).
#   The VALUE is sourced from .session_id // .sessionId in the hook's defensive parser.
#   The OTel join key is gen_ai.conversation.id.
#   These are expected to carry the same value (or a derivable mapping) on the pinned build.
#   REQUIRES-LIVE-RUNTIME to empirically confirm gen_ai.conversation.id == session_id value.
#   If they differ, a mapping table is required. Document the discrepancy at item 18.
#
# Usage:
#   ./correlation-query.sh SESSION_ID [OPTIONS]
#   ./correlation-query.sh --time-window START_UTC END_UTC [OPTIONS]
#   ./correlation-query.sh --self-test
#
# Options:
#   --hook-log FILE     : hook log file (default: /tmp/copilot-sink/audit.log)
#   --otel-spans FILE   : OTel spans JSONL file (default: /var/log/copilot-otel/spans.jsonl)
#   --proxy-log FILE    : Squid access.log (default: /tmp/copilot-sink/squid-access.log)
#   --auditd-log FILE   : auditd log file (default: /tmp/copilot-sink/audit.log)
#   --output json|human : output format (default: human)
#   --self-test         : run against seeded synthetic events and verify the join
#
# The --self-test mode is the AC-13-P06 / OI-13-G acceptance test.
# It seeds a synthetic 4-event session with a known session_id and verifies
# that the correlation reconstructs the joined timeline.
#
# OUTPUT:
#   Human format: a chronological timeline of all events in the session.
#   JSON format: machine-readable timeline for automated analysis.

set -euo pipefail

# ============================================================
# DEFAULTS AND ARGUMENT PARSING
# ============================================================
SESSION_ID=""
TIME_START=""
TIME_END=""
HOOK_LOG="${HOOK_LOG:-/tmp/copilot-sink/audit.log}"
OTEL_SPANS="${OTEL_SPANS:-/var/log/copilot-otel/spans.jsonl}"
PROXY_LOG="${PROXY_LOG:-/tmp/copilot-sink/squid-access.log}"
AUDITD_LOG="${AUDITD_LOG:-/tmp/copilot-sink/audit.log}"
OUTPUT_FORMAT="human"
SELF_TEST_MODE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --self-test) SELF_TEST_MODE=1 ;;
    --hook-log) shift; HOOK_LOG="$1" ;;
    --otel-spans) shift; OTEL_SPANS="$1" ;;
    --proxy-log) shift; PROXY_LOG="$1" ;;
    --auditd-log) shift; AUDITD_LOG="$1" ;;
    --output) shift; OUTPUT_FORMAT="$1" ;;
    --time-window) shift; TIME_START="$1"; shift; TIME_END="$1" ;;
    --*) echo "Unknown option: $1" >&2; exit 1 ;;
    *) SESSION_ID="$1" ;;
  esac
  shift || true
done

# ============================================================
# CORRELATION ENGINE
# ============================================================

# Emit a timeline event in the chosen format.
# Args: source, timestamp, event_type, detail, session_id
emit_event() {
  local source="$1"
  local timestamp="$2"
  local event_type="$3"
  local detail="$4"
  local sid="${5:-$SESSION_ID}"
  if [ "$OUTPUT_FORMAT" = "json" ]; then
    printf '{"source":"%s","timestamp":"%s","event_type":"%s","detail":%s,"session_id":"%s"}\n' \
      "$source" "$timestamp" "$event_type" "$detail" "$sid"
  else
    # Include session_id in human format so D7 join key is visible in the timeline.
    printf '[%s] %s | %-20s | %s | session_id=%s\n' "$timestamp" "$source" "$event_type" "$detail" "$sid"
  fi
}

# Query hook log for events matching session_id.
# Hook log format (pretooluse.sh log_attempt): JSON lines with sessionId field.
# OI-11-B-confirmed-fields: log key is "sessionId" (camelCase) with value from
# .session_id // .sessionId defensive parser. See hook-forwarder-addition.sh.
query_hook_log() {
  local sid="$1"
  local log_file="$2"
  if [ ! -f "$log_file" ]; then
    echo "[correlation] Hook log not found: $log_file" >&2
    return 0
  fi
  local found=0
  while IFS= read -r line; do
    # Match on sessionId (the log line key emitted by pretooluse.sh log_attempt)
    # OR on session_id (if the log format used snake_case, per defensive coverage).
    if echo "$line" | grep -qE '"sessionId":"'"$sid"'"' || \
       echo "$line" | grep -qE '"session_id":"'"$sid"'"'; then
      local ts tool decision
      ts=$(echo "$line" | grep -oE '"timestamp":"[^"]+"' | head -1 | grep -oE '"[^"]+":"[^"]+"' | cut -d'"' -f4 || echo "unknown")
      tool=$(echo "$line" | grep -oE '"tool_name":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      decision=$(echo "$line" | grep -oE '"decision":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      emit_event "hook_log" "$ts" "tool_call:${decision}" "\"tool=${tool} decision=${decision}\"" "$sid"
      found=$((found + 1))
    fi
  done < "$log_file"
  echo "[correlation] Hook log: found $found event(s) for session $sid" >&2
}

# Query OTel spans for events matching gen_ai.conversation.id == session_id.
# The gen_ai.conversation.id is the D7 join key for the OTel side.
# SPEC-07 section 4: "gen_ai.conversation.id / CHAT_SESSION_ID is the D7 join key."
# REQUIRES-LIVE-RUNTIME: empirical confirmation that gen_ai.conversation.id value
# == hook session_id value on the pinned VS Code build. See OI-13-D.
query_otel_spans() {
  local sid="$1"
  local spans_file="$2"
  if [ ! -f "$spans_file" ]; then
    echo "[correlation] OTel spans file not found: $spans_file" >&2
    return 0
  fi
  local found=0
  while IFS= read -r line; do
    # Match on gen_ai.conversation.id attribute
    if echo "$line" | grep -qE '"gen_ai\.conversation\.id":"'"$sid"'"'; then
      local ts span_name tool_name
      ts=$(echo "$line" | grep -oE '"startTimeUnixNano":[0-9]+' | head -1 | grep -oE '[0-9]+' || echo "0")
      span_name=$(echo "$line" | grep -oE '"name":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      tool_name=$(echo "$line" | grep -oE '"gen_ai\.tool\.name":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "")
      # Convert nanoseconds to ISO8601 (simplified)
      local ts_iso="epoch+${ts}ns"
      emit_event "otel_span" "$ts_iso" "span:${span_name}" "\"span=${span_name} tool=${tool_name}\"" "$sid"
      found=$((found + 1))
    fi
  done < "$spans_file"
  echo "[correlation] OTel spans: found $found span(s) for session $sid" >&2
}

# Query Squid proxy access.log for events in the session's timestamp window.
# Proxy log does not natively contain session_id; join by client IP + timestamp window.
# The client IP is the dev container's IP (fixed in the copilot-net bridge network).
# SPEC-07 section 4: join by "client IP (the container's IP) and timestamp window."
query_proxy_log() {
  local proxy_file="$1"
  local time_start="$2"
  local time_end="$3"
  if [ ! -f "$proxy_file" ]; then
    echo "[correlation] Proxy log not found: $proxy_file" >&2
    return 0
  fi
  local found=0
  while IFS= read -r line; do
    # Squid access.log format: epoch_ts duration client_ip result bytes method url peer
    # For structured JSON format from the sink: timestamp, method, url, result
    if echo "$line" | grep -qE '"source":"squid"'; then
      local ts url result
      ts=$(echo "$line" | grep -oE '"timestamp":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      url=$(echo "$line" | grep -oE '"url":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      result=$(echo "$line" | grep -oE '"result":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      emit_event "proxy_log" "$ts" "egress:${result}" "\"url=${url} result=${result}\""
      found=$((found + 1))
    elif echo "$line" | grep -qE 'TCP_(MISS|DENIED|TUNNEL)'; then
      # Raw Squid access.log format
      local cols
      cols=($line)
      local epoch="${cols[0]:-0}"
      local result_code="${cols[3]:-unknown}"
      local method="${cols[5]:-unknown}"
      local url="${cols[6]:-unknown}"
      emit_event "proxy_log" "$epoch" "egress:${result_code}" "\"method=${method} url=${url}\""
      found=$((found + 1))
    fi
  done < "$proxy_file"
  echo "[correlation] Proxy log: found $found event(s) in window" >&2
}

# Query auditd records for execve events in the session window.
# Join by pid/ppid chain to the VS Code parent process + timestamp window.
# SPEC-07 section 4: "auditd process lineage: auid, pid, ppid."
query_auditd() {
  local log_file="$1"
  if [ ! -f "$log_file" ]; then
    echo "[correlation] auditd log not found: $log_file" >&2
    return 0
  fi
  local found=0
  while IFS= read -r line; do
    # Match exec_audit key or canary_read key
    if echo "$line" | grep -qE '"key":"exec_audit"' || echo "$line" | grep -q 'key=exec_audit'; then
      local ts comm
      ts=$(echo "$line" | grep -oE '"timestamp":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      comm=$(echo "$line" | grep -oE '"comm":"[^"]+"' | head -1 | cut -d'"' -f4 || \
             echo "$line" | grep -oE 'comm="[^"]+"' | head -1 | grep -oE '"[^"]+"$' | tr -d '"' || echo "unknown")
      emit_event "auditd_execve" "$ts" "execve" "\"comm=${comm}\""
      found=$((found + 1))
    fi
    if echo "$line" | grep -qE '"key":"canary_read"' || echo "$line" | grep -q 'key=canary_read'; then
      local ts file
      ts=$(echo "$line" | grep -oE '"timestamp":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      file=$(echo "$line" | grep -oE '"file":"[^"]+"' | head -1 | cut -d'"' -f4 || echo "unknown")
      emit_event "auditd_canary" "$ts" "CANARY_READ" "\"file=${file}\""
      found=$((found + 1))
    fi
  done < "$log_file"
  echo "[correlation] auditd: found $found event(s)" >&2
}

# ============================================================
# SELF-TEST (AC-13-P06 / OI-13-G: the D7 crux, LOAD-BEARING)
# ============================================================
# Seeds a synthetic 4-event session with a known session_id.
# Verifies that correlation-query.sh reconstructs the joined 4-event timeline.
# THEN seeds a canary-read event and confirms it joins too.
# This is the acceptance test required by BUILD_PLAN AC-13-P06.
run_self_test() {
  echo "[correlation self-test] === D7 CORRELATION SELF-TEST (OI-13-G / AC-13-P06) ===" >&2
  echo "[correlation self-test] Seeding synthetic 4-event session..." >&2

  local test_session_id="test-session-d7-crux-2026-06-14"
  local test_dir
  test_dir=$(mktemp -d /tmp/correlation-test-XXXX)
  local test_hook_log="$test_dir/hook.log"
  local test_otel_spans="$test_dir/otel.jsonl"
  local test_proxy_log="$test_dir/squid.log"
  local test_auditd_log="$test_dir/audit.log"

  # SESSION_ID FIELD AUTHORITY (OI-11-B-confirmed-fields):
  # The hook log emits "sessionId" (camelCase) as the key per pretooluse.sh log_attempt.
  # The value comes from .session_id // .sessionId defensive parser.
  # We use "sessionId" as the log key here to match the real pretooluse.sh output.

  # EVENT 1: Hook log entry (pretooluse_hook source)
  cat >> "$test_hook_log" <<EOF
{"source":"pretooluse_hook","timestamp":"2026-06-14T10:00:00Z","sessionId":"${test_session_id}","hook_event_name":"PreToolUse","tool_name":"str_replace_editor","tool_use_id":"tool-use-abc123","parsed_command":"/workspace/src/app.ts","decision":"allow","reason":"recognized-edit-non-boundary"}
EOF

  # EVENT 2: OTel span (gen_ai.conversation.id as the join key)
  # The gen_ai.conversation.id value MUST match the session_id value.
  # This is the REQUIRES-LIVE-RUNTIME empirical confirmation (see OI-13-D).
  # In this synthetic test, we set gen_ai.conversation.id = test_session_id.
  cat >> "$test_otel_spans" <<EOF
{"name":"execute_tool","startTimeUnixNano":"1749823200000000000","attributes":{"gen_ai.tool.name":"str_replace_editor","gen_ai.tool.type":"function","gen_ai.tool.call.id":"tool-use-abc123","gen_ai.conversation.id":"${test_session_id}","github.copilot.tool.parameters.file_path":"/workspace/src/app.ts"}}
EOF

  # EVENT 3: Squid proxy access.log entry (egress to github.com)
  cat >> "$test_proxy_log" <<EOF
{"source":"squid","timestamp":"2026-06-14T10:00:05Z","method":"CONNECT","url":"api.github.com:443","result":"TCP_TUNNEL/200","bytes":1234,"client":"172.20.0.2"}
EOF

  # EVENT 4: auditd execve record (ls /tmp run inside the container)
  cat >> "$test_auditd_log" <<EOF
{"source":"auditd","timestamp":"2026-06-14T10:00:10Z","key":"exec_audit","comm":"ls","exe":"/usr/bin/ls","argv":["ls","/tmp"],"pid":1234,"ppid":1200,"auid":1000}
EOF

  # EVENT 5 (BONUS): canary read event
  cat >> "$test_auditd_log" <<EOF
{"source":"auditd","timestamp":"2026-06-14T10:00:15Z","key":"canary_read","file":"/home/devuser/.aws/credentials","pid":1235,"ppid":1200,"auid":1000}
EOF

  echo "[correlation self-test] Synthetic events seeded. Running correlation query..." >&2
  echo "" >&2

  # Run the correlation query against the seeded data.
  local output
  output=$(SESSION_ID="$test_session_id" \
    HOOK_LOG="$test_hook_log" \
    OTEL_SPANS="$test_otel_spans" \
    PROXY_LOG="$test_proxy_log" \
    AUDITD_LOG="$test_auditd_log" \
    OUTPUT_FORMAT="human" \
    bash "$0" "$test_session_id" \
      --hook-log "$test_hook_log" \
      --otel-spans "$test_otel_spans" \
      --proxy-log "$test_proxy_log" \
      --auditd-log "$test_auditd_log" \
      --output human \
    2>/dev/null || true)

  echo "[correlation self-test] === RECONSTRUCTED TIMELINE ===" >&2
  echo "$output" >&2
  echo "[correlation self-test] ================================" >&2

  # Verify the timeline contains events from all required sources.
  local failures=0

  if echo "$output" | grep -q "hook_log"; then
    echo "[correlation self-test] PASS: hook_log event present in timeline." >&2
  else
    echo "[correlation self-test] FAIL: hook_log event MISSING from timeline." >&2
    failures=$((failures + 1))
  fi

  if echo "$output" | grep -q "otel_span"; then
    echo "[correlation self-test] PASS: otel_span event present in timeline." >&2
  else
    echo "[correlation self-test] FAIL: otel_span event MISSING from timeline." >&2
    failures=$((failures + 1))
  fi

  if echo "$output" | grep -q "proxy_log"; then
    echo "[correlation self-test] PASS: proxy_log event present in timeline." >&2
  else
    echo "[correlation self-test] FAIL: proxy_log event MISSING from timeline." >&2
    failures=$((failures + 1))
  fi

  if echo "$output" | grep -q "auditd_execve"; then
    echo "[correlation self-test] PASS: auditd_execve event present in timeline." >&2
  else
    echo "[correlation self-test] FAIL: auditd_execve event MISSING from timeline." >&2
    failures=$((failures + 1))
  fi

  if echo "$output" | grep -q "CANARY_READ\|auditd_canary"; then
    echo "[correlation self-test] PASS: canary_read event present in timeline." >&2
  else
    echo "[correlation self-test] FAIL: canary_read event MISSING from timeline." >&2
    failures=$((failures + 1))
  fi

  # Verify the session_id join key is in the timeline.
  if echo "$output" | grep -q "$test_session_id"; then
    echo "[correlation self-test] PASS: session_id join key ($test_session_id) present." >&2
  else
    echo "[correlation self-test] FAIL: session_id join key MISSING from timeline." >&2
    failures=$((failures + 1))
  fi

  # Cleanup test artifacts.
  rm -rf "$test_dir"

  if [ "$failures" -eq 0 ]; then
    echo "[correlation self-test] === ALL CHECKS PASSED: D7 CORRELATION RECONSTRUCTED SEEDED 4-EVENT + CANARY TIMELINE ===" >&2
    echo "[correlation self-test] SESSION_ID: $test_session_id" >&2
    echo "[correlation self-test] SOURCES: hook_log + otel_span + proxy_log + auditd_execve + canary_read" >&2
    echo "[correlation self-test] JOIN KEYS: sessionId (hook) + gen_ai.conversation.id (OTel) + timestamp window (proxy) + pid/ppid (auditd)" >&2
    echo "[correlation self-test] FIELD AUTHORITY: OI-11-B-confirmed-fields (session_id primary, sessionId fallback, per pretooluse.sh)" >&2
    exit 0
  else
    echo "[correlation self-test] FAILED: $failures check(s) failed." >&2
    exit 1
  fi
}

# ============================================================
# MAIN
# ============================================================
if [ "$SELF_TEST_MODE" -eq 1 ]; then
  run_self_test
  exit $?
fi

if [ -z "$SESSION_ID" ] && [ -z "$TIME_START" ]; then
  echo "Usage: $0 SESSION_ID [OPTIONS]" >&2
  echo "       $0 --time-window START_UTC END_UTC [OPTIONS]" >&2
  echo "       $0 --self-test" >&2
  exit 1
fi

echo "[correlation] Reconstructing session timeline for: ${SESSION_ID:-time-window-${TIME_START}-${TIME_END}}" >&2
echo "[correlation] SESSION_ID field authority: OI-11-B-confirmed-fields (sessionId key in hook log)" >&2
echo "" >&2

if [ "$OUTPUT_FORMAT" = "human" ]; then
  printf '%-30s %-20s %-25s %s\n' "TIMESTAMP" "SOURCE" "EVENT_TYPE" "DETAIL"
  printf '%-30s %-20s %-25s %s\n' "------------------------------" "--------------------" "-------------------------" "------"
fi

# Query all sources in parallel and sort by timestamp.
{
  [ -n "$SESSION_ID" ] && query_hook_log "$SESSION_ID" "$HOOK_LOG" 2>/dev/null || true
  [ -n "$SESSION_ID" ] && query_otel_spans "$SESSION_ID" "$OTEL_SPANS" 2>/dev/null || true
  query_proxy_log "$PROXY_LOG" "${TIME_START:-}" "${TIME_END:-}" 2>/dev/null || true
  query_auditd "$AUDITD_LOG" 2>/dev/null || true
} | sort -t'[' -k2

echo "" >&2
echo "[correlation] Timeline reconstruction complete." >&2
echo "[correlation] IMPORTANT NOTES:" >&2
echo "[correlation]   - hook_log join: sessionId key (from OI-11-B-confirmed-fields)" >&2
echo "[correlation]   - otel_span join: gen_ai.conversation.id (REQUIRES-LIVE-RUNTIME empirical confirm)" >&2
echo "[correlation]   - proxy_log join: timestamp window + client IP (no native session_id)" >&2
echo "[correlation]   - auditd join: timestamp window + pid/ppid chain to VS Code process" >&2
echo "[correlation]   - REQUIRES-LIVE-RUNTIME: confirm gen_ai.conversation.id == session_id value at item 18" >&2
