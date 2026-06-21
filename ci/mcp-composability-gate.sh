#!/usr/bin/env bash
# ci/mcp-composability-gate.sh
#
# CI gate: verify that a gate-decision record exists whose composability_check_covers_set
# exactly equals the current set of enabled servers in mcp.json.
#
# PASS: A gate-decision record exists (in GATE_DECISIONS_DIR) whose
#       composability_check_covers_set field (sorted) is an exact match
#       for the current set of server IDs in mcp.json (sorted).
# PASS (trivial): mcp.json has an empty servers object - no gate-decision record is required.
# FAIL: No such record exists, or the record's covered-set is stale (does not cover the current SET).
#
# This gate enforces AC-MCP-N04 and RT-MCP-04 mechanically.
# The rule requires a SINGLE record whose covered-set exactly matches the current set.
# (SPEC-06 section 3 BUG-2 fix OI-12-D: the prose previously said "union of all records"
#  but the implementation requires a single record for a sorted exact match. The prose has
#  been aligned to match this implementation: "a single gate-decision record whose
#  composability_check_covers_set exactly equals the current server set." This is the
#  STRICTER and CORRECT behavior: a union-of-partial-records approach would not guarantee
#  freshness of the composability check for the current SET.)
#
# Exit codes:
#   0 - gate passes (zero servers, OR a fresh composability record covers the current set)
#   1 - gate fails (stale, partial, or missing composability record; build MUST fail)
#
# Dependencies: jq (for mcp.json parsing), python3 + PyYAML (for YAML parsing of gate records)
# BUG-1 fix (OI-12-C): uses shopt -s nullglob instead of the inert "2>/dev/null" on the for-glob.
#   This ensures an empty GATE_DECISIONS_DIR yields an empty loop (no literal *.yaml token),
#   and the gate correctly fails closed when servers are present but no records exist.
#
# Source: SPEC-06 section 3, AC-MCP-N04, RT-MCP-04. ADR-006 D2 condition (d).

set -euo pipefail

MCP_JSON="${MCP_JSON_PATH:-.vscode/mcp.json}"
GATE_DECISIONS_DIR="${GATE_DECISIONS_DIR:-docs/decisions/mcp-gate-decisions}"

# BUG-1 fix (OI-12-C): shopt -s nullglob so the *.yaml glob in the loop below
# yields an empty list (not a literal token) when GATE_DECISIONS_DIR is empty or absent.
shopt -s nullglob

if ! command -v jq >/dev/null 2>&1; then
  echo "[composability-gate] FATAL: jq is required but not found." >&2
  exit 1
fi

if [ ! -f "$MCP_JSON" ]; then
  echo "[composability-gate] FATAL: $MCP_JSON not found." >&2
  exit 1
fi

# Extract the current set of server IDs from mcp.json (keys of the "servers" object).
# The result is a sorted newline-separated list of server IDs.
# Empty servers object -> empty list -> trivial PASS.
CURRENT_SERVERS=$(jq -r '(.servers // {}) | keys | sort | .[]' "$MCP_JSON" 2>/dev/null || true)

if [ -z "$CURRENT_SERVERS" ]; then
  echo "[composability-gate] OK: zero servers in $MCP_JSON; composability gate passes trivially."
  exit 0
fi

CURRENT_SET=$(printf '%s\n' "$CURRENT_SERVERS" | sort)
echo "[composability-gate] Current server set: $(echo "$CURRENT_SET" | tr '\n' ' ')"

# For each gate-decision record, extract composability_check_covers_set and check
# whether it exactly matches the current server set.
# We require at least ONE record whose covered-set is an exact sorted match
# for the current server set. This enforces freshness: a record from a prior
# single-server era cannot satisfy a two-server SET check.
FOUND_FRESH=0

# BUG-1 fix: nullglob is set above, so the glob below yields an empty list
# if no *.yaml files exist in GATE_DECISIONS_DIR. The loop body never executes
# in that case, FOUND_FRESH stays 0, and the gate fails closed (correct: if servers
# are present and no gate-decision record exists, the build should fail).
for record in "$GATE_DECISIONS_DIR"/*.yaml; do
  [ -f "$record" ] || continue

  # Extract composability_check_covers_set as a sorted newline-separated list.
  # Uses python3 + PyYAML for YAML parsing. If PyYAML is absent, the || true
  # yields an empty COVERED string, which cannot match CURRENT_SET (non-empty),
  # so FOUND_FRESH stays 0 and the gate fails closed. No fail-open on missing YAML parser.
  COVERED=$(python3 -c "
import sys, yaml
with open('$record') as f:
    d = yaml.safe_load(f)
covered = d.get('composability_check_covers_set', [])
print('\n'.join(sorted(covered)))
" 2>/dev/null || true)

  if [ "$COVERED" = "$CURRENT_SET" ]; then
    FOUND_FRESH=1
    echo "[composability-gate] OK: fresh composability check found in $record covering current SET."
    break
  fi
done

if [ "$FOUND_FRESH" -eq 0 ]; then
  echo "[composability-gate] FAIL: no gate-decision record found whose composability_check_covers_set" >&2
  echo "[composability-gate] exactly matches the current server set: $(echo "$CURRENT_SET" | tr '\n' ' ')" >&2
  echo "[composability-gate] The composability check is STALE for the current SET." >&2
  echo "[composability-gate] Required action: re-run the condition (d) composability check (SPEC-06 section 3)" >&2
  echo "[composability-gate] for the full current SET and create/update a gate-decision record with:" >&2
  echo "[composability-gate]   composability_check_covers_set:" >&2
  for sid in $CURRENT_SET; do
    echo "[composability-gate]     - $sid" >&2
  done
  echo "[composability-gate] See SPEC-06 section 3, ADR-006 D2(d), AC-MCP-N04, RT-MCP-04." >&2
  exit 1
fi

echo "[composability-gate] OK: composability gate PASSED for current server set."
