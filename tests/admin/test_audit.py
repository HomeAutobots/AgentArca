"""
test_audit.py

Covers:
  AC-27-P0-05: Audit sink host-side, O_APPEND, no secret, correct fields
  AC-27-P0-05b: Audit log append-only (no truncation via API, lines preserved)
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.admin.audit import write_audit_record, AuditWriteError

TEST_PORT = 8080
VALID_HOST = f"127.0.0.1:{TEST_PORT}"


class TestAuditRecordFields:
    """AC-27-P0-05: Correct fields, valid timestamps, no secret."""

    def test_record_written_and_parseable(self, tmp_path):
        """A written audit record must be parseable JSON."""
        audit_path = tmp_path / "audit.jsonl"
        write_audit_record(
            audit_path,
            session_id="test-session-001",
            domain="skeleton",
            action="login",
            outcome="applied",
        )
        assert audit_path.exists()
        lines = audit_path.read_text().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["action"] == "login"

    def test_required_fields_present(self, tmp_path):
        """All required fields must be present in every audit record."""
        audit_path = tmp_path / "audit.jsonl"
        write_audit_record(
            audit_path,
            session_id="test-session-002",
            domain="skeleton",
            action="health_check",
            outcome="applied",
        )
        record = json.loads(audit_path.read_text().splitlines()[0])
        required = {"schema_version", "timestamp_utc", "session_id", "domain", "action", "outcome"}
        missing = required - set(record.keys())
        assert not missing, f"Missing required fields: {missing}"

    def test_timestamp_is_utc_iso8601(self, tmp_path):
        """timestamp_utc must be a valid ISO 8601 UTC timestamp ending with Z."""
        audit_path = tmp_path / "audit.jsonl"
        write_audit_record(
            audit_path,
            session_id="test-session-003",
            domain="skeleton",
            action="login",
            outcome="applied",
        )
        record = json.loads(audit_path.read_text().splitlines()[0])
        ts = record["timestamp_utc"]
        assert ts.endswith("Z"), f"timestamp_utc must end with Z (UTC). Got: {ts!r}"
        # Basic ISO 8601 structure check.
        assert "T" in ts, f"timestamp_utc must contain T separator. Got: {ts!r}"
        assert len(ts) >= 20, f"timestamp_utc too short: {ts!r}"

    def test_schema_version_is_1(self, tmp_path):
        audit_path = tmp_path / "audit.jsonl"
        write_audit_record(
            audit_path,
            session_id="sess-xyz",
            domain="skeleton",
            action="login",
            outcome="applied",
        )
        record = json.loads(audit_path.read_text().splitlines()[0])
        assert record["schema_version"] == "1"

    def test_secret_not_in_record(self, tmp_path):
        """The audit record must not contain the test secret value."""
        from tests.admin.conftest import TEST_SECRET
        audit_path = tmp_path / "audit.jsonl"
        write_audit_record(
            audit_path,
            session_id="sess-secret-check",
            domain="skeleton",
            action="login",
            outcome="applied",
            detail="user logged in",
        )
        content = audit_path.read_text()
        assert TEST_SECRET not in content, (
            "The shared secret appeared in an audit record."
        )

    def test_login_audit_record_via_api(self, client, test_settings):
        """After login via the API, an audit record with action=login must appear."""
        from tests.admin.conftest import TEST_SECRET
        resp = client.post(
            "/api/v1/login",
            json={"secret": TEST_SECRET},
            headers={"Host": VALID_HOST},
        )
        assert resp.status_code == 200
        audit_path = test_settings.audit_log_path

        # Give the write a moment in case it's async (it should be synchronous).
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if audit_path.exists() and audit_path.stat().st_size > 0:
                break
            time.sleep(0.05)

        assert audit_path.exists(), "Audit log file was not created after login."
        lines = [l for l in audit_path.read_text().splitlines() if l.strip()]
        assert lines, "Audit log is empty after login."
        records = [json.loads(l) for l in lines]
        login_records = [r for r in records if r.get("action") == "login"]
        assert login_records, "No login audit record found after successful login."


class TestAuditAppendOnly:
    """AC-27-P0-05b: Audit log is append-only; prior records are never destroyed."""

    def test_five_records_produce_five_lines(self, tmp_path):
        audit_path = tmp_path / "audit.jsonl"
        for i in range(5):
            write_audit_record(
                audit_path,
                session_id=f"sess-{i}",
                domain="skeleton",
                action="health_check",
                outcome="applied",
            )
        lines = [l for l in audit_path.read_text().splitlines() if l.strip()]
        assert len(lines) == 5, f"Expected 5 lines, got {len(lines)}."

    def test_three_more_records_appended_to_five(self, tmp_path):
        """After 5 records, adding 3 more yields 8 lines; the first 5 are intact."""
        audit_path = tmp_path / "audit.jsonl"
        for i in range(5):
            write_audit_record(
                audit_path,
                session_id=f"sess-{i}",
                domain="skeleton",
                action="health_check",
                outcome="applied",
                detail=f"record-{i}",
            )
        first_five = audit_path.read_text()

        for i in range(3):
            write_audit_record(
                audit_path,
                session_id=f"sess-extra-{i}",
                domain="skeleton",
                action="health_check",
                outcome="applied",
                detail=f"extra-record-{i}",
            )

        full_content = audit_path.read_text()
        assert full_content.startswith(first_five), (
            "The first 5 records were modified or overwritten."
        )
        lines = [l for l in full_content.splitlines() if l.strip()]
        assert len(lines) == 8, f"Expected 8 lines, got {len(lines)}."

    def test_no_api_route_truncates_audit_log(self, test_app):
        """There must be no API endpoint that can truncate the audit log."""
        from starlette.testclient import TestClient
        banned_path_substrings = ["/logs/audit"]
        banned_methods = {"DELETE", "PUT", "PATCH"}
        for route in test_app.routes:
            path = getattr(route, "path", "")
            methods = getattr(route, "methods", set()) or set()
            if any(s in path for s in banned_path_substrings):
                if methods & banned_methods:
                    pytest.fail(
                        f"Route {path!r} with methods {methods & banned_methods} "
                        f"could allow audit log truncation."
                    )

    def test_invalid_domain_raises_value_error(self, tmp_path):
        """An invalid domain value must raise ValueError, not silently write."""
        audit_path = tmp_path / "audit.jsonl"
        with pytest.raises(ValueError, match="Invalid audit domain"):
            write_audit_record(
                audit_path,
                session_id="sess",
                domain="invalid-domain-xyz",
                action="test",
                outcome="applied",
            )

    def test_invalid_outcome_raises_value_error(self, tmp_path):
        """An invalid outcome value must raise ValueError."""
        audit_path = tmp_path / "audit.jsonl"
        with pytest.raises(ValueError, match="Invalid audit outcome"):
            write_audit_record(
                audit_path,
                session_id="sess",
                domain="skeleton",
                action="test",
                outcome="invalid-outcome-xyz",
            )

    def test_rejected_outcome_in_schema(self, tmp_path):
        """'rejected-by-stop-and-flag' is a valid outcome from Phase 0 (reserved for Phase 3)."""
        audit_path = tmp_path / "audit.jsonl"
        # Must not raise.
        write_audit_record(
            audit_path,
            session_id="sess",
            domain="skeleton",
            action="test",
            outcome="rejected-by-stop-and-flag",
        )
        record = json.loads(audit_path.read_text().splitlines()[0])
        assert record["outcome"] == "rejected-by-stop-and-flag"
