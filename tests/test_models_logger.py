"""
Tests for models and logger.

Verifies CEE structure and structured logging output.
"""

import json
from datetime import datetime
from io import StringIO

from wyatt.core.models import CanonicalExecutionEvent, EnforcementLog, PolicyDecision


def test_cee_creation():
    """CEE can be created with all required fields."""
    cee = CanonicalExecutionEvent(
        operation="read_file",
        principal="agent-001",
        state_delta={"path": "/etc/passwd", "mode": "r"},
        policy_basis="agent-001 permitted to read_file",
    )

    assert cee.operation == "read_file"
    assert cee.principal == "agent-001"
    assert cee.state_delta == {"path": "/etc/passwd", "mode": "r"}
    assert cee.policy_basis == "agent-001 permitted to read_file"


def test_policy_decision_creation():
    """PolicyDecision captures allow/deny with reason."""
    allowed = PolicyDecision(allowed=True, reason="Permitted by rule X")
    denied = PolicyDecision(allowed=False, reason="Deny by default")

    assert allowed.allowed is True
    assert allowed.reason == "Permitted by rule X"
    assert denied.allowed is False
    assert denied.reason == "Deny by default"


def test_enforcement_log_from_cee():
    """EnforcementLog can be created from CEE."""
    cee = CanonicalExecutionEvent(
        operation="delete_file",
        principal="agent-002",
        state_delta={"path": "/tmp/test.txt"},
        policy_basis="Deny by default",
    )

    log = EnforcementLog.from_cee(cee, decision="DENY")

    assert log.operation == "delete_file"
    assert log.principal == "agent-002"
    assert log.state_delta == {"path": "/tmp/test.txt"}
    assert log.decision == "DENY"
    assert log.policy_basis == "Deny by default"
    assert isinstance(log.timestamp, datetime)


def test_enforcement_log_serialization():
    """EnforcementLog can be serialized to JSON."""
    cee = CanonicalExecutionEvent(
        operation="read_file",
        principal="agent-001",
        state_delta={"path": "/etc/passwd"},
        policy_basis="Permitted",
    )

    log = EnforcementLog.from_cee(cee, decision="ALLOW")
    json_str = log.model_dump_json()
    parsed = json.loads(json_str)

    assert parsed["operation"] == "read_file"
    assert parsed["principal"] == "agent-001"
    assert parsed["decision"] == "ALLOW"
    assert "timestamp" in parsed


def test_logger_output_structure(capsys):
    """Logger produces structured JSON output."""
    from wyatt.core.logger import log_enforcement

    log_enforcement(
        operation="read_file",
        principal="agent-001",
        state_delta={"path": "/test.txt"},
        decision="ALLOW",
        policy_basis="Test policy",
    )

    captured = capsys.readouterr()
    log_line = captured.out.strip()

    # Should be valid JSON
    log_data = json.loads(log_line)

    assert log_data["event"] == "enforcement_decision"
    assert log_data["operation"] == "read_file"
    assert log_data["principal"] == "agent-001"
    assert log_data["decision"] == "ALLOW"
    assert log_data["policy_basis"] == "Test policy"
    assert "timestamp" in log_data
