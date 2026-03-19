"""
Tests for models and logger.

Verifies CEE structure and structured logging output.
"""

import json

from wyatt.core.models import CanonicalExecutionEvent, PolicyDecision


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
