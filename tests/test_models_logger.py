"""
Tests for models and logger.

Verifies CEE structure and human-readable logging output.
"""

from core.models import CanonicalExecutionEvent, PolicyDecision


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
    """Logger produces human-readable output with key fields."""
    from core.logger import log_enforcement

    log_enforcement(
        operation="read_file",
        principal="agent-001",
        state_delta={"path": "/test.txt"},
        decision="ALLOW",
        policy_basis="Test policy",
    )

    captured = capsys.readouterr()
    output = captured.out

    # v0.2.0 uses human-readable format, not JSON
    # Check key elements are present
    assert "read_file" in output      # operation
    assert "agent-001" in output      # principal
    assert "ALLOW" in output          # decision
    assert "/test.txt" in output      # args
    assert "[REQ]" in output          # tag format
    assert "[AFB04" in output         # AFB tag
