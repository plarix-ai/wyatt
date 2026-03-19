"""
Tests for the daemon.

Verifies end-to-end enforcement: policy check → log → execute or deny.
Requires OPA running: make start
"""

import pytest

from wyatt.core.daemon import WyattDaemon
from wyatt.core.exceptions import PolicyViolationError


# Mock tool functions for testing
def mock_read_file(path: str) -> str:
    """Mock tool that simulates reading a file."""
    return f"Contents of {path}"


def mock_delete_file(path: str) -> str:
    """Mock tool that simulates deleting a file."""
    return f"Deleted {path}"


def mock_unknown_tool() -> str:
    """Mock tool that is not in the policy."""
    return "This should never execute"


@pytest.mark.asyncio
async def test_daemon_executes_permitted_tool():
    """Daemon executes tool when policy allows."""
    daemon = WyattDaemon()

    result = await daemon.execute_tool(
        agent_id="agent-001",
        tool_name="read_file",
        tool_callable=mock_read_file,
        tool_args={"path": "/etc/passwd"},
    )

    assert result == "Contents of /etc/passwd"


@pytest.mark.asyncio
async def test_daemon_denies_forbidden_tool():
    """Daemon raises PolicyViolationError when policy denies."""
    daemon = WyattDaemon()

    with pytest.raises(PolicyViolationError) as exc_info:
        await daemon.execute_tool(
            agent_id="agent-001",
            tool_name="delete_file",
            tool_callable=mock_delete_file,
            tool_args={"path": "/tmp/test.txt"},
        )

    # Verify the exception details
    assert exc_info.value.operation == "delete_file"
    assert exc_info.value.principal == "agent-001"
    assert "Denied by default" in exc_info.value.reason


@pytest.mark.asyncio
async def test_daemon_denies_unknown_tool():
    """Daemon denies unknown tools by default."""
    daemon = WyattDaemon()

    with pytest.raises(PolicyViolationError):
        await daemon.execute_tool(
            agent_id="agent-001",
            tool_name="unknown_tool",
            tool_callable=mock_unknown_tool,
            tool_args={},
        )


@pytest.mark.asyncio
async def test_daemon_tool_never_executes_when_denied():
    """Tool callable is never invoked when policy denies."""
    daemon = WyattDaemon()
    executed = {"called": False}

    def tool_with_side_effect() -> str:
        executed["called"] = True
        return "Should not run"

    with pytest.raises(PolicyViolationError):
        await daemon.execute_tool(
            agent_id="agent-001",
            tool_name="forbidden_tool",
            tool_callable=tool_with_side_effect,
            tool_args={},
        )

    # Tool should never have been called
    assert executed["called"] is False


@pytest.mark.asyncio
async def test_daemon_logs_allow_decision(capsys):
    """Daemon logs CEE for allowed operations."""
    daemon = WyattDaemon()

    await daemon.execute_tool(
        agent_id="agent-001",
        tool_name="read_file",
        tool_callable=mock_read_file,
        tool_args={"path": "/test.txt"},
    )

    captured = capsys.readouterr()
    assert "enforcement_decision" in captured.out
    assert "ALLOW" in captured.out
    assert "agent-001" in captured.out
    assert "read_file" in captured.out


@pytest.mark.asyncio
async def test_daemon_logs_deny_decision(capsys):
    """Daemon logs CEE for denied operations."""
    daemon = WyattDaemon()

    with pytest.raises(PolicyViolationError):
        await daemon.execute_tool(
            agent_id="agent-001",
            tool_name="delete_file",
            tool_callable=mock_delete_file,
            tool_args={"path": "/test.txt"},
        )

    captured = capsys.readouterr()
    assert "enforcement_decision" in captured.out
    assert "DENY" in captured.out
    assert "agent-001" in captured.out
    assert "delete_file" in captured.out


@pytest.mark.asyncio
async def test_daemon_handles_tool_args_none():
    """Daemon handles tool_args=None by using empty dict."""
    daemon = WyattDaemon()

    def no_arg_tool() -> str:
        return "No args needed"

    result = await daemon.execute_tool(
        agent_id="agent-001",
        tool_name="read_file",
        tool_callable=no_arg_tool,
        tool_args=None,
    )

    assert result == "No args needed"
