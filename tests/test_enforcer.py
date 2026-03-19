"""
Tests for enforcer and OPA policy integration.

These tests require OPA to be running: make start
"""

import pytest

from wyatt.core.enforcer import PolicyEnforcer
from wyatt.core.exceptions import EnforcerError


@pytest.mark.asyncio
async def test_enforcer_allows_permitted_operation():
    """Enforcer returns allow for agent-001 using read_file."""
    enforcer = PolicyEnforcer()

    decision = await enforcer.check_policy(
        agent="agent-001",
        tool="read_file",
        args={"path": "/etc/passwd"},
    )

    assert decision.allowed is True
    assert "Permitted" in decision.reason
    assert "agent-001" in decision.reason


@pytest.mark.asyncio
async def test_enforcer_denies_forbidden_operation():
    """Enforcer returns deny for agent-001 using delete_file."""
    enforcer = PolicyEnforcer()

    decision = await enforcer.check_policy(
        agent="agent-001",
        tool="delete_file",
        args={"path": "/tmp/test.txt"},
    )

    assert decision.allowed is False
    assert "Denied by default" in decision.reason


@pytest.mark.asyncio
async def test_enforcer_denies_unknown_agent():
    """Enforcer returns deny for unknown agent."""
    enforcer = PolicyEnforcer()

    decision = await enforcer.check_policy(
        agent="unknown-agent",
        tool="read_file",
        args={"path": "/etc/passwd"},
    )

    assert decision.allowed is False
    assert "Denied by default" in decision.reason


@pytest.mark.asyncio
async def test_enforcer_denies_unknown_tool():
    """Enforcer returns deny for unknown tool."""
    enforcer = PolicyEnforcer()

    decision = await enforcer.check_policy(
        agent="agent-001",
        tool="unknown_tool",
        args={},
    )

    assert decision.allowed is False
    assert "Denied by default" in decision.reason


@pytest.mark.asyncio
async def test_enforcer_multiple_permitted_tools():
    """Agent-researcher can use multiple tools."""
    enforcer = PolicyEnforcer()

    # search_web should be allowed
    decision1 = await enforcer.check_policy(
        agent="agent-researcher",
        tool="search_web",
        args={"query": "test"},
    )
    assert decision1.allowed is True

    # read_file should be allowed
    decision2 = await enforcer.check_policy(
        agent="agent-researcher",
        tool="read_file",
        args={"path": "/tmp/test"},
    )
    assert decision2.allowed is True

    # delete_file should be denied
    decision3 = await enforcer.check_policy(
        agent="agent-researcher",
        tool="delete_file",
        args={"path": "/tmp/test"},
    )
    assert decision3.allowed is False


@pytest.mark.asyncio
async def test_enforcer_raises_on_bad_opa_url():
    """Enforcer raises EnforcerError if OPA is unreachable."""
    enforcer = PolicyEnforcer(opa_url="http://localhost:9999")

    with pytest.raises(EnforcerError, match="Failed to communicate with OPA"):
        await enforcer.check_policy(
            agent="agent-001",
            tool="read_file",
            args={},
        )
