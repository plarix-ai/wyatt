"""
Wyatt daemon - the enforcement entry point.

Every tool call flows through here. The daemon:
1. Creates a CEE from the tool call
2. Asks the enforcer for a policy decision
3. Logs the decision
4. Either executes the tool (ALLOW) or raises PolicyViolationError (DENY)

No tool executes without passing through this layer.

Connects to:
- enforcer.py: Gets policy decisions
- logger.py: Logs every CEE
- exceptions.py: Raises PolicyViolationError on deny
- examples/simple_agent.py: Agents call execute_tool()
"""

from typing import Any, Callable, TypeVar

from wyatt.core.enforcer import PolicyEnforcer
from wyatt.core.exceptions import PolicyViolationError
from wyatt.core.logger import log_enforcement
from wyatt.core.models import CanonicalExecutionEvent

# Type variable for tool return types
T = TypeVar("T")


class WyattDaemon:
    """
    The enforcement daemon.

    This is the single entry point for all tool executions.
    Agents call execute_tool(), which enforces policy before running anything.
    """

    def __init__(self, enforcer: PolicyEnforcer | None = None) -> None:
        """
        Initialize the daemon.

        Args:
            enforcer: Policy enforcer instance. Defaults to new PolicyEnforcer()
        """
        self.enforcer = enforcer or PolicyEnforcer()

    async def execute_tool(
        self,
        agent_id: str,
        tool_name: str,
        tool_callable: Callable[..., T],
        tool_args: dict[str, Any] | None = None,
    ) -> T:
        """
        Execute a tool after policy enforcement.

        This is the primary method. Every tool call must go through here.

        Args:
            agent_id: The agent attempting to use the tool (principal)
            tool_name: Name of the tool (operation)
            tool_callable: The actual tool function to call if permitted
            tool_args: Arguments to pass to the tool (state delta)

        Returns:
            The result of the tool execution if allowed

        Raises:
            PolicyViolationError: If policy denies the operation
            EnforcerError: If communication with OPA fails

        Example:
            async def read_file(path: str) -> str:
                return open(path).read()

            result = await daemon.execute_tool(
                agent_id="agent-001",
                tool_name="read_file",
                tool_callable=read_file,
                tool_args={"path": "/etc/passwd"}
            )
        """
        args = tool_args or {}

        # Step 1: Check policy
        decision = await self.enforcer.check_policy(
            agent=agent_id,
            tool=tool_name,
            args=args,
        )

        # Step 2: Create CEE
        cee = CanonicalExecutionEvent(
            operation=tool_name,
            principal=agent_id,
            state_delta=args,
            policy_basis=decision.reason,
        )

        # Step 3: Log the decision
        if decision.allowed:
            log_enforcement(
                operation=cee.operation,
                principal=cee.principal,
                state_delta=cee.state_delta,
                decision="ALLOW",
                policy_basis=cee.policy_basis,
            )

            # Step 4: Execute the tool
            # Tool execution happens AFTER policy allows it
            # If the tool fails, that's a separate concern from policy
            result = tool_callable(**args)
            return result  # type: ignore[return-value]

        else:
            # Policy denied
            log_enforcement(
                operation=cee.operation,
                principal=cee.principal,
                state_delta=cee.state_delta,
                decision="DENY",
                policy_basis=cee.policy_basis,
            )

            # Raise PolicyViolationError to prevent execution
            raise PolicyViolationError(
                operation=tool_name,
                principal=agent_id,
                reason=decision.reason,
            )
