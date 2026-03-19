"""
Policy enforcer for Wyatt.

Communicates with OPA to get policy decisions. Single responsibility:
call OPA REST API, receive allow/deny decision, return to daemon.

No policy logic lives here. This is pure translation.

Connects to:
- daemon.py: Daemon calls check_policy() before executing tools
- OPA: Posts to http://localhost:8181/v1/data/wyatt/allow
- models.py: Returns PolicyDecision objects
"""

import os
from typing import Any

import httpx

from wyatt.core.exceptions import EnforcerError
from wyatt.core.models import PolicyDecision


class PolicyEnforcer:
    """
    Enforces policy by querying OPA.

    This class has one job: ask OPA if an operation is allowed.
    """

    def __init__(self, opa_url: str | None = None) -> None:
        """
        Initialize the enforcer.

        Args:
            opa_url: OPA server URL. Defaults to http://localhost:8181
        """
        self.opa_url = opa_url or os.getenv("OPA_URL", "http://localhost:8181")
        self.decision_endpoint = f"{self.opa_url}/v1/data/wyatt/allow"

    async def check_policy(
        self,
        agent: str,
        tool: str,
        args: dict[str, Any],
    ) -> PolicyDecision:
        """
        Check if an operation is allowed by policy.

        Args:
            agent: Agent ID (principal)
            tool: Tool name (operation)
            args: Tool arguments (state delta for v0.1.0)

        Returns:
            PolicyDecision with allowed bool and reason string

        Raises:
            EnforcerError: If OPA communication fails

        Example:
            decision = await enforcer.check_policy(
                agent="agent-001",
                tool="read_file",
                args={"path": "/etc/passwd"}
            )
            if decision.allowed:
                # Execute tool
            else:
                # Raise PolicyViolationError
        """
        # Build the OPA input payload
        payload = {"input": {"agent": agent, "tool": tool, "args": args}}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.decision_endpoint,
                    json=payload,
                    timeout=5.0,
                )
                response.raise_for_status()
        except httpx.HTTPError as e:
            raise EnforcerError(f"Failed to communicate with OPA: {e}") from e

        # Parse OPA response
        try:
            result = response.json()
            decision_data = result["result"]

            # OPA returns {"allowed": true/false, "reason": "..."}
            return PolicyDecision(
                allowed=decision_data["allowed"],
                reason=decision_data["reason"],
            )
        except (KeyError, ValueError) as e:
            raise EnforcerError(f"Invalid OPA response format: {e}") from e
