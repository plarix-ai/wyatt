"""
Data models for Wyatt.

Defines the Canonical Execution Event (CEE) and related structures.
Every interception produces exactly one CEE. This is the authoritative
record of what happened.

Connects to:
- logger.py: CEE is logged as structured JSON
- daemon.py: Creates CEE from interceptions
- enforcer.py: Policy basis comes from OPA decision
"""

from typing import Any

from pydantic import BaseModel, Field


class CanonicalExecutionEvent(BaseModel):
    """
    The atomic unit of enforcement.

    Every tool call interception produces exactly one CEE. Four fields, nothing else.

    Attributes:
        operation: What action is being attempted (e.g., "read_file", "delete_database")
        principal: Who or what is attempting it (e.g., "agent-001")
        state_delta: What will change in the world if allowed (tool args for v0.1.0)
        policy_basis: Why the policy said yes or no
    """

    operation: str = Field(..., description="The tool/action being attempted")
    principal: str = Field(..., description="Agent or entity making the request")
    state_delta: dict[str, Any] = Field(
        ..., description="What changes if this executes (tool args for v0.1.0)"
    )
    policy_basis: str = Field(..., description="Why this was allowed or denied")


class PolicyDecision(BaseModel):
    """
    Result from OPA policy evaluation.

    Attributes:
        allowed: Whether the operation is permitted
        reason: Policy basis for the decision
    """

    allowed: bool = Field(..., description="Whether the operation is allowed")
    reason: str = Field(..., description="Why this decision was made")

