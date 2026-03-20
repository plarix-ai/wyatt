"""
Data models for Wyatt v0.2.0.

Defines the Canonical Execution Event (CEE), AFB decisions, and related structures.
Every interception produces exactly one CEE. This is the authoritative
record of what happened.

v0.2.0 additions:
- Verdict enum (ALLOW, DENY, REDACT)
- AFBDecision for granular boundary checks
- DataBoundaryRule for argument-level policies
- ToolRequest/ToolResponse for socket protocol

Connects to:
- logger.py: CEE is logged with colored output
- daemon.py: Creates CEE from interceptions
- enforcer.py: Policy basis comes from OPA decision
- boundaries.py: Uses AFBDecision for each boundary check
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """
    Enforcement verdict for a tool call.

    ALLOW: Tool executes, result returned unchanged
    DENY: Tool never executes, error returned
    REDACT: Tool executes, but sensitive data removed from result
    """

    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"


class AFBType(str, Enum):
    """
    AFB boundary types from the spec.

    AFB04 (Unauthorized Action) has sub-boundaries:
    - TOOL: Is this tool permitted for this agent?
    - DATA: Are the arguments/paths permitted?
    - EXEC: Execution constraints (timeout, sandbox, etc.)
    - CTX: Context/output filtering
    """

    TOOL = "TOOL"  # Tool boundary - which tools allowed
    DATA = "DATA"  # Data boundary - which arguments allowed
    EXEC = "EXEC"  # Execution boundary - resource limits
    CTX = "CTX"  # Context boundary - output filtering


class AFBDecision(BaseModel):
    """
    Result of a single AFB boundary check.

    Each tool call passes through multiple boundary checks:
    1. TOOL boundary - is the tool permitted?
    2. DATA boundary - are the arguments permitted?
    3. EXEC boundary - execution constraints
    4. CTX boundary - output filtering

    The first DENY stops the chain.
    """

    afb: AFBType = Field(..., description="Which AFB boundary was checked")
    verdict: Verdict = Field(..., description="Result of the check")
    reason: str = Field(..., description="Explanation of the decision")

    def __str__(self) -> str:
        return f"AFB04:{self.afb.value} {self.verdict.value.upper()} ({self.reason})"


class DataBoundaryRule(BaseModel):
    """
    Rule for argument-level (Data Boundary) enforcement.

    Specifies what argument values are permitted or forbidden
    for a specific agent-tool combination.

    Example:
        agent-001 can read_file from /tmp/* but not /etc/*
    """

    agent: str = Field(..., description="Agent this rule applies to, or '*' for all")
    tool: str = Field(..., description="Tool this rule applies to")
    arg_name: str = Field(..., description="Argument to check (e.g., 'path')")
    allow_patterns: list[str] = Field(
        default_factory=list, description="Glob patterns that are allowed"
    )
    deny_patterns: list[str] = Field(
        default_factory=list, description="Glob patterns that are denied"
    )


class ToolRequest(BaseModel):
    """
    Request from agent to Wyatt daemon via socket.

    This is the wire format for tool execution requests.
    """

    action: str = Field(default="execute", description="Action type")
    agent_id: str = Field(..., description="Agent making the request")
    tool: str = Field(..., description="Tool to execute")
    args: dict[str, Any] = Field(default_factory=dict, description="Tool arguments")


class ToolResponse(BaseModel):
    """
    Response from Wyatt daemon to agent via socket.

    Contains the verdict and either a result (on ALLOW)
    or an error reason (on DENY).
    """

    verdict: Verdict = Field(..., description="Enforcement verdict")
    result: Any = Field(default=None, description="Tool result if allowed")
    reason: str = Field(default="", description="Explanation (especially for DENY)")
    afb_checks: list[AFBDecision] = Field(
        default_factory=list, description="All AFB checks performed"
    )


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


# =============================================================================
# Boundary Configuration (loaded from policy or config)
# =============================================================================


class BoundaryConfig(BaseModel):
    """
    Configuration for all AFB04 boundaries.

    Loaded at daemon startup from policy file or OPA.
    """

    # Tool boundary: which agents can use which tools
    tool_allowlist: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Map of agent_id -> list of permitted tools",
    )

    # Data boundary: argument-level rules
    data_rules: list[DataBoundaryRule] = Field(
        default_factory=list,
        description="Rules for argument validation",
    )

    # Execution boundary: resource limits
    exec_timeout_seconds: int = Field(
        default=30,
        description="Max execution time for any tool",
    )

    # Context boundary: patterns to redact from output
    redact_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns to redact from tool output",
    )
