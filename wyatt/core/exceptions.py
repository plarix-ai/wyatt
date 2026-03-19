"""
Custom exceptions for Wyatt.

Defines exceptions raised during policy enforcement.

Connects to:
- daemon.py: Raises PolicyViolationError when policy denies operation
- examples/simple_agent.py: Catches this exception to demonstrate denial
"""


class WyattError(Exception):
    """Base exception for all Wyatt errors."""

    pass


class PolicyViolationError(WyattError):
    """
    Raised when a tool call is denied by policy.

    This exception is raised BEFORE the tool executes, preventing
    unauthorized operations from running.

    Attributes:
        operation: The operation that was denied
        principal: Who attempted it
        reason: Why it was denied (from policy basis)
    """

    def __init__(self, operation: str, principal: str, reason: str) -> None:
        self.operation = operation
        self.principal = principal
        self.reason = reason
        super().__init__(f"Policy denied {operation} for {principal}: {reason}")


class EnforcerError(WyattError):
    """
    Raised when communication with OPA fails.

    This indicates a system-level problem, not a policy denial.
    """

    pass
