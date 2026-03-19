"""
Structured logging for Wyatt.

Every enforcement decision produces exactly one CEE, which is logged
as structured JSON. No print statements. Clean audit trail.

Connects to:
- daemon.py: Calls log_enforcement() for every decision
- models.py: Uses same CEE field names for consistency
"""

import sys

import structlog

# Configure structlog for JSON output
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
    cache_logger_on_first_use=True,
)


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a structured logger instance.

    Args:
        name: Logger name (typically module name)

    Returns:
        A bound logger that outputs JSON
    """
    return structlog.get_logger(name)


def log_enforcement(
    operation: str,
    principal: str,
    state_delta: dict,
    decision: str,
    policy_basis: str,
) -> None:
    """
    Log an enforcement decision (CEE).

    This is the primary logging function. Every tool call interception
    calls this exactly once.

    Args:
        operation: Tool being called
        principal: Agent making the call
        state_delta: Tool arguments
        decision: "ALLOW" or "DENY"
        policy_basis: Why this decision was made

    Returns:
        None. Logs to stdout as JSON.

    Example JSON output:
        {
            "event": "enforcement_decision",
            "timestamp": "2026-03-19T12:00:00.000000Z",
            "level": "info",
            "operation": "read_file",
            "principal": "agent-001",
            "state_delta": {"path": "/etc/passwd"},
            "decision": "ALLOW",
            "policy_basis": "agent-001 permitted to read_file"
        }
    """
    logger = get_logger("wyatt.enforcement")
    logger.info(
        "enforcement_decision",
        operation=operation,
        principal=principal,
        state_delta=state_delta,
        decision=decision,
        policy_basis=policy_basis,
    )
