"""
Colored human-readable logging for Wyatt v0.2.0.

Replaces JSON structlog with clear [TAG] format and ANSI colors.
Designed for live terminal feedback during daemon operation.

Example output:
    [WYATT] Daemon started on /tmp/wyatt.sock
    [REQ]   agent-001 → read_file({path: /etc/passwd})
    [AFB04] TOOL: ALLOW (read_file in allowlist)
    [AFB04] DATA: DENY (path matches /etc/*)
    [DENY]  Blocked: /etc/* forbidden for agent-001
"""

import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Color(Enum):
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Tag colors
    BLUE = "\033[34m"   # Info tags
    GREEN = "\033[32m"  # Success/Allow
    RED = "\033[31m"    # Deny/Error
    WHITE = "\033[37m"  # Default text


# Check if terminal supports colors
def _supports_color() -> bool:
    """Check if stdout supports ANSI colors."""
    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


COLORS_ENABLED = _supports_color()


def _color(text: str, color: Color, bold: bool = False) -> str:
    """Apply ANSI color to text if colors are enabled."""
    if not COLORS_ENABLED:
        return text
    prefix = f"{Color.BOLD.value}" if bold else ""
    return f"{prefix}{color.value}{text}{Color.RESET.value}"


def _tag(name: str, color: Color, width: int = 7) -> str:
    """Format a tag like [WYATT] with color and fixed width."""
    tag = f"[{name}]".ljust(width + 2)
    return _color(tag, color, bold=True)


def _timestamp() -> str:
    """Get current timestamp in HH:MM:SS format."""
    now = datetime.now(timezone.utc)
    return _color(now.strftime("%H:%M:%S"), Color.WHITE)


def _format_args(args: dict[str, Any] | None) -> str:
    """Format tool arguments for display."""
    if not args:
        return "()"
    parts = [f"{k}: {v}" for k, v in args.items()]
    return "({" + ", ".join(parts) + "})"


# =============================================================================
# Public Logging Functions
# =============================================================================


def log_wyatt(message: str) -> None:
    """Log a Wyatt system message."""
    print(f"{_tag('WYATT', Color.BLUE)} {message}")


def log_wyatt_banner(version: str = "0.2.0") -> None:
    """Print the Wyatt startup banner."""
    line = "═" * 55
    print(f"{_tag('WYATT', Color.BLUE)} {_color(line, Color.BLUE)}")
    print(
        f"{_tag('WYATT', Color.BLUE)} "
        f"{_color(f'Wyatt v{version} - Runtime Policy Enforcement Daemon', Color.BLUE, bold=True)}"
    )
    print(f"{_tag('WYATT', Color.BLUE)} {_color(line, Color.BLUE)}")


def log_connection(agent_id: str, action: str = "connected") -> None:
    """Log agent connection/disconnection."""
    print(f"{_tag('CONN', Color.BLUE)} Agent {action}: {_color(agent_id, Color.WHITE, bold=True)}")


def log_request(agent_id: str, tool: str, args: dict[str, Any] | None = None) -> None:
    """Log an incoming tool request."""
    arrow = _color("→", Color.WHITE)
    agent = _color(agent_id, Color.WHITE, bold=True)
    tool_name = _color(tool, Color.WHITE, bold=True)
    formatted_args = _color(_format_args(args), Color.WHITE)
    print(f"{_tag('REQ', Color.BLUE)} {agent} {arrow} {tool_name}{formatted_args}")


def log_afb(afb_type: str, verdict: str, reason: str) -> None:
    """
    Log an AFB boundary check result.

    Args:
        afb_type: Type of boundary (e.g., "TOOL", "DATA", "EXEC", "CTX")
        verdict: "ALLOW" or "DENY"
        reason: Explanation of the decision
    """
    tag = f"AFB04:{afb_type}"
    verdict_color = Color.GREEN if verdict == "ALLOW" else Color.RED
    verdict_text = _color(verdict, verdict_color, bold=True)
    print(f"{_tag(tag, Color.BLUE)} {verdict_text} ({reason})")


def log_allow(message: str) -> None:
    """Log an ALLOW decision."""
    print(f"{_tag('ALLOW', Color.GREEN)} {_color(message, Color.GREEN)}")


def log_deny(message: str) -> None:
    """Log a DENY decision."""
    print(f"{_tag('DENY', Color.RED)} {_color(message, Color.RED, bold=True)}")


def log_agent(message: str) -> None:
    """Log an agent-side message."""
    print(f"{_tag('AGENT', Color.BLUE)} {message}")


def log_agent_banner(name: str = "Adversarial Agent", version: str = "0.2.0") -> None:
    """Print the agent startup banner."""
    line = "═" * 55
    print(f"{_tag('AGENT', Color.BLUE)} {_color(line, Color.BLUE)}")
    print(
        f"{_tag('AGENT', Color.BLUE)} "
        f"{_color(f'{name} v{version} - Policy Stress Test', Color.BLUE, bold=True)}"
    )
    print(f"{_tag('AGENT', Color.BLUE)} {_color(line, Color.BLUE)}")


def log_attack(strategy_num: int, description: str) -> None:
    """Log an attack strategy being executed."""
    header = _color(f"Task {strategy_num}:", Color.WHITE, bold=True)
    print(f"\n{_tag('TASK', Color.BLUE)} {header} {description}")


def log_result(verdict: str, message: str) -> None:
    """Log an attack result."""
    verdict_color = Color.GREEN if verdict == "ALLOW" else Color.RED
    verdict_text = _color(verdict, verdict_color, bold=True)
    print(f"{_tag('RESULT', Color.BLUE)} {verdict_text} - {message}")


def log_summary(total: int, blocked: int, allowed: int) -> None:
    """Log attack summary."""
    line = "═" * 55
    print(f"\n{_color(line, Color.WHITE)}")
    summary = (
        f"{_color(str(total), Color.WHITE, bold=True)} actions attempted, "
        f"{_color(str(blocked), Color.RED, bold=True)} blocked, "
        f"{_color(str(allowed), Color.GREEN, bold=True)} allowed"
    )
    print(f"{_tag('SUMMARY', Color.BLUE)} {summary}")
    print(f"{_color(line, Color.WHITE)}\n")


def log_error(message: str) -> None:
    """Log an error message."""
    print(f"{_tag('ERROR', Color.RED)} {_color(message, Color.RED, bold=True)}")


# =============================================================================
# Legacy Compatibility (for existing tests)
# =============================================================================


def log_enforcement(
    operation: str,
    principal: str,
    state_delta: dict,
    decision: str,
    policy_basis: str,
) -> None:
    """
    Log an enforcement decision (CEE) - legacy compatibility.

    This maintains backward compatibility with v0.1.0 tests.
    In v0.2.0, use log_request + log_afb + log_allow/log_deny instead.
    """
    log_request(principal, operation, state_delta)
    log_afb("TOOL", decision, policy_basis)
    if decision == "ALLOW":
        log_allow(f"Executed {operation}")
    else:
        log_deny(f"Blocked: {policy_basis}")


def get_logger(name: str):
    """
    Legacy compatibility - returns a simple logger object.

    In v0.2.0, use the specific log_* functions instead.
    """

    class SimpleLogger:
        def info(self, event: str, **kwargs):
            if event == "enforcement_decision":
                log_enforcement(
                    operation=kwargs.get("operation", "unknown"),
                    principal=kwargs.get("principal", "unknown"),
                    state_delta=kwargs.get("state_delta", {}),
                    decision=kwargs.get("decision", "DENY"),
                    policy_basis=kwargs.get("policy_basis", ""),
                )

    return SimpleLogger()
