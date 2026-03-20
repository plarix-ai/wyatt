"""
AFB boundary enforcement for Wyatt v0.2.0.

Implements the 4 sub-boundaries of AFB04 (Unauthorized Action):
1. TOOL boundary - which tools are permitted for this agent
2. DATA boundary - which arguments/paths are permitted
3. EXEC boundary - execution constraints (timeout, sandbox)
4. CTX boundary - context/output filtering

Each boundary check returns an AFBDecision. The first DENY stops execution.
"""

import fnmatch
import re
from pathlib import Path

from wyatt.core.logger import log_afb
from wyatt.core.models import AFBDecision, AFBType, BoundaryConfig, DataBoundaryRule, Verdict


class BoundaryEnforcer:
    """
    Enforces all AFB04 sub-boundaries.

    Usage:
        enforcer = BoundaryEnforcer(config)
        decisions = enforcer.check_all(agent_id, tool, args)
        if any(d.verdict == Verdict.DENY for d in decisions):
            # Block execution
    """

    def __init__(self, config: BoundaryConfig | None = None):
        """
        Initialize with boundary configuration.

        Args:
            config: BoundaryConfig with rules. If None, uses permissive defaults.
        """
        self.config = config or BoundaryConfig()

    def check_all(
        self, agent_id: str, tool: str, args: dict | None = None
    ) -> list[AFBDecision]:
        """
        Check all AFB04 boundaries in order.

        Returns list of all decisions. Stops at first DENY.
        """
        args = args or {}
        decisions: list[AFBDecision] = []

        # 1. TOOL boundary
        tool_decision = self.check_tool_boundary(agent_id, tool)
        decisions.append(tool_decision)
        log_afb(AFBType.TOOL.value, tool_decision.verdict.value.upper(), tool_decision.reason)
        if tool_decision.verdict == Verdict.DENY:
            return decisions

        # 2. DATA boundary
        data_decision = self.check_data_boundary(agent_id, tool, args)
        decisions.append(data_decision)
        log_afb(AFBType.DATA.value, data_decision.verdict.value.upper(), data_decision.reason)
        if data_decision.verdict == Verdict.DENY:
            return decisions

        # 3. EXEC boundary (placeholder for v0.2.0)
        exec_decision = self.check_exec_boundary(agent_id, tool, args)
        decisions.append(exec_decision)
        log_afb(AFBType.EXEC.value, exec_decision.verdict.value.upper(), exec_decision.reason)
        if exec_decision.verdict == Verdict.DENY:
            return decisions

        # 4. CTX boundary is checked post-execution (output filtering)
        # Not checked here - see check_ctx_boundary()

        return decisions

    def check_tool_boundary(self, agent_id: str, tool: str) -> AFBDecision:
        """
        Check if agent is permitted to use this tool.

        Checks the tool_allowlist in config.
        """
        allowlist = self.config.tool_allowlist.get(agent_id, [])

        # Also check wildcard agent
        wildcard_list = self.config.tool_allowlist.get("*", [])

        if tool in allowlist or tool in wildcard_list:
            return AFBDecision(
                afb=AFBType.TOOL,
                verdict=Verdict.ALLOW,
                reason=f"{tool} permitted for {agent_id}",
            )
        else:
            return AFBDecision(
                afb=AFBType.TOOL,
                verdict=Verdict.DENY,
                reason=f"{tool} not in allowlist for {agent_id}",
            )

    def check_data_boundary(
        self, agent_id: str, tool: str, args: dict
    ) -> AFBDecision:
        """
        Check if arguments are permitted for this agent-tool combination.

        Order of checks:
        1. Path traversal detection (catches .., %2e, null bytes)
        2. Deny pattern matching
        3. Allow pattern matching
        """
        # FIRST: check for path traversal attacks on ALL args
        # This must run before pattern matching to catch evasions
        for arg_name, arg_value in args.items():
            if isinstance(arg_value, str) and self._is_path_traversal(arg_value):
                return AFBDecision(
                    afb=AFBType.DATA,
                    verdict=Verdict.DENY,
                    reason=f"path traversal detected in {arg_name}",
                )

        # Find applicable rules
        applicable_rules = [
            rule
            for rule in self.config.data_rules
            if (rule.agent == agent_id or rule.agent == "*") and rule.tool == tool
        ]

        # If no rules, allow by default (tool boundary already passed)
        if not applicable_rules:
            return AFBDecision(
                afb=AFBType.DATA,
                verdict=Verdict.ALLOW,
                reason="no data rules configured",
            )

        # Check each rule
        for rule in applicable_rules:
            arg_value = args.get(rule.arg_name)
            if arg_value is None:
                continue

            # Convert to string for pattern matching
            arg_str = str(arg_value)

            # Check deny patterns first (deny takes precedence)
            for pattern in rule.deny_patterns:
                if self._matches_pattern(arg_str, pattern):
                    return AFBDecision(
                        afb=AFBType.DATA,
                        verdict=Verdict.DENY,
                        reason=f"{rule.arg_name}={arg_str} matches deny pattern {pattern}",
                    )

            # Check allow patterns
            if rule.allow_patterns:
                matched = any(
                    self._matches_pattern(arg_str, p) for p in rule.allow_patterns
                )
                if not matched:
                    return AFBDecision(
                        afb=AFBType.DATA,
                        verdict=Verdict.DENY,
                        reason=f"{rule.arg_name}={arg_str} not in allow patterns",
                    )

        return AFBDecision(
            afb=AFBType.DATA,
            verdict=Verdict.ALLOW,
            reason="arguments validated",
        )

    def check_exec_boundary(
        self, agent_id: str, tool: str, args: dict
    ) -> AFBDecision:
        """
        Check execution constraints.

        In v0.2.0, this is a placeholder that always allows.
        Future versions will add:
        - Timeout enforcement
        - Sandbox constraints
        - Resource limits
        """
        return AFBDecision(
            afb=AFBType.EXEC,
            verdict=Verdict.ALLOW,
            reason=f"timeout={self.config.exec_timeout_seconds}s",
        )

    def check_ctx_boundary(self, output: str) -> tuple[Verdict, str]:
        """
        Check and filter output (Context Boundary).

        Called after tool execution to redact sensitive data.

        Returns:
            (verdict, filtered_output)
            REDACT if patterns matched, ALLOW otherwise
        """
        if not self.config.redact_patterns:
            return Verdict.ALLOW, output

        filtered = output
        redacted = False

        for pattern in self.config.redact_patterns:
            try:
                regex = re.compile(pattern)
                if regex.search(filtered):
                    filtered = regex.sub("[REDACTED]", filtered)
                    redacted = True
            except re.error:
                pass  # Skip invalid regex

        if redacted:
            return Verdict.REDACT, filtered
        return Verdict.ALLOW, output

    def _matches_pattern(self, value: str, pattern: str) -> bool:
        """
        Check if value matches a glob pattern.

        Supports:
        - * for any characters
        - ** for recursive path matching
        - ? for single character
        """
        # Normalize paths
        if "/" in value or "/" in pattern:
            value = str(Path(value).resolve()) if not value.startswith("..") else value
            # Handle ** for recursive matching
            if "**" in pattern:
                pattern = pattern.replace("**", "*")

        return fnmatch.fnmatch(value, pattern)

    def _is_path_traversal(self, value: str) -> bool:
        """
        Detect path traversal attacks.

        Checks for:
        - ../ sequences
        - Encoded variants (%2e%2e)
        - Null bytes
        """
        # Check for basic traversal
        if ".." in value:
            return True

        # Check for URL encoded variants
        if "%2e" in value.lower() or "%252e" in value.lower():
            return True

        # Check for null bytes
        if "\x00" in value:
            return True

        return False


# =============================================================================
# Default configuration for v0.2.0 demo
# =============================================================================


def create_default_config() -> BoundaryConfig:
    """
    Create default boundary configuration for demo/testing.

    This matches the base.rego policy but adds data boundary rules
    for argument-level enforcement (the DATA sub-boundary of AFB04).
    """
    return BoundaryConfig(
        # Tool boundary: which agents can use which tools
        # Must match base.rego permitted_tools
        tool_allowlist={
            "agent-001": ["read_file"],
            "agent-researcher": ["search_web", "read_file"],
            "devops-agent": ["read_file", "list_directory"],
            "adversarial-agent": ["read_file", "list_directory"],
        },
        # Data boundary: argument-level rules
        data_rules=[
            # agent-001 can read from /tmp and /home, but not /etc or /root
            DataBoundaryRule(
                agent="agent-001",
                tool="read_file",
                arg_name="path",
                allow_patterns=["/tmp/*", "/home/*", "/var/tmp/*"],
                deny_patterns=["/etc/*", "/root/*", "*.key", "*.pem", "*shadow*", "*passwd*"],
            ),
            # devops-agent: production agent with restricted file access
            DataBoundaryRule(
                agent="devops-agent",
                tool="read_file",
                arg_name="path",
                allow_patterns=["/tmp/*", "/home/*", "/var/log/*"],
                deny_patterns=["/etc/*", "/root/*", "*.key", "*.pem", "*shadow*", "*passwd*"],
            ),
            # devops-agent can list /tmp and /home, not /etc or /root
            DataBoundaryRule(
                agent="devops-agent",
                tool="list_directory",
                arg_name="path",
                allow_patterns=["/tmp/*", "/tmp", "/home/*"],
                deny_patterns=["/etc/*", "/root/*"],
            ),
            # adversarial-agent has same restrictions as devops-agent
            DataBoundaryRule(
                agent="adversarial-agent",
                tool="read_file",
                arg_name="path",
                allow_patterns=["/tmp/*", "/home/*"],
                deny_patterns=["/etc/*", "/root/*", "*.key", "*.pem", "*shadow*"],
            ),
            # adversarial-agent can list only /tmp
            DataBoundaryRule(
                agent="adversarial-agent",
                tool="list_directory",
                arg_name="path",
                allow_patterns=["/tmp/*", "/tmp"],
                deny_patterns=["/etc/*", "/root/*", "/home/*"],
            ),
        ],
        # Exec boundary: max tool execution time
        exec_timeout_seconds=30,
        # Context boundary: redact sensitive patterns in tool output
        redact_patterns=[
            r"password\s*[:=]\s*\S+",
            r"api[_-]?key\s*[:=]\s*\S+",
            r"secret\s*[:=]\s*\S+",
            r"-----BEGIN.*PRIVATE KEY-----",
        ],
    )
