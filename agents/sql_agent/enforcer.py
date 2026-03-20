"""
Wyatt enforcer for SQL Agent.

Uses the SQL adapter to enforce data access policies.
"""

import sys
from pathlib import Path
from dataclasses import dataclass

# Import from adapters
sys.path.insert(0, str(Path(__file__).parent / "../../adapters/sql"))
from adapter import enforce_data_access, PolicyDecision


class WyattEnforcer:
    """
    Wyatt policy enforcer.

    enabled=True: Calls OPA via adapter
    enabled=False: Bypass (vulnerable mode)
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def check(self, sql: str, user_id: str) -> PolicyDecision:
        """Check if SQL query is allowed for user."""
        if not self.enabled:
            return PolicyDecision(allowed=True, reason="Wyatt disabled")
        return enforce_data_access(sql, user_id)

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False


# For backward compatibility with test scripts
check_policy_with_opa = enforce_data_access
