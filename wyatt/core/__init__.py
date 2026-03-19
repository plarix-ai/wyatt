"""
Wyatt Core - Runtime policy enforcement components.

This package contains the four core components:
- daemon: Intercepts tool calls and routes through enforcer
- enforcer: Communicates with OPA for policy decisions
- logger: Structured CEE logging
- models: CEE and related data structures
- exceptions: PolicyViolationError and related errors
"""

from wyatt.core.daemon import WyattDaemon
from wyatt.core.exceptions import EnforcerError, PolicyViolationError, WyattError
from wyatt.core.logger import log_enforcement
from wyatt.core.models import CanonicalExecutionEvent, EnforcementLog, PolicyDecision

__all__ = [
    "WyattDaemon",
    "CanonicalExecutionEvent",
    "EnforcementLog",
    "PolicyDecision",
    "WyattError",
    "PolicyViolationError",
    "EnforcerError",
    "log_enforcement",
]
