"""
Wyatt Core v0.2.0 - Runtime policy enforcement components.

This package contains the core components:
- daemon: Intercepts tool calls and routes through enforcer
- enforcer: Communicates with OPA for policy decisions
- boundaries: AFB04 sub-boundary enforcement (TOOL, DATA, EXEC, CTX)
- logger: Colored human-readable logging
- models: CEE, Verdict, AFBDecision, and related data structures
- exceptions: PolicyViolationError and related errors
"""

from wyatt.core.boundaries import BoundaryEnforcer, create_default_config
from wyatt.core.daemon import WyattDaemon
from wyatt.core.exceptions import EnforcerError, PolicyViolationError, WyattError
from wyatt.core.logger import log_enforcement
from wyatt.core.socket_server import WyattSocketServer
from wyatt.core.models import (
    AFBDecision,
    AFBType,
    BoundaryConfig,
    CanonicalExecutionEvent,
    DataBoundaryRule,
    PolicyDecision,
    ToolRequest,
    ToolResponse,
    Verdict,
)

__all__ = [
    # Daemon
    "WyattDaemon",
    # Socket Server
    "WyattSocketServer",
    # Models
    "CanonicalExecutionEvent",
    "PolicyDecision",
    "Verdict",
    "AFBType",
    "AFBDecision",
    "DataBoundaryRule",
    "BoundaryConfig",
    "ToolRequest",
    "ToolResponse",
    # Boundaries
    "BoundaryEnforcer",
    "create_default_config",
    # Exceptions
    "WyattError",
    "PolicyViolationError",
    "EnforcerError",
    # Logging
    "log_enforcement",
]
