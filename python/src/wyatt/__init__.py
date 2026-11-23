"""Python client for Wyatt, a runtime policy enforcement daemon for AI agents.

    from wyatt import Client

    with Client("ops", session="task-42") as w:
        logs = w.call("read_logs", path="/var/log/app.log").result

        @w.tool("send_email")
        def send_email(to: str, body: str) -> str:
            ...

Adapters live in `wyatt.langchain` and `wyatt.openai_agents` and import
their frameworks only when used.
"""

from .client import (
    Call,
    Client,
    ConnectError,
    Control,
    Decision,
    Denied,
    Hello,
    Report,
    RequestError,
    ToolFailed,
    WyattError,
    agent_socket,
    control_socket,
)

__all__ = [
    "Call",
    "Client",
    "ConnectError",
    "Control",
    "Decision",
    "Denied",
    "Hello",
    "Report",
    "RequestError",
    "ToolFailed",
    "WyattError",
    "agent_socket",
    "control_socket",
]

__version__ = "1.0.0rc1"
