"""Clients for the Wyatt daemon's agent and control sockets.

The wire format is one JSON object per line over a Unix socket. Every
request gets exactly one reply, in order, so a client is a socket, a lock
and a line reader.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, TypeVar

MAX_LINE = 1 << 20

F = TypeVar("F", bound=Callable[..., Any])


def _runtime_dir() -> Path:
    if os.geteuid() == 0:
        return Path("/run/wyatt")
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "wyatt"
    return Path(f"/tmp/wyatt-{os.getuid()}")


def agent_socket() -> Path:
    """Where the daemon listens for agents: $WYATT_SOCKET, else the runtime dir."""
    return Path(os.environ.get("WYATT_SOCKET") or _runtime_dir() / "agent.sock")


def control_socket() -> Path:
    return Path(os.environ.get("WYATT_CONTROL") or _runtime_dir() / "control.sock")


class WyattError(Exception):
    """Base class for everything this package raises."""


class ConnectError(WyattError):
    """The daemon could not be reached. Callers should fail closed."""


class RequestError(WyattError):
    """The daemon refused a request: bad protocol use, identity, unknown ticket."""

    def __init__(self, status: str, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Decision:
    """The daemon's answer for one tool call."""

    decision: str
    code: str
    reason: str
    audit: Optional[int] = None
    rule: Optional[str] = None
    ticket: Optional[str] = None
    #: The arguments as checked, after normalization. Run these, not the originals.
    args: Any = None
    #: False in monitor mode, where `decision` is allow and `would` holds the real verdict.
    enforced: bool = True
    would: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def describe(self) -> str:
        tag = []
        if self.rule:
            tag.append(f"rule {self.rule}")
        if self.audit is not None:
            tag.append(f"audit #{self.audit}")
        return f"{self.reason} [{', '.join(tag)}]" if tag else self.reason

    @classmethod
    def _from(cls, r: Mapping[str, Any]) -> "Decision":
        return cls(
            decision=r.get("decision", "deny"),
            code=r.get("code", ""),
            reason=r.get("reason", ""),
            audit=r.get("audit"),
            rule=r.get("rule"),
            ticket=r.get("ticket"),
            args=r.get("args"),
            enforced=r.get("enforced", True),
            would=r.get("would"),
        )


class Denied(WyattError):
    """The policy did not allow the call."""

    def __init__(self, tool: str, decision: Decision):
        super().__init__(f"wyatt denied {tool}: {decision.describe()}")
        self.tool = tool
        self.decision = decision


class ToolFailed(WyattError):
    """The call was allowed but the tool did not finish: refused by the kernel, timed out, or failed."""

    def __init__(self, tool: str, status: str, message: str, decision: Decision):
        super().__init__(f"{tool} {status}: {message}")
        self.tool = tool
        self.status = status
        self.message = message
        self.decision = decision


@dataclass(frozen=True)
class Hello:
    agent: str
    session: str
    labels: frozenset
    policy: Mapping[str, Any]
    #: Tool entries the policy lets this agent reach: name, driver, args, description.
    tools: list = field(default_factory=list)


@dataclass(frozen=True)
class Call:
    """A tool Wyatt ran itself (proc, fs, http)."""

    decision: Decision
    result: Any
    labels: frozenset
    redacted: Mapping[str, int]


@dataclass(frozen=True)
class Report:
    """The daemon's answer to a reported output."""

    output: Any
    labels: frozenset
    redacted: Mapping[str, int]


class _Line:
    def __init__(self, path: Path, timeout: Optional[float]):
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect(str(path))
        except OSError as e:
            self.sock.close()
            raise ConnectError(f"cannot reach wyatt at {path} (is `wyatt serve` running?): {e}") from e
        self.r = self.sock.makefile("rb")
        self.lock = threading.Lock()

    def send(self, req: Mapping[str, Any]) -> dict:
        data = json.dumps(req, separators=(",", ":"), default=_jsonable).encode() + b"\n"
        with self.lock:
            try:
                self.sock.sendall(data)
                line = self.r.readline(MAX_LINE + 1)
            except OSError as e:
                raise ConnectError(f"lost the connection to wyatt: {e}") from e
        if not line:
            raise ConnectError("wyatt closed the connection")
        if len(line) > MAX_LINE:
            raise WyattError("reply from wyatt is too long")
        return json.loads(line)

    def close(self) -> None:
        self.r.close()
        self.sock.close()


def _jsonable(v: Any) -> Any:
    if isinstance(v, (set, frozenset, tuple)):
        return list(v)
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    if isinstance(v, os.PathLike):
        return os.fspath(v)
    return str(v)


def _raise_error(r: Mapping[str, Any]) -> None:
    e = r.get("error")
    if e is not None:
        raise RequestError(e.get("status", "error"), e.get("message", ""))


class Client:
    """One agent connection.

    Safe to share between threads; requests on one client are sent one at a
    time. A call that waits for a human approval holds the connection, so
    give parallel workers their own client with the same `session` name to
    share labels and counters.
    """

    def __init__(
        self,
        agent: str,
        *,
        session: Optional[str] = None,
        token: Optional[str] = None,
        socket_path: Optional[os.PathLike | str] = None,
        timeout: Optional[float] = None,
    ):
        self.agent = agent
        self.session_name = session
        self.token = token if token is not None else os.environ.get("WYATT_TOKEN") or None
        self.socket_path = Path(socket_path) if socket_path else agent_socket()
        self.timeout = timeout
        self._conn: Optional[_Line] = None
        self._hello: Optional[Hello] = None
        self._open = threading.Lock()

    def __enter__(self) -> "Client":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def connect(self) -> Hello:
        with self._open:
            if self._conn is None:
                conn = _Line(self.socket_path, self.timeout)
                r = conn.send({"op": "hello", "agent": self.agent, "token": self.token, "session": self.session_name})
                if "error" in r:
                    conn.close()
                    _raise_error(r)
                self._conn = conn
                self._hello = Hello(
                    agent=r["agent"],
                    session=r["session"],
                    labels=frozenset(r.get("labels", [])),
                    policy=r.get("policy", {}),
                    tools=r.get("tools", []),
                )
            assert self._hello is not None
            return self._hello

    def close(self) -> None:
        with self._open:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _send(self, req: dict) -> dict:
        self.connect()
        assert self._conn is not None
        return self._conn.send(req)

    def call(self, tool: str, args: Optional[Mapping[str, Any]] = None, /, **kwargs: Any) -> Call:
        """Asks Wyatt to run a tool it owns (proc, fs, http).

        Raises `Denied` when the policy says no and `ToolFailed` when the
        tool was allowed but did not finish.
        """
        r = self._send({"op": "call", "tool": tool, "args": {**(args or {}), **kwargs}})
        if "decision" not in r:
            _raise_error(r)
        d = Decision._from(r)
        if not d.allowed:
            raise Denied(tool, d)
        if "error" in r:
            e = r["error"]
            raise ToolFailed(tool, e.get("status", "error"), e.get("message", ""), d)
        return Call(d, r.get("result"), frozenset(r.get("labels", [])), r.get("redacted", {}))

    def check(
        self,
        tool: str,
        args: Optional[Mapping[str, Any]] = None,
        *,
        ticket: Optional[str] = None,
        ask: bool = False,
    ) -> Decision:
        """Decides a call the agent will run itself. Does not raise on deny.

        With `ask=True` an approve verdict comes back at once for the caller
        to put to its own user; otherwise the daemon waits for an approver.
        """
        req: dict = {"op": "check", "tool": tool, "args": dict(args or {}), "ask": ask}
        if ticket is not None:
            req["ticket"] = ticket
        r = self._send(req)
        if "decision" not in r:
            _raise_error(r)
        return Decision._from(r)

    def report(self, ticket: str, output: Any, *, ok: bool = True) -> Report:
        """Reports what a checked call returned. The reply carries the output after DLP."""
        r = self._send({"op": "result", "ticket": ticket, "ok": ok, "output": output})
        _raise_error(r)
        return Report(r.get("output"), frozenset(r.get("labels", [])), r.get("redacted", {}))

    def run(self, tool: str, fn: Callable[..., Any], args: Mapping[str, Any]) -> Any:
        """Checks, runs `fn` with the checked arguments, and reports the output.

        Returns the original output, or the redacted one if DLP found secrets.
        """
        d = self.check(tool, args)
        if not d.allowed:
            raise Denied(tool, d)
        checked = d.args if isinstance(d.args, Mapping) else args
        try:
            out = fn(**checked)
        except Exception as e:
            if d.ticket:
                self.report(d.ticket, f"{type(e).__name__}: {e}", ok=False)
            raise
        if not d.ticket:
            return out
        rep = self.report(d.ticket, _wire(out))
        return rep.output if rep.redacted else out

    def tool(self, name: Optional[str] = None) -> Callable[[F], F]:
        """Decorator for a delegate tool: every call goes through `run`.

            @client.tool("send_email")
            def send_email(to: str, body: str) -> str: ...
        """

        def wrap(fn: F) -> F:
            sig = inspect.signature(fn)
            tool_name = name or fn.__name__

            @functools.wraps(fn)
            def guarded(*a: Any, **kw: Any) -> Any:
                bound = sig.bind(*a, **kw)
                bound.apply_defaults()
                return self.run(tool_name, fn, dict(bound.arguments))

            return guarded  # type: ignore[return-value]

        return wrap

    def visible(self, tools: list[str]) -> list[str]:
        """Which of these tool names this agent could ever be allowed to call."""
        r = self._send({"op": "visible", "tools": list(tools)})
        _raise_error(r)
        return list(r.get("tools", []))

    def notice(self, event: str, *, tool: Optional[str] = None, detail: Any = None) -> int:
        """Puts an event on the audit record. Returns its sequence number."""
        r = self._send({"op": "notice", "event": event, "tool": tool, "detail": detail})
        _raise_error(r)
        return int(r["audit"])

    @property
    def labels(self) -> frozenset:
        """Labels as of the last hello. `Call.labels` and `Report.labels` are current."""
        return self.connect().labels


def _wire(v: Any) -> Any:
    """Output as JSON the daemon can scan; anything else becomes text."""
    try:
        json.dumps(v)
        return v
    except (TypeError, ValueError):
        return json.loads(json.dumps(v, default=_jsonable))


class Control:
    """The operator socket: status, approvals and the kill switch.

    The daemon only accepts connections from its own user or root.
    """

    def __init__(self, socket_path: Optional[os.PathLike | str] = None, timeout: Optional[float] = 10.0):
        self.socket_path = Path(socket_path) if socket_path else control_socket()
        self.timeout = timeout

    def _req(self, req: dict) -> dict:
        conn = _Line(self.socket_path, self.timeout)
        try:
            r = conn.send(req)
        finally:
            conn.close()
        _raise_error(r)
        return r

    def status(self) -> dict:
        return self._req({"op": "status"})

    def sessions(self) -> list:
        return self._req({"op": "sessions"})["sessions"]

    def approvals(self) -> list:
        return self._req({"op": "approvals"})["approvals"]

    def approve(self, id: int) -> None:
        self._req({"op": "approve", "id": id})

    def deny(self, id: int, reason: Optional[str] = None) -> None:
        self._req({"op": "deny", "id": id, "reason": reason})

    def freeze(self, reason: Optional[str] = None) -> None:
        self._req({"op": "freeze", "reason": reason})

    def unfreeze(self) -> None:
        self._req({"op": "unfreeze"})

    def reload(self) -> dict:
        return self._req({"op": "reload"})
