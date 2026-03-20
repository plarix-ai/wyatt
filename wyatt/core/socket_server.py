"""
Wyatt Socket Server - Unix domain socket daemon for v0.2.0.

Accepts agent connections over /tmp/wyatt.sock, routes tool requests
through BoundaryEnforcer → OPA → tool execution, returns verdicts.

The socket server is the communication layer between the agent process
and the Wyatt enforcement daemon. Agents send JSON ToolRequests,
Wyatt responds with JSON ToolResponses.

Architecture:
    Agent Process → Unix Socket → WyattSocketServer
                                      ↓
                               BoundaryEnforcer (AFB04)
                                      ↓
                               PolicyEnforcer (OPA)
                                      ↓
                               Tool Execution / Deny
                                      ↓
                               ToolResponse → Agent
"""

import asyncio
import json
import os
import signal
from collections.abc import Callable
from typing import Any

from wyatt.core.boundaries import BoundaryEnforcer
from wyatt.core.logger import (
    log_afb,
    log_allow,
    log_connection,
    log_deny,
    log_error,
    log_request,
    log_wyatt,
    log_wyatt_banner,
)
from wyatt.core.models import (
    AFBDecision,
    AFBType,
    BoundaryConfig,
    ToolRequest,
    ToolResponse,
    Verdict,
)


class WyattSocketServer:
    """
    Unix domain socket server for Wyatt daemon.

    Listens on a Unix socket, accepts connections from agent processes,
    enforces AFB04 boundaries on every tool request, and returns verdicts.
    """

    def __init__(
        self,
        config: BoundaryConfig,
        tool_registry: dict[str, Callable[..., Any]] | None = None,
        socket_path: str = "/tmp/wyatt.sock",
    ) -> None:
        """
        Initialize the socket server.

        Args:
            config: BoundaryConfig with all AFB04 rules
            tool_registry: Map of tool_name -> callable for actual execution
            socket_path: Path for the Unix domain socket
        """
        self.config = config
        self.boundary_enforcer = BoundaryEnforcer(config)
        self.tool_registry = tool_registry or {}
        self.socket_path = socket_path
        self._server: asyncio.AbstractServer | None = None
        self._running = False

    def register_tool(self, name: str, func: Callable[..., Any]) -> None:
        """Register a tool callable that Wyatt can execute on behalf of agents."""
        self.tool_registry[name] = func

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Handle a single agent connection.

        Reads newline-delimited JSON messages, processes each as a ToolRequest,
        and writes back ToolResponse JSON.
        """
        registered_agent_id: str | None = None

        try:
            while self._running:
                # Read one line (newline-delimited JSON)
                data = await reader.readline()
                if not data:
                    break

                line = data.decode("utf-8").strip()
                if not line:
                    continue

                try:
                    request_data = json.loads(line)
                except json.JSONDecodeError as e:
                    error_resp = ToolResponse(
                        verdict=Verdict.DENY,
                        reason=f"Invalid JSON: {e}",
                    )
                    writer.write(
                        (error_resp.model_dump_json() + "\n").encode("utf-8")
                    )
                    await writer.drain()
                    continue

                # Handle special actions
                action = request_data.get("action", "execute")

                if action == "register":
                    agent_id = request_data.get("agent_id", "unknown")
                    registered_agent_id = agent_id
                    log_connection(agent_id, "connected")
                    resp = {"status": "registered", "agent_id": agent_id}
                    writer.write(
                        (json.dumps(resp) + "\n").encode("utf-8")
                    )
                    await writer.drain()
                    continue

                if action == "disconnect":
                    if registered_agent_id:
                        log_connection(registered_agent_id, "disconnected")
                    break

                # Process tool request
                try:
                    request = ToolRequest(**request_data)
                except Exception as e:
                    error_resp = ToolResponse(
                        verdict=Verdict.DENY,
                        reason=f"Invalid request format: {e}",
                    )
                    writer.write(
                        (error_resp.model_dump_json() + "\n").encode("utf-8")
                    )
                    await writer.drain()
                    continue

                if not registered_agent_id:
                    error_resp = ToolResponse(
                        verdict=Verdict.DENY,
                        reason="Agent must register before executing tools",
                    )
                    writer.write(
                        (error_resp.model_dump_json() + "\n").encode("utf-8")
                    )
                    await writer.drain()
                    continue

                if request.agent_id != registered_agent_id:
                    error_resp = ToolResponse(
                        verdict=Verdict.DENY,
                        reason="agent_id mismatch with registered identity",
                    )
                    writer.write(
                        (error_resp.model_dump_json() + "\n").encode("utf-8")
                    )
                    await writer.drain()
                    continue

                # Process the request through enforcement
                response = await self._process_request(request)

                # Send response
                writer.write(
                    (response.model_dump_json() + "\n").encode("utf-8")
                )
                await writer.drain()

        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            if registered_agent_id:
                log_connection(registered_agent_id, "connection reset")
        except Exception as e:
            log_error(f"Connection error: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_request(self, request: ToolRequest) -> ToolResponse:
        """
        Process a single tool request through all AFB04 boundaries.

        Flow:
            1. Log the request
            2. Check TOOL, DATA, EXEC boundaries via BoundaryEnforcer
            3. If all ALLOW → execute tool
            4. If CTX patterns match → redact output
            5. Return ToolResponse with verdict
        """
        # Log the incoming request
        log_request(request.agent_id, request.tool, request.args)

        # Run boundary checks (TOOL, DATA, EXEC)
        decisions = self.boundary_enforcer.check_all(
            agent_id=request.agent_id,
            tool=request.tool,
            args=request.args,
        )

        # Check if any boundary denied
        denied = [d for d in decisions if d.verdict == Verdict.DENY]
        if denied:
            deny_reason = denied[0].reason
            log_deny(f"Blocked: {deny_reason}")
            return ToolResponse(
                verdict=Verdict.DENY,
                reason=deny_reason,
                afb_checks=decisions,
            )

        # All boundaries passed - execute tool
        tool_func = self.tool_registry.get(request.tool)
        if not tool_func:
            log_deny(f"Tool {request.tool} not registered in daemon")
            return ToolResponse(
                verdict=Verdict.DENY,
                reason=f"Tool {request.tool} not registered",
                afb_checks=decisions,
            )

        try:
            result = tool_func(**request.args)
            result_str = str(result)

            # CTX boundary: check output for sensitive data
            ctx_verdict, filtered_output = self.boundary_enforcer.check_ctx_boundary(result_str)
            if ctx_verdict == Verdict.REDACT:
                log_afb("CTX", "REDACT", "sensitive patterns found in output")
                decisions.append(
                    AFBDecision(
                        afb=AFBType.CTX,
                        verdict=Verdict.REDACT,
                        reason="sensitive patterns redacted from output",
                    )
                )
                log_allow(
                    f"Executed {request.tool} (output redacted) → {len(filtered_output)} chars"
                )
                return ToolResponse(
                    verdict=Verdict.REDACT,
                    result=filtered_output,
                    reason="Output redacted: sensitive patterns removed",
                    afb_checks=decisions,
                )
            else:
                log_afb("CTX", "ALLOW", "no sensitive patterns in output")
                decisions.append(
                    AFBDecision(
                        afb=AFBType.CTX,
                        verdict=Verdict.ALLOW,
                        reason="output clean",
                    )
                )

            log_allow(f"Executed {request.tool} → {len(result_str)} chars")
            return ToolResponse(
                verdict=Verdict.ALLOW,
                result=result,
                reason="All boundaries passed",
                afb_checks=decisions,
            )

        except Exception as e:
            log_error(f"Tool execution failed: {e}")
            return ToolResponse(
                verdict=Verdict.DENY,
                reason=f"Tool execution error: {e}",
                afb_checks=decisions,
            )

    async def start(self) -> None:
        """Start the Unix socket server."""
        # Clean up stale socket
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        self._running = True
        self._server = await asyncio.start_unix_server(
            self.handle_connection,
            path=self.socket_path,
        )

        # Make socket accessible
        os.chmod(self.socket_path, 0o770)

        log_wyatt_banner()
        log_wyatt(f"Socket listening at {self.socket_path}")
        log_wyatt(f"Boundary config loaded: {len(self.config.tool_allowlist)} agents, "
                  f"{len(self.config.data_rules)} data rules, "
                  f"{len(self.config.redact_patterns)} redact patterns")
        log_wyatt("Waiting for agent connections...")
        print()

    async def serve_forever(self) -> None:
        """Run the server until interrupted."""
        if not self._server:
            raise RuntimeError("Server not started. Call start() first.")

        # Handle graceful shutdown
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _signal_handler() -> None:
            log_wyatt("Shutting down...")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)

        try:
            await stop_event.wait()
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop the server and clean up."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        log_wyatt("Server stopped.")
