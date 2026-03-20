"""
Tests for the socket server.

Tests socket communication, request handling, and enforcement pipeline.
These tests don't require OPA - they test the local boundary enforcement.
"""

import asyncio
import json
import os

import pytest

from wyatt.core.boundaries import create_default_config
from wyatt.core.socket_server import WyattSocketServer

# Test socket path (avoid conflicts with real daemon)
TEST_SOCKET = "/tmp/wyatt-test.sock"


@pytest.fixture
def config():
    return create_default_config()


@pytest.fixture
def server(config):
    """Create a test server with mock tools."""

    def mock_read_file(path: str) -> str:
        return f"Mock contents of {path}"

    def mock_list_directory(path: str) -> str:
        return f"Mock listing of {path}"

    srv = WyattSocketServer(
        config=config,
        socket_path=TEST_SOCKET,
    )
    srv.register_tool("read_file", mock_read_file)
    srv.register_tool("list_directory", mock_list_directory)
    return srv


async def send_request(
    request: dict,
    socket_path: str = TEST_SOCKET,
    register_first: bool = True,
) -> dict:
    """Helper: send a JSON request and get response."""
    reader, writer = await asyncio.open_unix_connection(socket_path)
    action = request.get("action", "execute")
    if register_first and action not in ("register", "disconnect"):
        register = json.dumps({
            "action": "register",
            "agent_id": request.get("agent_id", "unknown"),
        })
        writer.write((register + "\n").encode("utf-8"))
        await writer.drain()
        await reader.readline()

    writer.write((json.dumps(request) + "\n").encode("utf-8"))
    await writer.drain()
    data = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return json.loads(data.decode("utf-8").strip())


@pytest.mark.asyncio
async def test_server_starts_and_stops(server):
    """Server can start and stop cleanly."""
    await server.start()
    assert os.path.exists(TEST_SOCKET)
    await server.stop()
    assert not os.path.exists(TEST_SOCKET)


@pytest.mark.asyncio
async def test_agent_registration(server):
    """Agent can register with the daemon."""
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(TEST_SOCKET)
        register = json.dumps({
            "action": "register",
            "agent_id": "test-agent",
        })
        writer.write((register + "\n").encode("utf-8"))
        await writer.drain()

        data = await reader.readline()
        resp = json.loads(data.decode("utf-8").strip())
        assert resp["status"] == "registered"
        assert resp["agent_id"] == "test-agent"

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_non_object_json_returns_deny(server):
    """Non-object JSON payloads should return a DENY response."""
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(TEST_SOCKET)
        writer.write(b"[\"not\", \"an\", \"object\"]\n")
        await writer.drain()

        data = await reader.readline()
        resp = json.loads(data.decode("utf-8").strip())
        assert resp["verdict"] == "deny"
        assert "must be an object" in resp["reason"]

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_execute_requires_registration(server):
    """Agent must register before execution requests are accepted."""
    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "read_file",
            "args": {"path": "/tmp/test.log"},
        }, register_first=False)
        assert resp["verdict"] == "deny"
        assert "must register" in resp["reason"]
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_allowed_tool_request(server):
    """Permitted tool with safe path should return ALLOW."""
    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "read_file",
            "args": {"path": "/tmp/test.log"},
        })
        assert resp["verdict"] == "allow"
        assert "Mock contents" in resp["result"]
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_denied_tool_request(server):
    """Forbidden tool should return DENY at TOOL boundary."""
    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "delete_file",
            "args": {"path": "/tmp/test"},
        })
        assert resp["verdict"] == "deny"
        assert "not in allowlist" in resp["reason"]
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_registered_identity_mismatch_denied(server):
    """Registered agent identity is authoritative for the socket session."""
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(TEST_SOCKET)

        register = json.dumps({
            "action": "register",
            "agent_id": "devops-agent",
        })
        writer.write((register + "\n").encode("utf-8"))
        await writer.drain()
        await reader.readline()

        execute_as_other = json.dumps({
            "action": "execute",
            "agent_id": "unknown-agent",
            "tool": "read_file",
            "args": {"path": "/tmp/test.log"},
        })
        writer.write((execute_as_other + "\n").encode("utf-8"))
        await writer.drain()

        data = await reader.readline()
        resp = json.loads(data.decode("utf-8").strip())
        assert resp["verdict"] == "deny"
        assert "mismatch" in resp["reason"]

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_reregister_same_identity_allowed(server):
    """Re-registering with the same identity should be idempotent."""
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(TEST_SOCKET)

        register = json.dumps({"action": "register", "agent_id": "devops-agent"})
        writer.write((register + "\n").encode("utf-8"))
        await writer.drain()
        first = json.loads((await reader.readline()).decode("utf-8").strip())
        assert first["status"] == "registered"
        assert first["agent_id"] == "devops-agent"

        writer.write((register + "\n").encode("utf-8"))
        await writer.drain()
        second = json.loads((await reader.readline()).decode("utf-8").strip())
        assert second["status"] == "registered"
        assert second["agent_id"] == "devops-agent"

        exec_request = json.dumps({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "read_file",
            "args": {"path": "/tmp/test.log"},
        })
        writer.write((exec_request + "\n").encode("utf-8"))
        await writer.drain()

        exec_resp = json.loads((await reader.readline()).decode("utf-8").strip())
        assert exec_resp["verdict"] == "allow"

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_reregister_different_identity_denied(server):
    """Re-registering with a different identity should be denied and closed."""
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(TEST_SOCKET)

        register_a = json.dumps({"action": "register", "agent_id": "devops-agent"})
        writer.write((register_a + "\n").encode("utf-8"))
        await writer.drain()
        first = json.loads((await reader.readline()).decode("utf-8").strip())
        assert first["status"] == "registered"
        assert first["agent_id"] == "devops-agent"

        register_b = json.dumps({"action": "register", "agent_id": "unknown-agent"})
        writer.write((register_b + "\n").encode("utf-8"))
        await writer.drain()
        deny = json.loads((await reader.readline()).decode("utf-8").strip())
        assert deny["verdict"] == "deny"
        assert "Re-registration" in deny["reason"]

        # server closes the connection after rejecting identity switch
        closed = await reader.readline()
        assert closed == b""

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_denied_path_request(server):
    """Permitted tool with forbidden path should return DENY at DATA boundary."""
    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "read_file",
            "args": {"path": "/etc/shadow"},
        })
        assert resp["verdict"] == "deny"
        assert "deny pattern" in resp["reason"]
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_path_traversal_denied(server):
    """Path traversal should be caught and denied."""
    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "read_file",
            "args": {"path": "../../etc/passwd"},
        })
        assert resp["verdict"] == "deny"
        assert "traversal" in resp["reason"]
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_unknown_agent_denied(server):
    """Unknown agent should be denied at TOOL boundary."""
    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "unknown-hacker",
            "tool": "read_file",
            "args": {"path": "/tmp/test"},
        })
        assert resp["verdict"] == "deny"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_afb_checks_included_in_response(server):
    """Response should include all AFB check decisions."""
    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "read_file",
            "args": {"path": "/tmp/test.log"},
        })
        assert "afb_checks" in resp
        afb_types = [c["afb"] for c in resp["afb_checks"]]
        assert "TOOL" in afb_types
        assert "DATA" in afb_types
        assert "EXEC" in afb_types
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_output_redaction(server):
    """Tool output containing secrets should be redacted."""
    # Register a tool that returns sensitive data
    def leaky_tool(path: str) -> str:
        return "config loaded\npassword = super_secret\nready"

    server.register_tool("leaky_read", leaky_tool)
    # Add leaky_read to devops-agent allowlist
    server.config.tool_allowlist["devops-agent"].append("leaky_read")

    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "leaky_read",
            "args": {"path": "/tmp/test"},
        })
        assert resp["verdict"] == "redact"
        assert "super_secret" not in resp["result"]
        assert "[REDACTED]" in resp["result"]
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_invalid_json_handled(server):
    """Invalid JSON should return a DENY response, not crash."""
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(TEST_SOCKET)
        writer.write(b"not valid json\n")
        await writer.drain()

        data = await reader.readline()
        resp = json.loads(data.decode("utf-8").strip())
        assert resp["verdict"] == "deny"
        assert "Invalid JSON" in resp["reason"]

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_unregistered_tool_denied(server):
    """Request for a tool not registered in daemon returns DENY even if policy allows."""
    # The tool is in the allowlist but not registered as a callable
    server.config.tool_allowlist["devops-agent"].append("super_tool")

    await server.start()
    try:
        resp = await send_request({
            "action": "execute",
            "agent_id": "devops-agent",
            "tool": "super_tool",
            "args": {},
        })
        assert resp["verdict"] == "deny"
        assert "not registered" in resp["reason"]
    finally:
        await server.stop()
