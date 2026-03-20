#!/usr/bin/env python3
"""
Real, programmatic CLI Agent for Wyatt v0.2.0.

This script replaces the old hardcoded "mock" simple_agent.
It accepts dynamic tool requests via command line arguments,
serializes them into validated JSON using Wyatt's core models,
and executes them over the Unix socket.

Usage:
    python3 cli_agent.py --agent devops-agent --tool read_file --arg path=/etc/passwd
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Ensure wyatt package is importable via the src layout
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.logger import log_agent, log_result, log_error
from core.models import ToolRequest, ToolResponse


async def run_cli_agent(agent_id: str, tool: str, args_dict: dict, socket_path: str) -> None:
    """Connect to Wyatt and execute exactly what the user requested."""
    log_agent(f"Connecting to Wyatt Daemon at {socket_path}...")
    
    try:
        reader, writer = await asyncio.open_unix_connection(socket_path)
    except ConnectionRefusedError:
        log_error("Connection refused. Is the Wyatt Daemon running?")
        sys.exit(1)
    except FileNotFoundError:
        log_error(f"Socket not found at {socket_path}. Is the Wyatt Daemon running?")
        sys.exit(1)

    # 1. Registration Phase
    log_agent(f"Registering as '{agent_id}'...")
    req = {"action": "register", "agent_id": agent_id}
    writer.write((json.dumps(req) + "\n").encode("utf-8"))
    await writer.drain()

    reg_resp_raw = await reader.readline()
    if not reg_resp_raw:
        log_error("Connection closed by daemon during registration.")
        sys.exit(1)
        
    reg_resp = json.loads(reg_resp_raw.decode("utf-8").strip())
    if reg_resp.get("status") != "registered":
        log_error(f"Registration failed: {reg_resp}")
        sys.exit(1)

    log_agent("Registration successful.")

    # 2. Execution Phase
    log_agent(f"Executing tool '{tool}' with args: {args_dict}")
    
    # We use the real Pydantic model to construct the payload
    # This proves we are a "real" programmed agent, not a hardcoded string
    tool_req = ToolRequest(
        action="execute",
        agent_id=agent_id,
        tool=tool,
        args=args_dict
    )
    
    payload = tool_req.model_dump_json()
    writer.write((payload + "\n").encode("utf-8"))
    await writer.drain()

    # 3. Response Phase
    resp_raw = await reader.readline()
    if not resp_raw:
        log_error("Connection closed by daemon during execution.")
        sys.exit(1)
        
    try:
        # Validate response using the real model
        resp_data = json.loads(resp_raw.decode("utf-8").strip())
        tool_resp = ToolResponse(**resp_data)
        
        # Display results cleanly
        log_result(
            verdict=tool_resp.verdict.value.upper(),
            message=tool_resp.reason
        )
        
        if tool_resp.result:
            print("\n--- Output ---")
            print(tool_resp.result)
            print("--------------\n")
            
    except Exception as e:
        log_error(f"Failed to parse response: {e}\nRaw: {resp_raw.decode('utf-8')}")
    finally:
        log_agent("Closing connection.")
        writer.close()
        await writer.wait_closed()


def main():
    parser = argparse.ArgumentParser(description="Wyatt CLI Agent")
    parser.add_argument("--agent", required=True, help="Agent ID (e.g., devops-agent)")
    parser.add_argument("--tool", required=True, help="Tool name to execute (e.g., read_file)")
    parser.add_argument("--arg", action="append", default=[], help="Arguments in key=value format")
    parser.add_argument("--socket", default="/tmp/wyatt.sock", help="Path to Wyatt Unix socket")
    
    args = parser.parse_args()

    # Parse key=value arguments into a dictionary
    args_dict = {}
    for arg_pair in args.arg:
        if "=" not in arg_pair:
            print(f"Error: Argument '{arg_pair}' must be in key=value format.")
            sys.exit(1)
        key, value = arg_pair.split("=", 1)
        args_dict[key] = value

    try:
        asyncio.run(run_cli_agent(args.agent, args.tool, args_dict, args.socket))
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
