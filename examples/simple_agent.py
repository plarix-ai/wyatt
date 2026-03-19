#!/usr/bin/env python3
"""
Simple agent demonstrating Wyatt v0.1.0 enforcement.

This agent attempts three tool calls:
1. Permitted tool (read_file) → ALLOW, executes
2. Forbidden tool (delete_database) → DENY, PolicyViolationError
3. Unknown tool (hack_system) → DENY by default

Run with: python3 examples/simple_agent.py

Expected output: Three CEE log entries showing enforcement decisions.
"""

import asyncio
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Callable

# Add parent directory to path so we can import wyatt
sys.path.insert(0, str(Path(__file__).parent.parent))

from wyatt.core import PolicyViolationError, WyattDaemon


# ============================================================================
# TOOL DEFINITIONS
# These are the actual functions the agent wants to use
# ============================================================================


def read_file(path: str) -> str:
    """
    Read a file from disk.

    This is a PERMITTED tool for agent-001.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read().strip()


def delete_database(name: str) -> str:
    """
    Delete a database (destructive operation).

    This is FORBIDDEN for agent-001 (not in allowlist).
    """
    # This function should NEVER execute for agent-001
    return f"[DANGER] Deleted database: {name}"


def hack_system(target: str) -> str:
    """
    Unknown malicious tool.

    This is UNKNOWN (not in policy at all) → deny by default.
    """
    # This function should NEVER execute
    return f"[DANGER] Hacked system: {target}"


# ============================================================================
# AGENT IMPLEMENTATION
# ============================================================================


async def run_agent():
    """
    Run the example agent through all three scenarios.
    """
    daemon = WyattDaemon()
    agent_id = "agent-001"

    async def run_scenario(
        name: str,
        tool_name: str,
        tool_callable: Callable[..., str],
        tool_args: dict[str, Any],
    ) -> None:
        input_payload = {
            "agent": agent_id,
            "tool": tool_name,
            "args": tool_args,
        }

        log_buffer = io.StringIO()
        output_text = ""

        try:
            with redirect_stdout(log_buffer):
                result = await daemon.execute_tool(
                    agent_id=agent_id,
                    tool_name=tool_name,
                    tool_callable=tool_callable,
                    tool_args=tool_args,
                )
            output_text = f"tool executed successfully: {result}"
        except PolicyViolationError as e:
            output_text = f"execution blocked: {e.reason}"

        raw_log = ""
        log_data: dict[str, Any] = {}
        decode_error = False
        for line in reversed(log_buffer.getvalue().splitlines()):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and parsed.get("event") == "enforcement_decision":
                raw_log = stripped
                log_data = parsed
                break

        if not raw_log:
            for line in log_buffer.getvalue().splitlines():
                stripped = line.strip()
                if stripped:
                    raw_log = stripped
                    break
        try:
            if raw_log and not log_data:
                log_data = json.loads(raw_log)
        except json.JSONDecodeError:
            decode_error = True
            log_data = {}
        decision = log_data.get("decision", "UNKNOWN")
        reason = log_data.get("policy_basis", "No policy basis recorded")
        if decode_error and raw_log:
            reason = f"CEE log parse error: {raw_log}"

        print(f"SCENARIO: {name}")
        print(f"INPUT:    {json.dumps(input_payload)}")
        print(f"DECISION: {decision}")
        print(f"REASON:   {reason}")
        print(f"OUTPUT:   {output_text}")
        print(f"CEE LOG:  {raw_log}")
        print()

    await run_scenario(
        name="permitted tool: read_file",
        tool_name="read_file",
        tool_callable=read_file,
        tool_args={"path": "/etc/hostname"},
    )
    await run_scenario(
        name="forbidden tool: delete_database",
        tool_name="delete_database",
        tool_callable=delete_database,
        tool_args={"name": "production"},
    )
    await run_scenario(
        name="unknown tool: hack_system",
        tool_name="hack_system",
        tool_callable=hack_system,
        tool_args={"target": "mainframe"},
    )


# ============================================================================
# MAIN
# ============================================================================


def main():
    """Entry point."""
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        print("\n\nAgent interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nAgent failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
