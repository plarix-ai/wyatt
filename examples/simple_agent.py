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
import sys
from pathlib import Path

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
    # For demo purposes, we'll just simulate reading
    return f"[Simulated] Contents of {path}: Lorem ipsum dolor sit amet..."


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

    # SCENARIO 1: Permitted Tool
    print("SCENARIO 1: read_file (permitted)")
    try:
        result = await daemon.execute_tool(
            agent_id=agent_id,
            tool_name="read_file",
            tool_callable=read_file,
            tool_args={"path": "/etc/passwd"},
        )
        print(f"✓ result: {result}")
    except PolicyViolationError as e:
        print(f"✗ denied (unexpected): {e}")

    print()

    # SCENARIO 2: Forbidden Tool (in policy but not permitted for this agent)
    print("SCENARIO 2: delete_database (forbidden)")
    try:
        result = await daemon.execute_tool(
            agent_id=agent_id,
            tool_name="delete_database",
            tool_callable=delete_database,
            tool_args={"name": "production"},
        )
        print(f"✗ executed (SHOULD NEVER HAPPEN): {result}")
    except PolicyViolationError as e:
        print(f"✓ blocked: {e.reason}")

    print()

    # SCENARIO 3: Unknown Tool (deny by default)
    print("SCENARIO 3: hack_system (unknown — deny by default)")
    try:
        result = await daemon.execute_tool(
            agent_id=agent_id,
            tool_name="hack_system",
            tool_callable=hack_system,
            tool_args={"target": "mainframe"},
        )
        print(f"✗ executed (SHOULD NEVER HAPPEN): {result}")
    except PolicyViolationError as e:
        print(f"✓ blocked: {e.reason}")


# ============================================================================
# MAIN
# ============================================================================


def main():
    """Entry point."""
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        print("\nAgent interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nAgent failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
