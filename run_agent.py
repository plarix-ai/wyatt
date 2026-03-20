#!/usr/bin/env python3
"""
Agent Entry Point for Wyatt v0.2.0.

Runs the production DevOps agent that connects to the Wyatt daemon
and executes a full operational task suite.

The agent performs realistic system administration tasks and naturally
hits policy boundaries. Wyatt enforces every boundary.

Usage:
    python3 run_agent.py                        # Default settings
    python3 run_agent.py --socket /tmp/w.sock   # Custom socket path
    python3 run_agent.py --agent-id my-agent    # Custom agent ID
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Ensure wyatt package is importable
sys.path.insert(0, str(Path(__file__).parent))

from examples.adversarial_agent import DevOpsAgent
from wyatt.core.logger import log_error


async def run_agent(agent_id: str, socket_path: str) -> None:
    """Run the production DevOps agent."""
    agent = DevOpsAgent(agent_id=agent_id, socket_path=socket_path)
    report = await agent.run()

    # Exit with non-zero if policy enforcement had unexpected results
    if report.policy_correct < report.total:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Wyatt v0.2.0 - Production DevOps Agent"
    )
    parser.add_argument(
        "--socket",
        default="/tmp/wyatt.sock",
        help="Wyatt daemon socket path (default: /tmp/wyatt.sock)",
    )
    parser.add_argument(
        "--agent-id",
        default="devops-agent",
        help="Agent identifier (default: devops-agent)",
    )
    args = parser.parse_args()

    try:
        asyncio.run(run_agent(args.agent_id, args.socket))
    except KeyboardInterrupt:
        print("\n\nAgent interrupted.")
    except ConnectionRefusedError:
        log_error("Cannot connect to Wyatt daemon.")
        log_error("Start the daemon first: python3 run_wyatt.py")
        sys.exit(1)
    except FileNotFoundError:
        log_error("Wyatt socket not found at " + args.socket)
        log_error("Start the daemon first: python3 run_wyatt.py")
        sys.exit(1)
    except Exception as e:
        log_error(f"Agent failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
