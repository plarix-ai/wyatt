#!/usr/bin/env python3
"""
Wyatt v0.2.0 Daemon Entry Point.

Starts the Wyatt runtime policy enforcement daemon:
1. Loads boundary configuration (tool allowlist, data rules, redact patterns)
2. Registers tool implementations
3. Starts Unix socket server at /tmp/wyatt.sock
4. Logs every enforcement decision with colored [TAG] output

Run this in Terminal 1, then run the agent in Terminal 2.

Usage:
    python3 run_wyatt.py                    # Default config
    python3 run_wyatt.py --socket /tmp/w.sock  # Custom socket path
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Ensure wyatt package is importable
sys.path.insert(0, str(Path(__file__).parent))

from wyatt.core.boundaries import BoundaryEnforcer, create_default_config
from wyatt.core.logger import log_error, log_wyatt
from wyatt.core.socket_server import WyattSocketServer


# =============================================================================
# Tool Implementations (the real tools agents can call)
# =============================================================================


def read_file(path: str) -> str:
    """
    Read a file from disk.

    This is the actual tool implementation. Wyatt enforces policy BEFORE
    this code runs. If policy denies, this function is never called.
    """
    resolved = str(Path(path).resolve())
    with open(resolved, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def list_directory(path: str) -> str:
    """
    List contents of a directory.

    Returns one entry per line with type indicators.
    """
    resolved = Path(path).resolve()
    if not resolved.is_dir():
        return f"Error: {path} is not a directory"

    entries = []
    for entry in sorted(resolved.iterdir()):
        if entry.is_dir():
            entries.append(f"  [dir]  {entry.name}/")
        else:
            size = entry.stat().st_size
            entries.append(f"  [file] {entry.name} ({size} bytes)")

    header = f"Directory: {resolved}\n"
    return header + "\n".join(entries) if entries else header + "  (empty)"


# =============================================================================
# Main
# =============================================================================


async def run_daemon(socket_path: str) -> None:
    """Start the Wyatt daemon."""
    # Load boundary config
    config = create_default_config()

    # Create socket server
    server = WyattSocketServer(
        config=config,
        socket_path=socket_path,
    )

    # Register tool implementations
    server.register_tool("read_file", read_file)
    server.register_tool("list_directory", list_directory)

    log_wyatt(f"Registered tools: read_file, list_directory")

    # Check OPA connection (informational, not required for local enforcement)
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get("http://localhost:8181/health", timeout=2.0)
            if resp.status_code == 200:
                log_wyatt("OPA sidecar connected at http://localhost:8181")
            else:
                log_wyatt("OPA sidecar not responding (using local enforcement only)")
    except Exception:
        log_wyatt("OPA sidecar not detected (using local boundary enforcement only)")

    # Start server
    await server.start()
    await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(
        description="Wyatt v0.2.0 - Runtime Policy Enforcement Daemon"
    )
    parser.add_argument(
        "--socket",
        default="/tmp/wyatt.sock",
        help="Unix socket path (default: /tmp/wyatt.sock)",
    )
    args = parser.parse_args()

    try:
        asyncio.run(run_daemon(args.socket))
    except KeyboardInterrupt:
        print()  # Clean line after ^C
        log_wyatt("Daemon stopped.")
    except Exception as e:
        log_error(f"Daemon failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
