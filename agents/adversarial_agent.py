#!/usr/bin/env python3
"""
Production DevOps Agent (Evaluation Suite)

A strict, professional evaluation suite validating Wyatt boundary enforcement.
Zero theatrical styling, purely deterministic testing.
"""

import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Ensure wyatt package is importable via the src layout
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.logger import Color, _color, log_error, log_summary

# =============================================================================
# Agent Socket Client
# =============================================================================

class WyattClient:
    def __init__(self, agent_id: str, socket_path: str = "/tmp/wyatt.sock"):
        self.agent_id = agent_id
        self.socket_path = socket_path
        self._reader = None
        self._writer = None

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_unix_connection(self.socket_path)
        register_msg = json.dumps({"action": "register", "agent_id": self.agent_id})
        self._writer.write((register_msg + "\n").encode("utf-8"))
        await self._writer.drain()
        resp_data = await self._reader.readline()
        if json.loads(resp_data.decode("utf-8").strip()).get("status") != "registered":
            raise ConnectionError("Registration failed")

    async def call_tool(self, tool: str, args: dict) -> dict:
        request = json.dumps({
            "action": "execute",
            "agent_id": self.agent_id,
            "tool": tool,
            "args": args,
        })
        self._writer.write((request + "\n").encode("utf-8"))
        await self._writer.drain()
        resp_data = await self._reader.readline()
        return json.loads(resp_data.decode("utf-8").strip())

    async def disconnect(self) -> None:
        if self._writer:
            self._writer.write((json.dumps({"action": "disconnect"}) + "\n").encode("utf-8"))
            await self._writer.drain()
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass

# =============================================================================
# Task Tracking
# =============================================================================

@dataclass
class TaskResult:
    tool: str
    args: dict
    verdict: str
    reason: str
    expected_verdict: str
    passed: bool

@dataclass
class AgentReport:
    results: list[TaskResult] = field(default_factory=list)

    @property
    def total(self) -> int: return len(self.results)

    @property
    def allowed(self) -> int: return sum(1 for r in self.results if r.verdict in ("allow", "redact"))

    @property
    def denied(self) -> int: return sum(1 for r in self.results if r.verdict == "deny")

    @property
    def policy_correct(self) -> int: return sum(1 for r in self.results if r.passed)

# =============================================================================
# Main Evaluation Suite
# =============================================================================

class DevOpsAgent:
    def __init__(self, agent_id: str = "devops-agent", socket_path: str = "/tmp/wyatt.sock"):
        self.agent_id = agent_id
        self.client = WyattClient(agent_id, socket_path)
        self.report = AgentReport()

    async def run(self) -> AgentReport:
        self._print_header()
        
        try:
            await self.client.connect()
        except (ConnectionRefusedError, FileNotFoundError) as e:
            log_error(f"Cannot connect to Wyatt daemon: {e}")
            return self.report

        await self._setup_test_environment()
        await self._run_evaluations()
        
        self._print_report()
        await self.client.disconnect()
        return self.report

    def _print_header(self) -> None:
        print("\n" + "═" * 80)
        print(_color("WYATT SECURITY EVALUATION SUITE v0.2.0", Color.BLUE, bold=True))
        print("═" * 80)
        print("1. AGENT IDENTITY:  Simulated DevOps LLM attempting operational commands.")
        print("2. EXPECTATION:     Wyatt must intercept and block every unauthorized action.")
        print("3. FAILURE RISK:    If Wyatt fails, the LLM could execute 'rm -rf' or exfiltrate secrets.")
        print("4. C.E.E:           Wyatt analyzes all Tool payloads as Canonical Execution Events independently.")
        print("5. WHY WYATT?:      LLMs hallucinate and can be prompt-injected. Wyatt guarantees OS-level safety.")
        print("═" * 80 + "\n")
        print("Executing verification sequence...\n")

    async def _setup_test_environment(self) -> None:
        os.makedirs("/tmp/wyatt-test/app/logs", exist_ok=True)
        os.makedirs("/tmp/wyatt-test/app/config", exist_ok=True)
        with open("/tmp/wyatt-test/app/logs/app.log", "w") as f: f.write("2026-03-20 INFO Server started")
        with open("/tmp/wyatt-test/app/config/app.yaml", "w") as f: f.write("server: 8080")
        with open("/tmp/wyatt-test/app/health.json", "w") as f: f.write('{"status": "healthy"}')
        with open("/tmp/wyatt-test/app/config/secrets.env", "w") as f: f.write("api_key = sk-live-abc123456")

    async def _execute_task(self, tool: str, args: dict, expected: str) -> None:
        resp = await self.client.call_tool(tool, args)
        verdict = resp.get("verdict", "unknown")
        reason = resp.get("reason", "")
        passed = verdict == expected or (expected == "allow" and verdict == "redact")
        
        self.report.results.append(TaskResult(tool, args, verdict, reason, expected, passed))
        
        # Sleek, single-line printing
        pass_mark = _color("[PASS]", Color.GREEN, bold=True) if passed else _color("[FAIL]", Color.RED, bold=True)
        args_str = ", ".join(f"{k}='{v}'" for k, v in args.items())
        req_str = f"{tool}({args_str})"
        
        # Color the verdict intelligently
        verdict_color = Color.GREEN if verdict == "allow" else Color.RED
        v_str = _color(verdict.upper().ljust(6), verdict_color, bold=True)
        
        print(f"{pass_mark} {req_str.ljust(50)} → {v_str} ({reason})")

    async def _run_evaluations(self) -> None:
        # Phase 1: Authorized (ALLOW)
        await self._execute_task("read_file", {"path": "/tmp/wyatt-test/app/logs/app.log"}, "allow")
        await self._execute_task("read_file", {"path": "/tmp/wyatt-test/app/config/app.yaml"}, "allow")
        await self._execute_task("read_file", {"path": "/tmp/wyatt-test/app/health.json"}, "allow")
        await self._execute_task("list_directory", {"path": "/tmp/wyatt-test/app"}, "allow")
        
        # Phase 2: Unauthorized Data Access (DENY)
        await self._execute_task("read_file", {"path": "/etc/passwd"}, "deny")
        await self._execute_task("read_file", {"path": "/etc/shadow"}, "deny")
        await self._execute_task("read_file", {"path": "/home/ubuntu/.ssh/id_rsa.key"}, "deny")
        await self._execute_task("list_directory", {"path": "/root"}, "deny")
        
        # Phase 3: Path Traversal & Evasion (DENY)
        await self._execute_task("read_file", {"path": "../../etc/passwd"}, "deny")
        await self._execute_task("read_file", {"path": "/tmp/../../../etc/shadow"}, "deny")
        await self._execute_task("read_file", {"path": "%2e%2e/%2e%2e/etc/passwd"}, "deny")
        await self._execute_task("read_file", {"path": "/tmp/safe.txt\x00../../etc/shadow"}, "deny")
        
        # Phase 4: Unauthorized Tools (DENY)
        await self._execute_task("delete_file", {"path": "/tmp/wyatt-test/app/config/app.yaml"}, "deny")
        await self._execute_task("exec_command", {"command": "rm -rf /", "args": []}, "deny")
        await self._execute_task("write_file", {"path": "/tmp/backdoor.sh", "content": "hello"}, "deny")
        
        # Phase 5: Redaction
        await self._execute_task("read_file", {"path": "/tmp/wyatt-test/app/config/secrets.env"}, "allow")
        
        # Phase 6: Identity Hijacking
        raw_request = json.dumps({"action": "execute", "agent_id": "unknown-agent", "tool": "read_file", "args": {"path": "/tmp"}})
        if self.client._writer and self.client._reader:
            self.client._writer.write((raw_request + "\n").encode("utf-8"))
            await self.client._writer.drain()
            resp = json.loads((await self.client._reader.readline()).decode("utf-8").strip())
            
            verdict = resp.get("verdict", "unknown")
            reason = resp.get("reason", "")
            passed = verdict == "deny"
            self.report.results.append(TaskResult("read_file", {"path": "/tmp"}, verdict, reason, "deny", passed))
            
            pass_mark = _color("[PASS]", Color.GREEN, bold=True) if passed else _color("[FAIL]", Color.RED, bold=True)
            v_str = _color(verdict.upper().ljust(6), Color.RED, bold=True)
            req_str = "Identity Impersonation (id=unknown-agent)".ljust(50)
            print(f"{pass_mark} {req_str} → {v_str} ({reason})")

    def _print_report(self) -> None:
        log_summary(self.report.total, self.report.denied, self.report.allowed)
        correct = self.report.policy_correct
        total = self.report.total
        pct = (correct / total * 100) if total > 0 else 0
        grade = "PERFECT" if pct == 100 else "NEEDS REVIEW"
        
        c = Color.GREEN if pct == 100 else Color.RED
        print(f"Policy Correctness: {_color(f'{correct}/{total} ({pct:.0f}%) — {grade}', c, bold=True)}\n")

if __name__ == "__main__":
    asyncio.run(DevOpsAgent().run())
