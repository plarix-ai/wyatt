# Wyatt v0.2

**Runtime policy enforcement daemon for AI agentic systems.**

Wyatt sits between an AI agent and its tools. Before any tool executes, Wyatt intercepts it, evaluates it against policy boundaries, and either allows, denies, or redacts the output. Every decision is recorded as a Canonical Execution Event (CEE).

**Deny by default. Always.**

---

## What's New in v0.2

| Feature | v0.1 | v0.2 |
|---------|--------|--------|
| Architecture | Library import (same process) | Unix socket daemon (parallel processes) |
| Enforcement | Tool name only | All 4 AFB04 boundaries (TOOL, DATA, EXEC, CTX) |
| Argument checks | None | Path restrictions, traversal detection, null byte injection |
| Output filtering | None | Regex-based redaction of secrets, keys, passwords |
| Logging | JSON structlog | Colored `[TAG]` human-readable output |
| Agent | 3 static scenarios | Production DevOps agent with 17 real attack scenarios |
| Tests | 16 | 52 |

---

## Architecture

```
Terminal 1: Wyatt Daemon              Terminal 2: Agent Process
┌────────────────────────┐            ┌────────────────────────┐
│ python3 run_wyatt.py   │            │ python3 run_agent.py   │
│                        │            │                        │
│ [WYATT] Listening...   │◄──────────►│ [AGENT] Connecting...  │
│                        │   Socket   │                        │
│ [REQ] read_file        │◄───────────│ Request: read_file     │
│ [AFB04:TOOL] ALLOW     │            │                        │
│ [AFB04:DATA] DENY      │───────────►│ [RESULT] DENY          │
└────────────────────────┘            └────────────────────────┘
         /tmp/wyatt.sock
```

### The Four AFB04 Boundaries

Every tool request passes through 4 enforcement boundaries in order. The first DENY stops the chain:

1. **TOOL Boundary** — Is this tool permitted for this agent?
2. **DATA Boundary** — Are the arguments/paths permitted? (path traversal, deny patterns, allow patterns)
3. **EXEC Boundary** — Execution constraints (timeout, sandbox)
4. **CTX Boundary** — Post-execution output filtering (redact passwords, API keys, secrets)

### The Canonical Execution Event (CEE)

Every interception produces exactly one CEE with four fields:

| Field | Description | Example |
|-------|-------------|---------|
| **Operation** | What action is being attempted | `read_file` |
| **Principal** | Who is attempting it | `devops-agent` |
| **State Delta** | What will change if allowed | `{path: /etc/shadow}` |
| **Policy Basis** | Why it was allowed or denied | `path matches deny pattern /etc/*` |

---

## Quick Start

### Prerequisites

- Python 3.10+
- Docker & Docker Compose

### Setup

```bash
cd wyatt

# Install dependencies
pip install -e .
pip install httpx pydantic pytest pytest-asyncio

# Start OPA sidecar
make start

# Verify OPA is running
curl http://localhost:8181/health
# Should return: {}
```

### Run It

Open **two terminals**:

```bash
# Terminal 1: Start Wyatt daemon
cd wyatt
make daemon
```

```bash
# Terminal 2: Run the DevOps agent
cd wyatt
make agent
```

Or without make:

```bash
# Terminal 1
PYTHONPATH=. python3 run_wyatt.py

# Terminal 2
PYTHONPATH=. python3 run_agent.py
```

---

## What You'll See

### Terminal 1 (Wyatt Daemon)

```
[WYATT]   ═══════════════════════════════════════════════════════
[WYATT]   Wyatt v0.2 - Runtime Policy Enforcement Daemon
[WYATT]   ═══════════════════════════════════════════════════════
[WYATT]   Registered tools: read_file, list_directory
[WYATT]   Socket listening at /tmp/wyatt.sock
[WYATT]   Boundary config loaded: 4 agents, 5 data rules, 4 redact patterns
[WYATT]   Waiting for agent connections...

[CONN]    Agent connected: devops-agent
[REQ]     devops-agent → read_file({path: /tmp/wyatt-test/app/logs/app.log})
[AFB04:TOOL] ALLOW (read_file permitted for devops-agent)
[AFB04:DATA] ALLOW (arguments validated)
[AFB04:EXEC] ALLOW (timeout=30s)
[AFB04:CTX]  ALLOW (no sensitive patterns in output)
[ALLOW]   Executed read_file → 312 chars

[REQ]     devops-agent → read_file({path: /etc/shadow})
[AFB04:TOOL] ALLOW (read_file permitted for devops-agent)
[AFB04:DATA] DENY (path=/etc/shadow matches deny pattern /etc/*)
[DENY]    Blocked: path=/etc/shadow matches deny pattern /etc/*
```

### Terminal 2 (DevOps Agent)

```
[AGENT]   ═══════════════════════════════════════════════════════
[AGENT]   DevOps Production Agent v0.2 - Policy Stress Test
[AGENT]   ═══════════════════════════════════════════════════════
[AGENT]   Agent ID: devops-agent
[AGENT]   Connected!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE 1: Routine Diagnostics
  (All tasks should be ALLOWED by policy)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[ATTACK]  Strategy 1: Read application logs
[AGENT]   → read_file(/tmp/wyatt-test/app/logs/app.log)
[RESULT]  ALLOW - 2026-03-20 12:00:01 INFO Server started on port 8080...
         ✓ (expected allow, got allow)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE 2: Security Incident Investigation
  (Agent escalates access — some should be DENIED)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[ATTACK]  Strategy 6: Read /etc/shadow for password hashes
[AGENT]   → read_file(/etc/shadow)
[RESULT]  DENY - path=/etc/shadow matches deny pattern /etc/*
         ✓ (expected deny, got deny)

═══════════════════════════════════════════════════════════════
[SUMMARY] 17 attacks attempted, 12 blocked, 5 allowed
═══════════════════════════════════════════════════════════════
[POLICY]  Policy correctness: 17/17 (100%) — PERFECT
```

---

## The DevOps Agent

The production DevOps agent simulates what a real AI assistant does daily:

| Phase | Description | Expected |
|-------|-------------|----------|
| **Phase 1** | Routine diagnostics — read logs, configs, health checks | All ALLOW |
| **Phase 2** | Incident investigation — try /etc/passwd, /etc/shadow, SSH keys | All DENY |
| **Phase 3** | Path traversal — `../../`, URL-encoded `%2e%2e`, null bytes | All DENY |
| **Phase 4** | Unauthorized tools — delete_file, exec_command, write_file | All DENY (TOOL) |
| **Phase 5** | Context boundary — read file containing passwords/API keys | REDACT |
| **Phase 6** | Identity — impersonate unknown-agent | DENY (TOOL) |

---

## Project Structure

```
wyatt/
├── wyatt/
│   ├── core/
│   │   ├── daemon.py           # Tool execution entry point
│   │   ├── enforcer.py         # OPA REST client
│   │   ├── boundaries.py       # AFB04 boundary enforcement (TOOL, DATA, EXEC, CTX)
│   │   ├── socket_server.py    # Unix domain socket server
│   │   ├── logger.py           # Colored [TAG] logging
│   │   ├── models.py           # CEE, Verdict, AFBDecision, ToolRequest/Response
│   │   └── exceptions.py       # PolicyViolationError
│   └── policies/
│       ├── base.rego            # OPA policy rules
│       └── README.md            # Policy documentation
├── tests/
│   ├── test_boundaries.py      # 25 tests: all 4 AFB boundary checks
│   ├── test_socket_server.py   # 11 tests: socket communication & enforcement
│   ├── test_daemon.py          # 7 tests: daemon integration
│   ├── test_enforcer.py        # 6 tests: OPA communication
│   └── test_models_logger.py   # 3 tests: models & logging
├── examples/
│   ├── adversarial_agent.py    # Production DevOps agent (17 attack scenarios)
│   └── simple_agent.py         # v0.1.0 simple demonstration
├── run_wyatt.py                # Daemon entry point
├── run_agent.py                # Agent entry point
├── docker-compose.yml          # OPA sidecar
├── Makefile                    # make start, daemon, agent, test
└── README.md
```

---

## Running Tests

```bash
# Start OPA first (required for OPA-integration tests)
make start

# Run all 52 tests
make test

# Run specific test files
PYTHONPATH=. python3 -m pytest tests/test_boundaries.py -v       # Boundary tests
PYTHONPATH=. python3 -m pytest tests/test_socket_server.py -v    # Socket tests
```

**Note:** `test_boundaries.py` and `test_socket_server.py` do NOT require OPA — they test local boundary enforcement only.

---

## Policy Configuration

### OPA Policy (base.rego)

Defines which agents can use which tools:

```rego
permitted_tools := {
    "agent-001": ["read_file"],
    "devops-agent": ["read_file", "list_directory"],
}
```

### Boundary Configuration (boundaries.py)

Extends OPA with argument-level rules:

```python
# devops-agent can read from /tmp and /home, but NOT /etc or /root
DataBoundaryRule(
    agent="devops-agent",
    tool="read_file",
    arg_name="path",
    allow_patterns=["/tmp/*", "/home/*", "/var/log/*"],
    deny_patterns=["/etc/*", "/root/*", "*.key", "*.pem", "*shadow*"],
)
```

To add a new agent:

1. Add to `permitted_tools` in `wyatt/policies/base.rego`
2. Add tool allowlist in `create_default_config()` in `wyatt/core/boundaries.py`
3. Add data rules (optional) for argument restrictions
4. Restart OPA: `make stop && make start`

---

## Commands Reference

```bash
make help       # Show all commands
make install    # Install dependencies
make start      # Start OPA sidecar (Docker)
make stop       # Stop OPA sidecar
make daemon     # Run Wyatt daemon (Terminal 1)
make agent      # Run DevOps agent (Terminal 2)
make test       # Run all tests
make logs       # Show OPA logs
make clean      # Clean up everything
```

---

## Design Principles

1. **Deny by default** — Nothing executes without explicit permission
2. **Defense in depth** — 4 boundary checks, not just tool name
3. **Separation of concerns** — daemon enforces, OPA decides, logger records
4. **CEE as the atom** — Every decision is a structured, auditable event
5. **No backdoors** — Every tool must go through the socket

---

## License

(Add your license here)

---

**Wyatt v0.2 — Deny by default. Always.**
