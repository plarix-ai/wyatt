# Wyatt v0.1.0

**Runtime policy enforcement daemon for AI agentic systems.**

Wyatt sits between an AI agent and its tools. Before any tool executes, Wyatt intercepts it, evaluates it against a policy, and either allows or denies it. Every decision is recorded.

**Deny by default. Always.**

---

## What Problem Does This Solve?

AI agents today can call any tool they have access to with zero runtime enforcement. A system prompt saying "don't delete files" is not enforcement—it's a suggestion.

**Wyatt is the enforcement layer.**

An agent that wants to delete a file must ask Wyatt first. If the policy doesn't explicitly permit it, the tool never executes. No exceptions.

---

## Architecture

```
AI Agent → Daemon → Enforcer → OPA (policy engine)
              ↓
           Logger (every decision → CEE)
```

### The Four Components

1. **Daemon** (`wyatt/core/daemon.py`) - Entry point for all tool calls
2. **Enforcer** (`wyatt/core/enforcer.py`) - Communicates with OPA REST API
3. **Policy** (`wyatt/policies/base.rego`) - Rego policy defining what's permitted
4. **Logger** (`wyatt/core/logger.py`) - Structured CEE logging (JSON)

### The Canonical Execution Event (CEE)

Every interception produces exactly one CEE:

```json
{
  "timestamp": "2026-03-19T12:00:00Z",
  "operation": "read_file",
  "principal": "agent-001",
  "state_delta": {"path": "/etc/passwd"},
  "decision": "ALLOW",
  "policy_basis": "Permitted: agent-001 allowed to read_file"
}
```

Four fields that matter:
- **Operation** - What action is being attempted
- **Principal** - Who or what is attempting it
- **State Delta** - What will change if allowed
- **Policy Basis** - Why the policy said yes or no

---

## Setup From Zero

### Prerequisites

- Python 3.10+
- Docker & Docker Compose
- pip

### Installation

```bash
# Clone the repository
cd wyatt

# Install dependencies
pip install httpx pydantic structlog pytest pytest-asyncio

# Start OPA sidecar
make start

# Verify OPA is running
curl http://localhost:8181/health
# Should return: {}
```

---

## Running the Example

The example agent demonstrates all three scenarios:

```bash
python3 examples/simple_agent.py
```

**Expected output:**

```
SCENARIO: permitted tool: read_file
INPUT:    {"agent": "agent-001", "tool": "read_file", "args": {"path": "/etc/hostname"}}
DECISION: ALLOW
REASON:   Permitted: agent-001 allowed to read_file
OUTPUT:   tool executed successfully: <file contents>
CEE LOG:  {"operation":"read_file",...,"decision":"ALLOW",...}

SCENARIO: forbidden tool: delete_database
INPUT:    {"agent": "agent-001", "tool": "delete_database", "args": {"name": "production"}}
DECISION: DENY
REASON:   Denied by default policy: agent-001 is not permitted to delete_database
OUTPUT:   execution blocked: Denied by default policy: agent-001 is not permitted to delete_database
CEE LOG:  {"operation":"delete_database",...,"decision":"DENY",...}

SCENARIO: unknown tool: hack_system
INPUT:    {"agent": "agent-001", "tool": "hack_system", "args": {"target": "mainframe"}}
DECISION: DENY
REASON:   Denied by default policy: agent-001 is not permitted to hack_system
OUTPUT:   execution blocked: Denied by default policy: agent-001 is not permitted to hack_system
CEE LOG:  {"operation":"hack_system",...,"decision":"DENY",...}
```

Each scenario produces a structured CEE log entry showing the enforcement decision.

---

## Using Wyatt in Your Agent

```python
import asyncio
from wyatt.core import WyattDaemon, PolicyViolationError

# Your tool function
def read_file(path: str) -> str:
    return open(path).read()

# Create daemon
daemon = WyattDaemon()

# Execute tool through Wyatt
async def main():
    try:
        result = await daemon.execute_tool(
            agent_id="agent-001",
            tool_name="read_file",
            tool_callable=read_file,
            tool_args={"path": "/etc/passwd"}
        )
        print(f"Success: {result}")
    except PolicyViolationError as e:
        print(f"Blocked: {e.reason}")

asyncio.run(main())
```

**If policy allows:** Tool executes, result returned
**If policy denies:** `PolicyViolationError` raised, tool never executes

---

## Adding Policy Permissions

Policies are defined in `wyatt/policies/base.rego`.

To permit a new agent or tool:

1. Edit `wyatt/policies/base.rego`
2. Find the `permitted_tools` map
3. Add or modify an entry:

```rego
permitted_tools := {
    "agent-001": ["read_file", "write_file"],  # Added write_file
    "agent-new": ["search_web"],               # New agent
}
```

4. Restart OPA:

```bash
make stop
make start
```

That's it. One file, one change.

See [wyatt/policies/README.md](wyatt/policies/README.md) for detailed policy documentation.

---

## Running Tests

```bash
# Run all tests
make test

# Or with pytest directly
PYTHONPATH=. python3 -m pytest tests/ -v
```

**Expected:** 18 tests passing

Tests verify:
- CEE structure and logging
- OPA communication
- Policy enforcement (allow/deny)
- End-to-end flow through daemon

**Note:** Tests require OPA running (`make start`)

---

## Project Structure

```
wyatt/
├── wyatt/
│   ├── core/
│   │   ├── daemon.py        # Entry point for tool calls
│   │   ├── enforcer.py      # OPA REST client
│   │   ├── logger.py        # Structured CEE logging
│   │   ├── models.py        # CEE and PolicyDecision
│   │   └── exceptions.py    # PolicyViolationError
│   └── policies/
│       ├── base.rego        # Policy rules
│       └── README.md        # Policy documentation
├── tests/
│   ├── test_daemon.py
│   ├── test_enforcer.py
│   └── test_models_logger.py
├── examples/
│   └── simple_agent.py      # Demonstration of all three scenarios
├── docker-compose.yml       # OPA sidecar
├── Makefile                 # make start, test, stop
└── README.md                # This file
```

---

## What's in v0.1.0

✅ **Deny by default policy enforcement**
✅ **Agent-tool allowlist in Rego**
✅ **Structured CEE logging (JSON)**
✅ **OPA integration via REST API**
✅ **PolicyViolationError on deny**
✅ **Async daemon for tool execution**
✅ **18 passing tests**
✅ **Runnable example demonstrating all scenarios**

### Limitations

- **Policy:** Simple agent-tool allowlist only (no argument-level policies)
- **State Delta:** Currently just dumps tool args (not precise state modeling)
- **Interface:** Python library import only (no HTTP API)
- **Logging:** stdout only (no log shipping/rotation)
- **Persistence:** No decision storage beyond logs

These are intentional simplifications for v0.1.0.

---

## What's Coming in Future Versions

**v0.2.0** - Argument-level policies
- Allow `read_file` for `/tmp/*` but deny `/etc/*`
- Time-based restrictions
- Rate limiting

**v0.3.0** - HTTP API
- Run Wyatt as a service
- Language-agnostic agent integration
- Health checks and metrics

**v0.4.0** - Decision storage
- Query enforcement history
- Analytics and reporting
- Policy impact analysis

---

## Commands Reference

```bash
# Start OPA sidecar
make start

# Stop OPA
make stop

# Run tests
make test

# View OPA logs
make logs

# Clean up containers
make clean

# Install dependencies
make install
```

---

## OPA Policy Testing

You can test policies directly:

```bash
# Test agent-001 can read_file
curl -X POST http://localhost:8181/v1/data/wyatt/allow \
  -H 'Content-Type: application/json' \
  -d '{"input": {"agent": "agent-001", "tool": "read_file", "args": {}}}'

# Returns: {"result": {"allowed": true, "reason": "..."}}
```

```bash
# Test agent-001 cannot delete_file
curl -X POST http://localhost:8181/v1/data/wyatt/allow \
  -H 'Content-Type: application/json' \
  -d '{"input": {"agent": "agent-001", "tool": "delete_file", "args": {}}}'

# Returns: {"result": {"allowed": false, "reason": "Denied by default policy"}}
```

---

## Design Principles

1. **Deny by default** - Nothing executes without explicit permission
2. **Single source of truth** - Policy lives in one place (base.rego)
3. **Separation of concerns** - Daemon enforces, OPA decides, logger records
4. **CEE as the atom** - Every decision is a structured, auditable event
5. **No backdoors** - Every tool must go through the daemon

---

## FAQ

### Q: Can an agent bypass Wyatt?

**A:** Only if you give it direct access to tools. The agent must call `daemon.execute_tool()`. If you give an agent a raw tool function, Wyatt can't intercept it. This is a deployment/architecture concern, not a Wyatt limitation.

### Q: What if OPA is down?

**A:** The enforcer raises `EnforcerError` (not `PolicyViolationError`). This is a system failure, not a policy denial. Handle it like any other infrastructure failure.

### Q: Can I use this in production?

**A:** v0.1.0 is a proof of concept. It demonstrates the core enforcement model. For production:
- Add proper log shipping
- Add metrics and monitoring
- Add policy versioning and rollback
- Add decision persistence
- Add HTTP API for language-agnostic use

The foundation is sound. Production requires operational maturity.

### Q: Why OPA instead of building a policy engine?

**A:** OPA is production-grade (used by Kubernetes, Envoy, etc.). It handles policy evaluation, versioning, testing, and validation. We focus on enforcement, not reinventing policy engines.

### Q: Can I write policies in Python instead of Rego?

**A:** Not in v0.1.0. OPA uses Rego. If you want Python policies, you'd need a different policy engine or build your own. Rego is declarative, explicit, and well-tested for this use case.

---

## License

(Add your license here)

---

## Contributing

v0.1.0 is a proof of concept. Feedback welcome.

---

**Wyatt v0.1.0 - Deny by default. Always.**
