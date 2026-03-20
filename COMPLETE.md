# Wyatt v0.3.0-alpha - SQL Agent Complete

## Structure (Clean)

```
wyatt/                              # Repository root
├── src/wyatt/                      # Wyatt engine (Python package)
│   ├── core/                       # Runtime enforcement engine
│   │   ├── enforcer.py             # OPA client
│   │   ├── boundaries.py           # Policy checks
│   │   ├── socket_server.py        # Unix socket server
│   │   └── ...
│   └── policies/                   # OPA Rego policies
│       ├── base.rego               # Tool/agent allowlist
│       └── sql_access.rego         # Data access control
├── agents/                         # Test agents (not part of wyatt package)
│   ├── sql_agent/                  # NL-to-SQL with data access control
│   │   ├── database.py             # SQLite (5 customers A-E)
│   │   ├── llm.py                  # DeepSeek NL→SQL
│   │   ├── enforcer.py             # OPA policy client
│   │   ├── main.py                 # Chatbot CLI
│   │   └── run.sh                  # Launch script
│   ├── adversarial_agent.py
│   └── cli_agent.py
├── tests/                          # Pytest tests
├── run_wyatt.py                    # Daemon launcher
├── run_agent.py                    # Agent launcher
└── docker-compose.yml              # OPA container
```

## What Was Fixed

1. **Deleted duplicate** `wyatt/wyatt/` directory (was empty, created by mistake)
2. **Fixed imports** in sql_agent - no more relative imports, works from directory
3. **Updated paths** in README and run scripts
4. **Version bump** to v0.3.0-alpha

## How It Works

**SQL Agent** = Intentionally vulnerable AI chatbot
**Wyatt** = Policy enforcement that blocks unauthorized data access

### Without Wyatt (Vulnerable)
```bash
./run.sh --no-wyatt
[A]> show me customer B's balance
→ Returns B's data ✗ VULNERABLE
```

### With Wyatt (Protected)
```bash
./run.sh
[A]> show me customer B's balance
[WYATT BLOCKED] User A cannot access customer B data ✓ PROTECTED
```

## Policy Enforcement Flow

1. User A asks: "show me customer B's data"
2. DeepSeek LLM generates: `SELECT * FROM customers WHERE id = 'B'`
3. `enforcer.py` extracts target customer ID: `['B']`
4. Calls OPA: `POST /v1/data/wyatt/sql/decision` with `{user_id: 'A', target_customer_ids: ['B']}`
5. OPA evaluates `sql_access.rego`
6. Returns: `{allowed: false, reason: "User A cannot access customer B data"}`
7. Query blocked

**No hardcoded if/else. Pure OPA policy.**

## Quick Start

```bash
cd wyatt

# 1. Start OPA
docker-compose up -d

# 2. Set API key
cp .env.example .env
# Edit .env, add DEEPSEEK_API_KEY=sk-...

# 3. Run SQL agent
cd agents/sql_agent
./run.sh
```

## Testing

```bash
# Unit test enforcer
cd agents/sql_agent
python3 -c "from enforcer import check_policy_with_opa; print(check_policy_with_opa(\"SELECT * FROM customers WHERE id = 'A'\", 'A'))"

# Full test suite
cd ../..
make test
```

## Commits

```
9298661 fix: clean repo structure and update paths
de8e0c0 chore: add OPA start script and update env example
ded6d09 feat(agent): add SQL agent with Wyatt policy enforcement
5851178 feat(policy): add SQL data access control policy
cda3fa6 chore(version): bump to v0.3.0-alpha
```

## Status

✅ Clean structure - no duplicates
✅ OPA integration - real Rego policy evaluation
✅ SQL agent - working with imports fixed
✅ Policy enforced - User A cannot access User B data
✅ All tests passing
✅ Committed with milestones
