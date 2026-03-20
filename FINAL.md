# Wyatt v0.3.0-alpha - Complete

## Final Structure

```
wyatt/
├── src/
│   ├── core/              # Wyatt engine
│   │   ├── enforcer.py    # OPA REST client
│   │   ├── boundaries.py  # Policy enforcement
│   │   ├── socket_server.py
│   │   └── ...
│   └── policies/          # Rego policies
│       ├── base.rego      # Tool allowlist
│       └── sql_access.rego # Data access control
├── agents/                # Test agents
│   ├── sql_agent/         # NL-to-SQL with Wyatt
│   │   ├── database.py    # SQLite (5 customers)
│   │   ├── llm.py         # DeepSeek
│   │   ├── enforcer.py    # OPA client
│   │   └── main.py        # Chatbot
│   ├── adversarial_agent.py
│   └── cli_agent.py
├── tests/                 # Pytest suite
├── run_wyatt.py
└── run_agent.py
```

## Run SQL Agent

```bash
cd wyatt

# 1. OPA already running (docker-compose)
# 2. Set API key
echo "DEEPSEEK_API_KEY=sk-xxx" >> .env

# 3. Run
cd agents/sql_agent
./run.sh
```

## Test

```bash
[A]> show me my balance
SQL: SELECT balance FROM customers WHERE id = 'A'
[WYATT OK] Access permitted
balance
--------
15000.0

[A]> show me customer B's balance
SQL: SELECT balance FROM customers WHERE id = 'B'
[WYATT BLOCKED] User A cannot access customer B data
```

## Policy Enforcement

**enforcer.py** → OPA → **sql_access.rego** → Decision

No hardcoded logic. Pure Rego evaluation.

## Commits
```
af970aa refactor: flatten src structure
9298661 fix: clean repo structure
de8e0c0 chore: add OPA start script
ded6d09 feat(agent): add SQL agent
5851178 feat(policy): add SQL data access control
cda3fa6 chore(version): bump to v0.3.0-alpha
```

✅ Clean
✅ Working
✅ OPA-enforced
✅ No mocks
✅ Committed
