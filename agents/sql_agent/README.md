# SQL Agent - Natural Language to SQL with Wyatt Policy Enforcement

AI chatbot that converts plain English to SQL queries. With Wyatt enabled, users can only access their own data.

## Architecture

```
User Question → DeepSeek LLM → SQL Query → Wyatt/OPA Check → SQLite Execute → Response
```

## The Wyatt Difference

**Without Wyatt** (`--no-wyatt`):
```
[A]> Show me customer B's balance
SQL: SELECT balance FROM customers WHERE id = 'B'
balance: 8500.50  ← User A sees B's data (VULNERABLE)
```

**With Wyatt** (default):
```
[A]> Show me customer B's balance
SQL: SELECT balance FROM customers WHERE id = 'B'
[WYATT BLOCKED] User A cannot access customer B data
```

## How It Works

1. User asks question in plain English
2. DeepSeek converts it to SQL
3. Enforcer extracts target customer IDs from SQL
4. Enforcer calls OPA with: `{user_id, target_customer_ids, accesses_all}`
5. OPA evaluates Rego policy (`wyatt/sql`)
6. If allowed: execute SQL. If denied: block.

## Policy (Rego)

```rego
# User can only access their own data
allow if {
    every cid in input.target_customer_ids {
        cid == input.user_id
    }
}
```

## Setup

```bash
# 1. Start OPA (Docker already running on :8181)
# 2. Load policy
curl -X PUT http://localhost:8181/v1/policies/sql_access \
  --data-binary @../../src/wyatt/policies/sql_access.rego

# 3. Set API key
cp ../../.env.example ../../.env
# Edit .env, add DEEPSEEK_API_KEY

# 4. Initialize database
python3 database.py

# 5. Run
./run.sh
```

## Commands

| Command | Action |
|---------|--------|
| `/wyatt on` | Enable OPA enforcement |
| `/wyatt off` | Disable (vulnerable mode) |
| `/user X` | Switch to user X (A-E) |
| `/status` | Show current state |
| `/sql` | Show last generated SQL |
| `/quit` | Exit |

## Files

| File | Purpose |
|------|---------|
| `main.py` | Chatbot interface |
| `database.py` | SQLite operations |
| `llm.py` | DeepSeek NL→SQL |
| `enforcer.py` | OPA policy calls |
| `run.sh` | Launch script |

## Database

5 customers (A, B, C, D, E) with orders. Schema in `database.py`.
