# Wyatt Adapters

Domain-specific adapters for Wyatt policy enforcement.

## Purpose

Wyatt core is domain-agnostic. Adapters bridge domain-specific systems (SQL, REST APIs, etc.) to Wyatt's policy engine.

## Structure

```
adapters/
└── sql/              # SQL query adapter
    ├── adapter.py    # SQL context extraction and OPA enforcement
    └── __init__.py
```

## SQL Adapter

**Function:** Extracts security context from SQL queries and enforces data access policies.

**What it does:**
1. Parses SQL to extract customer IDs
2. Detects if query accesses all customers
3. Sends context to OPA
4. Returns policy decision

**Used by:** `agents/sql_agent`

## Usage

```python
from adapters.sql.adapter import enforce_data_access

decision = enforce_data_access(
    sql="SELECT * FROM customers WHERE id = 'A'",
    user_id="A"
)

if decision.allowed:
    # Execute query
else:
    # Block with decision.reason
```

## Adding New Adapters

Create `adapters/<domain>/adapter.py` with:
- Context extraction logic
- OPA policy call
- Return `PolicyDecision`

Keep Wyatt core clean. Domain logic belongs in adapters.
