# Wyatt Policy Rules

This directory contains Rego policies that OPA evaluates to make enforcement decisions.

## Understanding base.rego

Every line explained in plain English for someone who has never seen Rego.

### The Package Declaration

```rego
package wyatt
```

This groups all rules under the namespace "wyatt". When querying OPA, we ask for `wyatt.allow`.

### Deny by Default

```rego
default allow := false
```

**What it does:** If no explicit allow rule matches, the answer is false (deny).

**Why this matters:** This is the foundation of Wyatt's security model. Unless you explicitly permit something, it's denied. No tool executes without permission.

### Allow Rules

```rego
allow := {"allowed": true, "reason": reason} if {
    is_permitted
    reason := sprintf("Permitted: %s allowed to %s", [input.agent, input.tool])
}
```

**What it does:** If `is_permitted` is true (the agent-tool pair is in the allowlist), return an allow decision with a reason.

**Input format:** OPA receives JSON like `{"agent": "agent-001", "tool": "read_file", "args": {...}}`

**Output format:** Returns `{"allowed": true, "reason": "Permitted: agent-001 allowed to read_file"}`

```rego
allow := {"allowed": false, "reason": reason} if {
    not is_permitted
    reason := "Denied by default policy"
}
```

**What it does:** If `is_permitted` is false, explicitly return a deny with reason.

### The Permission Check

```rego
is_permitted if {
    permitted_tools[input.agent][_] == input.tool
}
```

**What it does:** Checks if the tool name appears in the list of tools permitted for this agent.

**How it works:**
- `permitted_tools[input.agent]` looks up the agent's allowed tool list
- `[_]` iterates through that list
- `== input.tool` checks if the tool matches

If any tool in the agent's list matches, `is_permitted` is true.

### The Allowlist

```rego
permitted_tools := {
    "agent-001": ["read_file"],
    "agent-researcher": ["search_web", "read_file"],
}
```

**What it does:** Maps agent IDs to lists of tools they're allowed to use.

**Example:**
- `agent-001` can only use `read_file`
- `agent-researcher` can use `search_web` and `read_file`
- Any other agent → denied by default
- Any tool not in the list → denied by default

**How to add permission:** Add an entry to this map or extend an existing agent's list.

## Adding New Permissions

To permit a new agent or tool:

1. Find the `permitted_tools` map in `base.rego`
2. Add or modify an entry:
   ```rego
   "agent-new": ["allowed_tool_1", "allowed_tool_2"],
   ```
3. Restart OPA: `make stop && make start`

That's it. One change, one place.

## Testing Policies

You can test policies directly with OPA:

```bash
# Check if agent-001 can read_file
curl -X POST http://localhost:8181/v1/data/wyatt/allow \
  -H 'Content-Type: application/json' \
  -d '{"input": {"agent": "agent-001", "tool": "read_file", "args": {}}}'

# Expected: {"result": {"allowed": true, "reason": "..."}}
```

```bash
# Check if agent-001 can delete_file
curl -X POST http://localhost:8181/v1/data/wyatt/allow \
  -H 'Content-Type: application/json' \
  -d '{"input": {"agent": "agent-001", "tool": "delete_file", "args": {}}}'

# Expected: {"result": {"allowed": false, "reason": "Denied by default policy"}}
```

## Policy Evolution (Future Versions)

v0.1.0 uses a simple agent-tool allowlist. Future versions may add:

- Time-based policies (only allow during business hours)
- Argument-level policies (allow read /tmp/* but deny read /etc/*)
- Rate limiting (max 10 calls per minute)
- Conditional policies (allow if previous tool succeeded)

The Rego structure supports all of this. For now: keep it simple.
