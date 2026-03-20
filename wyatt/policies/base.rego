package wyatt

# DENY BY DEFAULT
# Everything not explicitly permitted is denied.
default allow := false

# Allow decision structure
# Returns both the decision and the reason
allow := {"allowed": true, "reason": reason} if {
    # Check if this (principal, operation) pair is in the allowlist
    is_permitted
    reason := sprintf("Permitted: %s allowed to %s", [input.agent, input.tool])
}

allow := {"allowed": false, "reason": reason} if {
    # Explicit deny if not permitted
    not is_permitted
    reason := sprintf("Denied by default policy: %s is not permitted to %s", [input.agent, input.tool])
}

# ALLOWLIST
# Define which agents can use which tools
# To add a new permission: add a rule here
is_permitted if {
    permitted_tools[input.agent][_] == input.tool
}

# Agent-to-tool mapping
# Each agent has an explicit list of permitted tools
permitted_tools := {
    "agent-001": ["read_file"],
    "agent-researcher": ["search_web", "read_file"],
    "devops-agent": ["read_file", "list_directory"],
    "adversarial-agent": ["read_file", "list_directory"],
}
