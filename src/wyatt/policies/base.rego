package wyatt

import rego.v1

# DENY BY DEFAULT
default allow := false

# Allow decision structure
allow := {"allowed": true, "reason": reason} if {
    is_permitted
    reason := sprintf("Permitted: %s allowed to %s", [input.agent, input.tool])
}

allow := {"allowed": false, "reason": reason} if {
    not is_permitted
    reason := sprintf("Denied by default policy: %s is not permitted to %s", [input.agent, input.tool])
}

# ALLOWLIST
is_permitted if {
    permitted_tools[input.agent][_] == input.tool
}

# Agent-to-tool mapping
permitted_tools := {
    "agent-001": ["read_file"],
    "agent-researcher": ["search_web", "read_file"],
    "devops-agent": ["read_file", "list_directory"],
    "adversarial-agent": ["read_file", "list_directory"],
}
