# Wyatt v0.3.0-alpha - SQL Data Access Policy
#
# Enforces: User can only access their own data.
# User A can only query customer_id = 'A'. Any other access is blocked.
#
# Input:
# {
#   "user_id": "A",                    -- Authenticated user
#   "target_customer_ids": ["A"],      -- Customer IDs found in SQL
#   "accesses_all": false              -- True if no customer filter
# }

package wyatt.sql

import rego.v1

default allow := false

# ALLOW: User accessing only their own data
allow if {
    count(input.target_customer_ids) > 0
    every cid in input.target_customer_ids {
        cid == input.user_id
    }
}

# DENY: Query accesses all customers (no filter)
deny_reason := "Query accesses all customers without filter" if {
    input.accesses_all == true
}

# DENY: User accessing other customer's data
deny_reason := msg if {
    not input.accesses_all
    some cid in input.target_customer_ids
    cid != input.user_id
    msg := sprintf("User %s cannot access customer %s data", [input.user_id, cid])
}

# DENY: No targets found but touches customer tables
deny_reason := "Cannot determine target customer from query" if {
    count(input.target_customer_ids) == 0
    not input.accesses_all
}

# Final decision structure returned to caller
decision := {"allowed": true, "reason": "Access permitted"} if {
    allow
}

decision := {"allowed": false, "reason": deny_reason} if {
    not allow
    deny_reason
}

decision := {"allowed": false, "reason": "Denied by default policy"} if {
    not allow
    not deny_reason
}
