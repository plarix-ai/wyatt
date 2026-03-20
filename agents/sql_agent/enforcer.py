"""
OPA-based policy enforcer for SQL Agent.

Calls OPA REST API to evaluate Rego policy. No hardcoded logic.
Policy decision comes entirely from OPA.
"""

import os
import re
from dataclasses import dataclass

import httpx


OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = "/v1/data/wyatt/sql/decision"


@dataclass
class PolicyDecision:
    """OPA policy decision."""
    allowed: bool
    reason: str


def extract_customer_ids(sql: str) -> list[str]:
    """
    Extract customer IDs from SQL query.

    Looks for patterns:
    - customer_id = 'X'
    - id = 'X' (in customers context)
    - WHERE id = 'X'
    """
    ids = set()

    # customer_id = 'X'
    ids.update(re.findall(r"customer_id\s*=\s*['\"]([A-E])['\"]", sql, re.IGNORECASE))

    # customers table with id = 'X'
    if "customers" in sql.lower():
        ids.update(re.findall(r"(?:customers\.)?id\s*=\s*['\"]([A-E])['\"]", sql, re.IGNORECASE))

    # WHERE id = 'X'
    ids.update(re.findall(r"WHERE\s+id\s*=\s*['\"]([A-E])['\"]", sql, re.IGNORECASE))

    # IN ('A', 'B')
    in_match = re.search(r"IN\s*\(\s*(['\"][A-E]['\"](?:\s*,\s*['\"][A-E]['\"])*)\s*\)", sql, re.IGNORECASE)
    if in_match:
        ids.update(re.findall(r"['\"]([A-E])['\"]", in_match.group(1)))

    return list(ids)


def query_accesses_all(sql: str) -> bool:
    """Check if query accesses all customers (no WHERE filter on customer)."""
    sql_upper = sql.upper()

    if "CUSTOMERS" not in sql_upper and "ORDERS" not in sql_upper:
        return False

    if "WHERE" not in sql_upper:
        return True

    where_idx = sql_upper.find("WHERE")
    where_clause = sql_upper[where_idx:]

    has_filter = (
        "CUSTOMER_ID" in where_clause or
        "CUSTOMERS.ID" in where_clause or
        re.search(r"\bID\s*=\s*['\"][A-E]['\"]", where_clause)
    )

    return not has_filter


def check_policy_with_opa(sql: str, user_id: str) -> PolicyDecision:
    """
    Call OPA to evaluate policy.

    Sends input to OPA, receives decision from Rego policy.
    """
    target_ids = extract_customer_ids(sql)
    accesses_all = query_accesses_all(sql)

    opa_input = {
        "input": {
            "user_id": user_id,
            "target_customer_ids": target_ids,
            "accesses_all": accesses_all
        }
    }

    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.post(f"{OPA_URL}{OPA_POLICY_PATH}", json=opa_input)
            response.raise_for_status()

        result = response.json()
        decision = result.get("result", {})

        return PolicyDecision(
            allowed=decision.get("allowed", False),
            reason=decision.get("reason", "No reason from OPA")
        )

    except httpx.HTTPError as e:
        return PolicyDecision(allowed=False, reason=f"OPA error: {e}")
    except Exception as e:
        return PolicyDecision(allowed=False, reason=f"Policy check failed: {e}")


class WyattEnforcer:
    """
    Wyatt policy enforcer.

    enabled=True: Calls OPA for every query
    enabled=False: Allows everything (vulnerable mode)
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def check(self, sql: str, user_id: str) -> PolicyDecision:
        """Check if SQL query is allowed for user."""
        if not self.enabled:
            return PolicyDecision(allowed=True, reason="Wyatt disabled")
        return check_policy_with_opa(sql, user_id)

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False
