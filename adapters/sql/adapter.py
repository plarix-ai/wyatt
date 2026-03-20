"""
SQL Adapter for Wyatt Policy Enforcement.

Extracts security context from SQL queries and enforces data access policies.
"""

import os
import re
from dataclasses import dataclass

import httpx


OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    allowed: bool
    reason: str


def extract_customer_ids(sql: str) -> list[str]:
    """Extract customer IDs referenced in SQL query."""
    ids = set()
    ids.update(re.findall(r"customer_id\s*=\s*['\"]([A-E])['\"]", sql, re.IGNORECASE))
    if "customers" in sql.lower():
        ids.update(re.findall(r"(?:customers\.)?id\s*=\s*['\"]([A-E])['\"]", sql, re.IGNORECASE))
    ids.update(re.findall(r"WHERE\s+id\s*=\s*['\"]([A-E])['\"]", sql, re.IGNORECASE))
    in_match = re.search(r"IN\s*\(\s*(['\"][A-E]['\"](?:\s*,\s*['\"][A-E]['\"])*)\s*\)", sql, re.IGNORECASE)
    if in_match:
        ids.update(re.findall(r"['\"]([A-E])['\"]", in_match.group(1)))
    return list(ids)


def has_customer_filter(sql: str) -> bool:
    """Check if query filters by customer ID."""
    sql_upper = sql.upper()
    if "CUSTOMERS" not in sql_upper and "ORDERS" not in sql_upper:
        return True
    if "WHERE" not in sql_upper:
        return False
    where_clause = sql_upper[sql_upper.find("WHERE"):]
    return bool(
        "CUSTOMER_ID" in where_clause or
        "CUSTOMERS.ID" in where_clause or
        re.search(r"\bID\s*=\s*['\"][A-E]['\"]", where_clause)
    )


def enforce_data_access(sql: str, user_id: str) -> PolicyDecision:
    """
    Enforce data access policy via OPA.

    Args:
        sql: SQL query to evaluate
        user_id: Authenticated user ID

    Returns:
        PolicyDecision with allowed status and reason
    """
    target_ids = extract_customer_ids(sql)
    accesses_all = not has_customer_filter(sql)

    opa_input = {
        "input": {
            "user_id": user_id,
            "target_customer_ids": target_ids,
            "accesses_all": accesses_all
        }
    }

    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.post(
                f"{OPA_URL}/v1/data/wyatt/sql/decision",
                json=opa_input
            )
            response.raise_for_status()

        result = response.json()
        decision = result.get("result", {})

        return PolicyDecision(
            allowed=decision.get("allowed", False),
            reason=decision.get("reason", "No decision from OPA")
        )

    except Exception as e:
        return PolicyDecision(allowed=False, reason=f"Policy check failed: {e}")
