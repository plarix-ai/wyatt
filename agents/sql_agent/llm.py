"""
DeepSeek LLM integration for natural language to SQL conversion.
"""

import os
import re
from typing import Optional

import httpx

from database import get_schema


DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"


def get_api_key() -> str:
    """Get DeepSeek API key from environment."""
    key = os.getenv("DEEPSEEK_API_KEY")
    if not key:
        raise ValueError("DEEPSEEK_API_KEY not set")
    return key


def build_system_prompt(user_id: str) -> str:
    """Build system prompt for SQL generation."""
    schema = get_schema()
    return f"""You are a SQL query generator. Convert user questions into SQLite queries.

{schema}

RULES:
1. Return ONLY the SQL query, no explanations
2. Current user is customer ID: {user_id}
3. "my" refers to customer_id = '{user_id}'
4. Only SELECT statements allowed
5. No DROP, DELETE, UPDATE, INSERT, ALTER, CREATE

Example:
User: "show me my orders"
SQL: SELECT id, amount, date, status FROM orders WHERE customer_id = '{user_id}'
""".strip()


def extract_sql(response: str) -> Optional[str]:
    """Extract SQL from LLM response."""
    code_block = re.search(r"```(?:sql)?\s*(.*?)```", response, re.DOTALL | re.IGNORECASE)
    if code_block:
        return code_block.group(1).strip()
    cleaned = response.strip()
    if cleaned.upper().startswith("SELECT"):
        return cleaned
    return None


def generate_sql(question: str, user_id: str) -> str:
    """Convert natural language question to SQL."""
    api_key = get_api_key()

    payload = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": build_system_prompt(user_id)},
            {"role": "user", "content": question}
        ],
        "temperature": 0.1,
        "max_tokens": 500
    }

    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            DEEPSEEK_API_URL,
            json=payload,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        )
        response.raise_for_status()

    result = response.json()
    llm_response = result["choices"][0]["message"]["content"]

    sql = extract_sql(llm_response)
    if not sql:
        raise ValueError(f"Could not extract SQL: {llm_response}")
    return sql


def validate_sql(sql: str) -> tuple[bool, str]:
    """Basic SQL safety check."""
    sql_upper = sql.upper().strip()
    forbidden = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE"]
    for kw in forbidden:
        if kw in sql_upper.split():
            return False, f"Forbidden: {kw}"
    if not sql_upper.startswith("SELECT"):
        return False, "Only SELECT allowed"
    return True, "OK"
