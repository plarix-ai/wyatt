"""
SQLite database operations for the SQL Agent.

Tables:
- customers: id, name, email, balance, tier
- orders: id, customer_id, amount, date, status
"""

import sqlite3
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).parent / "data.db"


def get_connection() -> sqlite3.Connection:
    """Get a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database() -> None:
    """Initialize the database with schema and sample data."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS customers;

        CREATE TABLE customers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            balance REAL NOT NULL DEFAULT 0,
            tier TEXT NOT NULL DEFAULT 'basic'
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id TEXT NOT NULL,
            amount REAL NOT NULL,
            date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        );
    """)

    customers = [
        ("A", "Alice Anderson", "alice@example.com", 15000.00, "premium"),
        ("B", "Bob Baker", "bob@example.com", 8500.50, "basic"),
        ("C", "Charlie Chen", "charlie@example.com", 42000.00, "enterprise"),
        ("D", "Diana Davis", "diana@example.com", 3200.75, "basic"),
        ("E", "Eve Edwards", "eve@example.com", 28500.00, "premium"),
    ]
    cursor.executemany(
        "INSERT INTO customers (id, name, email, balance, tier) VALUES (?, ?, ?, ?, ?)",
        customers
    )

    orders = [
        ("A", 250.00, "2024-03-15", "completed"),
        ("A", 175.50, "2024-03-18", "completed"),
        ("B", 89.99, "2024-03-10", "completed"),
        ("B", 320.00, "2024-03-19", "pending"),
        ("C", 1500.00, "2024-03-12", "completed"),
        ("C", 2200.00, "2024-03-17", "completed"),
        ("C", 800.00, "2024-03-20", "pending"),
        ("D", 45.00, "2024-03-08", "completed"),
        ("E", 650.00, "2024-03-14", "completed"),
        ("E", 420.00, "2024-03-16", "completed"),
    ]
    cursor.executemany(
        "INSERT INTO orders (customer_id, amount, date, status) VALUES (?, ?, ?, ?)",
        orders
    )

    conn.commit()
    conn.close()


def execute_query(sql: str) -> list[dict[str, Any]]:
    """Execute a SQL query and return results as list of dicts."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(sql)
    columns = [d[0] for d in cursor.description] if cursor.description else []
    rows = cursor.fetchall()
    conn.close()
    return [dict(zip(columns, row)) for row in rows]


def get_schema() -> str:
    """Return database schema for LLM context."""
    return """
TABLE customers (
    id TEXT PRIMARY KEY,         -- Customer ID (A, B, C, D, E)
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    balance REAL NOT NULL,
    tier TEXT NOT NULL           -- basic, premium, enterprise
)

TABLE orders (
    id INTEGER PRIMARY KEY,
    customer_id TEXT NOT NULL,   -- References customers.id
    amount REAL NOT NULL,
    date TEXT NOT NULL,
    status TEXT NOT NULL         -- pending, completed
)
""".strip()


if __name__ == "__main__":
    init_database()
    print(f"Database initialized at {DB_PATH}")
