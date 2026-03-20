"""
SQL Agent Chatbot - Natural Language to SQL with Wyatt Policy Enforcement.

Usage:
    cd wyatt/agents/sql_agent
    ./run.sh                    # Default (user A, Wyatt ON)
    ./run.sh --user B           # Start as user B
    ./run.sh --no-wyatt         # Disable Wyatt (vulnerable mode)

Commands:
    /wyatt on   - Enable Wyatt (OPA policy enforcement)
    /wyatt off  - Disable Wyatt (vulnerable mode)
    /user X     - Switch to user X (A, B, C, D, E)
    /status     - Show current state
    /sql        - Show last SQL
    /quit       - Exit
"""

import argparse
import sys
from pathlib import Path

# Allow imports from this directory
sys.path.insert(0, str(Path(__file__).parent))

from database import init_database, execute_query, DB_PATH
from llm import generate_sql, validate_sql
from enforcer import WyattEnforcer


def format_results(results: list[dict]) -> str:
    """Format query results as table."""
    if not results:
        return "No results."

    cols = list(results[0].keys())
    widths = {c: max(len(c), max(len(str(r[c])) for r in results)) for c in cols}

    header = " | ".join(c.ljust(widths[c]) for c in cols)
    sep = "-+-".join("-" * widths[c] for c in cols)
    rows = "\n".join(" | ".join(str(r[c]).ljust(widths[c]) for c in cols) for r in results)

    return f"\n{header}\n{sep}\n{rows}"


def main() -> None:
    parser = argparse.ArgumentParser(description="SQL Agent Chatbot")
    parser.add_argument("--user", default="A", choices=list("ABCDE"))
    parser.add_argument("--no-wyatt", action="store_true", help="Disable Wyatt (vulnerable)")
    args = parser.parse_args()

    user = args.user
    enforcer = WyattEnforcer(enabled=not args.no_wyatt)
    last_sql = None

    if not DB_PATH.exists():
        print("Initializing database...")
        init_database()

    print("\n" + "=" * 60)
    print("  SQL Agent - Wyatt v0.3.0-alpha")
    print("=" * 60)
    print(f"User: {user}")
    print(f"Wyatt: {'ON (OPA enforcement)' if enforcer.enabled else 'OFF (vulnerable)'}")
    print("Type /help for commands")
    print("-" * 60)

    while True:
        try:
            inp = input(f"\n[{user}]> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break

        if not inp:
            continue

        if inp.startswith("/"):
            cmd = inp.lower()
            if cmd in ("/quit", "/exit"):
                break
            elif cmd == "/help":
                print(__doc__)
            elif cmd == "/status":
                print(f"User: {user}")
                print(f"Wyatt: {'ON' if enforcer.enabled else 'OFF'}")
            elif cmd == "/sql":
                print(f"Last SQL: {last_sql}" if last_sql else "No SQL yet")
            elif cmd == "/wyatt on":
                enforcer.enable()
                print("Wyatt ON")
            elif cmd == "/wyatt off":
                enforcer.disable()
                print("Wyatt OFF (vulnerable)")
            elif cmd.startswith("/user "):
                new_user = cmd.split()[1].upper()
                if new_user in "ABCDE":
                    user = new_user
                    print(f"Switched to {user}")
                else:
                    print("Invalid user")
            else:
                print(f"Unknown: {cmd}")
            continue

        try:
            print("Generating SQL...")
            sql = generate_sql(inp, user)
            last_sql = sql
            print(f"SQL: {sql}")

            ok, reason = validate_sql(sql)
            if not ok:
                print(f"[BLOCKED] {reason}")
                continue

            decision = enforcer.check(sql, user)
            if not decision.allowed:
                print(f"[WYATT BLOCKED] {decision.reason}")
                continue

            if enforcer.enabled:
                print(f"[WYATT OK] {decision.reason}")

            results = execute_query(sql)
            print(format_results(results))

        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()
