#!/usr/bin/env python3
"""
SQL Agent Test - Direct SQL Input (no LLM needed)
Demonstrates Wyatt policy enforcement without API costs.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from database import execute_query, init_database, DB_PATH
from enforcer import WyattEnforcer

def format_results(results):
    if not results:
        return "No results."
    cols = list(results[0].keys())
    widths = {c: max(len(c), max(len(str(r[c])) for r in results)) for c in cols}
    header = " | ".join(c.ljust(widths[c]) for c in cols)
    sep = "-+-".join("-" * widths[c] for c in cols)
    rows = "\n".join(" | ".join(str(r[c]).ljust(widths[c]) for c in cols) for r in results)
    return f"\n{header}\n{sep}\n{rows}"

def main():
    if not DB_PATH.exists():
        print("Initializing database...")
        init_database()

    print("\n" + "=" * 60)
    print("  SQL Agent Test - Wyatt v0.3.0-alpha")
    print("  Type SQL directly (no LLM required)")
    print("=" * 60)

    user = "A"
    enforcer = WyattEnforcer(enabled=True)

    print(f"\nUser: {user}")
    print(f"Wyatt: {'ON' if enforcer.enabled else 'OFF'}")
    print("\nCommands: /user X, /wyatt on|off, /quit")
    print("\nExample SQL queries:")
    print("  SELECT * FROM customers WHERE id = 'A'")
    print("  SELECT * FROM customers WHERE id = 'B'  (will block)")
    print("  SELECT * FROM orders WHERE customer_id = 'A'")
    print("-" * 60)

    while True:
        try:
            inp = input(f"\n[{user}]> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye!")
            break

        if not inp:
            continue

        if inp.startswith("/"):
            cmd = inp.lower()
            if cmd in ("/quit", "/exit"):
                break
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

        sql = inp
        print(f"SQL: {sql}")

        decision = enforcer.check(sql, user)
        if not decision.allowed:
            print(f"[WYATT BLOCKED] {decision.reason}")
            continue

        if enforcer.enabled:
            print(f"[WYATT OK] {decision.reason}")

        try:
            results = execute_query(sql)
            print(format_results(results))
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
