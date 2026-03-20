import asyncio
import json
import re
from dataclasses import dataclass

@dataclass
class PolicyDecision:
    allowed: bool
    reason: str

async def _send_to_wyatt(sql: str, user_id: str) -> dict:
    try:
        reader, writer = await asyncio.open_unix_connection("/tmp/wyatt.sock")
    except Exception as e:
        return {"verdict": "deny", "reason": f"Connection error: {e}"}

    agent_id = "sql-agent"
    
    # 1. Register with Daemon
    writer.write((json.dumps({"action": "register", "agent_id": agent_id}) + "\n").encode())
    await writer.drain()
    await reader.readline()

    # 2. Dynamic Parsing without hardcoded logic
    tables = list(set(m.lower() for m in re.findall(r"(?:FROM|JOIN)\s+([a-zA-Z0-9_]+)", sql, re.IGNORECASE)))
    user_refs = list(set(re.findall(r"id\s*=\s*['\"]([^'\"]+)['\"]", sql, re.IGNORECASE)))
    
    req = {
        "action": "execute",
        "agent_id": agent_id,
        "tool": "query_db",
        "args": {
            "sql": sql, 
            "tables": tables,
            "target_user_refs": user_refs,
            "caller_user": user_id
        }
    }
    
    # 3. Request evaluation
    writer.write((json.dumps(req) + "\n").encode())
    await writer.drain()
    
    resp_raw = await reader.readline()
    if not resp_raw:
        return {"verdict": "deny", "reason": "Daemon disconnected cleanly"}
    
    resp = json.loads(resp_raw.decode("utf-8").strip())

    # 4. Cleanup
    writer.write((json.dumps({"action": "disconnect"}) + "\n").encode())
    await writer.drain()
    writer.close()
    
    try:
        await writer.wait_closed()
    except Exception:
        pass
        
    return resp

def enforce_data_access(sql: str, user_id: str) -> PolicyDecision:
    resp = asyncio.run(_send_to_wyatt(sql, user_id))
    return PolicyDecision(
        allowed=(resp.get("verdict") == "allow"),
        reason=resp.get("reason", "Unknown")
    )
