import asyncio
import uuid

import pytest

from wyatt import Client


def client(daemon):
    return Client("bot", socket_path=daemon["agent"], session=f"a-{uuid.uuid4().hex[:8]}")


TOKEN = "ghp_" + "a" * 36


def test_langchain_tools_are_checked_and_scanned(daemon):
    pytest.importorskip("langchain_core")
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import tool

    from wyatt.langchain import protect

    sent = []

    @tool
    def send_email(to: str, body: str) -> str:
        """Send an email."""
        sent.append(to)
        return f"sent to {to}"

    @tool
    async def search(q: str) -> str:
        """Search the wiki."""
        return f"result for {q}: deploy key {TOKEN}"

    with client(daemon) as w:
        mail, find = protect(w, send_email), protect(w, search)
        assert mail.name == "send_email" and mail.args == send_email.args
        assert mail.invoke({"to": "ops@example.com", "body": "hi"}) == "sent to ops@example.com"

        # Called the way an agent calls it, the denial is the tool message.
        msg = mail.invoke(
            {"type": "tool_call", "name": "send_email", "id": "call_1", "args": {"to": "x@evil.test", "body": "hi"}}
        )
        assert isinstance(msg, ToolMessage) and "wyatt denied send_email" in msg.content

        out = asyncio.run(find.ainvoke({"q": "keys"}))
        assert TOKEN not in out and "[REDACTED:" in out
        assert "denied" in mail.invoke({"to": "ops@example.com", "body": out})
    assert sent == ["ops@example.com"]


def test_openai_agents_guardrails_run_inside_the_agent_loop(daemon):
    pytest.importorskip("agents")
    from agents import Agent, Runner, function_tool, set_tracing_disabled
    from agents.testing import ScriptedModel, assistant_message, function_call

    from wyatt.openai_agents import protect

    set_tracing_disabled(True)
    sent = []

    @function_tool
    def send_email(to: str, body: str) -> str:
        """Send an email."""
        sent.append(to)
        return f"sent to {to}"

    @function_tool
    def search(q: str) -> str:
        """Search the wiki."""
        return f"deploy key {TOKEN}"

    model = ScriptedModel(
        [
            [function_call("send_email", {"to": "x@evil.test", "body": "hi"}, call_id="c1")],
            [function_call("send_email", {"to": "ops@example.com", "body": "hi"}, call_id="c2")],
            [function_call("search", {"q": "keys"}, call_id="c3")],
            [function_call("send_email", {"to": "ops@example.com", "body": "the key"}, call_id="c4")],
            [assistant_message("done")],
        ]
    )
    with client(daemon) as w:
        agent = Agent(name="t", model=model, tools=protect(w, send_email, search))
        result = Runner.run_sync(agent, "go")

    assert result.final_output == "done"
    assert sent == ["ops@example.com"]
    out = {i.raw_item["call_id"]: str(i.output) for i in result.new_items if i.type == "tool_call_output_item"}
    assert out["c1"].startswith("wyatt denied this call")
    assert out["c2"] == "sent to ops@example.com"
    assert TOKEN not in out["c3"] and "[REDACTED:" in out["c3"]
    assert "rule no-exfil" in out["c4"]
