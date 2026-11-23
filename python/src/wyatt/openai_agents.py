"""Wyatt for the OpenAI Agents SDK, as tool guardrails.

    from agents import Agent, function_tool
    from wyatt import Client
    from wyatt.openai_agents import protect

    @function_tool
    def send_email(to: str, body: str) -> str:
        ...

    w = Client("support-bot", session=conversation_id)
    agent = Agent(name="support", tools=protect(w, send_email))

The input guardrail checks each call before the tool runs; a denial
replaces the tool output with the reason, so the model sees it. The
output guardrail reports what the tool returned and, if DLP found
secrets, the model gets the redacted output instead.

The SDK's guardrails cannot rewrite arguments. When Wyatt normalizes
them (a path with `..`, say), the call is turned back with the checked
arguments in the message, and the model has to call again with those.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Sequence, TypeVar

from agents import (
    FunctionTool,
    ToolGuardrailFunctionOutput,
    ToolInputGuardrail,
    ToolInputGuardrailData,
    ToolOutputGuardrail,
    ToolOutputGuardrailData,
    tool_input_guardrail,
    tool_output_guardrail,
)

from .client import Client, RequestError, _wire

T = TypeVar("T", bound=FunctionTool)


def guardrails(client: Client) -> tuple[ToolInputGuardrail[Any], ToolOutputGuardrail[Any]]:
    """The input and output guardrail pair, for attaching by hand."""

    @tool_input_guardrail(name="wyatt")
    async def check(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        ctx = data.context
        try:
            args = json.loads(ctx.tool_arguments or "{}")
        except json.JSONDecodeError:
            return ToolGuardrailFunctionOutput.reject_content("wyatt: the tool arguments are not valid JSON")
        d = await asyncio.to_thread(client.check, ctx.tool_name, args, ticket=ctx.tool_call_id)
        if not d.allowed:
            return ToolGuardrailFunctionOutput.reject_content(
                f"wyatt denied this call: {d.describe()}", output_info={"code": d.code, "audit": d.audit}
            )
        if isinstance(d.args, dict) and d.args != args:
            return ToolGuardrailFunctionOutput.reject_content(
                "wyatt normalized the arguments; call the tool again with exactly these: " + json.dumps(d.args),
                output_info={"code": "normalized", "audit": d.audit},
            )
        return ToolGuardrailFunctionOutput.allow(output_info={"audit": d.audit})

    @tool_output_guardrail(name="wyatt")
    async def scan(data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
        ctx = data.context
        try:
            rep = await asyncio.to_thread(client.report, ctx.tool_call_id, _wire(data.output))
        except RequestError as e:
            # No ticket: the input guardrail is missing from this tool.
            return ToolGuardrailFunctionOutput.reject_content(f"wyatt withheld this output: {e.message}")
        if not rep.redacted:
            return ToolGuardrailFunctionOutput.allow()
        text = rep.output if isinstance(rep.output, str) else json.dumps(rep.output)
        return ToolGuardrailFunctionOutput.reject_content(text, output_info={"redacted": dict(rep.redacted)})

    return check, scan


def protect(client: Client, *tools: T) -> list[T]:
    """Adds the Wyatt guardrails to each function tool and returns them as a list."""
    check, scan = guardrails(client)
    for t in tools:
        if not isinstance(t, FunctionTool):
            raise TypeError(f"{t!r} is not a FunctionTool; Wyatt guardrails attach to function tools")
        t.tool_input_guardrails = [*(t.tool_input_guardrails or []), check]
        t.tool_output_guardrails = [*(t.tool_output_guardrails or []), scan]
    return list(tools)


__all__: Sequence[str] = ["guardrails", "protect"]
