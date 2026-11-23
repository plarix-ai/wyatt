"""Wyatt for LangChain tools.

    from langchain_core.tools import tool
    from wyatt import Client
    from wyatt.langchain import protect

    @tool
    def send_email(to: str, body: str) -> str:
        "Send an email."
        ...

    w = Client("support-bot", session=thread_id)
    tools = [protect(w, send_email)]

The wrapped tool keeps the original name, description and schema. A
denial comes back to the model as the tool's output (LangChain's
`handle_tool_error`), so the agent sees why and can carry on.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.tools import BaseTool, StructuredTool, ToolException

from .client import Client, Denied


def protect(client: Client, tool: BaseTool, *, name: Optional[str] = None) -> StructuredTool:
    """Returns `tool` with every call checked by Wyatt. `name` is the policy
    tool name when it differs from the LangChain one."""
    if tool.args_schema is None:
        raise TypeError(f"{tool.name} has no args_schema; wrap a structured tool")
    policy_name = name or tool.name

    def run(**kwargs: Any) -> Any:
        try:
            return client.run(policy_name, lambda **a: tool.invoke(a), kwargs)
        except Denied as e:
            raise ToolException(str(e)) from e

    async def arun(**kwargs: Any) -> Any:
        async def call(**a: Any) -> Any:
            return await tool.ainvoke(a)

        try:
            return await client.arun(policy_name, call, kwargs)
        except Denied as e:
            raise ToolException(str(e)) from e

    return StructuredTool.from_function(
        func=run,
        coroutine=arun,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        return_direct=tool.return_direct,
        handle_tool_error=True,
    )
