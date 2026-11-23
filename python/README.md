# wyatt-client

Python client for [Wyatt](https://github.com/plarix-ai/wyatt). It speaks the
daemon's line protocol over a Unix socket and has no dependencies.

```python
from wyatt import Client, Denied

with Client("ops", session="task-42") as w:
    # Tools Wyatt runs itself: fs, proc, http.
    logs = w.call("read_logs", path="/var/log/app.log").result

    # Tools your code runs: Wyatt checks the arguments first and scans the
    # output for secrets after.
    @w.tool("send_email")
    def send_email(to: str, body: str) -> str:
        ...

    try:
        send_email("someone@outside.test", logs["content"])
    except Denied as e:
        print(e.decision.reason, e.decision.audit)
```

`Client.check` and `Client.report` are the two halves of `Client.run`, for
code that needs to run the tool some other way. `Control` talks to the
operator socket: status, approvals, freeze.

Adapters:

- `wyatt.langchain.protect(client, tool)` wraps any LangChain `BaseTool`.
- `wyatt.openai_agents.protect(client, *tools)` adds Wyatt as a tool input
  and output guardrail on OpenAI Agents SDK function tools.

The tests start a real daemon. Build it first with `cargo build`, then run
`python -m pytest` in this directory.
