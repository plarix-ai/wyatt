# OWASP Top 10 for Agentic Applications

How Wyatt maps to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) (December 2025). "Strong" means Wyatt enforces a control the agent cannot get around for tools on mediated drivers. "Partial" means it limits the damage or covers one path into the risk. "None" means it does not address the risk.

| | Risk | Coverage |
|---|---|---|
| ASI01 | Agent Goal Hijack | Partial |
| ASI02 | Tool Misuse and Exploitation | Strong |
| ASI03 | Identity and Privilege Abuse | Strong on one host |
| ASI04 | Agentic Supply Chain Vulnerabilities | Partial |
| ASI05 | Unexpected Code Execution | Partial |
| ASI06 | Memory and Context Poisoning | Partial |
| ASI07 | Insecure Inter-Agent Communication | None |
| ASI08 | Cascading Failures | Partial |
| ASI09 | Human-Agent Trust Exploitation | Partial |
| ASI10 | Rogue Agents | Partial |

## ASI01 Agent Goal Hijack

Wyatt does not detect injected instructions. It assumes the agent's goal will be hijacked and limits what the hijacked agent can do: deny by default, typed arguments, path and host allowlists, and labels that block "read the secret, then send it" across calls and sessions. The MCP gateway hides tools whose descriptions carry steering text or invisible characters, which closes one route for injection.

To use: allow only the tools and arguments a task needs. Add a `no-exfil` rule on `history.labels` for every tool that can send data out.

## ASI02 Tool Misuse and Exploitation

This is what Wyatt is built for. Each call is checked against a typed schema and the rules before it runs. Paths are confined twice, the second time by the kernel. HTTP tools refuse private and metadata addresses after DNS and pin the checked address. Processes run without a shell. Rate limits and per-session call budgets stop loops. `approve` rules put a human in front of calls that change things.

Limit: tools on the `delegate` and `mcp` drivers run in the agent, so the agent can skip the check. See [LIMITATIONS.md](LIMITATIONS.md).

## ASI03 Identity and Privilege Abuse

Agents are identified by the kernel (`SO_PEERCRED` uid and gid, the executable path) and optionally a token, not by a name they claim. The credentials tools need stay in the daemon's environment and are filled into process environments and HTTP headers at run time, so the agent never holds them. Rules and limits apply per agent.

Limit: identity is local to one host. There is no delegation chain (an agent acting for a particular user) and no identity between agents on different machines.

## ASI04 Agentic Supply Chain Vulnerabilities

`wyatt mcp` pins every tool definition by hash and hides a tool whose definition changes (a rug pull) until an operator runs `--repin`. It hides tools with invisible Unicode, bidi controls or known steering phrases, and warns on mentions of credential files. `wyatt mcp --scan` shows all of this before the server is first used.

Limit: no signature or provenance check on servers or packages, no typosquatting check, and the poisoning checks are patterns.

## ASI05 Unexpected Code Execution

Tools on the `proc` driver run without a shell, with a cleared environment, limits on memory and CPU time, a timeout that kills the process group, and a Landlock ruleset that confines files and TCP. A rule that lets an agent pass any argument to a command still cannot reach files outside the sandbox.

Limit: Wyatt does not sandbox the agent's own process, and code the agent runs on its own is outside its reach. Landlock does not cover UDP, and there is no seccomp filter.

## ASI06 Memory and Context Poisoning

Wyatt does not inspect or protect memory stores. Labels let a policy react to what entered the context: a tool that returns untrusted content (web pages, emails, tickets) can carry `labels: [untrusted]`, and rules can then deny or require approval for sensitive tools in any session that has read untrusted input. DLP keeps secrets out of what the model reads, so they do not end up in its memory.

## ASI07 Insecure Inter-Agent Communication

Not covered. Wyatt authenticates agents to the daemon on one host and does not carry or check messages between agents.

## ASI08 Cascading Failures

Rate limits per agent, call budgets per session, tool timeouts and output caps bound how much one agent can do. Wyatt fails closed: when the daemon is unreachable or cannot write its audit log, calls stop instead of going through. A policy with errors is refused at startup, and `wyatt reload` keeps the old policy if the new one has errors. `wyatt freeze` stops every agent at once.

Limit: no circuit breakers between agents and no view across hosts.

## ASI09 Human-Agent Trust Exploitation

Approvals show the operator the checked arguments, the rule and its reason, not the agent's summary of what it wants to do. Each approval is recorded with the name of the operator who gave it, and a rule can limit who may approve. Unanswered approvals are denied after `approval_timeout`.

Limit: Wyatt cannot stop a person from approving a harmful call they were talked into.

## ASI10 Rogue Agents

An agent cannot act outside its policy, so a rogue agent is limited to what it was allowed. Every call and outcome is in a signed audit log. `wyatt freeze` denies all calls and kills running tools. `mode: monitor` shows what a policy would block before it is enforced. `history.labels` keeps an agent from shedding what it has touched by opening new sessions.

Limit: Wyatt does not detect that an agent has gone rogue. It contains it.
