# Wyatt design

Wyatt is a reference monitor for AI agents. An agent asks Wyatt to run a tool. Wyatt decides, runs the tool itself under limits, filters the output, and writes a signed audit record. The agent never holds the credentials or file access that the tool needs, so it cannot skip the check.

## Threat model

The agent is untrusted. Its model can be jailbroken or prompt-injected through any text it reads, so we assume that any tool call it makes may be hostile.

We defend against:

- calls to tools the agent was never given
- arguments that reach outside the allowed scope: path traversal, symlink escape, SSRF to cloud metadata and private networks, extra or misspelled arguments
- data exfiltration by a chain of calls that are each allowed on their own (read a secret, then send it out)
- secrets leaking back to the model in tool output
- one agent claiming to be another
- runaway loops: call floods and long-running processes
- edits to the audit log after the fact

We do not defend against:

- a compromised kernel or root on the host
- an agent running as the same Unix user as the daemon. That agent can read the daemon's key and state files, so run the daemon as its own user.
- harm done through an allowed tool with allowed arguments. A policy that allows `rm -rf` on a directory allows it.
- what the model says to the user. Wyatt governs actions, not text.

## Architecture

```
 agent process (uid 1001)           wyattd (uid wyatt)
 ┌──────────────────────┐   unix    ┌──────────────────────────────────────────┐
 │ python SDK / MCP /   │──socket──►│ identity: SO_PEERCRED + exe + token      │
 │ framework adapter    │           │ schema check, path normalisation         │
 └──────────────────────┘           │ policy engine (deny overrides allow)     │
                                    │ session and agent labels, limits         │
 operator                           │ approvals queue, kill switch             │
 ┌──────────────────────┐  control  │ drivers: fs (openat2), proc (landlock,   │
 │ wyatt CLI            │──socket──►│   rlimits), http (curl, pinned DNS)      │
 └──────────────────────┘  (0600)   │ DLP redaction of output                  │
                                    │ audit: hash chain, ed25519 per record    │
                                    └──────────────────────────────────────────┘
```

Two crates:

- `wyatt-core`: the policy model, condition matching, path normalisation, decision engine, session state, DLP and static checks. It has no I/O and no clock (time comes in as an argument), so every decision is reproducible in tests.
- `wyatt`: the daemon, CLI, tool drivers, audit log, MCP gateway and Claude Code hook.

The Python package `wyatt-client` speaks the socket protocol and has adapters for LangChain and the OpenAI Agents SDK. The protocol is one JSON object per line, so a client in another language is a few hundred lines.

The daemon uses one OS thread per connection and no async runtime. Local agents are few, and a small codebase is easier to audit.

## Decisions

1. **Identity comes from the kernel.** The daemon reads the peer's uid, gid and pid with `SO_PEERCRED`, then reads `/proc/<pid>/exe`. An agent entry in the policy binds a name to a uid, an exe glob, a token, or a mix. The client only names which agent it claims to be, and the daemon rejects the claim if the binding does not match. An agent with no binding is a policy error.
2. **Deny by default, and deny wins.** All rules that match a call are collected. Any `deny` gives deny. Otherwise any `approve` holds the call for a human. Otherwise any `allow` gives allow. If nothing matches, the call is denied. Rule order does not change the result, so a new rule can never open a hole by being placed early. Cedar and AWS IAM use the same rule.
3. **Arguments are typed.** Each tool declares its arguments. Unknown arguments, missing required ones and wrong types are denied before the rules run. The v0.3 prototype let a call skip a path rule by leaving the argument out or renaming it. That is now impossible.
4. **Paths are checked twice.** First lexically: the path is joined to the tool's root, `.` and `..` are folded, and a result outside the root is denied. Then at open time, the fs driver opens the file with `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` relative to the root directory fd. A symlink planted inside the root cannot escape, even if it is swapped in between the check and the open.
5. **Information flow is tracked per session and per agent.** Tools and rules attach labels such as `secret` or `untrusted` to the session when they run, and DLP adds `secret` when it redacts output. Rules can test `session.labels`. This blocks "read the customer table, then post it" even though each call alone is allowed. AGT lists this as a known gap in its LIMITATIONS document. Clients name their own sessions, so the daemon also keeps the union of an agent's labels across sessions as `history.labels`; a rule on it cannot be escaped by opening a new session.
6. **The daemon runs the tool.** Built-in drivers cover files, processes and HTTP. `proc` tools run without a shell, with a cleared environment, rlimits, a new process group that is killed on timeout, and a Landlock ruleset that limits file access and TCP. `http` tools resolve DNS first, reject private and metadata addresses, and pin the checked IP with `curl --resolve`, which defeats DNS rebinding. A `delegate` driver exists for tools that must run inside the agent. It is advisory, and the docs say so.
7. **The audit log records outcomes.** A decision record holds the verdict, the rule, the reason and the redacted arguments. An outcome record holds the status, the duration, the output size and the SHA-256 of the output as the agent received it. Records form a SHA-256 chain and each one is signed with Ed25519, so `wyatt audit verify` names the exact line that was edited, removed or moved. Signing every record is affordable: a `check` over the socket, including its signed record, takes 66 µs at the median on a laptop i3. The log cannot show that records were cut from the end; [LIMITATIONS.md](LIMITATIONS.md) says what to do about that. If the log cannot be written, the daemon exits rather than decide calls it cannot record.
8. **Monitor mode for rollout.** With `mode: monitor` the daemon computes every decision and logs `would_deny`, but still runs the call. Teams can see what a policy would break before they enforce it.
9. **Policies are tested like code.** `wyatt check` runs static checks: unknown names, arguments that a tool does not have, invalid regexes, conditions that can never hold (such as `time.hour: 24`), allow rules that a deny always overrides, allow rules hidden behind an `approve` rule with no condition, and broad allows with no conditions. `wyatt test` runs YAML test cases, including multi-step sessions, fixed times and prior history, and fails CI on a wrong verdict.
10. **Approvals go where the human is.** By default an `approve` verdict holds the call in the daemon until an operator answers on the control socket, and the answer is recorded under the operator's Unix user name, which is what a rule's `approvers` list matches. A client with its own user interface (Claude Code asks the user itself) can ask for the verdict instead and handle the question; the call then counts against the session at once, since a yes runs the tool without coming back.
11. **The kill switch is enforced by the daemon.** `wyatt freeze` denies every new call, denies every waiting approval and sends SIGKILL to the process group of every running tool. The caller of a killed tool gets status `stopped` with the reason, so it can tell a freeze from a crash.
12. **MCP servers sit behind the same policy.** `wyatt mcp` runs a stdio MCP server as a child and proxies JSON-RPC between it and the host. Tool names become `mcp__<server>__<tool>`, and a policy can cover a whole server with a pattern such as `mcp__github__*`; an exact entry wins over a pattern. On `tools/list` the gateway asks the daemon which tools the agent could ever be allowed (the `visible` op), inspects each definition for hidden characters and steering text, and compares it with its pinned hash; tools that fail any of these are left out of the list and refused if called. Each `tools/call` is checked first, and the result goes back through DLP. Gateway events such as a changed definition are written to the daemon's audit log with the `notice` op, so the gateway needs no key of its own.

## What Wyatt is not

It is not a model guardrail. It does not try to detect prompt injection in text. It assumes injection will happen and limits what an injected agent can do.
