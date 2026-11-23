# Limitations

What Wyatt does not do, or does only in part. Each item says what to do about it where something can be done.

## Deployment

**Linux only.** Identity uses `SO_PEERCRED`, file tools use `openat2` (Linux 5.6), and the process sandbox uses Landlock (Linux 5.13 for files, 6.7 for TCP). On a kernel that lacks a feature a tool needs, that tool is refused. It is never run with less protection.

**The daemon and the agent must be different Unix users.** An agent running as the daemon's user can read the signing key, the state directory and the control socket, and Wyatt protects nothing. [packaging/wyatt.service](../packaging/wyatt.service) sets this up.

**One host.** There is no clustering and no fleet view. If the daemon stops, agents cannot call tools: the client raises `ConnectError` before anything runs, and the adapters let that exception reach the framework as a tool failure.

**State is in memory.** Sessions, labels, `history.labels`, rate windows, pending approvals and approval tickets are lost when the daemon restarts. A call waiting for approval fails when the daemon stops. The policy and the audit log are on disk.

## Tools the agent runs itself

**`delegate` and `mcp` tools are advisory.** Wyatt checks the call and scans the output the client reports, but it cannot stop code that calls the tool without asking. The same holds for the Claude Code hook: Claude Code runs the tool, and the hook only tells it whether to. Put anything with real power (production credentials, deletes, payments) on a mediated driver (`fs.*`, `proc`, `http`), where the daemon holds the access and the agent has none.

**Claude Code needs a version that honours `onFailure`.** The settings from `wyatt hook claude-code --print-settings` use `"onFailure": "block"`, so a hook that crashes or times out blocks the tool. Versions before 2.1.295 ignore the key and run the tool when the hook fails.

**OpenAI Agents SDK guardrails cannot change arguments.** When Wyatt normalises a call's arguments (a relative path made absolute, a default filled in), the input guardrail rejects the call and sends the checked arguments back to the model to retry, because the SDK has no way to rewrite them in place.

**LangChain tools need an `args_schema`.** `wyatt.langchain.protect` raises `TypeError` for a tool without one, since Wyatt cannot check arguments it cannot name.

## The process sandbox

**Landlock does not cover UDP.** A `proc` tool with `net: false` cannot open TCP connections but can still send UDP, which includes DNS queries. A tool that can run arbitrary code can therefore leak data through DNS. Run such tools in a network namespace with no route out (for example a systemd unit with `PrivateNetwork=yes`, or a container), or do not give them arbitrary code.

**Older kernels scope less.** Before Landlock ABI 6 (Linux 6.12), a sandboxed process can still connect to abstract Unix sockets and signal processes outside the sandbox that run as the same user.

**`setsid` escapes the kill.** Timeouts and `wyatt freeze` kill the tool's process group. A tool that calls `setsid` starts a new group and survives. The systemd unit's cgroup still contains it, and `TasksMax` caps how many there can be; `systemctl stop wyatt` ends them.

**No process count limit and no namespaces.** The driver sets limits on address space, CPU time and open files, but not on processes; use `TasksMax` from the systemd unit. Tools share the host's PID and mount namespaces, so they can see the process list and read the system paths Landlock allows (`/usr`, `/lib`, `/bin` and a few files under `/etc`).

**No seccomp filter.** Landlock limits what files and ports a tool can reach, not which system calls it can make.

## HTTP

**The `http` driver runs `curl`.** It needs `curl` in `/usr/bin`, `/bin`, `/usr/local/bin` or the daemon's `PATH`. Each call is one request: redirects are refused, responses are not streamed, and the body is cut at `max_output`.

## Sessions and labels

**The client names its session.** An agent that controls its own code can open a new session to leave its labels behind. Rules that guard against exfiltration should test `history.labels`, which holds the labels of all the agent's sessions. `session.labels` is for rules where a fresh task should start clean.

**Labels only grow.** There is no way to remove a label short of restarting the daemon, and no declassification step.

**Labels only see what passes through Wyatt.** A secret the agent got another way (in its prompt, from a tool Wyatt does not mediate, from memory) carries no label.

## DLP

**Detection is by pattern.** The redactor finds known token formats, key blocks, credentials in URLs and `key=value` assignments. It misses secrets in unknown formats, encoded (base64, hex), split across calls or reworded. `card_number` matches digit runs and can redact numbers that are not cards. Add patterns for your own token formats under `redact.patterns`.

**Arguments are not blocked by DLP.** Secrets in arguments are redacted in the audit log, but the call is decided by rules alone. Use labels to stop a session that has seen a secret from sending things out.

## Audit log

**Removing the end of the log is not detectable from the log alone.** Each record is chained to the one before and signed, so an edit, a deletion in the middle or a reorder is caught. Cutting records off the end leaves a shorter log that still verifies. Stream records off the host (`wyatt audit tail -f --json`) so a copy exists that the host cannot change.

**Records are written but not synced to disk one by one.** A daemon crash loses nothing that was written. A power loss can lose the last records. If the log cannot be written at all, the daemon stops rather than deciding calls it cannot record.

**The signing key lives on the host.** Root, or anyone who reads `/var/lib/wyatt/audit.key`, can sign forged records. The signatures protect against edits by the agent, not against the machine's administrator.

## MCP gateway

**stdio only.** `wyatt mcp` wraps servers started as a command. Servers reached over HTTP are not supported.

**Requests from the server pass through.** Sampling, elicitation and roots requests from the server to the host are relayed without a policy check. Only `tools/list` and `tools/call` are governed.

**Batches are refused.** A JSON-RPC batch from the host gets an error, because each call in it would need its own decision.

**Poisoning checks are patterns.** The gateway hides tools whose definitions contain invisible characters or known steering phrases. An instruction worded in a way the patterns do not know gets through. Hidden or denied tools are a backstop; the policy on `tools/call` is the control.

**Pins are trust on first use.** A tool definition is pinned the first time the gateway sees it. A server that is already poisoned when first run, in a way the scan does not catch, is pinned as it is. Run `wyatt mcp --scan` and read the definitions before the first real run.

**No typosquatting check.** The gateway does not compare server or tool names against known ones.

## Policy language

**Time is UTC.** `time.hour` and `time.weekday` are in UTC. Business hours in another zone need the hours shifted, and the shift changes with daylight saving time.

**No outside data.** Conditions see the call, the agent, the session and the time. They cannot query a database, a directory or another policy engine.

## What Wyatt is not

It does not detect prompt injection, moderate what the model says, or check that a tool's result is true. It assumes the agent will be manipulated and limits what a manipulated agent can do.
