# Wyatt

Wyatt is a runtime policy enforcement daemon for AI agents. The agent asks Wyatt to use a tool. Wyatt decides the call from a policy file, runs the tool itself inside a sandbox, removes secrets from the output, and writes a signed audit record of what was asked, what was decided and what happened.

The agent runs as a different Unix user from the daemon. It does not hold the file access, network access or API keys its tools need, so a prompt-injected or jailbroken agent cannot skip the check: there is nothing on its side of the socket to skip it with.

```
$ wyatt eval -p examples/devops/wyatt.yaml -a oncall post_incident \
    '{"url":"https://hooks.slack.com/services/T0/B0/x","body":"hi"}' --label secret
deny  rule  this session has read a secret, so it cannot post outside
args  {"body":"hi","url":"https://hooks.slack.com/services/T0/B0/x"}
rules
  incident-channel  allow    skip   args.url.path = "/services/T0/B0/x" fails prefix
  no-exfil          deny     match
```

## What it enforces

- **Identity from the kernel.** Each agent in the policy is bound to a uid, an executable path, a token, or a mix. The daemon reads the caller's credentials with `SO_PEERCRED` and rejects a claim that does not match.
- **Deny by default.** A call no rule allows is denied. A matching `deny` beats `approve`, which beats `allow`, so rule order never opens a hole. There is no permissive mode to leave on by accident.
- **Typed arguments.** Every tool declares its arguments. Unknown, missing and mistyped arguments are refused before any rule runs.
- **Paths checked twice.** Lexically against the tool's root, then by the kernel with `openat2(RESOLVE_BENEATH)`, which also stops symlinks swapped in during the call.
- **Processes in a sandbox.** No shell, a cleared environment, rlimits, a Landlock ruleset for files and TCP, and a process group that is killed on timeout or freeze.
- **HTTP without SSRF.** Host allowlists, DNS resolved and checked against private and metadata ranges, the checked address pinned for the connection, no redirects.
- **Information flow across calls.** Sessions collect labels such as `secret` or `untrusted` as tools run. A rule can deny `post` once the agent has read a secret, even though each call alone is allowed, and `history.labels` keeps the label when the agent opens a new session.
- **Secrets kept out of the model.** Tool output passes through a redactor (private keys, cloud and API tokens, JWTs, connection strings, card numbers, your own patterns) before the agent sees it.
- **Humans in the loop.** `approve` rules hold a call until a named operator runs `wyatt approve`, or until the agent's own UI asks the user.
- **A kill switch that stops things.** `wyatt freeze` denies every new call and kills the process group of every running tool.
- **An audit log you can check.** Every record is hash chained and signed with Ed25519. Records cover outcomes too: exit status, duration, and the size and SHA-256 of the output. `wyatt audit verify` names the line that was changed.
- **MCP servers behind policy.** `wyatt mcp` sits between an MCP host and a stdio server. It hides tools the policy never allows, hides tools whose descriptions carry hidden or steering instructions, pins each tool definition so a later change is caught, checks every `tools/call`, and redacts results.
- **Ready to deploy.** A hardened systemd unit runs the daemon as its own user, gives agents the agent socket through one group and operators the control socket through another.

## Quick start

Linux only. Fs tools need Linux 5.6 or later (`openat2`), and sandboxed processes with no network need Linux 6.7 or later (Landlock ABI 4). On an older kernel those tools are refused, not run unsandboxed.

```sh
cargo build --release
sudo install target/release/wyatt /usr/local/bin/
pip install ./python
```

A policy for an agent that may read one directory and call one API:

```yaml
# wyatt.yaml
version: 1

agents:
  support-bot: { uid: 1001 }

tools:
  read_doc:
    driver: fs.read
    root: /srv/kb
  create_ticket:
    driver: http
    method: post
    hosts: [api.tickets.example.com]
    headers: { Authorization: "Bearer ${env:TICKETS_TOKEN}" }

rules:
  - { id: docs, allow: read_doc }
  - { id: tickets, allow: create_ticket }
  - id: no-secrets-out
    deny: create_ticket
    when: { history.labels: { contains: secret } }
```

Check it and try it as yourself first (set `uid` to your own, `id -u`):

```sh
wyatt check wyatt.yaml
wyatt serve -p wyatt.yaml
```

For real use, the daemon must run as a user the agent is not, or the agent could read the daemon's key and state. [packaging/wyatt.service](packaging/wyatt.service) runs it as `wyatt` with systemd hardening, and agents reach `/run/wyatt/agent.sock` through the `wyatt` group. The comments at the top of the file have the install steps.

The agent, running as uid 1001 with `WYATT_SOCKET=/run/wyatt/agent.sock`:

```python
from wyatt import Client, Denied

with Client("support-bot") as w:
    doc = w.call("read_doc", path="refunds.md").result["content"]
    try:
        w.call("create_ticket", url="https://api.tickets.example.com/v1/tickets", body=doc)
    except Denied as e:
        print(e.decision.rule, e.decision.reason)
```

If `refunds.md` holds something that looks like a credential, the redactor removes it from `doc` and labels the session `secret`, and `no-secrets-out` then denies the ticket. The token in `TICKETS_TOKEN` lives in the daemon's environment, so the agent never sees it.

## Using it with what you have

| You have | Use |
|---|---|
| Python code calling tools | `Client.call` for tools Wyatt runs, `@client.tool(name)` for tools your code runs |
| LangChain | `wyatt.langchain.protect(client, tool)` |
| OpenAI Agents SDK | `wyatt.openai_agents.protect(client, *tools)` (input and output guardrails) |
| An MCP server | `wyatt mcp --server github -- npx -y @modelcontextprotocol/server-github` as the server command in the host |
| Claude Code | `wyatt hook claude-code --print-settings` prints the `PreToolUse` and `PostToolUse` hooks |
| Any other language | The protocol is one JSON object per line over a Unix socket; see `crates/wyatt/src/proto.rs` |

Tools your own code runs (`delegate` and `mcp` drivers) get the policy check, DLP on the output and the audit record, but Wyatt cannot stop code that skips the check. Anything that touches production should run on a mediated driver (`fs.*`, `proc`, `http`).

## Operating it

| Command | Does |
|---|---|
| `wyatt check` | Validates and lints a policy: unknown names, impossible conditions, rules another rule always overrides, broad allows |
| `wyatt test` | Runs YAML test cases, including multi-step sessions and fixed times; exits 1 on a wrong verdict |
| `wyatt eval` | Decides one call and shows every rule that matched or why it did not |
| `wyatt serve` | Runs the daemon |
| `wyatt status`, `sessions` | What the daemon is doing |
| `wyatt approvals`, `approve`, `deny` | The approval queue |
| `wyatt freeze`, `unfreeze` | The kill switch |
| `wyatt reload` | Loads the policy again; a file with errors is refused and the old policy stays |
| `wyatt audit tail -f`, `show`, `verify` | Reads and verifies the audit log |
| `wyatt mcp --scan` | Starts an MCP server, lists its tools and shows which ones the gateway would hide |
| `wyatt token` | Makes an agent token and the hash for the policy |
| `wyatt bench` | Measures the decision engine on one call |

Set `mode: monitor` to log what a new policy would deny without enforcing it.

## Numbers

Measured on an Intel i3-1115G4 laptop with the release build.

| What | p50 | p99 |
|---|---|---|
| Decision engine alone (`wyatt bench`, 200,000 decisions) | 1.9 µs | 3.4 µs |
| `check` from Python over the socket, with a signed audit record | 66 µs | 140 µs |
| `call` of an `fs.read` tool: decide, open, read, redact, two signed records | 74 µs | 154 µs |

A model call takes hundreds of milliseconds, so the check is not the slow part.

## Attacks it stops

`examples/attacks/run.py` starts a daemon and attacks it through the Python client. Every row below is a real run:

```
  held  path traversal with ..                           policy: path_escape
  held  symlink pointing out of the root                 kernel: openat2 RESOLVE_BENEATH (refused)
  held  symlink swapped in while reading (300 reads)     kernel: 123 reads inside, 177 refused, 0 escaped
  held  extra argument smuggled into a tool              policy: bad_args
  held  shell injection in arguments                     driver: argv without a shell, printed literally
  held  careless rule lets cat read any path             kernel: Landlock, cat got "Permission denied"
  held  secret in tool output reaches the model          DLP: redacted secret_assignment; session labelled secret
  held  read a secret, then send it out                  policy: rule no-exfil on the session's labels
  held  read a secret, then send it from a new session   policy: rule no-exfil on history.labels
  held  SSRF to the cloud metadata address               driver: link-local address refused after DNS
  held  SSRF through a name that resolves to loopback    driver: loopback address refused after DNS
  held  claim another agent's name                       identity: SO_PEERCRED uid does not match the agent
  held  guess a token-bound agent's token                identity: token hash mismatch (the right token still works)
  held  flood the output                                 driver: timeout after the tool timeout, output capped
  held  run an approval-gated tool with nobody watching  policy: approval_timeout
  held  keep a tool running after the kill switch        control: process group killed after 0.5 s, new calls frozen
  held  edit the audit log afterwards                    audit: verify points at line 3, the edited record (hash chain, Ed25519)

17 of 17 attacks stopped
```

## Compared with Microsoft's Agent Governance Toolkit

AGT is the best known open source project in this space, and it covers far more ground than Wyatt. The two make a different bet about where enforcement lives. AGT is a library inside the agent's process. Its own docs list it as "application-layer middleware", not "OS kernel / hardware isolation" ([LIMITATIONS.md, section 6](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/LIMITATIONS.md)). Wyatt is a separate process the agent cannot reach into. The table uses AGT's README and LIMITATIONS.md for v4.1, read in November 2026.

| | AGT | Wyatt |
|---|---|---|
| Where the check runs | In the agent's process (`govern(my_tool, policy=...)`) | In a daemon running as another user |
| Who runs the tool | The agent | The daemon, for `fs`, `proc` and `http` tools |
| Agent identity | SPIFFE, DIDs, mTLS, trust scores | Kernel peer credentials, executable path, tokens |
| Default when nothing matches | Configurable; "if the policy evaluator has no policies loaded, the default action is `allow`" (LIMITATIONS 9) | Deny, always |
| Chains of allowed calls (read then post) | Not correlated; workflow policies are listed as "what we're building" (LIMITATIONS 1) | Labels per session and per agent, tested by rules |
| Audit log | Tamper evident; records "attempts, not outcomes" (LIMITATIONS 2) | Hash chain, Ed25519 on every record, outcome records with exit status and output hash |
| Kill switch | Calls a registered callback; "stops non-cooperating execution only if the registered callback stops it" (LIMITATIONS 13) | Kills the tool's process group |
| OS sandbox for tools | Agent Runtime offers "execution sandboxing with four privilege rings"; the recommended architecture puts OS and network isolation in a separate infrastructure layer | Landlock, rlimits, `openat2`, pinned DNS, enforced by the daemon |
| MCP | Security gateway: poisoning, drift, typosquatting, hidden instructions | Gateway: policy on calls, poisoning and hidden characters, definition pinning, DLP on results; no typosquatting check |
| Policy languages | YAML, OPA Rego, Cedar | YAML with a typed condition language |
| Languages | Python, TypeScript, .NET, Go, Rust SDKs | Rust daemon; Python client; any language over the socket protocol |
| Frameworks | 14 listed, including Microsoft Agent Framework, Semantic Kernel, LangChain, CrewAI, OpenAI Agents SDK, Claude Code, Copilot CLI | LangChain, OpenAI Agents SDK, MCP, Claude Code |
| Multi-agent mesh, trust scoring, SRE, compliance mappings | Yes | No |
| Platforms | Anywhere its SDKs run | Linux |
| Policy decision time | Under 0.1 ms (published) | 1.9 µs p50 engine, 66 µs p50 end to end |

Pick AGT for a fleet of agents across languages and clouds, when you need trust between agents or compliance paperwork, or when you run on Windows. Pick Wyatt when one host runs agents you do not trust with real credentials, and you need a check the agent cannot get around. The two can be combined: AGT in the agent for governance across a fleet, Wyatt under it as the last line on the host.

## Documents

- [docs/POLICY.md](docs/POLICY.md): the policy file, every field and test.
- [docs/DESIGN.md](docs/DESIGN.md): threat model and the decisions behind the design.
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md): what Wyatt does not do. Read it before you rely on it.
- [docs/OWASP.md](docs/OWASP.md): how Wyatt maps to the OWASP Top 10 for Agentic Applications.
- [examples/](examples/): an on-call DevOps agent, a Claude Code policy and the attack suite, each with tests.

## Building and testing

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cd python && python -m pytest        # starts a real daemon from target/debug
python examples/attacks/run.py
wyatt test examples/*/tests.yaml
```

The crates are `wyatt-core` (policy model, conditions, decision engine, DLP, MCP checks; no I/O and no clock, so every decision is reproducible) and `wyatt` (daemon, CLI, drivers, audit log, MCP gateway, hooks).

## Author

Built by [Aryan Haghighi](https://www.aryanhaghighi.com) at [Plarix](https://plarix.dev). To cite it, use `CITATION.cff` (GitHub's "Cite this repository" button).
