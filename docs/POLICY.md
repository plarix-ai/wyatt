# Policy reference

A policy is one YAML file. `wyatt check` validates it, `wyatt test` runs test cases against it, and `wyatt serve` enforces it. Unknown keys are errors everywhere, so a typo cannot silently turn a rule off.

```yaml
version: 1
name: devops-oncall
mode: enforce            # or monitor

defaults:
  timeout: 20s           # per tool call
  max_output: 512KiB     # per tool call
  approval_timeout: 15m  # how long a call waits for a human

agents: { ... }
tools: { ... }
rules: [ ... ]
limits: [ ... ]
redact: { ... }
```

Durations take `ms`, `s`, `m` or `h`. Sizes take `B`, `KiB`, `MiB`, `GiB` (powers of 1024) or `KB`, `MB`, `GB` (powers of 1000). Rates take a count per unit: `5/s`, `60/min`, `1000/h`, `10000/day`.

## Agents

An agent is a name bound to something the kernel can prove. The client says which agent it is; the daemon checks the claim against the peer's credentials from `SO_PEERCRED` and rejects it if any binding fails. An agent with no binding is an error.

```yaml
agents:
  oncall:
    uid: 990                       # peer uid
    gid: 990                       # peer gid
    exe: /opt/oncall/bin/*         # glob on /proc/<pid>/exe
    token_sha256: 3f1c...          # sha256 of a token the client sends
    labels: [team.sre]             # visible to rules as agent.labels
```

`wyatt token` prints a fresh token and the hash to put here. Tokens matter when several agents share a uid, for example in containers that all map to one user.

## Tools

Each tool has a driver. The first five run inside the daemon, so the agent never holds the file handles, keys or network access they need.

| Driver | Runs | Arguments the agent sends | Settings |
|---|---|---|---|
| `fs.read` | in the daemon | `path` | `root` |
| `fs.list` | in the daemon | `path` (default `.`) | `root` |
| `fs.write` | in the daemon | `path`, `content` | `root` |
| `proc` | in the daemon | `args` (list, appended to `command`) | `command`, `cwd`, `env`, `sandbox` |
| `http` | in the daemon | `url`, plus `body` for post, put and patch | `method`, `hosts`, `headers`, `allow_private` |
| `delegate` | in the agent | declared in `args` | |
| `mcp` | in an MCP server, through `wyatt mcp` | declared in `args` | |

Settings every tool takes: `description`, `args`, `labels`, `timeout`, `max_output`.

### fs tools

Paths are joined to `root`, `.` and `..` are folded, and a path that ends up outside the root is denied with code `path_escape` before any rule runs. The driver then opens the file with `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` from a handle on the root, so a symlink inside the root cannot lead out of it, even one swapped in between the check and the open. Rules see the normalised absolute path in `args.path`.

### proc tools

```yaml
kubectl_get:
  driver: proc
  command: [/usr/local/bin/kubectl, get, --request-timeout=10s]
  env:
    KUBECONFIG: /etc/oncall/kubeconfig
    API_TOKEN: ${env:ONCALL_API_TOKEN}   # filled in from the daemon's environment
  sandbox:
    read: [/etc/oncall/kubeconfig]
    write: []
    net: true
    memory: 512MiB
    cpu: 20s
```

There is no shell. `command` and the agent's `args` become one argv, so `$(id)` stays the literal string `$(id)`. The process starts with a cleared environment holding only `env`, in a new process group that is killed on timeout or freeze, with rlimits on address space and CPU time from the sandbox settings, a cap on open files, and no core dumps.

The sandbox is a Landlock ruleset. By default the process can read the system library and binary directories, the command itself and `cwd`, write only `/dev/null`, and open no TCP connections. `read` and `write` add paths; `net: true` allows TCP. If the kernel has no Landlock, the call is refused unless the tool says `sandbox: { enabled: false }`, which `wyatt check` warns about.

### http tools

```yaml
post_incident:
  driver: http
  method: post
  hosts: [hooks.slack.com]
  headers:
    Authorization: Bearer ${env:SLACK_TOKEN}
```

The host must match `hosts` (globs allowed) or the call is denied with code `egress`. The driver then resolves the name, refuses loopback, private, link-local, CGNAT and metadata addresses unless `allow_private: true`, and pins the checked address with `curl --resolve`, so a DNS answer that changes between the check and the connect is not used. Redirects are not followed. Rules can test the parts of the URL as `args.url.host`, `args.url.scheme`, `args.url.port` and `args.url.path`.

### delegate and mcp tools

These run outside the daemon. Wyatt checks the call, and the client reports the output back so DLP and labels still apply. Wyatt cannot stop an agent that skips the check and runs the tool directly, so put tools that touch anything important on a mediated driver.

Their names may be patterns, such as `mcp__github__*`. An exact entry wins over a pattern, and among patterns the most specific one wins. Rules and limits see the name the call used.

### Argument schemas

```yaml
args:
  service: string
  replicas: int?                   # ? makes it optional
  env: { type: string, one_of: [staging, prod] }
  ref: { type: string, pattern: '[a-f0-9]{40}', max_len: 40 }
  dry_run: { type: bool, default: true }
  "*": any                         # let undeclared arguments through
```

Types: `string`, `path`, `url`, `int`, `number`, `bool`, `list`, `object`, `any`. An argument the schema does not name is denied with `bad_args`, as are missing required arguments and wrong types. `args: any` turns checking off for the tool; `wyatt check` warns about it.

## Rules

```yaml
rules:
  - id: incident-channel
    allow: post_incident             # a tool, a glob, or a list of either
    agents: oncall                   # optional; same forms
    when: { args.url.path: { prefix: /services/T0001/B0002/ } }

  - id: no-exfil
    deny: post_incident
    when: { session.labels: { contains: secret } }
    reason: this session has read a secret, so it cannot post outside

  - id: restart
    approve: restart_service
    approvers: [alice, bob]
    labels: [changed-prod]           # added to the session when the call runs
```

Every rule that matches a call counts. One `deny` makes the call denied. Otherwise one `approve` holds the call for a human. Otherwise one `allow` lets it run. A call no rule matches is denied with code `no_rule`. The order of rules never matters.

### Conditions

`when` is a map from a fact to a test. All keys must hold. `any`, `all` and `not` combine conditions, and YAML anchors let a rule reuse another rule's condition.

| Fact | Value |
|---|---|
| `args.<name>` | the argument after normalisation, and `args.<url>.host` and the like for url arguments |
| `tool`, `agent` | names |
| `agent.labels`, `session.labels` | lists of labels |
| `session.calls` | calls this session has made |
| `session.tools` | tools this session has used |
| `history.labels` | labels from every session of this agent since the daemon started, this one included |
| `time.hour` | 0 to 23, UTC |
| `time.weekday` | 0 (Monday) to 6, or `mon` to `sun` |

| Test | Holds when the value |
|---|---|
| a scalar, or `eq` | equals it |
| a list, or `in` | equals one of them |
| `ne`, `not_in` | the opposite |
| `glob` | matches the glob, or one of a list of globs |
| `regex` | matches somewhere (anchor it with `^...$` to match the whole value) |
| `prefix`, `suffix` | starts or ends with it |
| `contains`, `contains_any`, `contains_all` | is a list or string holding the item(s) |
| `lt`, `le`, `gt`, `ge` | compares as a number |
| `exists` | is present, or absent with `exists: false` |
| `max_len` | is at most this long |
| `each` | is a list and every item passes the inner test |

On a list value, a test of one value (`glob`, `regex`, `prefix`, `in`, comparisons) holds if any item passes. Use `each` to require all of them. A missing fact fails every test except `exists: false`.

`wyatt check` rejects a condition that can never be true, such as `time.hour: 24`.

## Limits

```yaml
limits:
  - { id: overall, agents: oncall, rate: 120/min, max_calls: 2000 }
  - { id: cluster, tools: kubectl_get, rate: 20/min }
```

`rate` is a sliding window per agent. `max_calls` counts per session. A call over a limit is denied with `rate_limited` or `call_limit`. Denied calls count toward the rate, so an agent cannot retry its way around it.

## Labels and DLP

Labels record what a session has touched. A tool's `labels` and a rule's `labels` are added to the session after a call succeeds. Rules read them with `session.labels`, which is how a policy says "after reading the customer table, nothing may leave the network".

The client names its session, so an agent that controls its own code could read a secret in one session and send it out from another. `history.labels` closes that: it holds the labels of all the agent's sessions. Use it for rules that guard against exfiltration by an agent you do not trust, and `session.labels` where a fresh task should start clean. History lives in memory and is cleared when the daemon restarts.

Every tool output passes through the redactor before the agent sees it. Built-in detectors: `private_key`, `aws_access_key`, `github_token`, `gitlab_token`, `slack_token`, `anthropic_key`, `openai_key`, `stripe_key`, `google_api_key`, `jwt`, `connection_string`, `secret_assignment`, `card_number`. When one fires, the session gets the label `secret`.

```yaml
redact:
  detectors: [private_key, aws_access_key, github_token]   # default: all
  patterns:
    - { name: internal_token, regex: 'itk_[A-Za-z0-9]{32}' }
  label_secrets: true
```

## Monitor mode

`mode: monitor` decides every call as usual, writes the verdict the policy would have given to the audit log as `enforced: false`, and runs the call anyway. Malformed calls (bad arguments, path escapes, unknown tools) are still refused, because there is no safe way to run them. Use it to see what a new policy would break before switching to `enforce`.

## Tests

```yaml
policy: wyatt.yaml
tests:
  - name: deploys wait for an approver on a weekday morning
    agent: oncall
    tool: deploy
    args: { service: api, version: "1.4.2" }
    now: 2026-11-24T10:00:00Z
    expect: approve
    rule: deploy-business-hours

  - name: no posting after a secret was read
    agent: oncall
    before:
      - { tool: read_log, args: { path: /var/log/app/env.log }, output: "DB_PASSWORD=hunter22" }
    tool: post_incident
    args: { url: https://hooks.slack.com/services/T0001/B0002/x, body: hi }
    expect: deny
    rule: no-exfil
```

`before` runs earlier calls in the same session, and their `output` goes through DLP, so labels build up as they would in the daemon. `session` sets the starting state directly: `labels`, `calls`, `tools`, `limits` (calls already counted against a `max_calls` limit) and `history` (labels from the agent's other sessions). `code` and `rule` are optional extra checks on the result. `wyatt test` exits 1 if any case fails.
