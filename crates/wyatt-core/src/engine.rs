//! The decision procedure.
//!
//! 1. The agent and the tool must exist in the policy.
//! 2. Arguments are checked against the tool's schema and normalised.
//! 3. Every rule that targets the (agent, tool) pair and whose condition holds
//!    is collected. Any deny wins. Otherwise any approve holds the call for a
//!    human. Otherwise any allow lets it run. Nothing matching means deny.
//! 4. A call that would run is then checked against rate and call limits.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::cond::Facts;
use crate::net::Url;
use crate::path::{self, PathError};
use crate::policy::{Agent, ArgSpec, ArgType, Args, Effect, Policy, Rule, Tool};
use crate::session::{RateState, Session};

#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub agent: &'a str,
    pub tool: &'a str,
    pub args: &'a Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Approve,
    Deny,
}

/// Why a verdict came out the way it did. Stable strings for logs and SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    Rule,
    NoRule,
    UnknownAgent,
    UnknownTool,
    BadArgs,
    PathEscape,
    RateLimited,
    CallLimit,
    Egress,
}

#[derive(Debug, Clone, Serialize)]
pub struct Trace {
    pub rule: String,
    pub effect: &'static str,
    pub matched: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub code: Code,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub reason: String,
    /// Arguments after schema defaults and normalisation. Drivers use these,
    /// never the raw request, so the tool runs exactly what the rules saw.
    pub args: Value,
    /// Labels the session gains if the call runs.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub labels: BTreeSet<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<String>,
    /// Limits that count this call.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<Trace>,
}

impl Decision {
    fn deny(mut self, code: Code, reason: String) -> Decision {
        self.verdict = Verdict::Deny;
        self.code = code;
        self.reason = reason;
        self
    }
}

struct Ctx<'a> {
    /// The name the call used, which a pattern tool does not fix.
    name: &'a str,
    agent: &'a Agent,
    args: &'a Value,
    derived: &'a BTreeMap<String, Value>,
    session: &'a Session,
    now_ms: u64,
}

fn set(s: &BTreeSet<String>) -> Value {
    Value::Array(s.iter().map(|x| Value::String(x.clone())).collect())
}

impl Facts for Ctx<'_> {
    fn get(&self, p: &str) -> Option<Cow<'_, Value>> {
        if let Some(v) = self.derived.get(p) {
            return Some(Cow::Borrowed(v));
        }
        let owned = |v: Value| Some(Cow::Owned(v));
        match p {
            "tool" => owned(Value::from(self.name)),
            "agent" => owned(Value::from(self.agent.name.as_str())),
            "agent.labels" => owned(set(&self.agent.labels)),
            "session.labels" => owned(set(&self.session.labels)),
            "session.tools" => owned(set(&self.session.tools)),
            "session.calls" => owned(Value::from(self.session.calls)),
            "time.hour" => owned(Value::from((self.now_ms / 3_600_000) % 24)),
            // 1970-01-01 was a Thursday; 0 is Monday.
            "time.weekday" => owned(Value::from((self.now_ms / 86_400_000 + 3) % 7)),
            "args" => Some(Cow::Borrowed(self.args)),
            _ => {
                let mut cur = self.args;
                for part in p.strip_prefix("args.")?.split('.') {
                    cur = match cur {
                        Value::Object(m) => m.get(part)?,
                        Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
                        _ => return None,
                    };
                }
                Some(Cow::Borrowed(cur))
            }
        }
    }
}

type ArgError = (Code, String);

/// Checks arguments against the tool's schema. Returns normalised arguments
/// and derived facts such as `args.url.host`.
pub fn validate(tool: &Tool, args: &Value) -> Result<(Value, BTreeMap<String, Value>), ArgError> {
    let obj = match args {
        Value::Null => Map::new(),
        Value::Object(m) => m.clone(),
        _ => return Err((Code::BadArgs, "arguments must be a JSON object".into())),
    };
    let Args::Schema(schema) = &tool.args else {
        return Ok((Value::Object(obj), BTreeMap::new()));
    };
    if let Some(k) = obj.keys().find(|k| !tool.extra_args && !schema.contains_key(*k)) {
        let known: Vec<&str> = schema.keys().map(String::as_str).collect();
        return Err((
            Code::BadArgs,
            format!("unknown argument `{k}` for `{}` (takes: {})", tool.name, known.join(", ")),
        ));
    }
    let mut out: Map<String, Value> =
        obj.iter().filter(|(k, _)| !schema.contains_key(*k)).map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut derived = BTreeMap::new();
    for (name, spec) in schema {
        let v = match obj.get(name).filter(|v| !v.is_null()) {
            Some(v) => v.clone(),
            None => match &spec.default {
                Some(d) => d.clone(),
                None if spec.required => return Err((Code::BadArgs, format!("missing required argument `{name}`"))),
                None => continue,
            },
        };
        let v = check_arg(tool, name, spec, v, &mut derived)?;
        out.insert(name.clone(), v);
    }
    Ok((Value::Object(out), derived))
}

fn check_arg(
    tool: &Tool,
    name: &str,
    spec: &ArgSpec,
    v: Value,
    derived: &mut BTreeMap<String, Value>,
) -> Result<Value, ArgError> {
    let bad = |want: &str| Err((Code::BadArgs, format!("argument `{name}` must be {want}")));
    let v = match spec.ty {
        ArgType::String if v.is_string() => v,
        ArgType::String => return bad("a string"),
        ArgType::Path => {
            let Some(s) = v.as_str() else { return bad("a path string") };
            match path::normalize(tool.root.as_deref(), s) {
                Ok(p) => Value::String(p),
                Err(e @ PathError::Escapes { .. }) => {
                    return Err((Code::PathEscape, format!("argument `{name}`: {e}")));
                }
                Err(e) => return Err((Code::BadArgs, format!("argument `{name}`: {e}"))),
            }
        }
        ArgType::Url => {
            let Some(s) = v.as_str() else { return bad("a URL string") };
            let u = Url::parse(s).map_err(|e| (Code::BadArgs, format!("argument `{name}`: {e}")))?;
            if let Some(hosts) = &tool.host_set
                && !hosts.is_match(u.bare_host())
            {
                return Err((Code::Egress, format!("host {} is not in the allowlist of `{}`", u.host, tool.name)));
            }
            derived.insert(format!("args.{name}.host"), Value::from(u.host.as_str()));
            derived.insert(format!("args.{name}.scheme"), Value::from(u.scheme.as_str()));
            derived.insert(format!("args.{name}.port"), Value::from(u.port));
            derived.insert(format!("args.{name}.path"), Value::from(u.target.split('?').next().unwrap_or("/")));
            Value::String(u.to_string())
        }
        ArgType::Int if v.is_i64() || v.is_u64() => v,
        ArgType::Int => return bad("a whole number"),
        ArgType::Number if v.is_number() => v,
        ArgType::Number => return bad("a number"),
        ArgType::Bool if v.is_boolean() => v,
        ArgType::Bool => return bad("true or false"),
        ArgType::List => match &v {
            Value::Array(a) if a.iter().all(|i| i.is_string() || i.is_number() || i.is_boolean()) => v,
            _ => return bad("a list of strings, numbers or booleans"),
        },
        ArgType::Object if v.is_object() => v,
        ArgType::Object => return bad("an object"),
        ArgType::Any => v,
    };
    if let Some(max) = spec.max_len {
        let len = match &v {
            Value::String(s) => s.chars().count(),
            Value::Array(a) => a.len(),
            _ => 0,
        };
        if len > max {
            return Err((Code::BadArgs, format!("argument `{name}` is longer than {max}")));
        }
    }
    if let Some(allowed) = &spec.one_of
        && !allowed.contains(&v)
    {
        return Err((Code::BadArgs, format!("argument `{name}` must be one of {}", Value::Array(allowed.clone()))));
    }
    if let Some(re) = &spec.pattern {
        let ok = match &v {
            Value::String(s) => re.is_match(s),
            Value::Array(a) => a.iter().all(|i| i.as_str().is_some_and(|s| re.is_match(s))),
            _ => false,
        };
        if !ok {
            return Err((Code::BadArgs, format!("argument `{name}` does not match its pattern")));
        }
    }
    Ok(v)
}

fn human_window(ms: u64) -> &'static str {
    match ms {
        1_000 => "second",
        60_000 => "minute",
        3_600_000 => "hour",
        _ => "day",
    }
}

pub fn decide(p: &Policy, req: &Request, s: &Session, rates: &RateState, now_ms: u64, explain: bool) -> Decision {
    let d = Decision {
        verdict: Verdict::Deny,
        code: Code::NoRule,
        rule: None,
        reason: String::new(),
        args: req.args.clone(),
        labels: BTreeSet::new(),
        approvers: Vec::new(),
        limits: Vec::new(),
        trace: Vec::new(),
    };
    let Some(agent) = p.agents.get(req.agent) else {
        return d.deny(Code::UnknownAgent, format!("unknown agent `{}`", req.agent));
    };
    let Some(tool) = p.tool(req.tool) else {
        return d.deny(Code::UnknownTool, format!("unknown tool `{}`", req.tool));
    };
    let mut d = d;
    d.limits = p.limits.iter().filter(|l| l.applies(&agent.name, req.tool)).map(|l| l.id.clone()).collect();
    let (args, derived) = match validate(tool, req.args) {
        Ok(x) => x,
        Err((code, msg)) => return d.deny(code, msg),
    };
    d.args = args;
    let cx = Ctx { name: req.tool, agent, args: &d.args, derived: &derived, session: s, now_ms };

    let mut deny: Option<&Rule> = None;
    let mut approve: Option<&Rule> = None;
    let mut allow: Option<&Rule> = None;
    let mut labels = tool.labels.clone();
    let mut approvers = BTreeSet::new();
    let mut trace = Vec::new();
    for rule in p.rules.iter().filter(|r| r.targets(&agent.name, req.tool)) {
        let matched = rule.when.eval(&cx);
        if explain {
            let note = if matched { String::new() } else { rule.when.why_not(&cx).unwrap_or_default() };
            trace.push(Trace { rule: rule.id.clone(), effect: rule.effect.name(), matched, note });
        }
        if !matched {
            continue;
        }
        match rule.effect {
            Effect::Deny => {
                deny.get_or_insert(rule);
            }
            Effect::Approve => {
                approve.get_or_insert(rule);
                approvers.extend(rule.approvers.iter().cloned());
                labels.extend(rule.labels.iter().cloned());
            }
            Effect::Allow => {
                allow.get_or_insert(rule);
                labels.extend(rule.labels.iter().cloned());
            }
        }
    }
    d.trace = trace;

    if let Some(r) = deny {
        d.rule = Some(r.id.clone());
        let reason = r.reason.clone().unwrap_or_else(|| format!("denied by rule `{}`", r.id));
        return d.deny(Code::Rule, reason);
    }
    let Some(r) = approve.or(allow) else {
        let reason = format!("no rule allows `{}` for agent `{}`", req.tool, agent.name);
        return d.deny(Code::NoRule, reason);
    };

    for l in p.limits.iter().filter(|l| l.applies(&agent.name, req.tool)) {
        if let Some((count, window)) = l.rate
            && rates.would_exceed(&l.id, &agent.name, count, window, now_ms)
        {
            let reason = format!("rate limit `{}`: {count} calls per {} used up", l.id, human_window(window));
            return d.deny(Code::RateLimited, reason);
        }
        if let Some(max) = l.max_calls
            && s.limit_calls.get(&l.id).copied().unwrap_or(0) >= max
        {
            return d.deny(Code::CallLimit, format!("limit `{}`: this session already made {max} calls", l.id));
        }
    }

    d.verdict = if r.effect == Effect::Approve { Verdict::Approve } else { Verdict::Allow };
    d.code = Code::Rule;
    d.rule = Some(r.id.clone());
    d.reason = r.reason.clone().unwrap_or_else(|| match d.verdict {
        Verdict::Approve => format!("rule `{}` requires approval", r.id),
        _ => format!("allowed by rule `{}`", r.id),
    });
    d.labels = labels;
    d.approvers = approvers.into_iter().collect();
    d
}

/// Counts the attempt against every rate limit that applies, whatever the verdict.
pub fn record_attempt(rates: &mut RateState, p: &Policy, agent: &str, d: &Decision, now_ms: u64) {
    for l in p.limits.iter().filter(|l| d.limits.contains(&l.id)) {
        if let Some((_, window)) = l.rate {
            rates.record(&l.id, agent, window, now_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POLICY: &str = r#"
version: 1
agents:
  ops: { uid: 1000, labels: [oncall] }
  intern: { uid: 1001 }
tools:
  read_file: { driver: fs.read, root: /srv/app }
  fetch: { driver: http, hosts: ["*"], labels: [untrusted] }
  post: { driver: http, method: POST, hosts: ["hooks.example.com"] }
  deploy: { driver: delegate, args: { env: { type: string, one_of: [staging, prod] } } }
rules:
  - id: read-app
    allow: read_file
  - id: secrets-are-secret
    allow: read_file
    agents: ops
    when: { args.path: { glob: "/srv/app/secrets/**" } }
    labels: [secret]
  - id: no-keys
    deny: read_file
    when: { args.path: { glob: ["**/*.pem", "**/*.key"] } }
    reason: key material never leaves the box
  - id: web
    allow: [fetch, post]
  - id: no-exfil
    deny: post
    when: { session.labels: { contains_any: [secret] } }
  - id: prod-needs-a-human
    approve: deploy
    when: { args.env: prod }
    approvers: [lead]
  - id: deploy
    allow: deploy
    agents: ops
limits:
  - id: fetch-rate
    tools: fetch
    rate: 2/min
  - id: per-session
    max_calls: 3
"#;

    fn policy() -> Policy {
        Policy::from_yaml(POLICY).unwrap()
    }

    fn run(p: &Policy, s: &Session, agent: &str, tool: &str, args: Value) -> Decision {
        decide(p, &Request { agent, tool, args: &args }, s, &RateState::default(), 0, true)
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = policy();
        let s = Session::default();
        let d = run(&p, &s, "ops", "read_file", json!({"path": "certs/tls.pem"}));
        assert_eq!((d.verdict, d.rule.as_deref()), (Verdict::Deny, Some("no-keys")));
        assert_eq!(d.reason, "key material never leaves the box");
        let d = run(&p, &s, "ops", "read_file", json!({"path": "logs/../logs/app.log"}));
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.args["path"], "/srv/app/logs/app.log");
    }

    #[test]
    fn default_deny_and_schema() {
        let p = policy();
        let s = Session::default();
        assert_eq!(run(&p, &s, "nobody", "read_file", json!({"path": "a"})).code, Code::UnknownAgent);
        assert_eq!(run(&p, &s, "ops", "rm_rf", json!({})).code, Code::UnknownTool);
        assert_eq!(run(&p, &s, "intern", "deploy", json!({"env": "staging"})).code, Code::NoRule);
        let d = run(&p, &s, "ops", "read_file", json!({"path": "a", "path2": "/etc/shadow"}));
        assert_eq!(d.code, Code::BadArgs);
        assert!(d.reason.contains("unknown argument `path2`"));
        assert_eq!(run(&p, &s, "ops", "read_file", json!({})).code, Code::BadArgs);
        assert_eq!(run(&p, &s, "ops", "read_file", json!({"path": "../../etc/shadow"})).code, Code::PathEscape);
        assert_eq!(run(&p, &s, "ops", "deploy", json!({"env": "qa"})).code, Code::BadArgs);
        assert_eq!(run(&p, &s, "ops", "fetch", json!({"url": "file:///etc/passwd"})).code, Code::BadArgs);
        assert_eq!(run(&p, &s, "ops", "post", json!({"url": "https://evil.example.net/"})).code, Code::Egress);
    }

    #[test]
    fn session_labels_block_exfiltration() {
        let p = policy();
        let mut s = Session::default();
        let post = json!({"url": "https://hooks.example.com/x", "body": "hi"});
        assert_eq!(run(&p, &s, "ops", "post", post.clone()).verdict, Verdict::Allow);

        let d = run(&p, &s, "ops", "read_file", json!({"path": "secrets/db.env"}));
        assert_eq!(d.verdict, Verdict::Allow);
        assert!(d.labels.contains("secret"));
        s.record_success("read_file", &d.labels, &d.limits);

        let d = run(&p, &s, "ops", "post", post);
        assert_eq!((d.verdict, d.rule.as_deref()), (Verdict::Deny, Some("no-exfil")));
    }

    #[test]
    fn approval_and_trace() {
        let p = policy();
        let d = run(&p, &Session::default(), "ops", "deploy", json!({"env": "prod"}));
        assert_eq!((d.verdict, d.approvers.clone()), (Verdict::Approve, vec!["lead".to_string()]));
        let d = run(&p, &Session::default(), "ops", "deploy", json!({"env": "staging"}));
        assert_eq!(d.verdict, Verdict::Allow);
        let skipped = d.trace.iter().find(|t| t.rule == "prod-needs-a-human").unwrap();
        assert!(!skipped.matched);
        assert_eq!(skipped.note, "args.env = \"staging\" fails eq");
    }

    #[test]
    fn url_facts() {
        let p = Policy::from_yaml(
            "version: 1\nagents: { a: { uid: 1 } }\ntools: { get: { driver: http, hosts: ['*'] } }\nrules:\n  - id: gh\n    allow: get\n    when: { args.url.host: api.github.com, args.url.scheme: https }\n",
        )
        .unwrap();
        let s = Session::default();
        assert_eq!(run(&p, &s, "a", "get", json!({"url": "https://API.github.com/repos"})).verdict, Verdict::Allow);
        assert_eq!(run(&p, &s, "a", "get", json!({"url": "https://api.github.com.evil.io/"})).verdict, Verdict::Deny);
        assert_eq!(run(&p, &s, "a", "get", json!({"url": "http://api.github.com/"})).verdict, Verdict::Deny);
    }

    #[test]
    fn extra_args_pass_through_but_declared_ones_are_checked() {
        let p = Policy::from_yaml(
            "version: 1\nagents: { a: { uid: 1 } }\ntools:\n  Read: { driver: delegate, args: { file_path: path, \"*\": any } }\nrules:\n  - { id: r, allow: Read, when: { args.file_path: { glob: \"/work/**\" } } }\n",
        )
        .unwrap();
        let s = Session::default();
        let d = run(&p, &s, "a", "Read", json!({"file_path": "/work/a.rs", "limit": 20}));
        assert_eq!((d.verdict, d.args["limit"].clone()), (Verdict::Allow, json!(20)));
        let d = run(&p, &s, "a", "Read", json!({"file_path": "/work/../home/u/.ssh/id_ed25519"}));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(run(&p, &s, "a", "Read", json!({"file_path": "notes.txt"})).code, Code::BadArgs);
    }

    #[test]
    fn pattern_tools_cover_mcp_servers() {
        let p = Policy::from_yaml(
            "version: 1\nagents: { a: { uid: 1 } }\ntools:\n  mcp__gh__*: { driver: mcp, args: any }\n  mcp__gh__delete_repo: { driver: mcp, args: { name: string } }\nrules:\n  - { id: gh, allow: mcp__gh__*, when: { tool: { ne: mcp__gh__delete_repo } } }\n  - { id: issues, approve: mcp__gh__create_issue }\n",
        )
        .unwrap();
        let s = Session::default();
        assert_eq!(run(&p, &s, "a", "mcp__gh__list_issues", json!({"q": 1})).verdict, Verdict::Allow);
        assert_eq!(run(&p, &s, "a", "mcp__gh__create_issue", json!({})).verdict, Verdict::Approve);
        // The exact entry wins over the pattern, and no rule allows it.
        assert_eq!(run(&p, &s, "a", "mcp__gh__delete_repo", json!({"name": "x"})).code, Code::NoRule);
        assert_eq!(run(&p, &s, "a", "mcp__other__x", json!({})).code, Code::UnknownTool);
        assert!(Policy::from_yaml("version: 1\ntools:\n  run*: { driver: proc, command: [/bin/true] }\n").is_err());
    }

    #[test]
    fn limits() {
        let p = policy();
        let mut rates = RateState::default();
        let mut s = Session::default();
        let args = json!({"url": "https://example.org/"});
        for t in [0, 1] {
            let d = decide(&p, &Request { agent: "ops", tool: "fetch", args: &args }, &s, &rates, t, false);
            assert_eq!(d.verdict, Verdict::Allow);
            record_attempt(&mut rates, &p, "ops", &d, t);
        }
        let d = decide(&p, &Request { agent: "ops", tool: "fetch", args: &args }, &s, &rates, 2, false);
        assert_eq!(d.code, Code::RateLimited);
        // A minute later the window has slid.
        let d = decide(&p, &Request { agent: "ops", tool: "fetch", args: &args }, &s, &rates, 60_001, false);
        assert_eq!(d.verdict, Verdict::Allow);

        for _ in 0..3 {
            s.record_success("read_file", &BTreeSet::new(), &["per-session".to_string()]);
        }
        assert_eq!(run(&p, &s, "ops", "read_file", json!({"path": "a"})).code, Code::CallLimit);
    }
}
