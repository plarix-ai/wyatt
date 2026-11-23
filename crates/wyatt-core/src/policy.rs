//! Policy files: parsing, validation and the compiled form the engine uses.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use globset::GlobSet;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cond::{self, Cond};
use crate::dlp::Dlp;
use crate::path;
use crate::units;

pub use crate::error::{PolicyError, PolicyErrors};

// ---------------------------------------------------------------------------
// File format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Enforce,
    Monitor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u32,
    name: Option<String>,
    #[serde(default)]
    mode: Mode,
    #[serde(default)]
    defaults: RawDefaults,
    #[serde(default)]
    agents: BTreeMap<String, RawAgent>,
    #[serde(default)]
    tools: BTreeMap<String, RawTool>,
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    limits: Vec<RawLimit>,
    redact: Option<RawRedact>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawDefaults {
    timeout: Option<String>,
    max_output: Option<String>,
    approval_timeout: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    uid: Option<u32>,
    gid: Option<u32>,
    exe: Option<String>,
    token_sha256: Option<String>,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTool {
    driver: String,
    #[serde(default)]
    description: String,
    args: Option<Value>,
    #[serde(default)]
    labels: Vec<String>,
    timeout: Option<String>,
    max_output: Option<String>,
    root: Option<String>,
    command: Option<Vec<String>>,
    cwd: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    sandbox: Option<RawSandbox>,
    method: Option<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    allow_private: bool,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSandbox {
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
    #[serde(default)]
    net: bool,
    memory: Option<String>,
    cpu: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, Clone)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    allow: Option<OneOrMany>,
    deny: Option<OneOrMany>,
    approve: Option<OneOrMany>,
    agents: Option<OneOrMany>,
    when: Option<Value>,
    reason: Option<String>,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    approvers: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimit {
    id: Option<String>,
    agents: Option<OneOrMany>,
    tools: Option<OneOrMany>,
    rate: Option<String>,
    max_calls: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRedact {
    detectors: Option<Vec<String>>,
    #[serde(default)]
    patterns: Vec<RawPattern>,
    #[serde(default = "yes")]
    label_secrets: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPattern {
    name: String,
    regex: String,
}

// ---------------------------------------------------------------------------
// Compiled form
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Policy {
    pub name: String,
    pub mode: Mode,
    /// SHA-256 of the policy source. Every audit record carries it.
    pub digest: String,
    pub agents: BTreeMap<String, Agent>,
    pub tools: BTreeMap<String, Tool>,
    pub rules: Vec<Rule>,
    pub limits: Vec<Limit>,
    pub dlp: Dlp,
    /// Add the `secret` label to a session when DLP redacts its output.
    pub label_secrets: bool,
    pub approval_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct Agent {
    pub name: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub exe: Option<(String, globset::GlobMatcher)>,
    pub token_sha256: Option<[u8; 32]>,
    pub labels: BTreeSet<String>,
}

/// What the kernel says about the process on the other end of the socket.
#[derive(Debug, Clone)]
pub struct Peer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub exe: Option<String>,
}

impl Agent {
    pub fn has_binding(&self) -> bool {
        self.uid.is_some() || self.gid.is_some() || self.exe.is_some() || self.token_sha256.is_some()
    }

    /// Checks every binding the agent declares. All must hold.
    pub fn admits(&self, peer: &Peer, token: Option<&str>) -> Result<(), String> {
        if !self.has_binding() {
            return Err(format!("agent `{}` has no identity binding (uid, gid, exe or token)", self.name));
        }
        if let Some(uid) = self.uid
            && uid != peer.uid
        {
            return Err(format!("uid {} is not bound to agent `{}`", peer.uid, self.name));
        }
        if let Some(gid) = self.gid
            && gid != peer.gid
        {
            return Err(format!("gid {} is not bound to agent `{}`", peer.gid, self.name));
        }
        if let Some((pat, m)) = &self.exe {
            match &peer.exe {
                Some(exe) if m.is_match(exe) => {}
                Some(exe) => return Err(format!("executable {exe} does not match `{pat}`")),
                None => return Err("could not read the peer's executable".into()),
            }
        }
        if let Some(want) = &self.token_sha256 {
            let got: [u8; 32] = Sha256::digest(token.unwrap_or("").as_bytes()).into();
            // Compare without an early exit so timing does not leak a prefix.
            let diff = want.iter().zip(got.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b));
            if token.is_none() || diff != 0 {
                return Err("token does not match".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    FsRead,
    FsList,
    FsWrite,
    Proc,
    Http,
    Delegate,
    Mcp,
}

impl Driver {
    pub fn parse(s: &str) -> Option<Driver> {
        Some(match s {
            "fs.read" => Driver::FsRead,
            "fs.list" => Driver::FsList,
            "fs.write" => Driver::FsWrite,
            "proc" => Driver::Proc,
            "http" => Driver::Http,
            "delegate" => Driver::Delegate,
            "mcp" => Driver::Mcp,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Driver::FsRead => "fs.read",
            Driver::FsList => "fs.list",
            Driver::FsWrite => "fs.write",
            Driver::Proc => "proc",
            Driver::Http => "http",
            Driver::Delegate => "delegate",
            Driver::Mcp => "mcp",
        }
    }

    pub fn is_fs(self) -> bool {
        matches!(self, Driver::FsRead | Driver::FsList | Driver::FsWrite)
    }

    /// Drivers whose tool runs inside the daemon. The others only get a decision.
    pub fn is_mediated(self) -> bool {
        !matches!(self, Driver::Delegate | Driver::Mcp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgType {
    String,
    Path,
    Url,
    Int,
    Number,
    Bool,
    List,
    Object,
    Any,
}

impl ArgType {
    fn parse(s: &str) -> Option<ArgType> {
        serde_json::from_value(Value::String(s.to_string())).ok()
    }

    pub fn name(self) -> &'static str {
        match self {
            ArgType::String => "string",
            ArgType::Path => "path",
            ArgType::Url => "url",
            ArgType::Int => "int",
            ArgType::Number => "number",
            ArgType::Bool => "bool",
            ArgType::List => "list",
            ArgType::Object => "object",
            ArgType::Any => "any",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArgSpec {
    pub ty: ArgType,
    pub required: bool,
    pub default: Option<Value>,
    pub max_len: Option<usize>,
    pub one_of: Option<Vec<Value>>,
    pub pattern: Option<regex::Regex>,
}

#[derive(Debug, Clone)]
pub enum Args {
    /// No schema: any object passes. Allowed, but `wyatt check` warns.
    Any,
    Schema(BTreeMap<String, ArgSpec>),
}

#[derive(Debug, Clone, Default)]
pub struct Sandbox {
    pub enabled: bool,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub net: bool,
    pub memory: Option<usize>,
    pub cpu: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub driver: Driver,
    pub description: String,
    pub args: Args,
    pub labels: BTreeSet<String>,
    pub timeout: Duration,
    pub max_output: usize,
    pub root: Option<String>,
    pub command: Vec<String>,
    pub cwd: Option<String>,
    /// Values may hold `${env:NAME}`; the daemon fills them in, the agent never sees them.
    pub env: BTreeMap<String, String>,
    pub sandbox: Sandbox,
    pub method: String,
    pub hosts: Vec<String>,
    pub host_set: Option<GlobSet>,
    pub allow_private: bool,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    Allow,
    Approve,
    Deny,
}

impl Effect {
    pub fn name(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Approve => "approve",
            Effect::Deny => "deny",
        }
    }
}

/// A set of name patterns (`read_*`, `*`).
#[derive(Debug, Clone)]
pub struct Names {
    pub patterns: Vec<String>,
    set: GlobSet,
}

impl Names {
    fn new(patterns: Vec<String>, at: &str) -> Result<Names, PolicyError> {
        if patterns.is_empty() {
            return Err(PolicyError { at: at.into(), msg: "empty list".into() });
        }
        let set = cond::glob_set(&patterns, false, at)?;
        Ok(Names { patterns, set })
    }

    pub fn matches(&self, name: &str) -> bool {
        self.set.is_match(name)
    }

    pub fn is_wildcard(&self) -> bool {
        self.patterns.iter().any(|p| p == "*")
    }

    pub fn literals(&self) -> impl Iterator<Item = &str> {
        self.patterns.iter().map(String::as_str).filter(|p| !p.contains(['*', '?', '[', '{']))
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    pub tools: Names,
    pub agents: Option<Names>,
    pub when: Cond,
    pub reason: Option<String>,
    pub labels: BTreeSet<String>,
    pub approvers: Vec<String>,
}

impl Rule {
    pub fn targets(&self, agent: &str, tool: &str) -> bool {
        self.tools.matches(tool) && self.agents.as_ref().is_none_or(|a| a.matches(agent))
    }
}

#[derive(Debug, Clone)]
pub struct Limit {
    pub id: String,
    pub agents: Option<Names>,
    pub tools: Option<Names>,
    pub rate: Option<(u32, u64)>,
    pub max_calls: Option<u64>,
}

impl Limit {
    pub fn applies(&self, agent: &str, tool: &str) -> bool {
        self.agents.as_ref().is_none_or(|a| a.matches(agent)) && self.tools.as_ref().is_none_or(|t| t.matches(tool))
    }
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_-.:/".contains(c))
}

struct Ctx {
    errors: Vec<PolicyError>,
}

impl Ctx {
    fn err(&mut self, at: impl Into<String>, msg: impl Into<String>) {
        self.errors.push(PolicyError { at: at.into(), msg: msg.into() });
    }

    fn take<T>(&mut self, r: Result<T, PolicyError>) -> Option<T> {
        r.map_err(|e| self.errors.push(e)).ok()
    }

    fn unit<T>(&mut self, at: &str, v: Option<&String>, f: fn(&str) -> Result<T, String>) -> Option<T> {
        let v = v?;
        f(v).map_err(|m| self.err(at, m)).ok()
    }

    fn labels(&mut self, at: &str, ls: Vec<String>) -> BTreeSet<String> {
        for l in &ls {
            if !valid_name(l) {
                self.err(at, format!("label `{l}` must use letters, digits and _-.:/"));
            }
        }
        ls.into_iter().collect()
    }
}

impl Policy {
    pub fn from_yaml(src: &str) -> Result<Policy, PolicyErrors> {
        let raw: RawPolicy = serde_yaml_ng::from_str(src)
            .map_err(|e| PolicyErrors(vec![PolicyError { at: String::new(), msg: e.to_string() }]))?;
        let digest = hex::encode(Sha256::digest(src.as_bytes()));
        let mut cx = Ctx { errors: Vec::new() };
        let p = compile(raw, digest, &mut cx);
        if cx.errors.is_empty() { Ok(p) } else { Err(PolicyErrors(cx.errors)) }
    }

    pub fn tool(&self, name: &str) -> Option<&Tool> {
        self.tools.get(name)
    }
}

fn compile(raw: RawPolicy, digest: String, cx: &mut Ctx) -> Policy {
    if raw.version != 1 {
        cx.err("version", format!("unsupported version {}; this build reads version 1", raw.version));
    }
    let d = &raw.defaults;
    let timeout = cx.unit("defaults.timeout", d.timeout.as_ref(), units::duration).unwrap_or(Duration::from_secs(10));
    let max_output = cx.unit("defaults.max_output", d.max_output.as_ref(), units::size).unwrap_or(1 << 20);
    let approval_timeout = cx
        .unit("defaults.approval_timeout", d.approval_timeout.as_ref(), units::duration)
        .unwrap_or(Duration::from_secs(300));

    let mut agents = BTreeMap::new();
    for (name, a) in raw.agents {
        let at = format!("agents.{name}");
        if !valid_name(&name) {
            cx.err(&at, "agent names use letters, digits and _-.:/");
        }
        let exe = a.exe.and_then(|p| match globset::GlobBuilder::new(&p).literal_separator(true).build() {
            Ok(g) => Some((p, g.compile_matcher())),
            Err(e) => {
                cx.err(format!("{at}.exe"), format!("bad glob: {e}"));
                None
            }
        });
        let token_sha256 = a.token_sha256.and_then(|h| {
            let bytes = hex::decode(h.trim()).ok().filter(|b| b.len() == 32);
            if bytes.is_none() {
                cx.err(format!("{at}.token_sha256"), "expected 64 hex characters (sha256 of the token)");
            }
            bytes.map(|b| b.try_into().unwrap())
        });
        let labels = cx.labels(&format!("{at}.labels"), a.labels);
        agents.insert(name.clone(), Agent { name, uid: a.uid, gid: a.gid, exe, token_sha256, labels });
    }

    let mut tools = BTreeMap::new();
    for (name, t) in raw.tools {
        let at = format!("tools.{name}");
        if !valid_name(&name) {
            cx.err(&at, "tool names use letters, digits and _-.:/");
        }
        if let Some(tool) = compile_tool(name.clone(), t, &at, timeout, max_output, cx) {
            tools.insert(name, tool);
        }
    }

    let mut rules = Vec::new();
    let mut ids = BTreeSet::new();
    for (i, r) in raw.rules.into_iter().enumerate() {
        let at = format!("rules[{i}]");
        if !ids.insert(r.id.clone()) {
            cx.err(&at, format!("duplicate rule id `{}`", r.id));
        }
        if !valid_name(&r.id) {
            cx.err(format!("{at}.id"), "rule ids use letters, digits and _-.:/");
        }
        let effects: Vec<(Effect, OneOrMany)> =
            [(Effect::Allow, r.allow), (Effect::Deny, r.deny), (Effect::Approve, r.approve)]
                .into_iter()
                .filter_map(|(e, v)| v.map(|v| (e, v)))
                .collect();
        let [(effect, tools_raw)] = <[_; 1]>::try_from(effects).unwrap_or_else(|v: Vec<_>| {
            cx.err(&at, format!("rule `{}` needs exactly one of allow, deny or approve (found {})", r.id, v.len()));
            [(Effect::Deny, OneOrMany::One("*".into()))]
        });
        let tools_names = cx.take(Names::new(tools_raw.into_vec(), &format!("{at}.{}", effect.name())));
        let agents_names = r.agents.and_then(|a| cx.take(Names::new(a.into_vec(), &format!("{at}.agents"))));
        let when = match &r.when {
            Some(v) => cx.take(cond::compile(v, &format!("{at}.when"))).unwrap_or(Cond::True),
            None => Cond::True,
        };
        if effect == Effect::Deny && !r.labels.is_empty() {
            cx.err(format!("{at}.labels"), "labels apply to calls that run; a deny rule cannot add them");
        }
        if effect != Effect::Approve && !r.approvers.is_empty() {
            cx.err(format!("{at}.approvers"), "approvers only make sense on an approve rule");
        }
        let labels = cx.labels(&format!("{at}.labels"), r.labels);
        if let Some(tools) = tools_names {
            rules.push(Rule {
                id: r.id,
                effect,
                tools,
                agents: agents_names,
                when,
                reason: r.reason,
                labels,
                approvers: r.approvers,
            });
        }
    }

    let mut limits = Vec::new();
    for (i, l) in raw.limits.into_iter().enumerate() {
        let at = format!("limits[{i}]");
        let rate = cx.unit(&format!("{at}.rate"), l.rate.as_ref(), units::rate);
        if l.rate.is_none() && l.max_calls.is_none() {
            cx.err(&at, "a limit needs rate, max_calls or both");
        }
        limits.push(Limit {
            id: l.id.unwrap_or_else(|| format!("limit-{i}")),
            agents: l.agents.and_then(|a| cx.take(Names::new(a.into_vec(), &format!("{at}.agents")))),
            tools: l.tools.and_then(|t| cx.take(Names::new(t.into_vec(), &format!("{at}.tools")))),
            rate,
            max_calls: l.max_calls,
        });
    }

    let (dlp, label_secrets) = match raw.redact {
        Some(r) => {
            let custom: Vec<(String, String)> = r.patterns.into_iter().map(|p| (p.name, p.regex)).collect();
            (cx.take(Dlp::new(r.detectors.as_deref(), &custom)).unwrap_or_default(), r.label_secrets)
        }
        None => (Dlp::new(None, &[]).expect("built-in detectors compile"), true),
    };

    Policy {
        name: raw.name.unwrap_or_else(|| "unnamed".into()),
        mode: raw.mode,
        digest,
        agents,
        tools,
        rules,
        limits,
        dlp,
        label_secrets,
        approval_timeout,
    }
}

fn implicit_args(driver: Driver, method: &str) -> Vec<(&'static str, ArgType, bool, Option<Value>)> {
    match driver {
        Driver::FsRead => vec![("path", ArgType::Path, true, None)],
        Driver::FsList => vec![("path", ArgType::Path, false, Some(Value::String(".".into())))],
        Driver::FsWrite => vec![("path", ArgType::Path, true, None), ("content", ArgType::String, true, None)],
        Driver::Proc => vec![("args", ArgType::List, false, Some(Value::Array(vec![])))],
        Driver::Http if matches!(method, "POST" | "PUT" | "PATCH") => {
            vec![("url", ArgType::Url, true, None), ("body", ArgType::String, false, None)]
        }
        Driver::Http => vec![("url", ArgType::Url, true, None)],
        Driver::Delegate | Driver::Mcp => vec![],
    }
}

fn compile_tool(
    name: String,
    t: RawTool,
    at: &str,
    timeout: Duration,
    max_output: usize,
    cx: &mut Ctx,
) -> Option<Tool> {
    let Some(driver) = Driver::parse(&t.driver) else {
        cx.err(
            format!("{at}.driver"),
            format!("unknown driver `{}`; use fs.read, fs.list, fs.write, proc, http, delegate or mcp", t.driver),
        );
        return None;
    };
    let method = t.method.as_deref().unwrap_or("GET").to_ascii_uppercase();
    let only = |cx: &mut Ctx, set: bool, field: &str, ok: bool, drivers: &str| {
        if set && !ok {
            cx.err(format!("{at}.{field}"), format!("`{field}` only applies to {drivers} tools"));
        }
    };
    only(cx, t.root.is_some(), "root", driver.is_fs(), "fs.*");
    only(cx, t.command.is_some(), "command", driver == Driver::Proc, "proc");
    only(cx, t.cwd.is_some(), "cwd", driver == Driver::Proc, "proc");
    only(cx, !t.env.is_empty(), "env", driver == Driver::Proc, "proc");
    only(cx, t.sandbox.is_some(), "sandbox", driver == Driver::Proc, "proc");
    only(cx, t.method.is_some(), "method", driver == Driver::Http, "http");
    only(cx, !t.hosts.is_empty(), "hosts", driver == Driver::Http, "http");
    only(cx, t.allow_private, "allow_private", driver == Driver::Http, "http");
    only(cx, !t.headers.is_empty(), "headers", driver == Driver::Http, "http");

    let root = match (&t.root, driver.is_fs()) {
        (Some(r), _) => match path::normalize(None, r) {
            Ok(r) => Some(r),
            Err(e) => {
                cx.err(format!("{at}.root"), format!("root must be an absolute path: {e}"));
                None
            }
        },
        (None, true) => {
            cx.err(at, format!("{} tools need a root directory", driver.name()));
            None
        }
        (None, false) => None,
    };

    let command = t.command.unwrap_or_default();
    if driver == Driver::Proc && command.first().is_none_or(|p| !p.starts_with('/')) {
        cx.err(format!("{at}.command"), "proc tools need a command whose first item is an absolute program path");
    }
    if driver == Driver::Http {
        if !matches!(method.as_str(), "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE") {
            cx.err(format!("{at}.method"), format!("unsupported method `{method}`"));
        }
        if t.hosts.is_empty() {
            cx.err(format!("{at}.hosts"), "http tools need a host allowlist; use [\"*\"] to allow any public host");
        }
    }
    let host_set = (!t.hosts.is_empty())
        .then(|| {
            cx.take(cond::glob_set(
                &t.hosts.iter().map(|h| h.to_ascii_lowercase()).collect::<Vec<_>>(),
                false,
                &format!("{at}.hosts"),
            ))
        })
        .flatten();

    let args = compile_args(t.args.as_ref(), driver, &method, at, cx);

    let sandbox = match t.sandbox {
        Some(s) => Sandbox {
            enabled: s.enabled,
            read: abs_paths(cx, &format!("{at}.sandbox.read"), s.read),
            write: abs_paths(cx, &format!("{at}.sandbox.write"), s.write),
            net: s.net,
            memory: cx.unit(&format!("{at}.sandbox.memory"), s.memory.as_ref(), units::size),
            cpu: cx.unit(&format!("{at}.sandbox.cpu"), s.cpu.as_ref(), units::duration),
        },
        None => Sandbox { enabled: true, ..Sandbox::default() },
    };

    let labels = cx.labels(&format!("{at}.labels"), t.labels);
    Some(Tool {
        name,
        driver,
        description: t.description,
        args,
        labels,
        timeout: cx.unit(&format!("{at}.timeout"), t.timeout.as_ref(), units::duration).unwrap_or(timeout),
        max_output: cx.unit(&format!("{at}.max_output"), t.max_output.as_ref(), units::size).unwrap_or(max_output),
        root,
        command,
        cwd: t.cwd,
        env: t.env,
        sandbox,
        method,
        hosts: t.hosts,
        host_set,
        allow_private: t.allow_private,
        headers: t.headers,
    })
}

fn abs_paths(cx: &mut Ctx, at: &str, ps: Vec<String>) -> Vec<String> {
    ps.into_iter()
        .filter_map(|p| match path::normalize(None, &p) {
            Ok(p) => Some(p),
            Err(e) => {
                cx.err(at, format!("`{p}`: {e}"));
                None
            }
        })
        .collect()
}

fn compile_args(raw: Option<&Value>, driver: Driver, method: &str, at: &str, cx: &mut Ctx) -> Args {
    let mut schema = BTreeMap::new();
    match raw {
        Some(Value::String(s)) if s == "any" => {
            if driver != Driver::Delegate && driver != Driver::Mcp {
                cx.err(format!("{at}.args"), "`args: any` is only allowed for delegate and mcp tools");
            }
            return Args::Any;
        }
        Some(Value::Object(m)) => {
            for (name, spec) in m {
                let here = format!("{at}.args.{name}");
                if let Some(s) = compile_arg(spec, &here, cx) {
                    schema.insert(name.clone(), s);
                }
            }
        }
        Some(_) => cx.err(format!("{at}.args"), "args must be a map of name: type, or the word any"),
        None => {}
    }
    for (name, ty, required, default) in implicit_args(driver, method) {
        match schema.get(name) {
            Some(s) if s.ty != ty => cx.err(
                format!("{at}.args.{name}"),
                format!("{} tools take `{name}` as {}, not {}", driver.name(), ty.name(), s.ty.name()),
            ),
            Some(_) => {}
            None => {
                schema.insert(
                    name.to_string(),
                    ArgSpec { ty, required, default, max_len: None, one_of: None, pattern: None },
                );
            }
        }
    }
    if driver.is_mediated() {
        let allowed: Vec<&str> = implicit_args(driver, method).iter().map(|a| a.0).collect();
        for name in schema.keys() {
            if !allowed.contains(&name.as_str()) {
                cx.err(
                    format!("{at}.args.{name}"),
                    format!("{} tools only take {}", driver.name(), allowed.join(", ")),
                );
            }
        }
    }
    Args::Schema(schema)
}

fn compile_arg(spec: &Value, at: &str, cx: &mut Ctx) -> Option<ArgSpec> {
    match spec {
        Value::String(s) => {
            let (name, required) = match s.strip_suffix('?') {
                Some(n) => (n, false),
                None => (s.as_str(), true),
            };
            let Some(ty) = ArgType::parse(name) else {
                cx.err(
                    at,
                    format!("unknown type `{name}`; use string, path, url, int, number, bool, list, object or any"),
                );
                return None;
            };
            Some(ArgSpec { ty, required, default: None, max_len: None, one_of: None, pattern: None })
        }
        Value::Object(m) => {
            for k in m.keys() {
                if !["type", "required", "default", "max_len", "one_of", "pattern"].contains(&k.as_str()) {
                    cx.err(at, format!("unknown key `{k}` in argument spec"));
                }
            }
            let ty = m.get("type").and_then(Value::as_str).and_then(ArgType::parse);
            let Some(ty) = ty else {
                cx.err(at, "argument spec needs a valid `type`");
                return None;
            };
            let default = m.get("default").cloned();
            let required = m.get("required").and_then(Value::as_bool).unwrap_or(default.is_none());
            let max_len = m.get("max_len").and_then(Value::as_u64).map(|n| n as usize);
            let one_of = m.get("one_of").and_then(Value::as_array).cloned();
            let pattern = m.get("pattern").and_then(Value::as_str).and_then(|p| {
                cx.take(
                    regex::Regex::new(&format!("^(?:{p})$"))
                        .map_err(|e| PolicyError { at: format!("{at}.pattern"), msg: e.to_string() }),
                )
            });
            Some(ArgSpec { ty, required, default, max_len, one_of, pattern })
        }
        _ => {
            cx.err(at, "expected a type name or a map with `type`");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"
version: 1
name: t
agents:
  ops: { uid: 1000, labels: [team.ops] }
tools:
  read_file: { driver: fs.read, root: /srv/app, labels: [internal] }
  post: { driver: http, method: post, hosts: ["*.example.com"] }
  lookup: { driver: delegate, args: { id: int, note: "string?" } }
rules:
  - id: read-logs
    allow: read_file
    agents: ops
    when: { args.path: { glob: "/srv/app/logs/**" } }
limits:
  - rate: 10/min
"#;

    #[test]
    fn compiles_a_policy() {
        let p = Policy::from_yaml(OK).unwrap();
        assert_eq!(p.tools["post"].method, "POST");
        let Args::Schema(s) = &p.tools["post"].args else { panic!() };
        assert!(s.contains_key("body") && !s["body"].required);
        let Args::Schema(s) = &p.tools["lookup"].args else { panic!() };
        assert!(s["id"].required && !s["note"].required);
        assert_eq!(p.limits[0].rate, Some((10, 60_000)));
        assert_eq!(p.digest.len(), 64);
    }

    #[test]
    fn collects_every_error() {
        let bad = r#"
version: 1
tools:
  a: { driver: fs.read }
  b: { driver: proc, command: [ls] }
  c: { driver: http, hosts: [] }
  d: { driver: fs.read, root: /x, args: { path: string } }
  e: { driver: teleport }
rules:
  - { id: r, allow: a, deny: a }
  - { id: r, allow: a, labels: ["bad label"] }
"#;
        let e = Policy::from_yaml(bad).unwrap_err().to_string();
        for want in [
            "tools.a: fs.read tools need a root",
            "tools.b.command",
            "tools.c.hosts",
            "tools.d.args.path: fs.read tools take `path` as path, not string",
            "unknown driver `teleport`",
            "needs exactly one of allow, deny or approve (found 2)",
            "duplicate rule id `r`",
            "label `bad label`",
        ] {
            assert!(e.contains(want), "missing {want:?} in:\n{e}");
        }
    }

    #[test]
    fn typos_in_structure_are_caught() {
        let e = Policy::from_yaml("version: 1\nrulez: []\n").unwrap_err().to_string();
        assert!(e.contains("unknown field `rulez`"), "{e}");
    }

    #[test]
    fn identity_bindings() {
        let p = Policy::from_yaml(&format!(
            "version: 1\nagents:\n  a: {{ uid: 7, exe: '/usr/bin/python3*', token_sha256: {} }}\n  b: {{}}\n",
            hex::encode(Sha256::digest(b"tok"))
        ))
        .unwrap();
        let peer = Peer { pid: 1, uid: 7, gid: 7, exe: Some("/usr/bin/python3.14".into()) };
        assert!(p.agents["a"].admits(&peer, Some("tok")).is_ok());
        assert!(p.agents["a"].admits(&peer, Some("nope")).is_err());
        assert!(p.agents["a"].admits(&peer, None).is_err());
        assert!(p.agents["a"].admits(&Peer { uid: 8, ..peer.clone() }, Some("tok")).is_err());
        assert!(p.agents["a"].admits(&Peer { exe: Some("/bin/sh".into()), ..peer.clone() }, Some("tok")).is_err());
        assert!(p.agents["b"].admits(&peer, None).is_err());
    }
}
