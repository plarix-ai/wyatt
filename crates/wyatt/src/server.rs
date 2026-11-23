//! The daemon: agent socket, control socket, sessions, approvals, kill switch
//! and hot reload.
//!
//! Threads: one per connection, one per listener, and the main thread waiting
//! for signals (SIGHUP reloads, SIGINT and SIGTERM stop). Locks are taken in
//! the order session, then rates; nothing holds a lock while a tool runs or
//! while waiting for a human.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use wyatt_core::check::{self, Level};
use wyatt_core::dlp::Findings;
use wyatt_core::engine::{self, Code, Decision, Request, Verdict};
use wyatt_core::policy::{Args, Effect, Mode, Peer, Policy};
use wyatt_core::{RateState, Session};

use crate::audit::Audit;
use crate::drivers::{self, Secrets};
use crate::proto::{self, AgentReq, ControlReq, Line};
use crate::{clock, peer};

const MAX_CONNECTIONS: usize = 256;
/// How long a named session keeps its labels with no connection open.
const SESSION_IDLE: Duration = Duration::from_secs(24 * 3600);
const TICKET_TTL: Duration = Duration::from_secs(3600);

pub struct Config {
    pub policy: PathBuf,
    pub socket: PathBuf,
    pub control: PathBuf,
    pub state_dir: PathBuf,
    pub socket_mode: u32,
    pub control_group: Option<String>,
}

pub struct Loaded {
    pub policy: Policy,
    secrets: BTreeMap<String, Secrets>,
}

/// Reads, validates and lints a policy file. Lint errors block loading.
pub fn load(path: &Path) -> anyhow::Result<Loaded> {
    let src = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let policy = Policy::from_yaml(&src).map_err(|e| anyhow::anyhow!("{}:\n{e}", path.display()))?;
    let errors: Vec<String> = check::lint(&policy)
        .into_iter()
        .filter(|d| d.level == Level::Error)
        .map(|d| format!("{}: {}", d.at, d.msg))
        .collect();
    if !errors.is_empty() {
        bail!("{} has errors (see `wyatt check`):\n{}", path.display(), errors.join("\n"));
    }
    let mut secrets = BTreeMap::new();
    for t in policy.tools.values() {
        secrets.insert(t.name.clone(), drivers::resolve(t).map_err(anyhow::Error::msg)?);
    }
    Ok(Loaded { policy, secrets })
}

struct Ticket {
    tool: String,
    audit: u64,
    created: Instant,
}

/// Live sessions keyed by (agent, session name).
type Sessions = HashMap<(String, String), Arc<Mutex<Sess>>>;

struct Sess {
    id: String,
    agent: String,
    state: Session,
    tickets: HashMap<String, Ticket>,
    last_used: Instant,
    connections: usize,
    /// Named sessions outlive their connections; anonymous ones end with them.
    named: bool,
}

enum Answer {
    Waiting,
    Approved(String),
    Denied(String, String),
    TimedOut,
}

struct Pending {
    session: String,
    agent: String,
    tool: String,
    args: Value,
    rule: Option<String>,
    reason: String,
    approvers: Vec<String>,
    created_ms: u64,
    answer: Answer,
}

#[derive(Default)]
struct Stats {
    allow: AtomicU64,
    deny: AtomicU64,
    approve: AtomicU64,
}

struct State {
    cfg: Config,
    loaded: RwLock<Arc<Loaded>>,
    audit: Audit,
    rates: Mutex<RateState>,
    sessions: Mutex<Sessions>,
    /// Every label any session of an agent has carried, by agent.
    history: Mutex<HashMap<String, BTreeSet<String>>>,
    approvals: Mutex<BTreeMap<u64, Pending>>,
    approval_cv: Condvar,
    frozen: Mutex<Option<String>>,
    /// Process groups of running tools, by the audit seq of their decision.
    running: Mutex<HashMap<u64, i32>>,
    /// Calls the kill switch cut short, with its reason, until their reply goes out.
    stopped: Mutex<HashMap<u64, String>>,
    next_id: AtomicU64,
    connections: AtomicUsize,
    stats: Stats,
    started: Instant,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn rec(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn random_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
}

impl State {
    fn policy(&self) -> Arc<Loaded> {
        Arc::clone(&self.loaded.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Audit failures stop the daemon: enforcement without a record is not allowed.
    /// Adds the session's labels to its agent's history and hands the
    /// history back to the session for the next decision.
    fn share_labels(&self, s: &mut Sess) {
        let mut h = lock(&self.history);
        let all = h.entry(s.agent.clone()).or_default();
        all.extend(s.state.labels.iter().cloned());
        s.state.history.clone_from(all);
    }

    fn log(&self, kind: &str, v: Value) -> u64 {
        match self.audit.append(kind, rec(v)) {
            Ok(seq) => seq,
            Err(e) => {
                eprintln!("wyatt: cannot write the audit log ({e}); stopping");
                std::process::exit(70);
            }
        }
    }

    fn reload(&self) -> anyhow::Result<(String, String)> {
        let new = load(&self.cfg.policy)?;
        let mut cur = self.loaded.write().unwrap_or_else(|e| e.into_inner());
        let from = cur.policy.digest.clone();
        let to = new.policy.digest.clone();
        *cur = Arc::new(new);
        drop(cur);
        self.log("reload", json!({ "from": from, "to": to, "policy": self.cfg.policy.display().to_string() }));
        Ok((from, to))
    }

    fn freeze(&self, reason: &str, by: &str) {
        *lock(&self.frozen) = Some(reason.to_string());
        {
            let mut a = lock(&self.approvals);
            for p in a.values_mut().filter(|p| matches!(p.answer, Answer::Waiting)) {
                p.answer = Answer::Denied(by.to_string(), format!("frozen: {reason}"));
            }
        }
        self.approval_cv.notify_all();
        // Both locks are held so a call cannot finish between being killed
        // and being marked as stopped.
        let killed = {
            let running = lock(&self.running);
            let mut stopped = lock(&self.stopped);
            for (seq, pg) in running.iter() {
                stopped.insert(*seq, reason.to_string());
                // SAFETY: signalling a process group this daemon started.
                unsafe { libc::kill(-pg, libc::SIGKILL) };
            }
            running.len()
        };
        self.log("control", json!({ "op": "freeze", "by": by, "reason": reason, "killed": killed }));
    }
}

fn redacted(p: &Policy, v: &Value) -> (Value, Findings) {
    let mut v = v.clone();
    let mut f = Findings::new();
    p.dlp.redact_value(&mut v, &mut f);
    (v, f)
}

/// The tools an agent could ever be allowed to use, for the hello reply.
fn tools_for(p: &Policy, agent: &str) -> Vec<Value> {
    p.tools
        .values()
        .filter(|t| p.rules.iter().any(|r| r.effect != Effect::Deny && r.targets(agent, &t.name)))
        .map(|t| {
            let args = match &t.args {
                Args::Any => json!("any"),
                Args::Schema(s) => Value::Object(
                    s.iter()
                        .map(|(k, a)| {
                            let mut spec = json!({ "type": a.ty.name(), "required": a.required });
                            if let Some(d) = &a.default {
                                spec["default"] = d.clone();
                            }
                            if let Some(o) = &a.one_of {
                                spec["one_of"] = Value::Array(o.clone());
                            }
                            (k.clone(), spec)
                        })
                        .collect(),
                ),
            };
            json!({ "name": t.name, "driver": t.driver.name(), "description": t.description, "args": args })
        })
        .collect()
}

/// How the agent asked: `call` runs the tool here, `check` only decides
/// and hands back a ticket for the result.
enum Kind {
    Call,
    Check {
        ticket: Option<String>,
        /// The client can ask its user, so an approve verdict is passed on
        /// instead of waiting for an approver.
        ask: bool,
    },
}

struct Outcome {
    verdict: Verdict,
    code: String,
    rule: Option<String>,
    reason: String,
    would: Option<Verdict>,
    audit: u64,
    /// The engine's decision; `None` when the kill switch answered first.
    decision: Option<Decision>,
}

fn reply(id: &Value, o: &Outcome) -> Value {
    let mut r = json!({
        "id": id,
        "decision": o.verdict,
        "code": o.code,
        "reason": o.reason,
        "audit": o.audit,
    });
    if let Some(rule) = &o.rule {
        r["rule"] = rule.clone().into();
    }
    if let Some(w) = o.would {
        r["enforced"] = false.into();
        r["would"] = json!(w);
    }
    r
}

fn code_name(c: Code) -> String {
    serde_json::to_value(c).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

/// Decides, audits and (for approve) waits. Returns the final verdict.
/// `client_asks`: the client will ask its own user on approve (Claude Code
/// does), so return at once instead of waiting on the control socket.
fn decide(
    st: &State,
    loaded: &Loaded,
    peer: &Peer,
    sess: &Mutex<Sess>,
    tool: &str,
    args: &Value,
    client_asks: bool,
) -> Outcome {
    let p = &loaded.policy;
    let now = clock::now_ms();
    let (session_id, agent) = {
        let s = lock(sess);
        (s.id.clone(), s.agent.clone())
    };
    let (audit_args, _) = redacted(p, args);
    let base = json!({
        "session": session_id, "agent": agent, "tool": tool, "args": audit_args,
        "peer": { "pid": peer.pid, "uid": peer.uid, "exe": peer.exe }, "policy": &p.digest[..12],
    });

    if let Some(reason) = lock(&st.frozen).clone() {
        let mut r = base;
        r["verdict"] = "deny".into();
        r["code"] = "frozen".into();
        r["reason"] = reason.clone().into();
        let audit = st.log("decision", r);
        st.stats.deny.fetch_add(1, Ordering::Relaxed);
        return Outcome {
            verdict: Verdict::Deny,
            code: "frozen".into(),
            rule: None,
            reason: format!("wyatt is frozen: {reason}"),
            would: None,
            audit,
            decision: None,
        };
    }

    // Decide and count the call under one lock, so two connections sharing a
    // session cannot both take the last slot of a limit.
    let mut s = lock(sess);
    st.share_labels(&mut s);
    let mut rates = lock(&st.rates);
    let d = engine::decide(p, &Request { agent: &agent, tool, args }, &s.state, &rates, now, false);
    engine::record_attempt(&mut rates, p, &agent, &d, now);
    drop(rates);

    let monitor = p.mode == Mode::Monitor;
    // Monitor mode lets policy decisions through but never a malformed call:
    // there is no safe way to run a tool with arguments that failed validation.
    let soft = matches!(d.code, Code::Rule | Code::NoRule | Code::RateLimited | Code::CallLimit);
    let (verdict, would) = match d.verdict {
        Verdict::Allow => (Verdict::Allow, None),
        v if monitor && (v == Verdict::Approve || soft) => (Verdict::Allow, Some(v)),
        v => (v, None),
    };
    let mut r = base.clone();
    r["verdict"] = json!(d.verdict);
    r["code"] = code_name(d.code).into();
    r["reason"] = d.reason.clone().into();
    if let Some(rule) = &d.rule {
        r["rule"] = rule.clone().into();
    }
    if would.is_some() {
        r["enforced"] = false.into();
    }
    // An approval the client handles counts now: if the user says yes the
    // tool runs without coming back here first.
    if verdict == Verdict::Allow || (verdict == Verdict::Approve && client_asks) {
        s.state.record_success(tool, &d.labels, &d.limits);
        st.share_labels(&mut s);
        s.last_used = Instant::now();
    }
    drop(s);
    let audit = st.log("decision", r);

    let approvers = d.approvers.clone();
    let (labels, limits) = (d.labels.clone(), d.limits.clone());
    let mut out = Outcome {
        verdict,
        code: code_name(d.code),
        rule: d.rule.clone(),
        reason: d.reason.clone(),
        would,
        audit,
        decision: Some(d),
    };
    if verdict != Verdict::Approve || client_asks {
        let counter = match verdict {
            Verdict::Allow => &st.stats.allow,
            Verdict::Approve => &st.stats.approve,
            Verdict::Deny => &st.stats.deny,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        return out;
    }

    st.stats.approve.fetch_add(1, Ordering::Relaxed);
    let id = st.next_id.fetch_add(1, Ordering::Relaxed);
    lock(&st.approvals).insert(
        id,
        Pending {
            session: session_id,
            agent: agent.clone(),
            tool: tool.to_string(),
            args: audit_args,
            rule: out.rule.clone(),
            reason: out.reason.clone(),
            approvers,
            created_ms: now,
            answer: Answer::Waiting,
        },
    );
    let answer = wait_for_answer(st, id, p.approval_timeout);
    let (v, code, by, why) = match answer {
        Answer::Approved(by) => (Verdict::Allow, "approved", by, String::new()),
        Answer::Denied(by, why) => (Verdict::Deny, "approval_denied", by, why),
        Answer::TimedOut | Answer::Waiting => {
            (Verdict::Deny, "approval_timeout", String::new(), format!("no answer within {:?}", p.approval_timeout))
        }
    };
    st.log("approval", json!({ "call": audit, "approval": id, "verdict": v, "code": code, "by": by, "reason": why }));
    out.verdict = v;
    out.code = code.into();
    if v == Verdict::Allow {
        let mut s = lock(sess);
        s.state.record_success(tool, &labels, &limits);
        st.share_labels(&mut s);
        st.stats.allow.fetch_add(1, Ordering::Relaxed);
    } else {
        out.reason = if why.is_empty() { format!("approval {code}") } else { why };
        st.stats.deny.fetch_add(1, Ordering::Relaxed);
    }
    out
}

fn wait_for_answer(st: &State, id: u64, timeout: Duration) -> Answer {
    let deadline = Instant::now() + timeout;
    let mut g = lock(&st.approvals);
    loop {
        match g.get(&id).map(|p| matches!(p.answer, Answer::Waiting)) {
            Some(true) => {}
            Some(false) => return g.remove(&id).map(|p| p.answer).unwrap_or(Answer::TimedOut),
            None => return Answer::TimedOut,
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            g.remove(&id);
            return Answer::TimedOut;
        }
        g = st.approval_cv.wait_timeout(g, left).unwrap_or_else(|e| e.into_inner()).0;
    }
}

/// DLP on tool output. A hit adds `secret` to the session when the policy asks.
fn scrub(st: &State, loaded: &Loaded, sess: &Mutex<Sess>, out: &mut Value) -> (Findings, BTreeSet<String>) {
    let p = &loaded.policy;
    let mut f = Findings::new();
    p.dlp.redact_value(out, &mut f);
    let mut s = lock(sess);
    if !f.is_empty() && p.label_secrets {
        s.state.labels.insert("secret".into());
        st.share_labels(&mut s);
    }
    (f, s.state.labels.clone())
}

/// Size and SHA-256 of the output as the agent receives it, after DLP, so
/// a copy kept elsewhere can be matched to its audit record. Hashing the
/// redacted form keeps short secrets from being guessed from the log.
fn digest(v: &Value) -> (usize, String) {
    let text = serde_json::to_string(v).unwrap_or_default();
    (text.len(), hex::encode(Sha256::digest(text.as_bytes())))
}

fn tool_call(st: &State, peer: &Peer, sess: &Mutex<Sess>, id: &Value, tool: &str, args: &Value, kind: Kind) -> Value {
    let loaded = st.policy();
    let ask = matches!(kind, Kind::Check { ask: true, .. });
    if let Some(t) = loaded.policy.tool(tool) {
        match (&kind, t.driver.is_mediated()) {
            (Kind::Call, false) => {
                return proto::protocol_error(
                    id,
                    format!("`{tool}` runs in the agent: send check, run it, then send result"),
                );
            }
            (Kind::Check { .. }, true) => {
                return proto::protocol_error(id, format!("`{tool}` runs inside wyatt: send call"));
            }
            _ => {}
        }
    }
    let o = decide(st, &loaded, peer, sess, tool, args, ask);
    let mut r = reply(id, &o);
    let go = o.verdict == Verdict::Allow || (ask && o.verdict == Verdict::Approve);
    let Some(d) = o.decision.as_ref().filter(|_| go) else {
        return r;
    };
    if let Kind::Check { ticket, .. } = kind {
        let ticket = ticket.unwrap_or_else(random_id);
        let mut s = lock(sess);
        s.tickets.retain(|_, t| t.created.elapsed() < TICKET_TTL);
        s.tickets.insert(ticket.clone(), Ticket { tool: tool.to_string(), audit: o.audit, created: Instant::now() });
        r["ticket"] = ticket.into();
        r["args"] = d.args.clone();
        return r;
    }

    let t = loaded.policy.tool(tool).expect("allowed tools exist");
    let secrets = &loaded.secrets[tool];
    let started = Instant::now();
    let seq = o.audit;
    let result = drivers::run(t, &d.args, secrets, &|pg| {
        lock(&st.running).insert(seq, pg);
    });
    lock(&st.running).remove(&seq);
    // A tool killed by freeze exits on a signal, which the driver reports as
    // an ordinary result. The agent should learn that it was stopped.
    let result = match lock(&st.stopped).remove(&seq) {
        Some(reason) => Err(drivers::Failure::Stopped(reason)),
        None => result,
    };
    let elapsed = started.elapsed().as_millis() as u64;
    match result {
        Ok(mut v) => {
            let (found, labels) = scrub(st, &loaded, sess, &mut v);
            let (bytes, sha) = digest(&v);
            st.log(
                "outcome",
                json!({ "call": seq, "status": "ok", "elapsed_ms": elapsed, "bytes": bytes, "output_sha256": sha, "redacted": found }),
            );
            r["result"] = v;
            r["labels"] = json!(labels);
            if !found.is_empty() {
                r["redacted"] = json!(found);
            }
        }
        Err(e) => {
            st.log(
                "outcome",
                json!({ "call": seq, "status": e.status(), "elapsed_ms": elapsed, "error": e.to_string() }),
            );
            r["error"] = json!({ "status": e.status(), "message": e.to_string() });
        }
    }
    r
}

fn tool_result(st: &State, sess: &Mutex<Sess>, id: &Value, ticket: &str, ok: bool, mut output: Value) -> Value {
    let loaded = st.policy();
    let Some(t) = lock(sess).tickets.remove(ticket) else {
        return proto::protocol_error(id, format!("unknown or already used ticket `{ticket}`"));
    };
    let (found, labels) = scrub(st, &loaded, sess, &mut output);
    let (bytes, sha) = digest(&output);
    st.log(
        "outcome",
        json!({ "call": t.audit, "tool": t.tool, "status": if ok { "ok" } else { "error" }, "reported": true,
                "bytes": bytes, "output_sha256": sha, "redacted": found }),
    );
    let mut r = json!({ "id": id, "output": output, "labels": labels });
    if !found.is_empty() {
        r["redacted"] = json!(found);
    }
    r
}

fn visible(st: &State, sess: &Mutex<Sess>, id: &Value, tools: Vec<String>) -> Value {
    let loaded = st.policy();
    let p = &loaded.policy;
    let agent = lock(sess).agent.clone();
    // Visible: some rule could allow or approve it, and no unconditional
    // deny rule covers it.
    let keep: Vec<String> = tools
        .into_iter()
        .filter(|t| {
            p.tool(t).is_some()
                && p.rules.iter().any(|r| r.effect != Effect::Deny && r.targets(&agent, t))
                && !p.rules.iter().any(|r| r.effect == Effect::Deny && r.when.is_true() && r.targets(&agent, t))
        })
        .collect();
    json!({ "id": id, "tools": keep })
}

fn notice(
    st: &State,
    peer: &Peer,
    sess: &Mutex<Sess>,
    id: &Value,
    event: &str,
    tool: Option<String>,
    detail: Value,
) -> Value {
    if event.is_empty() || event.len() > 64 || !event.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return proto::protocol_error(id, "event names use letters, digits, _ and -, up to 64");
    }
    let (agent, session) = {
        let g = lock(sess);
        (g.agent.clone(), g.id.clone())
    };
    let seq = st.log(
        "notice",
        json!({ "agent": agent, "session": session, "pid": peer.pid, "event": event, "tool": tool, "detail": detail }),
    );
    json!({ "id": id, "audit": seq })
}

fn hello(
    st: &State,
    peer: &Peer,
    agent: &str,
    token: Option<&str>,
    session: Option<String>,
) -> Result<(Arc<Mutex<Sess>>, Value), Value> {
    let loaded = st.policy();
    let p = &loaded.policy;
    let admitted = match p.agents.get(agent) {
        None => Err(format!("unknown agent `{agent}`")),
        Some(a) => a.admits(peer, token),
    };
    if let Err(why) = admitted {
        st.log("hello", json!({ "agent": agent, "admitted": false, "reason": why, "peer": { "pid": peer.pid, "uid": peer.uid, "exe": peer.exe } }));
        return Err(json!({ "error": { "status": "identity", "message": why } }));
    }
    let named = session.is_some();
    let name = session.unwrap_or_else(|| format!("c-{}", random_id()));
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(proto::protocol_error(&Value::Null, "session names are 1 to 128 printable characters"));
    }
    let mut all = lock(&st.sessions);
    all.retain(|_, s| {
        let s = lock(s);
        s.connections > 0 || (s.named && s.last_used.elapsed() < SESSION_IDLE)
    });
    let s = all
        .entry((agent.to_string(), name.clone()))
        .or_insert_with(|| {
            Arc::new(Mutex::new(Sess {
                id: name.clone(),
                agent: agent.to_string(),
                state: Session::default(),
                tickets: HashMap::new(),
                last_used: Instant::now(),
                connections: 0,
                named,
            }))
        })
        .clone();
    drop(all);
    let labels = {
        let mut g = lock(&s);
        g.connections += 1;
        g.last_used = Instant::now();
        g.state.labels.clone()
    };
    st.log("hello", json!({ "agent": agent, "admitted": true, "session": name, "peer": { "pid": peer.pid, "uid": peer.uid, "exe": peer.exe } }));
    let resp = json!({
        "agent": agent,
        "session": name,
        "labels": labels,
        "policy": { "name": p.name, "digest": p.digest, "mode": if p.mode == Mode::Monitor { "monitor" } else { "enforce" } },
        "tools": tools_for(p, agent),
    });
    Ok((s, resp))
}

fn serve_agent(st: &State, stream: UnixStream) {
    let Ok(peer) = peer::identify(&stream) else { return };
    let Ok(read_half) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut w = stream;
    let mut sess: Option<Arc<Mutex<Sess>>> = None;
    loop {
        let line = match proto::read_line(&mut reader) {
            Ok(Line::Text(s)) => s,
            Ok(Line::TooLong) => {
                let _ = proto::write_line(&mut w, &proto::protocol_error(&Value::Null, "request line is over 1 MiB"));
                break;
            }
            Ok(Line::Eof) | Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: AgentReq = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                if proto::write_line(&mut w, &proto::protocol_error(&Value::Null, e.to_string())).is_err() {
                    break;
                }
                continue;
            }
        };
        let (resp, close) = match (req, &sess) {
            (AgentReq::Hello { .. }, Some(_)) => (proto::protocol_error(&Value::Null, "already said hello"), false),
            (AgentReq::Hello { agent, token, session }, None) => {
                match hello(st, &peer, &agent, token.as_deref(), session) {
                    Ok((s, r)) => {
                        sess = Some(s);
                        (r, false)
                    }
                    Err(r) => (r, true),
                }
            }
            (
                AgentReq::Call { id, .. }
                | AgentReq::Check { id, .. }
                | AgentReq::Result { id, .. }
                | AgentReq::Visible { id, .. }
                | AgentReq::Notice { id, .. },
                None,
            ) => (proto::protocol_error(&id, "send hello first"), false),
            (AgentReq::Call { id, tool, args }, Some(s)) => {
                (tool_call(st, &peer, s, &id, &tool, &args, Kind::Call), false)
            }
            (AgentReq::Check { id, tool, args, ticket, ask }, Some(s)) => {
                (tool_call(st, &peer, s, &id, &tool, &args, Kind::Check { ticket, ask }), false)
            }
            (AgentReq::Result { id, ticket, ok, output }, Some(s)) => {
                (tool_result(st, s, &id, &ticket, ok, output), false)
            }
            (AgentReq::Visible { id, tools }, Some(s)) => (visible(st, s, &id, tools), false),
            (AgentReq::Notice { id, event, tool, detail }, Some(s)) => {
                (notice(st, &peer, s, &id, &event, tool, detail), false)
            }
        };
        if proto::write_line(&mut w, &resp).is_err() || close {
            break;
        }
    }
    if let Some(s) = sess {
        let mut g = lock(&s);
        g.connections = g.connections.saturating_sub(1);
        g.last_used = Instant::now();
    }
}

fn control(st: &State, by: &str, req: ControlReq) -> Value {
    match req {
        ControlReq::Status => {
            let l = st.policy();
            let p = &l.policy;
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "policy": { "name": p.name, "digest": p.digest, "path": st.cfg.policy.display().to_string(),
                            "mode": if p.mode == Mode::Monitor { "monitor" } else { "enforce" } },
                "frozen": *lock(&st.frozen),
                "sessions": lock(&st.sessions).len(),
                "pending": lock(&st.approvals).values().filter(|p| matches!(p.answer, Answer::Waiting)).count(),
                "running": lock(&st.running).len(),
                "decisions": { "allow": st.stats.allow.load(Ordering::Relaxed), "deny": st.stats.deny.load(Ordering::Relaxed),
                               "approve": st.stats.approve.load(Ordering::Relaxed) },
                "uptime_s": st.started.elapsed().as_secs(),
                "audit": st.audit.path().display().to_string(),
                "landlock_abi": drivers::landlock::abi(),
            })
        }
        ControlReq::Sessions => {
            let all = lock(&st.sessions);
            let list: Vec<Value> = all
                .values()
                .map(|s| {
                    let s = lock(s);
                    json!({ "session": s.id, "agent": s.agent, "labels": s.state.labels, "calls": s.state.calls,
                            "tools": s.state.tools, "connections": s.connections, "idle_s": s.last_used.elapsed().as_secs() })
                })
                .collect();
            json!({ "sessions": list })
        }
        ControlReq::Approvals => {
            let now = clock::now_ms();
            let a = lock(&st.approvals);
            let list: Vec<Value> = a
                .iter()
                .filter(|(_, p)| matches!(p.answer, Answer::Waiting))
                .map(|(id, p)| {
                    json!({ "id": id, "session": p.session, "agent": p.agent, "tool": p.tool, "args": p.args, "rule": p.rule,
                            "reason": p.reason, "approvers": p.approvers, "age_s": now.saturating_sub(p.created_ms) / 1000 })
                })
                .collect();
            json!({ "approvals": list })
        }
        ControlReq::Approve { id } => answer(st, id, by, Answer::Approved(by.to_string())),
        ControlReq::Deny { id, reason } => {
            answer(st, id, by, Answer::Denied(by.to_string(), reason.unwrap_or_else(|| format!("denied by {by}"))))
        }
        ControlReq::Freeze { reason } => {
            st.freeze(reason.as_deref().unwrap_or("kill switch"), by);
            json!({ "frozen": true })
        }
        ControlReq::Unfreeze => {
            *lock(&st.frozen) = None;
            st.log("control", json!({ "op": "unfreeze", "by": by }));
            json!({ "frozen": false })
        }
        ControlReq::Reload => match st.reload() {
            Ok((from, to)) => json!({ "reloaded": from != to, "from": from, "to": to }),
            Err(e) => json!({ "error": { "status": "invalid_policy", "message": format!("{e:#}") } }),
        },
    }
}

fn answer(st: &State, id: u64, by: &str, a: Answer) -> Value {
    let mut all = lock(&st.approvals);
    let Some(p) = all.get_mut(&id) else {
        return json!({ "error": { "status": "not_found", "message": format!("no pending approval {id}") } });
    };
    if !matches!(p.answer, Answer::Waiting) {
        return json!({ "error": { "status": "answered", "message": format!("approval {id} was already answered") } });
    }
    if !p.approvers.is_empty() && !p.approvers.iter().any(|a| a == by) {
        return json!({ "error": { "status": "not_approver", "message": format!("{by} is not an approver for this call ({})", p.approvers.join(", ")) } });
    }
    p.answer = a;
    drop(all);
    st.approval_cv.notify_all();
    json!({ "answered": id })
}

fn serve_control(st: &State, stream: UnixStream) {
    let Ok(peer) = peer::identify(&stream) else { return };
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if peer.uid != me && peer.uid != 0 {
        return;
    }
    let by = peer::username(peer.uid);
    let Ok(read_half) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut w = stream;
    while let Ok(Line::Text(line)) = proto::read_line(&mut reader) {
        let resp = match serde_json::from_str::<ControlReq>(&line) {
            Ok(req) => control(st, &by, req),
            Err(e) => proto::protocol_error(&Value::Null, e.to_string()),
        };
        if proto::write_line(&mut w, &resp).is_err() {
            break;
        }
    }
}

/// Hands the control socket to `group` with mode 660. The daemon's user must
/// be a member of the group.
fn share_with_group(path: &Path, group: &str) -> anyhow::Result<()> {
    let gid = peer::group_id(group).with_context(|| format!("no group named `{group}`"))?;
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: `c` is a valid NUL-terminated path; uid -1 leaves the owner alone.
    if unsafe { libc::chown(c.as_ptr(), u32::MAX, gid) } != 0 {
        let e = std::io::Error::last_os_error();
        bail!("giving {} to group `{group}`: {e} (is the daemon's user a member?)", path.display());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    Ok(())
}

fn bind(path: &Path, mode: u32) -> anyhow::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            bail!("another process is already listening on {}", path.display());
        }
        fs::remove_file(path).with_context(|| format!("removing stale socket {}", path.display()))?;
    }
    // Bind under a strict umask so the socket never exists with looser permissions.
    // SAFETY: umask only changes this process's file creation mask.
    let old = unsafe { libc::umask(0o177) };
    let l = UnixListener::bind(path);
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    let l = l.with_context(|| format!("binding {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(l)
}

fn accept_loop(st: Arc<State>, l: UnixListener, handler: fn(&State, UnixStream)) {
    for conn in l.incoming() {
        let Ok(conn) = conn else { continue };
        if st.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            st.connections.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let st = Arc::clone(&st);
        let spawned = std::thread::Builder::new().name("wyatt-conn".into()).spawn(move || {
            handler(&st, conn);
            st.connections.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            eprintln!("wyatt: cannot start a connection thread");
        }
    }
}

fn block_signals() -> libc::sigset_t {
    // SAFETY: sigset operations on a local, then masking for this thread
    // before any other thread exists, so every thread inherits the mask.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    }
}

pub fn serve(mut cfg: Config) -> anyhow::Result<()> {
    let signals = block_signals();
    // Reload reads this path later, maybe from another working directory.
    cfg.policy = fs::canonicalize(&cfg.policy).with_context(|| format!("policy {}", cfg.policy.display()))?;
    let loaded = load(&cfg.policy)?;
    let audit =
        Audit::open(&cfg.state_dir).with_context(|| format!("opening audit log in {}", cfg.state_dir.display()))?;
    let agents = bind(&cfg.socket, cfg.socket_mode)?;
    let controls = bind(&cfg.control, 0o600)?;
    if let Some(group) = &cfg.control_group {
        share_with_group(&cfg.control, group)?;
    }
    let p = &loaded.policy;
    eprintln!(
        "wyatt {}: policy {} ({}, {} tools, {} rules, {})",
        env!("CARGO_PKG_VERSION"),
        p.name,
        &p.digest[..12],
        p.tools.len(),
        p.rules.len(),
        if p.mode == Mode::Monitor { "MONITOR MODE: nothing is blocked" } else { "enforcing" },
    );
    eprintln!(
        "  agents  {}\n  control {}\n  audit   {}",
        cfg.socket.display(),
        cfg.control.display(),
        audit.path().display()
    );
    let abi = drivers::landlock::abi();
    if abi < 4 && p.tools.values().any(|t| t.driver == wyatt_core::policy::Driver::Proc && t.sandbox.enabled) {
        eprintln!("  warning: Landlock ABI {abi}; sandboxed proc tools will be refused (needs 4, Linux 6.7+)");
    }
    let start = json!({ "policy": p.digest, "name": p.name, "pid": std::process::id(), "version": env!("CARGO_PKG_VERSION"),
                        "public_key": audit.public_key() });
    let st = Arc::new(State {
        cfg,
        loaded: RwLock::new(Arc::new(loaded)),
        audit,
        rates: Mutex::new(RateState::default()),
        sessions: Mutex::new(HashMap::new()),
        approvals: Mutex::new(BTreeMap::new()),
        approval_cv: Condvar::new(),
        frozen: Mutex::new(None),
        running: Mutex::new(HashMap::new()),
        stopped: Mutex::new(HashMap::new()),
        history: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        connections: AtomicUsize::new(0),
        stats: Stats::default(),
        started: Instant::now(),
    });
    st.log("start", start);
    {
        let st = Arc::clone(&st);
        std::thread::Builder::new().name("wyatt-agents".into()).spawn(move || accept_loop(st, agents, serve_agent))?;
    }
    {
        let st = Arc::clone(&st);
        std::thread::Builder::new()
            .name("wyatt-control".into())
            .spawn(move || accept_loop(st, controls, serve_control))?;
    }
    loop {
        let mut sig = 0;
        // SAFETY: waits for one of the signals blocked above.
        if unsafe { libc::sigwait(&signals, &mut sig) } != 0 {
            continue;
        }
        if sig == libc::SIGHUP {
            match st.reload() {
                Ok((from, to)) if from == to => eprintln!("wyatt: reloaded, policy unchanged"),
                Ok((_, to)) => eprintln!("wyatt: reloaded policy {}", &to[..12]),
                Err(e) => eprintln!("wyatt: reload refused, keeping the current policy:\n{e:#}"),
            }
            continue;
        }
        st.log("stop", json!({ "signal": sig }));
        let _ = fs::remove_file(&st.cfg.socket);
        let _ = fs::remove_file(&st.cfg.control);
        eprintln!("wyatt: stopped");
        return Ok(());
    }
}
