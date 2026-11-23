//! `wyatt mcp`: a policy gateway in front of a stdio MCP server.
//!
//! The MCP host starts `wyatt mcp --server NAME -- <server command>` instead
//! of the server itself. Wyatt starts the server and relays JSON-RPC lines
//! both ways, changing three things:
//!
//! - `tools/list` results lose every tool the policy never allows this
//!   agent, every tool whose definition is poisoned, and every tool whose
//!   definition changed since it was first seen (pinned in the state dir).
//! - `tools/call` requests are checked with the daemon first. A denied call
//!   never reaches the server; the host gets a tool error with the reason.
//! - `tools/call` results go through DLP before the host sees them.
//!
//! Tool names in the policy follow Claude Code: `mcp__<server>__<tool>`, so
//! one policy covers both the hook and the gateway.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use serde_json::{Value, json};
use wyatt_core::mcp::{self, Finding, Severity};

use crate::client::Conn;
use crate::term::{bold, dim, green, pad, red, yellow};

const SCAN_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Opts {
    pub server: String,
    pub command: Vec<String>,
    pub agent: String,
    pub socket: PathBuf,
    pub state: PathBuf,
    pub session: Option<String>,
    pub allow_flagged: bool,
    pub repin: bool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn policy_name(server: &str, tool: &str) -> String {
    format!("mcp__{server}__{tool}")
}

fn token() -> Option<String> {
    std::env::var("WYATT_TOKEN").ok().filter(|t| !t.is_empty())
}

fn hello(o: &Opts, session: &str) -> anyhow::Result<(Conn, Value)> {
    let mut c = Conn::open(&o.socket)?;
    let r = c.send(&json!({ "op": "hello", "agent": o.agent, "token": token(), "session": session }))?;
    if let Some(e) = r.get("error") {
        bail!("{}", e["message"].as_str().unwrap_or("hello refused"));
    }
    Ok((c, r))
}

/// Tool definitions pinned on first sight, per server.
struct Pins {
    path: PathBuf,
    map: BTreeMap<String, String>,
}

impl Pins {
    fn load(state: &Path, server: &str) -> anyhow::Result<Pins> {
        let dir = state.join("mcp-pins");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{server}.json"));
        let map = match fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("{} is not valid JSON", path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Pins { path, map })
    }

    fn save(&self) -> io::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(&self.map)?)?;
        fs::rename(tmp, &self.path)
    }
}

struct Gate {
    opts: Opts,
    session: String,
    pins: Mutex<Pins>,
    /// Tools hidden for a poisoned or changed definition. Calls to them are
    /// refused even if the host still knows the name.
    hidden: Mutex<BTreeSet<String>>,
    /// Open daemon connections not in use. A call waiting on an approval
    /// holds its connection, so other calls take another one; all of them
    /// join the same named session.
    idle: Mutex<Vec<Conn>>,
    to_host: Mutex<io::Stdout>,
    /// Taken when the host closes its end, so the server sees EOF.
    to_server: Mutex<Option<ChildStdin>>,
    /// Request ids we are waiting on: tools/list, or tools/call with its ticket.
    pending: Mutex<HashMap<String, Pending>>,
}

enum Pending {
    List,
    Call { ticket: String },
}

fn id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

fn send(w: &Mutex<impl Write>, v: &Value) {
    let mut w = lock(w);
    let _ = writeln!(w, "{v}");
    let _ = w.flush();
}

fn tool_error(id: &Value, text: String) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": { "content": [{ "type": "text", "text": text }], "isError": true } })
}

impl Gate {
    fn daemon(&self, req: &Value) -> anyhow::Result<Value> {
        // A separate statement, so the pool lock is not held while sending.
        let pooled = lock(&self.idle).pop();
        if let Some(mut c) = pooled {
            // A pooled connection can be stale after a daemon restart.
            if let Ok(r) = c.send(req) {
                lock(&self.idle).push(c);
                return Ok(r);
            }
        }
        let (mut c, _) = hello(&self.opts, &self.session)?;
        let r = c.send(req)?;
        lock(&self.idle).push(c);
        Ok(r)
    }

    fn note(&self, event: &str, tool: &str, detail: Value) {
        let req = json!({ "op": "notice", "event": event, "tool": tool, "detail": detail });
        if let Err(e) = self.daemon(&req) {
            eprintln!("wyatt mcp: could not record {event} for {tool}: {e:#}");
        }
    }

    fn to_server(&self, v: &Value) {
        if let Some(w) = lock(&self.to_server).as_mut() {
            let _ = writeln!(w, "{v}");
            let _ = w.flush();
        }
    }

    /// Decides which listed tools the host may see.
    fn filter_list(&self, result: &mut Value) {
        let Some(tools) = result.get_mut("tools").and_then(Value::as_array_mut) else { return };
        let names: Vec<String> =
            tools.iter().filter_map(|t| t["name"].as_str()).map(|n| policy_name(&self.opts.server, n)).collect();
        let allowed: BTreeSet<String> = match self.daemon(&json!({ "op": "visible", "tools": names })) {
            Ok(r) => {
                r["tools"].as_array().into_iter().flatten().filter_map(|t| t.as_str().map(str::to_owned)).collect()
            }
            Err(e) => {
                eprintln!("wyatt mcp: cannot reach the daemon, hiding every tool: {e:#}");
                BTreeSet::new()
            }
        };
        let mut pins = lock(&self.pins);
        let mut hidden = lock(&self.hidden);
        hidden.clear();
        let mut changed_pins = false;
        tools.retain(|t| {
            let name = t["name"].as_str().unwrap_or_default().to_string();
            let full = policy_name(&self.opts.server, &name);
            let hash = mcp::fingerprint(t);
            match pins.map.get(&name) {
                Some(old) if *old != hash && !self.opts.repin => {
                    eprintln!(
                        "wyatt mcp: {full} changed since it was pinned; hidden (rerun with --repin after checking it)"
                    );
                    self.note("changed", &full, json!({ "pinned": old, "now": hash }));
                    hidden.insert(name);
                    return false;
                }
                Some(old) if *old == hash => {}
                _ => {
                    pins.map.insert(name.clone(), hash.clone());
                    changed_pins = true;
                    self.note("pinned", &full, json!({ "hash": hash }));
                }
            }
            let bad: Vec<Finding> = mcp::inspect(t).into_iter().filter(|f| f.severity == Severity::Block).collect();
            if !bad.is_empty() && !self.opts.allow_flagged {
                let what: Vec<String> = bad.iter().map(|f| format!("{}: {}", f.at, f.what)).collect();
                eprintln!("wyatt mcp: {full} looks poisoned; hidden ({})", what.join("; "));
                self.note("poisoned", &full, json!({ "findings": bad }));
                hidden.insert(name);
                return false;
            }
            allowed.contains(&full)
        });
        if changed_pins && let Err(e) = pins.save() {
            eprintln!("wyatt mcp: cannot save pins: {e}");
        }
    }

    fn host_message(self: &Arc<Self>, msg: Value) {
        let method = msg["method"].as_str().unwrap_or_default();
        let id = msg.get("id").cloned();
        match (method, id) {
            ("tools/list", Some(id)) => {
                lock(&self.pending).insert(id_key(&id), Pending::List);
                self.to_server(&msg);
            }
            ("tools/call", Some(id)) => {
                // Checks can wait on a human, so they run off the relay thread.
                let gate = Arc::clone(self);
                std::thread::spawn(move || gate.call(id, msg));
            }
            _ => self.to_server(&msg),
        }
    }

    fn call(&self, id: Value, mut msg: Value) {
        let name = msg["params"]["name"].as_str().unwrap_or_default().to_string();
        let full = policy_name(&self.opts.server, &name);
        let args = msg["params"].get("arguments").cloned().unwrap_or_else(|| json!({}));
        if lock(&self.hidden).contains(&name) {
            let text =
                format!("wyatt blocked this call: {full} was hidden because its definition looks poisoned or changed");
            return send(&self.to_host, &tool_error(&id, text));
        }
        let ticket = format!("mcp-{}-{}", self.opts.server, id_key(&id));
        let r = self.daemon(&json!({ "op": "check", "id": id, "tool": full, "args": args, "ticket": ticket }));
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                return send(
                    &self.to_host,
                    &tool_error(&id, format!("wyatt could not check this call, so it was blocked: {e:#}")),
                );
            }
        };
        if let Some(e) = r.get("error") {
            return send(
                &self.to_host,
                &tool_error(&id, format!("wyatt: {}", e["message"].as_str().unwrap_or("check failed"))),
            );
        }
        if r["decision"] != "allow" {
            let tag = r["audit"].as_u64().map(|a| format!(" [audit #{a}]")).unwrap_or_default();
            let text = format!("wyatt denied this call: {}{tag}", r["reason"].as_str().unwrap_or_default());
            return send(&self.to_host, &tool_error(&id, text));
        }
        if let Some(a) = r.get("args").filter(|a| !a.is_null()) {
            msg["params"]["arguments"] = a.clone();
        }
        lock(&self.pending).insert(id_key(&id), Pending::Call { ticket });
        self.to_server(&msg);
    }

    fn server_message(&self, mut msg: Value) {
        let waiting = msg
            .get("id")
            .filter(|_| msg.get("method").is_none())
            .and_then(|id| lock(&self.pending).remove(&id_key(id)));
        match waiting {
            Some(Pending::List) => {
                if let Some(result) = msg.get_mut("result") {
                    self.filter_list(result);
                }
            }
            Some(Pending::Call { ticket }) => {
                if let Some(result) = msg.get("result").cloned() {
                    let ok = result["isError"] != json!(true);
                    let reported =
                        self.daemon(&json!({ "op": "result", "ticket": ticket, "ok": ok, "output": result }));
                    match reported {
                        Ok(r) if r.get("error").is_none() => msg["result"] = r["output"].clone(),
                        // Without the DLP pass the output does not go out.
                        _ => {
                            msg["result"] = json!({ "content": [{ "type": "text", "text": "wyatt could not scan this result, so it was withheld" }], "isError": true })
                        }
                    }
                }
            }
            None => {}
        }
        send(&self.to_host, &msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("wyatt-pins-{}", std::process::id()));
        let mut p = Pins::load(&dir, "gh").unwrap();
        assert!(p.map.is_empty());
        p.map.insert("create_issue".into(), "ab".repeat(32));
        p.save().unwrap();
        let q = Pins::load(&dir, "gh").unwrap();
        assert_eq!(q.map.get("create_issue").map(String::len), Some(64));
        assert!(dir.join("mcp-pins/gh.json").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn denied_calls_come_back_as_tool_errors() {
        let e = tool_error(&json!(7), "no".into());
        assert_eq!(e["id"], 7);
        assert_eq!(e["result"]["isError"], true);
        assert_eq!(e["result"]["content"][0]["text"], "no");
        assert!(e.get("error").is_none(), "a JSON-RPC error would read as a broken server, not a refusal");
    }
}

fn spawn(cmd: &[String]) -> anyhow::Result<Child> {
    let (prog, args) = cmd.split_first().context("no server command given after --")?;
    Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("starting {prog}"))
}

/// Waits for the server to exit, killing it after `grace`.
fn reap(child: &Mutex<Child>, grace: Duration) -> i32 {
    let deadline = Instant::now() + grace;
    loop {
        {
            let mut c = lock(child);
            match c.try_wait() {
                Ok(Some(s)) => return s.code().unwrap_or(1),
                Ok(None) if Instant::now() < deadline => {}
                _ => {
                    let _ = c.kill();
                    return c.wait().ok().and_then(|s| s.code()).unwrap_or(1);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn gateway(o: Opts) -> anyhow::Result<i32> {
    let session = o.session.clone().unwrap_or_else(|| format!("mcp-{}-{}", o.server, std::process::id()));
    // Refuse to start at all if the daemon cannot be reached.
    let (first, _) = hello(&o, &session)?;
    let pins = Pins::load(&o.state, &o.server)?;
    let mut child = spawn(&o.command)?;
    let to_server = child.stdin.take().expect("piped");
    let from_server = child.stdout.take().expect("piped");
    let child = Arc::new(Mutex::new(child));
    let gate = Arc::new(Gate {
        opts: o,
        session,
        pins: Mutex::new(pins),
        hidden: Mutex::new(BTreeSet::new()),
        idle: Mutex::new(vec![first]),
        to_host: Mutex::new(io::stdout()),
        to_server: Mutex::new(Some(to_server)),
        pending: Mutex::new(HashMap::new()),
    });

    // When the server exits, the gateway exits with its status.
    let (g, c) = (Arc::clone(&gate), Arc::clone(&child));
    std::thread::spawn(move || {
        for line in BufReader::new(from_server).lines() {
            let Ok(line) = line else { break };
            match serde_json::from_str::<Value>(&line) {
                Ok(v) if v.is_object() => g.server_message(v),
                // Batches and anything else unparsed would skip the checks.
                _ => eprintln!("wyatt mcp: dropped a message from the server that is not a single JSON-RPC object"),
            }
        }
        let code = reap(&c, Duration::from_secs(5));
        let _ = io::stdout().flush();
        std::process::exit(code);
    });

    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(v) if v.is_object() => gate.host_message(v),
            Ok(v) => {
                let err = json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "wyatt mcp accepts one JSON-RPC object per line, not batches" } });
                eprintln!("wyatt mcp: refused a batch of {} messages", v.as_array().map_or(0, Vec::len));
                send(&gate.to_host, &err);
            }
            Err(e) => send(
                &gate.to_host,
                &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": e.to_string() } }),
            ),
        }
    }
    // The host closed its end. Close the server's stdin and give it a few
    // seconds; the relay thread exits the process once its stdout closes.
    lock(&gate.to_server).take();
    let code = reap(&child, Duration::from_secs(5));
    std::thread::sleep(Duration::from_secs(1));
    Ok(code)
}

/// Starts a server, lists its tools and reports findings without enforcing anything.
pub fn scan(server: &str, command: &[String], as_json: bool) -> anyhow::Result<bool> {
    let child = Arc::new(Mutex::new(spawn(command)?));
    let (mut w, mut r) = {
        let mut c = lock(&child);
        (c.stdin.take().expect("piped"), BufReader::new(c.stdout.take().expect("piped")))
    };
    // A server that never answers would hang the scan.
    let watchdog = Arc::clone(&child);
    std::thread::spawn(move || {
        std::thread::sleep(SCAN_TIMEOUT);
        let _ = lock(&watchdog).kill();
    });
    let mut rpc = |id: Option<u64>, method: &str, params: Value| -> anyhow::Result<Value> {
        let mut msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        let Some(id) = id else {
            writeln!(w, "{msg}")?;
            w.flush()?;
            return Ok(Value::Null);
        };
        msg["id"] = id.into();
        writeln!(w, "{msg}")?;
        w.flush()?;
        loop {
            let mut line = String::new();
            if r.read_line(&mut line)? == 0 {
                bail!("the server exited or went quiet before answering {method}");
            }
            let v: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v["id"] == json!(id) {
                if let Some(e) = v.get("error") {
                    bail!("{method} failed: {e}");
                }
                return Ok(v["result"].clone());
            }
        }
    };
    let init = rpc(
        Some(1),
        "initialize",
        json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "wyatt", "version": env!("CARGO_PKG_VERSION") } }),
    )?;
    rpc(None, "notifications/initialized", json!({}))?;
    let mut tools = Vec::new();
    let mut cursor: Option<Value> = None;
    for page in 2.. {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let res = rpc(Some(page), "tools/list", params)?;
        tools.extend(res["tools"].as_array().cloned().unwrap_or_default());
        cursor = res.get("nextCursor").filter(|c| !c.is_null()).cloned();
        if cursor.is_none() || page > 100 {
            break;
        }
    }
    {
        let mut c = lock(&child);
        let _ = c.kill();
        let _ = c.wait();
    }

    let rows: Vec<(String, String, Vec<Finding>)> = tools
        .iter()
        .map(|t| (t["name"].as_str().unwrap_or("?").to_string(), mcp::fingerprint(t), mcp::inspect(t)))
        .collect();
    let blocked = rows.iter().filter(|r| r.2.iter().any(|f| f.severity == Severity::Block)).count();
    if as_json {
        let list: Vec<Value> = rows
            .iter()
            .map(|(n, h, f)| json!({ "tool": n, "policy_name": policy_name(server, n), "fingerprint": h, "findings": f }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&json!({ "server": init["serverInfo"], "tools": list }))?);
        return Ok(blocked == 0);
    }
    let info = &init["serverInfo"];
    println!(
        "{}  {} tools  {}",
        bold(server),
        rows.len(),
        dim(&format!(
            "{} {}, protocol {}",
            info["name"].as_str().unwrap_or("?"),
            info["version"].as_str().unwrap_or(""),
            init["protocolVersion"].as_str().unwrap_or("?")
        ))
    );
    let w = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    for (name, hash, findings) in &rows {
        let tag = if findings.iter().any(|f| f.severity == Severity::Block) {
            red("HIDE")
        } else if findings.is_empty() {
            green("ok  ")
        } else {
            yellow("warn")
        };
        println!("  {tag}  {}  {}", pad(name, w), dim(&hash[..12]));
        for f in findings {
            println!("        {} {}", dim(&format!("{}:", f.at)), f.what);
        }
    }
    println!(
        "{}",
        if blocked == 0 { green("no poisoned tools found") } else { red(&format!("{blocked} tools would be hidden")) }
    );
    Ok(blocked == 0)
}
