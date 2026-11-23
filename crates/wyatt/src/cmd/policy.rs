//! Offline policy tools: check, eval, test, bench and token. None of them
//! need a running daemon.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, bail};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wyatt_core::check::{self, Level};
use wyatt_core::dlp::Findings;
use wyatt_core::engine::{self, Decision, Request, Verdict};
use wyatt_core::{Policy, RateState, Session};

use crate::clock;
use crate::term::{bold, cyan, dim, green, pad, red, verdict, yellow};

pub fn read_policy(path: &Path) -> anyhow::Result<(String, Result<Policy, wyatt_core::PolicyErrors>)> {
    let src = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let p = Policy::from_yaml(&src);
    Ok((src, p))
}

fn load(path: &Path) -> anyhow::Result<Policy> {
    match read_policy(path)?.1 {
        Ok(p) => Ok(p),
        Err(e) => bail!("{} does not load (run `wyatt check`):\n{e}", path.display()),
    }
}

pub fn lint(path: &Path, as_json: bool, strict: bool) -> anyhow::Result<bool> {
    let (_, res) = read_policy(path)?;
    let (diags, summary) = match &res {
        Ok(p) => {
            let d = check::lint(p);
            let s = format!(
                "{} agents, {} tools, {} rules, {} limits",
                p.agents.len(),
                p.tools.len(),
                p.rules.len(),
                p.limits.len()
            );
            (d.into_iter().map(|d| (d.level, d.at, d.msg)).collect::<Vec<_>>(), Some(s))
        }
        Err(errs) => (errs.0.iter().map(|e| (Level::Error, e.at.clone(), e.msg.clone())).collect(), None),
    };
    let errors = diags.iter().filter(|d| d.0 == Level::Error).count();
    let warnings = diags.iter().filter(|d| d.0 == Level::Warning).count();
    let ok = errors == 0 && (!strict || warnings == 0);
    if as_json {
        let list: Vec<Value> = diags.iter().map(|(l, at, msg)| json!({ "level": l, "at": at, "msg": msg })).collect();
        println!("{}", serde_json::to_string_pretty(&json!({ "ok": ok, "diagnostics": list }))?);
        return Ok(ok);
    }
    match &summary {
        Some(s) => println!("{}  {}", bold(&path.display().to_string()), dim(s)),
        None => println!("{}  {}", bold(&path.display().to_string()), red("does not load")),
    }
    let width = diags.iter().map(|d| d.1.len()).max().unwrap_or(0).min(40);
    for (level, at, msg) in &diags {
        let tag = match level {
            Level::Error => red("error  "),
            Level::Warning => yellow("warning"),
            Level::Note => cyan("note   "),
        };
        println!("  {tag}  {}  {msg}", pad(at, width));
    }
    let notes = diags.len() - errors - warnings;
    let line = format!("{errors} errors, {warnings} warnings, {notes} notes");
    println!("{}", if ok { green(&line) } else { red(&line) });
    Ok(ok)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prior {
    #[serde(default)]
    labels: BTreeSet<String>,
    #[serde(default)]
    calls: u64,
    #[serde(default)]
    tools: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    tool: String,
    #[serde(default)]
    args: Value,
    /// What the tool returned, so DLP can label the session.
    #[serde(default)]
    output: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    agent: String,
    tool: String,
    #[serde(default)]
    args: Value,
    #[serde(default)]
    session: Prior,
    #[serde(default)]
    before: Vec<Step>,
    /// RFC 3339 UTC time for `time.*` conditions.
    #[serde(default)]
    now: Option<String>,
    expect: Verdict,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    rule: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    #[serde(default)]
    policy: Option<PathBuf>,
    tests: Vec<Case>,
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Approve => "approve",
        Verdict::Deny => "deny",
    }
}

fn code_str(d: &Decision) -> String {
    serde_json::to_value(d.code).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

/// Runs one case; `Err` holds the reason it failed.
fn run_case(p: &Policy, c: &Case) -> Result<Decision, String> {
    let now = match &c.now {
        Some(t) => clock::parse_rfc3339(t).ok_or_else(|| format!("`now: {t}` is not an RFC 3339 UTC time"))?,
        None => clock::now_ms(),
    };
    let mut s = Session {
        labels: c.session.labels.clone(),
        calls: c.session.calls,
        tools: c.session.tools.clone(),
        ..Session::default()
    };
    let mut rates = RateState::default();
    for (i, step) in c.before.iter().enumerate() {
        let d =
            engine::decide(p, &Request { agent: &c.agent, tool: &step.tool, args: &step.args }, &s, &rates, now, false);
        engine::record_attempt(&mut rates, p, &c.agent, &d, now);
        if d.verdict == Verdict::Deny {
            return Err(format!("before[{i}] ({}) was denied: {}", step.tool, d.reason));
        }
        s.record_success(&step.tool, &d.labels, &d.limits);
        if let Some(out) = &step.output {
            let mut out = out.clone();
            let mut f = Findings::new();
            p.dlp.redact_value(&mut out, &mut f);
            if !f.is_empty() && p.label_secrets {
                s.labels.insert("secret".into());
            }
        }
    }
    let d = engine::decide(p, &Request { agent: &c.agent, tool: &c.tool, args: &c.args }, &s, &rates, now, false);
    let mut wrong = Vec::new();
    if d.verdict != c.expect {
        wrong.push(format!("expected {}, got {}", verdict_str(c.expect), verdict_str(d.verdict)));
    }
    if let Some(code) = &c.code
        && *code != code_str(&d)
    {
        wrong.push(format!("expected code {code}, got {}", code_str(&d)));
    }
    if let Some(rule) = &c.rule
        && Some(rule) != d.rule.as_ref()
    {
        wrong.push(format!("expected rule {rule}, got {}", d.rule.as_deref().unwrap_or("none")));
    }
    if wrong.is_empty() { Ok(d) } else { Err(format!("{} ({})", wrong.join("; "), d.reason)) }
}

pub fn test(policy: Option<&Path>, files: &[PathBuf], filter: Option<&str>) -> anyhow::Result<bool> {
    let (mut passed, mut failed) = (0, 0);
    for file in files {
        let src = fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let suite: Suite = serde_yaml_ng::from_str(&src).with_context(|| format!("parsing {}", file.display()))?;
        let ppath = match (policy, &suite.policy) {
            (Some(p), _) => p.to_path_buf(),
            (None, Some(rel)) => file.parent().unwrap_or(Path::new(".")).join(rel),
            (None, None) => crate::paths::policy(),
        };
        let p = load(&ppath)?;
        println!(
            "{}  {}",
            bold(&file.display().to_string()),
            dim(&format!("against {} ({})", ppath.display(), &p.digest[..12]))
        );
        for c in suite.tests.iter().filter(|c| filter.is_none_or(|f| c.name.contains(f))) {
            match run_case(&p, c) {
                Ok(_) => {
                    passed += 1;
                    println!("  {}  {}", green("ok  "), c.name);
                }
                Err(why) => {
                    failed += 1;
                    println!("  {}  {}\n        {}", red("FAIL"), c.name, why);
                }
            }
        }
    }
    let line = format!("{passed} passed, {failed} failed");
    println!("{}", if failed == 0 { green(&line) } else { red(&line) });
    Ok(failed == 0)
}

pub struct EvalArgs<'a> {
    pub policy: &'a Path,
    pub agent: &'a str,
    pub tool: &'a str,
    pub args: Value,
    pub labels: Vec<String>,
    pub calls: u64,
    pub now: Option<String>,
    pub json: bool,
}

pub fn eval(e: EvalArgs) -> anyhow::Result<bool> {
    let p = load(e.policy)?;
    let now = match &e.now {
        Some(t) => clock::parse_rfc3339(t).with_context(|| format!("`{t}` is not an RFC 3339 UTC time"))?,
        None => clock::now_ms(),
    };
    let s = Session { labels: e.labels.into_iter().collect(), calls: e.calls, ..Session::default() };
    let d = engine::decide(
        &p,
        &Request { agent: e.agent, tool: e.tool, args: &e.args },
        &s,
        &RateState::default(),
        now,
        true,
    );
    if e.json {
        println!("{}", serde_json::to_string_pretty(&d)?);
        return Ok(d.verdict != Verdict::Deny);
    }
    println!("{}  {}  {}", bold(&verdict(verdict_str(d.verdict))), dim(&code_str(&d)), d.reason);
    if !d.args.is_null() {
        println!("{}  {}", dim("args"), serde_json::to_string(&d.args)?);
    }
    if !d.labels.is_empty() {
        println!("{}  adds labels {}", dim("then"), d.labels.iter().cloned().collect::<Vec<_>>().join(", "));
    }
    if !d.trace.is_empty() {
        let w = d.trace.iter().map(|t| t.rule.len()).max().unwrap_or(0);
        println!("{}", dim("rules"));
        for t in &d.trace {
            let state = if t.matched { bold("match") } else { dim("skip ") };
            println!("  {}  {}  {state}  {}", pad(&t.rule, w), pad(t.effect, 7), dim(&t.note));
        }
    }
    Ok(d.verdict != Verdict::Deny)
}

pub fn bench(policy: &Path, agent: &str, tool: &str, args: Value, n: usize) -> anyhow::Result<()> {
    let p = load(policy)?;
    let s = Session::default();
    let rates = RateState::default();
    let now = clock::now_ms();
    let first = engine::decide(&p, &Request { agent, tool, args: &args }, &s, &rates, now, false);
    let mut times = Vec::with_capacity(n);
    let started = Instant::now();
    for _ in 0..n {
        let t = Instant::now();
        let d = engine::decide(&p, &Request { agent, tool, args: &args }, &s, &rates, now, false);
        times.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(d);
    }
    let total = started.elapsed();
    times.sort_unstable();
    let q = |f: f64| times[((n as f64 * f) as usize).min(n - 1)];
    let us = |ns: u64| format!("{:.1} µs", ns as f64 / 1000.0);
    println!(
        "{n} decisions of `{tool}` for `{agent}` ({}) in {:.0} ms",
        verdict(verdict_str(first.verdict)),
        total.as_secs_f64() * 1000.0
    );
    println!(
        "  {:.0}k/s on one core   p50 {}   p99 {}   p99.9 {}   max {}",
        n as f64 / total.as_secs_f64() / 1000.0,
        us(q(0.5)),
        us(q(0.99)),
        us(q(0.999)),
        us(times[n - 1])
    );
    println!("{}", dim("engine only: no socket, audit write or tool run"));
    Ok(())
}

pub fn token() -> anyhow::Result<()> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let t = format!("wyt_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b));
    let h = hex::encode(Sha256::digest(t.as_bytes()));
    println!("{}  {t}", dim("token "));
    println!("{}  token_sha256: {h}", dim("policy"));
    println!("{}", dim("Give the token to the agent (for example as WYATT_TOKEN). Only the hash goes in the policy."));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "
version: 1
agents: { ops: { uid: 1000 } }
tools:
  read: { driver: fs.read, root: /srv }
  post: { driver: http, method: post, hosts: [api.example.com] }
rules:
  - { id: read, allow: read, agents: ops }
  - { id: post, allow: post, agents: ops }
  - { id: no-exfil, deny: post, when: { session.labels: { contains: secret } } }
  - { id: night, deny: read, when: { time.hour: { lt: 6 } } }
";

    fn case(yaml: &str) -> Case {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    #[test]
    fn before_steps_and_outputs_carry_labels() {
        let p = Policy::from_yaml(POLICY).unwrap();
        let c = case(
            "{ name: x, agent: ops, tool: post, args: { url: 'https://api.example.com/' }, expect: deny, rule: no-exfil,
               now: '2026-11-23T12:00:00Z',
               before: [{ tool: read, args: { path: /srv/.env }, output: { content: 'AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz0123456789ABCD' } }] }",
        );
        run_case(&p, &c).unwrap();
        let c = case("{ name: y, agent: ops, tool: post, args: { url: 'https://api.example.com/' }, expect: allow }");
        run_case(&p, &c).unwrap();
    }

    #[test]
    fn time_and_mismatch_reporting() {
        let p = Policy::from_yaml(POLICY).unwrap();
        let c = case(
            "{ name: n, agent: ops, tool: read, args: { path: /srv/a }, now: '2026-11-23T03:00:00Z', expect: allow }",
        );
        let err = run_case(&p, &c).unwrap_err();
        assert!(err.starts_with("expected allow, got deny"), "{err}");
    }
}
