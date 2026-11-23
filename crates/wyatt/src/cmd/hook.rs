//! `wyatt hook claude-code`: enforce a Wyatt policy on Claude Code's tools.
//!
//! Claude Code runs this command before and after every tool call (see
//! `--print-settings`). PreToolUse asks the daemon with `check`; the answer
//! becomes allow, ask or deny, and normalised arguments are passed back as
//! `updatedInput` so Claude Code runs exactly what was checked. PostToolUse
//! reports the output with `result`; if DLP finds secrets, the redacted
//! output replaces what Claude would have seen and the session is labelled.
//!
//! The session is named after Claude Code's session_id, so labels carry
//! across calls even though each hook run is a new process.
//!
//! If the daemon cannot be reached, PreToolUse fails closed (exit 2).

use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail};
use serde_json::{Value, json};

use crate::client::Conn;

const MAX_INPUT: u64 = 16 << 20;

pub struct Opts<'a> {
    pub socket: &'a Path,
    pub agent: &'a str,
    pub token: Option<String>,
    /// Let a policy allow skip Claude Code's own permission prompt.
    pub auto_allow: bool,
}

pub fn settings() -> String {
    let hook = |timeout: u32| json!([{ "matcher": "*", "hooks": [{ "type": "command", "command": "wyatt hook claude-code", "timeout": timeout, "onFailure": "block" }] }]);
    let v = json!({ "hooks": { "PreToolUse": hook(15), "PostToolUse": hook(15) } });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

fn connect(o: &Opts, input: &Value) -> anyhow::Result<Conn> {
    let session = input["session_id"].as_str().filter(|s| !s.is_empty()).context("hook input has no session_id")?;
    let mut c = Conn::open(o.socket)?;
    c.timeout(Some(std::time::Duration::from_secs(10)))?;
    let r =
        c.send(&json!({ "op": "hello", "agent": o.agent, "token": o.token, "session": format!("cc-{session}") }))?;
    if let Some(e) = r.get("error") {
        bail!("{}", e["message"].as_str().unwrap_or("hello refused"));
    }
    Ok(c)
}

fn pre_output(decision: &str, reason: &str, updated: Option<&Value>) -> Value {
    let mut h =
        json!({ "hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason });
    if let Some(u) = updated {
        h["updatedInput"] = u.clone();
    }
    json!({ "hookSpecificOutput": h })
}

/// Turns a daemon reply to `check` into Claude Code's hook output.
/// `None` means print nothing and let Claude Code's own rules decide.
pub fn pre_decision(input: &Value, r: &Value, auto_allow: bool) -> Option<Value> {
    if let Some(e) = r.get("error") {
        let msg = e["message"].as_str().unwrap_or("request failed");
        return Some(pre_output("deny", &format!("wyatt: {msg}"), None));
    }
    let reason = r["reason"].as_str().unwrap_or_default();
    let tag = match (r["rule"].as_str(), r["audit"].as_u64()) {
        (Some(rule), Some(a)) => format!(" [rule {rule}, audit #{a}]"),
        (None, Some(a)) => format!(" [audit #{a}]"),
        _ => String::new(),
    };
    let original = &input["tool_input"];
    let changed = r.get("args").filter(|a| !a.is_null() && *a != original);
    match r["decision"].as_str() {
        Some("allow") => match (changed, auto_allow) {
            (Some(a), true) => Some(pre_output("allow", &format!("wyatt: {reason}{tag}"), Some(a))),
            (Some(a), false) => Some(pre_output(
                "ask",
                &format!("wyatt normalised the arguments; check them before running{tag}"),
                Some(a),
            )),
            (None, true) => Some(pre_output("allow", &format!("wyatt: {reason}{tag}"), None)),
            (None, false) => None,
        },
        Some("approve") => Some(pre_output("ask", &format!("wyatt: {reason}{tag}"), changed)),
        _ => Some(pre_output("deny", &format!("wyatt denied this: {reason}{tag}"), None)),
    }
}

fn pre(o: &Opts, input: &Value) -> anyhow::Result<Option<Value>> {
    let mut c = connect(o, input)?;
    let r = c.send(&json!({
        "op": "check",
        "id": 1,
        "tool": input["tool_name"],
        "args": input["tool_input"],
        "ticket": input["tool_use_id"],
        "ask": true,
    }))?;
    Ok(pre_decision(input, &r, o.auto_allow))
}

fn post(o: &Opts, input: &Value) -> anyhow::Result<Option<Value>> {
    let Some(ticket) = input["tool_use_id"].as_str() else { return Ok(None) };
    let mut c = connect(o, input)?;
    let r =
        c.send(&json!({ "op": "result", "id": 1, "ticket": ticket, "ok": true, "output": input["tool_response"] }))?;
    // An unknown ticket means PreToolUse never asked (the hook was added
    // mid-session, or the tool is not matched). Nothing to report.
    if r.get("error").is_some() {
        return Ok(None);
    }
    let Some(found) = r["redacted"].as_object().filter(|m| !m.is_empty()) else { return Ok(None) };
    let names: Vec<&str> = found.keys().map(String::as_str).collect();
    let mut note = format!("wyatt redacted secrets from this output ({}).", names.join(", "));
    if r["labels"].as_array().is_some_and(|l| l.iter().any(|x| x == "secret")) {
        note.push_str(" This session is now labelled secret, so the policy may block tools that send data out.");
    }
    Ok(Some(json!({
        "hookSpecificOutput": { "hookEventName": "PostToolUse", "updatedToolOutput": r["output"], "additionalContext": note }
    })))
}

/// Returns the process exit code: 0, or 2 to block a tool call.
pub fn claude_code(o: &Opts) -> u8 {
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().take(MAX_INPUT).read_to_string(&mut raw) {
        eprintln!("wyatt: cannot read hook input: {e}");
        return 2;
    }
    let input: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("wyatt: hook input is not JSON: {e}");
            return 2;
        }
    };
    let event = input["hook_event_name"].as_str().unwrap_or_default();
    let res = match event {
        "PreToolUse" => pre(o, &input),
        "PostToolUse" => post(o, &input),
        _ => return 0,
    };
    match res {
        Ok(Some(out)) => {
            println!("{out}");
            0
        }
        Ok(None) => 0,
        Err(e) if event == "PreToolUse" => {
            eprintln!("wyatt: blocked because the policy could not be checked: {e:#}");
            2
        }
        Err(e) => {
            eprintln!("wyatt: could not report the tool output: {e:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        json!({ "tool_name": "Read", "tool_input": { "file_path": "/work/a/../b.rs" } })
    }

    #[test]
    fn maps_daemon_verdicts() {
        let deny = json!({ "decision": "deny", "reason": "no rule allows `Read`", "audit": 7 });
        let out = pre_decision(&input(), &deny, false).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(out["hookSpecificOutput"]["permissionDecisionReason"].as_str().unwrap().ends_with("[audit #7]"));

        let same =
            json!({ "decision": "allow", "reason": "ok", "rule": "r", "audit": 8, "args": input()["tool_input"] });
        assert!(pre_decision(&input(), &same, false).is_none());
        assert_eq!(pre_decision(&input(), &same, true).unwrap()["hookSpecificOutput"]["permissionDecision"], "allow");

        let normalised =
            json!({ "decision": "allow", "reason": "ok", "audit": 9, "args": { "file_path": "/work/b.rs" } });
        let out = pre_decision(&input(), &normalised, false).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "ask");
        assert_eq!(out["hookSpecificOutput"]["updatedInput"]["file_path"], "/work/b.rs");

        let approve = json!({ "decision": "approve", "reason": "needs a human", "audit": 10 });
        assert_eq!(pre_decision(&input(), &approve, true).unwrap()["hookSpecificOutput"]["permissionDecision"], "ask");

        let err = json!({ "error": { "status": "protocol", "message": "boom" } });
        assert_eq!(pre_decision(&input(), &err, true).unwrap()["hookSpecificOutput"]["permissionDecision"], "deny");
    }
}
