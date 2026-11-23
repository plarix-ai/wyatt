//! Operator commands that talk to a running daemon over the control socket.

use std::path::Path;

use serde_json::{Value, json};

use crate::client;
use crate::term::{self, bold, dim, pad, red, yellow};

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

pub fn status(control: &Path, as_json: bool) -> anyhow::Result<()> {
    let v = client::request(control, json!({ "op": "status" }))?;
    if as_json {
        print_json(&v);
        return Ok(());
    }
    let p = &v["policy"];
    let mode = if s(&p["mode"]) == "monitor" { yellow("monitor (nothing is blocked)") } else { "enforcing".into() };
    println!(
        "{} {}  {}",
        bold("wyatt"),
        s(&v["version"]),
        dim(&format!("up {}", term::ago(v["uptime_s"].as_u64().unwrap_or(0))))
    );
    println!("policy    {}  {}  {mode}", bold(s(&p["name"])), dim(&s(&p["digest"])[..12.min(s(&p["digest"]).len())]));
    println!("          {}", dim(s(&p["path"])));
    match v["frozen"].as_str() {
        Some(why) => println!("state     {}", red(&format!("FROZEN: {why}"))),
        None => println!("state     running"),
    }
    let d = &v["decisions"];
    println!("decisions {} allowed, {} denied, {} sent for approval", d["allow"], d["deny"], d["approve"]);
    println!(
        "now       {} sessions, {} waiting for approval, {} tools running",
        v["sessions"], v["pending"], v["running"]
    );
    println!("audit     {}", s(&v["audit"]));
    let abi = v["landlock_abi"].as_i64().unwrap_or(0);
    println!("landlock  {}", if abi > 0 { format!("ABI {abi}") } else { red("not available") });
    Ok(())
}

pub fn sessions(control: &Path, as_json: bool) -> anyhow::Result<()> {
    let v = client::request(control, json!({ "op": "sessions" }))?;
    if as_json {
        print_json(&v);
        return Ok(());
    }
    let list = v["sessions"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no sessions");
        return Ok(());
    }
    println!(
        "{}",
        dim(&format!(
            "{} {} {} {} {}",
            pad("SESSION", 22),
            pad("AGENT", 12),
            pad("CALLS", 6),
            pad("IDLE", 7),
            "LABELS"
        ))
    );
    for x in list {
        let labels: Vec<&str> = x["labels"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        let labels =
            labels.iter().map(|l| if *l == "secret" { red(l) } else { l.to_string() }).collect::<Vec<_>>().join(" ");
        println!(
            "{} {} {} {} {}",
            pad(s(&x["session"]), 22),
            pad(s(&x["agent"]), 12),
            pad(&x["calls"].to_string(), 6),
            pad(&term::ago(x["idle_s"].as_u64().unwrap_or(0)), 7),
            labels
        );
    }
    Ok(())
}

pub fn approvals(control: &Path, as_json: bool) -> anyhow::Result<()> {
    let v = client::request(control, json!({ "op": "approvals" }))?;
    if as_json {
        print_json(&v);
        return Ok(());
    }
    let list = v["approvals"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("nothing is waiting for approval");
        return Ok(());
    }
    for x in list {
        let args = serde_json::to_string(&x["args"]).unwrap_or_default();
        println!(
            "{}  {} wants {}  {}",
            bold(&format!("#{}", x["id"])),
            s(&x["agent"]),
            bold(s(&x["tool"])),
            dim(&format!("{} ago, rule {}", term::ago(x["age_s"].as_u64().unwrap_or(0)), s(&x["rule"])))
        );
        println!("    {args}");
        let who: Vec<&str> = x["approvers"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if !who.is_empty() {
            println!("    {}", dim(&format!("approvers: {}", who.join(", "))));
        }
    }
    println!("{}", dim("answer with `wyatt approve <id>` or `wyatt deny <id> --reason ...`"));
    Ok(())
}

pub fn answer(control: &Path, id: u64, approve: bool, reason: Option<String>) -> anyhow::Result<()> {
    let req = if approve {
        json!({ "op": "approve", "id": id })
    } else {
        json!({ "op": "deny", "id": id, "reason": reason })
    };
    client::request(control, req)?;
    println!("{} #{id}", if approve { term::green("approved") } else { red("denied") });
    Ok(())
}

pub fn freeze(control: &Path, reason: Option<String>) -> anyhow::Result<()> {
    client::request(control, json!({ "op": "freeze", "reason": reason }))?;
    println!("{}: every call is denied and running tools were killed. `wyatt unfreeze` to resume.", red("frozen"));
    Ok(())
}

pub fn unfreeze(control: &Path) -> anyhow::Result<()> {
    client::request(control, json!({ "op": "unfreeze" }))?;
    println!("running");
    Ok(())
}

pub fn reload(control: &Path) -> anyhow::Result<()> {
    let v = client::request(control, json!({ "op": "reload" }))?;
    if v["reloaded"].as_bool() == Some(true) {
        println!("reloaded: {} -> {}", &s(&v["from"])[..12], &s(&v["to"])[..12]);
    } else {
        println!("policy unchanged ({})", &s(&v["to"])[..12]);
    }
    Ok(())
}
