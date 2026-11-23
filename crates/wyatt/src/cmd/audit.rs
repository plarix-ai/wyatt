//! `wyatt audit`: verify the chain, follow the log, show one call.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::{Value, json};

use crate::audit;
use crate::term::{bold, dim, green, pad, red, verdict, yellow};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn short(h: &str) -> &str {
    &h[..12.min(h.len())]
}

pub fn verify(state: &Path, key: Option<&str>, as_json: bool) -> anyhow::Result<bool> {
    let log = state.join("audit.jsonl");
    let key_text = match key {
        Some(k) => match k.strip_prefix('@') {
            Some(f) => std::fs::read_to_string(f).with_context(|| format!("reading {f}"))?,
            None => k.to_string(),
        },
        None => std::fs::read_to_string(state.join("audit.pub"))
            .with_context(|| format!("reading {}/audit.pub (or pass --key)", state.display()))?,
    };
    let vk = audit::read_public_key(&key_text).map_err(anyhow::Error::msg)?;
    let r = audit::verify(&log, &vk).with_context(|| format!("reading {}", log.display()))?;
    let ok = r.problems.is_empty();
    if as_json {
        let head = r.head.as_ref().map(|(seq, h)| json!({ "seq": seq, "hash": h }));
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({ "ok": ok, "records": r.records, "head": head, "problems": r.problems })
            )?
        );
        return Ok(ok);
    }
    if ok {
        println!("{}  {} records, chain and signatures intact", green("ok"), r.records);
    } else {
        println!("{}  {} problems in {} records", red("TAMPERED"), r.problems.len(), r.records);
        for p in r.problems.iter().take(50) {
            println!("  {p}");
        }
        if r.problems.len() > 50 {
            println!("  {}", dim(&format!("... and {} more", r.problems.len() - 50)));
        }
    }
    if let Some((seq, hash)) = &r.head {
        println!("{}  #{seq} {hash}", dim("head"));
        println!(
            "{}",
            dim("Store the head elsewhere: the chain alone cannot show that records were cut from the end.")
        );
    }
    Ok(ok)
}

/// One record as a single line for people.
pub fn line(r: &Value) -> String {
    let ts = s(&r["ts"]).replace('T', " ");
    let ts = ts.get(..19).unwrap_or(&ts).to_string();
    let kind = s(&r["kind"]);
    let what = match kind {
        "decision" => {
            let v = s(&r["verdict"]);
            let mut out = format!("{} {} {}  {}", s(&r["agent"]), dim("->"), bold(s(&r["tool"])), verdict(v));
            if let Some(rule) = r["rule"].as_str() {
                out.push_str(&format!(" {}", dim(rule)));
            } else {
                out.push_str(&format!(" {}", dim(s(&r["code"]))));
            }
            if r["enforced"] == json!(false) {
                out.push_str(&format!(" {}", dim("(monitor: not enforced)")));
            }
            out
        }
        "outcome" => {
            let mut out = format!("#{} {}", r["call"], verdict(s(&r["status"])));
            if let Some(ms) = r["elapsed_ms"].as_u64() {
                out.push_str(&format!(" {ms} ms"));
            }
            if let Some(m) = r["redacted"].as_object().filter(|m| !m.is_empty()) {
                let names: Vec<&str> = m.keys().map(String::as_str).collect();
                out.push_str(&format!("  {} {}", red("redacted"), names.join(", ")));
            }
            if let Some(e) = r["error"].as_str() {
                out.push_str(&format!("  {}", dim(e)));
            }
            out
        }
        "approval" => format!("#{} {} {}", r["call"], verdict(s(&r["code"])), dim(&format!("by {}", s(&r["by"])))),
        "hello" if r["admitted"] == json!(true) => {
            format!(
                "{} admitted {}",
                s(&r["agent"]),
                dim(&format!("session {}, pid {}", s(&r["session"]), r["peer"]["pid"]))
            )
        }
        "hello" => format!("{} {} {}", s(&r["agent"]), red("refused"), dim(s(&r["reason"]))),
        "notice" => format!("{} {} {}", s(&r["agent"]), yellow(s(&r["event"])), s(&r["tool"])),
        "control" => format!("{} by {} {}", s(&r["op"]), s(&r["by"]), dim(s(&r["reason"]))),
        "reload" => format!("{} {} {}", short(s(&r["from"])), dim("->"), short(s(&r["to"]))),
        "start" => format!("{} {} pid {}", s(&r["name"]), dim(short(s(&r["policy"]))), r["pid"]),
        _ => String::new(),
    };
    format!("{} {} {} {}", dim(&pad(&format!("#{}", r["seq"]), 6)), dim(&ts), pad(kind, 8), what)
}

pub fn tail(state: &Path, n: usize, follow: bool, as_json: bool) -> anyhow::Result<()> {
    let log = state.join("audit.jsonl");
    let mut f = File::open(&log).with_context(|| format!("opening {}", log.display()))?;
    let lines: Vec<String> = BufReader::new(&f).lines().collect::<Result<_, _>>()?;
    let show = |l: &str| match serde_json::from_str::<Value>(l) {
        Ok(v) if !as_json => println!("{}", line(&v)),
        _ => println!("{l}"),
    };
    for l in &lines[lines.len().saturating_sub(n)..] {
        show(l);
    }
    if !follow {
        return Ok(());
    }
    let mut pos = f.seek(SeekFrom::End(0))?;
    let mut partial = String::new();
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let len = f.metadata()?.len();
        if len < pos {
            bail!("{} shrank while following it", log.display());
        }
        if len == pos {
            continue;
        }
        f.seek(SeekFrom::Start(pos))?;
        let mut r = BufReader::new(&f);
        let mut buf = String::new();
        while r.read_line(&mut buf)? > 0 {
            if buf.ends_with('\n') {
                partial.push_str(buf.trim_end());
                show(&partial);
                partial.clear();
            } else {
                partial.push_str(&buf);
            }
            buf.clear();
        }
        pos = len;
    }
}

pub fn show(state: &Path, seq: u64) -> anyhow::Result<()> {
    let log = state.join("audit.jsonl");
    let f = File::open(&log).with_context(|| format!("opening {}", log.display()))?;
    let mut found = false;
    for l in BufReader::new(f).lines() {
        let v: Value = match serde_json::from_str(&l?) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v["seq"].as_u64() == Some(seq) || v["call"].as_u64() == Some(seq) {
            found = true;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
    }
    if !found {
        bail!("no record #{seq}");
    }
    Ok(())
}
