//! Wire protocol: one JSON object per line over a Unix socket.
//!
//! Agent socket:
//!   {"op":"hello","agent":"ops","token":"...","session":"task-42"}
//!   {"op":"call","id":1,"tool":"read_logs","args":{"path":"/var/log/app.log"}}
//!   {"op":"check","id":2,"tool":"Bash","args":{...},"ticket":"toolu_01"}
//!   {"op":"result","ticket":"toolu_01","ok":true,"output":"..."}
//!
//! Control socket (owner only):
//!   {"op":"status"} {"op":"sessions"} {"op":"approvals"}
//!   {"op":"approve","id":3} {"op":"deny","id":3,"reason":"..."}
//!   {"op":"freeze","reason":"..."} {"op":"unfreeze"} {"op":"reload"}

use std::io::{self, BufRead, Write};

use serde::Deserialize;
use serde_json::Value;

/// Longest request line accepted. Arguments past this are a client bug or an attack.
pub const MAX_LINE: u64 = 1 << 20;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentReq {
    Hello {
        agent: String,
        #[serde(default)]
        token: Option<String>,
        /// Join a named session (its labels and counters) instead of a fresh one.
        #[serde(default)]
        session: Option<String>,
    },
    Call {
        #[serde(default)]
        id: Value,
        tool: String,
        #[serde(default)]
        args: Value,
    },
    Check {
        #[serde(default)]
        id: Value,
        tool: String,
        #[serde(default)]
        args: Value,
        #[serde(default)]
        ticket: Option<String>,
    },
    Result {
        #[serde(default)]
        id: Value,
        ticket: String,
        ok: bool,
        #[serde(default)]
        output: Value,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlReq {
    Status,
    Sessions,
    Approvals,
    Approve { id: u64 },
    Deny { id: u64, reason: Option<String> },
    Freeze { reason: Option<String> },
    Unfreeze,
    Reload,
}

pub enum Line {
    Eof,
    TooLong,
    Text(String),
}

pub fn read_line<R: BufRead>(r: &mut R) -> io::Result<Line> {
    let mut buf = Vec::new();
    let n = io::Read::take(&mut *r, MAX_LINE + 1).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if buf.last() != Some(&b'\n') && n as u64 > MAX_LINE {
        return Ok(Line::TooLong);
    }
    String::from_utf8(buf)
        .map(|s| Line::Text(s.trim_end_matches(['\r', '\n']).to_string()))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request is not UTF-8"))
}

pub fn write_line(w: &mut impl Write, v: &Value) -> io::Result<()> {
    let mut s = serde_json::to_string(v)?;
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()
}

pub fn protocol_error(id: &Value, msg: impl Into<String>) -> Value {
    serde_json::json!({ "id": id, "error": { "status": "protocol", "message": msg.into() } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests_and_rejects_strays() {
        let r: AgentReq = serde_json::from_str(r#"{"op":"call","id":1,"tool":"t","args":{"a":1}}"#).unwrap();
        assert!(matches!(r, AgentReq::Call { tool, .. } if tool == "t"));
        assert!(serde_json::from_str::<AgentReq>(r#"{"op":"call","tool":"t","sudo":true}"#).is_err());
        assert!(serde_json::from_str::<AgentReq>(r#"{"op":"approve","id":1}"#).is_err());
        let c: ControlReq = serde_json::from_str(r#"{"op":"deny","id":4}"#).unwrap();
        assert!(matches!(c, ControlReq::Deny { id: 4, reason: None }));
    }

    #[test]
    fn caps_line_length() {
        let long = "x".repeat(MAX_LINE as usize + 10);
        let mut r = io::BufReader::new(long.as_bytes());
        assert!(matches!(read_line(&mut r).unwrap(), Line::TooLong));
        let mut r = io::BufReader::new(&b"{\"op\":\"status\"}\n"[..]);
        assert!(matches!(read_line(&mut r).unwrap(), Line::Text(s) if s == "{\"op\":\"status\"}"));
        assert!(matches!(read_line(&mut r).unwrap(), Line::Eof));
    }
}
