//! A blocking client for the daemon's sockets, used by the CLI and the hook.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::Value;

use crate::proto::{self, Line};

pub struct Conn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Conn {
    pub fn open(path: &Path) -> anyhow::Result<Conn> {
        let s = UnixStream::connect(path)
            .with_context(|| format!("cannot reach wyatt at {} (is `wyatt serve` running?)", path.display()))?;
        Ok(Conn { reader: BufReader::new(s.try_clone()?), writer: s })
    }

    pub fn timeout(&self, t: Option<Duration>) -> anyhow::Result<()> {
        self.writer.set_read_timeout(t)?;
        Ok(())
    }

    /// Sends one request and returns the reply. A reply with an `error`
    /// object of status `protocol` is turned into an `Err`.
    pub fn send(&mut self, req: &Value) -> anyhow::Result<Value> {
        proto::write_line(&mut self.writer, req)?;
        let line = match proto::read_line(&mut self.reader)? {
            Line::Text(s) => s,
            Line::Eof => bail!("wyatt closed the connection"),
            Line::TooLong => bail!("reply from wyatt is too long"),
        };
        let v: Value = serde_json::from_str(&line).context("reply from wyatt is not JSON")?;
        Ok(v)
    }
}

/// One request on a fresh connection. Errors in the reply become `Err`.
pub fn request(path: &Path, req: Value) -> anyhow::Result<Value> {
    let v = Conn::open(path)?.send(&req)?;
    if let Some(e) = v.get("error") {
        bail!("{}", e["message"].as_str().unwrap_or("request failed"));
    }
    Ok(v)
}
