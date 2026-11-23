//! Tool drivers. Each one runs a tool inside the daemon with the normalised
//! arguments from the decision, never the raw request.

pub mod fs;
pub mod landlock;
pub mod proc;

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde_json::Value;
use wyatt_core::policy::{Driver, Tool};

#[derive(Debug)]
pub enum Failure {
    /// The driver would not run the tool: no sandbox, a symlink escape, a private address.
    Refused(String),
    Timeout(Duration),
    Failed(String),
}

impl Failure {
    pub fn status(&self) -> &'static str {
        match self {
            Failure::Refused(_) => "refused",
            Failure::Timeout(_) => "timeout",
            Failure::Failed(_) => "error",
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Refused(m) | Failure::Failed(m) => f.write_str(m),
            Failure::Timeout(d) => write!(f, "killed after the {:?} timeout", d),
        }
    }
}

/// Values filled in from the daemon's own environment. The agent never sees them.
#[derive(Debug, Clone, Default)]
pub struct Secrets {
    pub env: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}

fn expand(s: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("${env:") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 6..];
        let j = after.find('}').ok_or_else(|| format!("unclosed ${{env:...}} in `{s}`"))?;
        let name = &after[..j];
        out.push_str(&std::env::var(name).map_err(|_| format!("environment variable {name} is not set"))?);
        rest = &after[j + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub fn resolve(t: &Tool) -> Result<Secrets, String> {
    let map = |m: &BTreeMap<String, String>| -> Result<BTreeMap<String, String>, String> {
        m.iter().map(|(k, v)| Ok((k.clone(), expand(v).map_err(|e| format!("tools.{}: {e}", t.name))?))).collect()
    };
    Ok(Secrets { env: map(&t.env)?, headers: map(&t.headers)? })
}

pub fn run(tool: &Tool, args: &Value, secrets: &Secrets, spawned: &dyn Fn(i32)) -> Result<Value, Failure> {
    match tool.driver {
        Driver::FsRead => fs::read(tool, args),
        Driver::FsList => fs::list(tool, args),
        Driver::FsWrite => fs::write(tool, args),
        Driver::Proc => proc::run(tool, args, secrets, spawned),
        Driver::Http => Err(Failure::Refused("the http driver is not built yet".into())),
        Driver::Delegate | Driver::Mcp => {
            Err(Failure::Refused(format!("`{}` runs outside the daemon; use check and result", tool.name)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_env() {
        // SAFETY: test-only, single-threaded use of a variable no other test reads.
        unsafe { std::env::set_var("WYATT_TEST_TOKEN", "t0k") };
        assert_eq!(expand("Bearer ${env:WYATT_TEST_TOKEN}!").unwrap(), "Bearer t0k!");
        assert!(expand("${env:WYATT_SURELY_UNSET_VAR}").is_err());
        assert!(expand("${env:OPEN").is_err());
    }
}
