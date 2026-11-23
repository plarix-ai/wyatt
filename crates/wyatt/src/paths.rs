//! Default locations. Each can be overridden by a flag or an environment variable.
//!
//! As root: /run/wyatt for sockets and /var/lib/wyatt for state. As a user:
//! $XDG_RUNTIME_DIR/wyatt (or /tmp/wyatt-<uid>) and $XDG_STATE_HOME/wyatt.
//! A per-user runtime directory is private to that user, so agents running
//! as other users need a socket in a shared place such as /run/wyatt.

use std::env;
use std::path::PathBuf;

fn root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

fn from_env(name: &str) -> Option<PathBuf> {
    env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

pub fn runtime_dir() -> PathBuf {
    if root() {
        return PathBuf::from("/run/wyatt");
    }
    match from_env("XDG_RUNTIME_DIR") {
        Some(d) => d.join("wyatt"),
        // SAFETY: getuid has no preconditions.
        None => PathBuf::from(format!("/tmp/wyatt-{}", unsafe { libc::getuid() })),
    }
}

pub fn agent_socket() -> PathBuf {
    from_env("WYATT_SOCKET").unwrap_or_else(|| runtime_dir().join("agent.sock"))
}

pub fn control_socket() -> PathBuf {
    from_env("WYATT_CONTROL").unwrap_or_else(|| runtime_dir().join("control.sock"))
}

pub fn state_dir() -> PathBuf {
    if let Some(d) = from_env("WYATT_STATE") {
        return d;
    }
    if root() {
        return PathBuf::from("/var/lib/wyatt");
    }
    from_env("XDG_STATE_HOME")
        .or_else(|| from_env("HOME").map(|h| h.join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("wyatt")
}

pub fn policy() -> PathBuf {
    from_env("WYATT_POLICY").unwrap_or_else(|| PathBuf::from("wyatt.yaml"))
}
