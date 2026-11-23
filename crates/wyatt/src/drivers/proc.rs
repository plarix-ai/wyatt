//! Process driver. Runs a fixed binary with an argument list, never a shell.
//!
//! The child starts with an empty environment (plus the tool's `env`), in its
//! own session and process group, with resource limits and, unless the policy
//! turns it off, a Landlock sandbox. On timeout the whole process group is
//! killed. Output is capped; the rest is read and thrown away so the child
//! cannot stall on a full pipe.

use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use wyatt_core::policy::Tool;

use super::landlock::{self, Ruleset, Tcp};
use super::{Failure, Secrets};

const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const MAX_FILES: u64 = 1024;
/// How long to wait for pipes to close after the process group was killed.
const DRAIN_GRACE: Duration = Duration::from_millis(500);

/// Everything the child does between fork and exec. Plain integers only.
#[derive(Clone, Copy, Default)]
pub struct ChildSetup {
    pub memory: Option<u64>,
    pub cpu_secs: Option<u64>,
    pub landlock: Option<RawFd>,
    /// Make this fd the child's fd 3.
    pub fd3: Option<RawFd>,
}

fn rlimit(res: libc::__rlimit_resource_t, n: u64) -> io::Result<()> {
    let lim = libc::rlimit { rlim_cur: n, rlim_max: n };
    // SAFETY: setrlimit with a valid pointer; async-signal-safe.
    if unsafe { libc::setrlimit(res, &lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl ChildSetup {
    pub fn apply(self, cmd: &mut Command) {
        // SAFETY: the closure only makes async-signal-safe syscalls and does not allocate.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                rlimit(libc::RLIMIT_CORE, 0)?;
                rlimit(libc::RLIMIT_NOFILE, MAX_FILES)?;
                if let Some(m) = self.memory {
                    rlimit(libc::RLIMIT_AS, m)?;
                }
                if let Some(c) = self.cpu_secs {
                    rlimit(libc::RLIMIT_CPU, c)?;
                }
                if let Some(fd) = self.fd3 {
                    if fd == 3 {
                        if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                    } else if libc::dup2(fd, 3) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if let Some(fd) = self.landlock {
                    landlock::restrict_self(fd)?;
                }
                Ok(())
            });
        }
    }
}

#[derive(Default)]
struct Capture {
    data: Vec<u8>,
    total: u64,
}

fn reader(mut src: impl Read + Send + 'static, cap: usize) -> (Arc<Mutex<Capture>>, std::thread::JoinHandle<()>) {
    let out = Arc::new(Mutex::new(Capture::default()));
    let sink = Arc::clone(&out);
    let h = std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match src.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut c = sink.lock().unwrap_or_else(|e| e.into_inner());
                    let room = cap.saturating_sub(c.data.len());
                    c.data.extend_from_slice(&buf[..n.min(room)]);
                    c.total += n as u64;
                }
            }
        }
    });
    (out, h)
}

fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    // SAFETY: pidfd_open takes a pid and flags; the result is checked.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0u32) } as RawFd;
    loop {
        if let Some(st) = child.try_wait()? {
            if pidfd >= 0 {
                // SAFETY: closing the fd we opened above.
                unsafe { libc::close(pidfd) };
            }
            return Ok(Some(st));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            if pidfd >= 0 {
                // SAFETY: as above.
                unsafe { libc::close(pidfd) };
            }
            return Ok(None);
        }
        if pidfd >= 0 {
            let mut p = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
            let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
            // SAFETY: one valid pollfd; EINTR just loops.
            unsafe { libc::poll(&mut p, 1, ms) };
        } else {
            std::thread::sleep(left.min(Duration::from_millis(5)));
        }
    }
}

pub struct Output {
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stdout_total: u64,
    pub stderr: Vec<u8>,
    pub stderr_total: u64,
    pub elapsed: Duration,
}

/// Spawns `cmd`, feeds `stdin`, captures capped output and kills the process
/// group at the deadline. `status` is `None` when the timeout fired.
pub fn spawn_capture(
    mut cmd: Command,
    stdin: Option<Vec<u8>>,
    cap: usize,
    timeout: Duration,
    spawned: &dyn Fn(i32),
) -> Result<Output, Failure> {
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| Failure::Failed(format!("could not start the process: {e}")))?;
    let pid = child.id() as i32;
    spawned(pid);
    let (out, out_h) = reader(child.stdout.take().expect("piped"), cap);
    let (err, err_h) = reader(child.stderr.take().expect("piped"), cap);
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        });
    }
    let status = wait_until(&mut child, started + timeout).map_err(|e| Failure::Failed(e.to_string()))?;
    // Kill whatever is left in the group: the child on timeout, and any
    // background processes it started either way.
    // SAFETY: signalling our own child's process group.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    let status = match status {
        Some(s) => Some(s),
        None => {
            let _ = child.wait();
            None
        }
    };
    let grace = Instant::now() + DRAIN_GRACE;
    for h in [out_h, err_h] {
        while !h.is_finished() && Instant::now() < grace {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let take = |c: &Arc<Mutex<Capture>>| {
        let mut c = c.lock().unwrap_or_else(|e| e.into_inner());
        (std::mem::take(&mut c.data), c.total)
    };
    let (stdout, stdout_total) = take(&out);
    let (stderr, stderr_total) = take(&err);
    Ok(Output { status, stdout, stdout_total, stderr, stderr_total, elapsed: started.elapsed() })
}

pub fn sandbox_for(t: &Tool) -> Result<Option<Ruleset>, Failure> {
    let sb = &t.sandbox;
    if !sb.enabled {
        return Ok(None);
    }
    let mut read: Vec<(&str, bool)> = landlock::BASE_READ.iter().map(|p| (*p, false)).collect();
    read.extend(sb.read.iter().map(|p| (p.as_str(), true)));
    read.push((t.command[0].as_str(), true));
    if let Some(cwd) = &t.cwd {
        read.push((cwd.as_str(), true));
    }
    let mut write: Vec<(&str, bool)> = landlock::BASE_WRITE.iter().map(|p| (*p, false)).collect();
    write.extend(sb.write.iter().map(|p| (p.as_str(), true)));
    let tcp = if sb.net { Tcp::Any } else { Tcp::Deny };
    Ruleset::build(&read, &write, &tcp).map(Some).map_err(|e| {
        Failure::Refused(format!("cannot sandbox `{}`: {e}. Set sandbox.enabled: false to run it without one", t.name))
    })
}

pub fn run(t: &Tool, args: &Value, secrets: &Secrets, spawned: &dyn Fn(i32)) -> Result<Value, Failure> {
    let ruleset = sandbox_for(t)?;
    let mut cmd = Command::new(&t.command[0]);
    cmd.args(&t.command[1..]);
    if let Some(extra) = args.get("args").and_then(Value::as_array) {
        cmd.args(extra.iter().map(|v| v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string())));
    }
    cmd.env_clear().env("PATH", DEFAULT_PATH).env("LANG", "C.UTF-8").envs(&secrets.env);
    cmd.current_dir(t.cwd.as_deref().unwrap_or("/"));
    ChildSetup {
        memory: t.sandbox.memory.map(|m| m as u64),
        cpu_secs: t.sandbox.cpu.map(|d| d.as_secs().max(1)),
        landlock: ruleset.as_ref().map(Ruleset::raw_fd),
        fd3: None,
    }
    .apply(&mut cmd);
    let out = spawn_capture(cmd, None, t.max_output, t.timeout, spawned)?;
    drop(ruleset);
    let Some(status) = out.status else {
        return Err(Failure::Timeout(t.timeout));
    };
    Ok(json!({
        "exit_code": status.code(),
        "signal": status.signal(),
        "stdout": String::from_utf8_lossy(&out.stdout),
        "stderr": String::from_utf8_lossy(&out.stderr),
        "truncated": out.stdout_total > out.stdout.len() as u64 || out.stderr_total > out.stderr.len() as u64,
        "elapsed_ms": out.elapsed.as_millis() as u64,
        "sandboxed": t.sandbox.enabled,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyatt_core::Policy;

    fn tool(yaml: &str) -> Tool {
        Policy::from_yaml(&format!("version: 1\ntools:\n  t: {yaml}\n")).unwrap().tools["t"].clone()
    }

    fn go(t: &Tool, args: Value) -> Result<Value, Failure> {
        run(t, &args, &Secrets::default(), &|_| {})
    }

    #[test]
    fn runs_without_a_shell_and_with_a_clean_env() {
        let t = tool("{ driver: proc, command: [/usr/bin/env], sandbox: { enabled: false } }");
        let out = go(&t, json!({})).unwrap();
        let mut env: Vec<&str> = out["stdout"].as_str().unwrap().lines().collect();
        env.sort_unstable();
        assert_eq!(env, ["LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin"]);
        let t = tool("{ driver: proc, command: [/usr/bin/echo], sandbox: { enabled: false } }");
        let out = go(&t, json!({"args": ["$(id)", "; rm -rf /"]})).unwrap();
        assert_eq!(out["stdout"], "$(id) ; rm -rf /\n");
    }

    #[test]
    fn kills_the_whole_group_on_timeout() {
        let t = tool(
            "{ driver: proc, command: [/usr/bin/sh, -c, 'sleep 30 & sleep 30'], timeout: 200ms, sandbox: { enabled: false } }",
        );
        let started = Instant::now();
        assert!(matches!(go(&t, json!({})), Err(Failure::Timeout(_))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn caps_output() {
        let t = tool(
            "{ driver: proc, command: [/usr/bin/head, -c, '100000', /dev/zero], max_output: 1KiB, sandbox: { enabled: false } }",
        );
        let out = go(&t, json!({})).unwrap();
        assert_eq!((out["stdout"].as_str().unwrap().len(), out["truncated"].as_bool()), (1024, Some(true)));
    }

    #[test]
    fn landlock_blocks_reads_outside_the_allowlist() {
        if landlock::abi() < 4 {
            eprintln!("skipped: Landlock ABI {} on this kernel", landlock::abi());
            return;
        }
        let home = std::env::var("HOME").unwrap();
        let t = tool("{ driver: proc, command: [/usr/bin/ls] }");
        let out = go(&t, json!({"args": [home]})).unwrap();
        assert_ne!(out["exit_code"], 0, "{out}");
        assert!(out["stderr"].as_str().unwrap().contains("Permission denied"), "{out}");
        let out = go(&t, json!({"args": ["/usr"]})).unwrap();
        assert_eq!(out["exit_code"], 0, "{out}");
    }
}
