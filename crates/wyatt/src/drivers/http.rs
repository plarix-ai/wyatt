//! HTTP driver, built on the system `curl` binary.
//!
//! The daemon resolves the host itself, refuses private and metadata
//! addresses (unless the tool sets `allow_private`), then pins curl to the
//! checked address with `--resolve`. A DNS server that answers differently on
//! the second lookup (rebinding) gets no second lookup. Redirects are not
//! followed, since a redirect is a new request the policy never saw.
//!
//! Header values can hold credentials, so they reach curl through a pipe on
//! fd 3, not the command line where other users could read them in /proc.

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use serde_json::{Map, Value, json};
use wyatt_core::net::{self, Url};
use wyatt_core::policy::Tool;

use super::landlock::{self, Ruleset, Tcp};
use super::proc::{ChildSetup, spawn_capture};
use super::{Failure, Secrets};

/// Room for the status line and response headers on top of `max_output`.
const HEADER_ROOM: usize = 64 * 1024;

fn curl() -> Result<&'static str, Failure> {
    static PATH: OnceLock<Option<String>> = OnceLock::new();
    PATH.get_or_init(|| {
        let dirs = std::env::var("PATH").unwrap_or_default();
        ["/usr/bin", "/bin", "/usr/local/bin"]
            .into_iter()
            .map(str::to_owned)
            .chain(dirs.split(':').map(str::to_owned))
            .map(|d| format!("{d}/curl"))
            .find(|p| std::path::Path::new(p).is_file())
    })
    .as_deref()
    .ok_or_else(|| Failure::Refused("http tools need curl, and it is not installed".into()))
}

/// Resolves the URL's host and returns the one address curl may connect to.
pub fn pick_address(u: &Url, allow_private: bool) -> Result<SocketAddr, Failure> {
    let host = u.bare_host();
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, u.port)],
        Err(_) => (host, u.port)
            .to_socket_addrs()
            .map_err(|e| Failure::Failed(format!("cannot resolve {host}: {e}")))?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(Failure::Failed(format!("{host} has no addresses")));
    }
    if !allow_private && let Some(bad) = addrs.iter().find(|a| !net::is_public(a.ip())) {
        // One private answer is enough to refuse: it is how DNS rebinding and
        // SSRF to cloud metadata start.
        return Err(Failure::Refused(format!("{host} resolves to {}, which is not a public address", bad.ip())));
    }
    Ok(addrs[0])
}

fn header_pipe(headers: &[(String, String)]) -> io::Result<OwnedFd> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two fds; both are wrapped right away.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fds from pipe2.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let mut body = String::new();
    for (k, v) in headers {
        body.push_str(&format!("{k}: {v}\n"));
    }
    // Fits in the pipe buffer (64 KiB on Linux), so this cannot block.
    if body.len() > 60 * 1024 {
        return Err(io::Error::other("headers are too large"));
    }
    std::fs::File::from(w).write_all(body.as_bytes())?;
    Ok(r)
}

fn check_header(k: &str, v: &str) -> Result<(), Failure> {
    let bad = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    if k.is_empty() || bad(k) || bad(v) || k.contains(':') {
        return Err(Failure::Refused(format!("header `{k}` contains a line break or colon")));
    }
    Ok(())
}

struct Response {
    status: u16,
    headers: Map<String, Value>,
    body: Vec<u8>,
}

/// Splits `-D -` output: skips 1xx interim responses, then reads one header block.
fn parse(raw: &[u8]) -> Result<Response, Failure> {
    let mut rest = raw;
    loop {
        let end = rest
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| Failure::Failed("malformed HTTP response".into()))?;
        let head = String::from_utf8_lossy(&rest[..end]).into_owned();
        rest = &rest[end + 4..];
        let mut lines = head.split("\r\n");
        let status: u16 = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Failure::Failed("malformed HTTP status line".into()))?;
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        let mut headers = Map::new();
        for l in lines {
            if let Some((k, v)) = l.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim().to_string();
                match headers.get_mut(&k) {
                    Some(Value::String(prev)) => {
                        prev.push_str(", ");
                        prev.push_str(&v);
                    }
                    _ => {
                        headers.insert(k, v.into());
                    }
                }
            }
        }
        return Ok(Response { status, headers, body: rest.to_vec() });
    }
}

pub fn run(t: &Tool, args: &Value, secrets: &Secrets, spawned: &dyn Fn(i32)) -> Result<Value, Failure> {
    let raw_url = args.get("url").and_then(Value::as_str).unwrap_or_default();
    let u = Url::parse(raw_url).map_err(|e| Failure::Refused(e.to_string()))?;
    if let Some(set) = &t.host_set
        && !set.is_match(u.bare_host())
    {
        return Err(Failure::Refused(format!("host {} is not in the allowlist", u.host)));
    }
    let addr = pick_address(&u, t.allow_private)?;
    let curl = curl()?;
    let headers: Vec<(String, String)> = secrets.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for (k, v) in &headers {
        check_header(k, v)?;
    }

    let mut cmd = Command::new(curl);
    // -q must come first: it stops curl reading ~/.curlrc.
    cmd.args(["-q", "--silent", "--show-error", "--include", "--http1.1", "--noproxy", "*"]);
    cmd.args(["--proto", "=http,https", "--max-redirs", "0"]);
    cmd.arg("--max-time").arg(format!("{:.3}", t.timeout.as_secs_f64()));
    cmd.arg("--max-filesize").arg(t.max_output.to_string());
    let ip = match addr.ip() {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    cmd.arg("--resolve").arg(format!("{}:{}:{ip}", u.bare_host(), u.port));
    match t.method.as_str() {
        "GET" => {}
        "HEAD" => {
            cmd.arg("--head");
        }
        m => {
            cmd.arg("--request").arg(m);
        }
    }
    let body = args.get("body").and_then(Value::as_str).map(|b| b.as_bytes().to_vec());
    if body.is_some() {
        cmd.args(["--data-binary", "@-"]);
    }
    let pipe = if headers.is_empty() {
        None
    } else {
        cmd.args(["--header", "@/dev/fd/3"]);
        Some(header_pipe(&headers).map_err(|e| Failure::Failed(e.to_string()))?)
    };
    cmd.arg("--").arg(u.to_string());
    cmd.env_clear().env("LANG", "C.UTF-8");

    // curl gets the same jail as a proc tool, with TCP limited to this port.
    let ruleset = if landlock::abi() >= 4 {
        let read: Vec<(&str, bool)> = landlock::BASE_READ.iter().map(|p| (*p, false)).collect();
        let write: Vec<(&str, bool)> = landlock::BASE_WRITE.iter().map(|p| (*p, false)).collect();
        Some(
            Ruleset::build(&read, &write, &Tcp::Connect(vec![u.port]))
                .map_err(|e| Failure::Failed(format!("sandbox for curl: {e}")))?,
        )
    } else {
        None
    };
    ChildSetup {
        memory: None,
        cpu_secs: None,
        landlock: ruleset.as_ref().map(Ruleset::raw_fd),
        fd3: pipe.as_ref().map(AsRawFd::as_raw_fd),
    }
    .apply(&mut cmd);

    let grace = t.timeout + Duration::from_secs(1);
    let out = spawn_capture(cmd, body, t.max_output + HEADER_ROOM, grace, spawned)?;
    drop((pipe, ruleset));
    let status = out.status.ok_or(Failure::Timeout(t.timeout))?;
    match status.code() {
        Some(0) => {}
        Some(28) => return Err(Failure::Timeout(t.timeout)),
        Some(63) => {
            return Err(Failure::Failed(format!("response is larger than max_output ({} bytes)", t.max_output)));
        }
        _ => {
            let msg = String::from_utf8_lossy(&out.stderr);
            let msg = msg.trim().trim_start_matches("curl: ");
            return Err(Failure::Failed(format!("request failed: {msg}")));
        }
    }
    let mut r = parse(&out.stdout)?;
    let truncated = r.body.len() > t.max_output;
    r.body.truncate(t.max_output);
    let mut res = json!({
        "status": r.status,
        "headers": r.headers,
        "truncated": truncated,
        "address": addr.ip().to_string(),
    });
    match String::from_utf8(r.body) {
        Ok(s) => res["body"] = s.into(),
        Err(e) => res["body_base64"] = base64::engine::general_purpose::STANDARD.encode(e.as_bytes()).into(),
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_private_targets() {
        for url in
            ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]:8080/", "http://localhost/"]
        {
            let u = Url::parse(url).unwrap();
            assert!(matches!(pick_address(&u, false), Err(Failure::Refused(_))), "{url}");
        }
        assert!(pick_address(&Url::parse("http://127.0.0.1/").unwrap(), true).is_ok());
    }

    #[test]
    fn parses_responses_after_interim_ones() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nX-A: 1\r\nx-a: 2\r\n\r\n{\"ok\":true}";
        let r = parse(raw).unwrap();
        assert_eq!(
            (r.status, r.headers["x-a"].as_str(), r.body.as_slice()),
            (201, Some("1, 2"), &b"{\"ok\":true}"[..])
        );
    }

    #[test]
    fn rejects_header_injection() {
        assert!(check_header("Authorization", "Bearer x\r\nX-Evil: 1").is_err());
        assert!(check_header("Authorization", "Bearer x").is_ok());
    }

    #[test]
    fn talks_to_a_local_server_through_curl() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        if curl().is_err() {
            return;
        }
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut seen = Vec::new();
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                seen.push(line.trim().to_string());
            }
            let mut body = vec![0u8; 5];
            io::Read::read_exact(&mut r, &mut body).unwrap();
            (&s).write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
            (seen, body)
        });
        let src = format!(
            "version: 1\ntools:\n  t: {{ driver: http, method: post, hosts: ['127.0.0.1'], allow_private: true, headers: {{ X-Key: s3cret }} }}\n"
        );
        let p = wyatt_core::Policy::from_yaml(&src).unwrap();
        let tool = &p.tools["t"];
        let secrets = super::super::resolve(tool).unwrap();
        let out = run(tool, &json!({"url": format!("http://127.0.0.1:{port}/x"), "body": "hello"}), &secrets, &|_| {})
            .unwrap();
        let (seen, body) = server.join().unwrap();
        assert_eq!((out["status"].as_u64(), out["body"].as_str()), (Some(200), Some("ok")));
        assert!(seen.iter().any(|h| h == "X-Key: s3cret"), "{seen:?}");
        assert_eq!(body, b"hello");
    }
}
