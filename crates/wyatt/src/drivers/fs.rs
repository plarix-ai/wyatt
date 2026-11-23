//! File drivers. Every open goes through `openat2` relative to the tool's
//! root directory with `RESOLVE_BENEATH`, so the kernel refuses any path that
//! leaves the root, including through a symlink swapped in after the policy
//! check. Writes also refuse symlinks entirely.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use base64::Engine;
use serde_json::{Value, json};
use wyatt_core::path;
use wyatt_core::policy::Tool;

use super::Failure;

const MAX_ENTRIES: usize = 10_000;

pub fn open_beneath(root: &str, target: &str, flags: i32, mode: u32, resolve: u64) -> Result<File, Failure> {
    let rel = path::relative_to(target, root).ok_or_else(|| Failure::Refused(format!("{target} is outside {root}")))?;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(root)
        .map_err(|e| Failure::Failed(format!("tool root {root}: {e}")))?;
    let c = CString::new(rel).map_err(|_| Failure::Refused("path contains a NUL byte".into()))?;
    // SAFETY: open_how is plain old data; all-zero is a valid starting value.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC | libc::O_NOCTTY) as u64;
    how.mode = u64::from(mode);
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | resolve;
    // SAFETY: valid dirfd, NUL-terminated path and a pointer to an initialised open_how of the given size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::EXDEV) => Failure::Refused(format!("{target} resolves outside {root} (symlink or mount point)")),
            Some(libc::ELOOP) => {
                Failure::Refused(format!("{target} goes through a symlink, which this tool does not follow"))
            }
            Some(libc::ENOSYS) => {
                Failure::Refused("the kernel has no openat2 (Linux 5.6+); refusing to open files".into())
            }
            _ => Failure::Failed(format!("{target}: {e}")),
        });
    }
    // SAFETY: the kernel returned a fresh fd that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn io_fail(e: io::Error) -> Failure {
    Failure::Failed(e.to_string())
}

fn root_and_path<'a>(t: &'a Tool, args: &'a Value) -> (&'a str, &'a str) {
    (t.root.as_deref().unwrap_or("/"), args.get("path").and_then(Value::as_str).unwrap_or_default())
}

pub fn read(t: &Tool, args: &Value) -> Result<Value, Failure> {
    let (root, target) = root_and_path(t, args);
    let f = open_beneath(root, target, libc::O_RDONLY, 0, 0)?;
    let meta = f.metadata().map_err(io_fail)?;
    if !meta.is_file() {
        return Err(Failure::Failed(format!("{target} is not a regular file")));
    }
    let mut buf = Vec::new();
    f.take(t.max_output as u64 + 1).read_to_end(&mut buf).map_err(io_fail)?;
    let truncated = buf.len() > t.max_output;
    buf.truncate(t.max_output);
    let content = match String::from_utf8(buf) {
        Ok(s) => json!({ "content": s }),
        // A cut in the middle of a multi-byte character is not binary data.
        Err(e) if truncated && e.utf8_error().error_len().is_none() => {
            let valid = e.utf8_error().valid_up_to();
            let mut bytes = e.into_bytes();
            bytes.truncate(valid);
            json!({ "content": String::from_utf8(bytes).unwrap_or_default() })
        }
        Err(e) => json!({ "content_base64": base64::engine::general_purpose::STANDARD.encode(e.as_bytes()) }),
    };
    let mut out = content;
    out["bytes"] = meta.len().into();
    out["truncated"] = truncated.into();
    Ok(out)
}

pub fn list(t: &Tool, args: &Value) -> Result<Value, Failure> {
    let (root, target) = root_and_path(t, args);
    let dir = open_beneath(root, target, libc::O_RDONLY | libc::O_DIRECTORY, 0, 0)?;
    let mut entries = Vec::new();
    let mut truncated = false;
    for e in std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd())).map_err(io_fail)? {
        if entries.len() == MAX_ENTRIES {
            truncated = true;
            break;
        }
        let e = e.map_err(io_fail)?;
        let ty = e.file_type().map_err(io_fail)?;
        let kind = if ty.is_dir() {
            "dir"
        } else if ty.is_symlink() {
            "symlink"
        } else if ty.is_file() {
            "file"
        } else {
            "other"
        };
        let mut v = json!({ "name": e.file_name().to_string_lossy(), "type": kind });
        if ty.is_file()
            && let Ok(m) = e.metadata()
        {
            v["size"] = m.len().into();
        }
        entries.push(v);
    }
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(json!({ "path": target, "entries": entries, "truncated": truncated }))
}

pub fn write(t: &Tool, args: &Value) -> Result<Value, Failure> {
    let (root, target) = root_and_path(t, args);
    let content = args.get("content").and_then(Value::as_str).unwrap_or_default();
    if content.len() > t.max_output {
        return Err(Failure::Refused(format!(
            "content is {} bytes; this tool writes at most {}",
            content.len(),
            t.max_output
        )));
    }
    let mut f =
        open_beneath(root, target, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644, libc::RESOLVE_NO_SYMLINKS)?;
    f.write_all(content.as_bytes()).map_err(io_fail)?;
    Ok(json!({ "path": target, "written": content.len() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use wyatt_core::Policy;

    fn setup(name: &str) -> (std::path::PathBuf, Policy) {
        let d = std::env::temp_dir().join(format!("wyatt-fs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("root/logs")).unwrap();
        std::fs::write(d.join("root/logs/app.log"), "started\n").unwrap();
        std::fs::write(d.join("secret.txt"), "outside").unwrap();
        let src = format!(
            "version: 1\ntools:\n  read: {{ driver: fs.read, root: {r} }}\n  ls: {{ driver: fs.list, root: {r} }}\n  write: {{ driver: fs.write, root: {r}, max_output: 16B }}\n",
            r = d.join("root").display()
        );
        (d, Policy::from_yaml(&src).unwrap())
    }

    fn at(d: &std::path::Path, rel: &str) -> Value {
        json!({ "path": d.join("root").join(rel).to_string_lossy() })
    }

    #[test]
    fn reads_lists_and_writes_inside_root() {
        let (d, p) = setup("ok");
        let out = read(&p.tools["read"], &at(&d, "logs/app.log")).unwrap();
        assert_eq!(out["content"], "started\n");
        let out = list(&p.tools["ls"], &at(&d, "logs")).unwrap();
        assert_eq!(out["entries"][0]["name"], "app.log");
        let mut args = at(&d, "logs/new.txt");
        args["content"] = "hi".into();
        write(&p.tools["write"], &args).unwrap();
        args["content"] = "x".repeat(17).into();
        assert!(matches!(write(&p.tools["write"], &args), Err(Failure::Refused(_))));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn symlinks_cannot_escape() {
        let (d, p) = setup("escape");
        // A link planted inside the root that points outside it. The lexical
        // check passes; the kernel stops the open.
        symlink(d.join("secret.txt"), d.join("root/logs/innocent.log")).unwrap();
        let err = read(&p.tools["read"], &at(&d, "logs/innocent.log")).unwrap_err();
        assert!(matches!(err, Failure::Refused(ref m) if m.contains("outside")), "{err}");
        symlink("/", d.join("root/up")).unwrap();
        assert!(list(&p.tools["ls"], &at(&d, "up")).is_err());
        // Writes refuse even in-root symlinks.
        symlink(d.join("root/logs/app.log"), d.join("root/logs/link.log")).unwrap();
        let mut args = at(&d, "logs/link.log");
        args["content"] = "x".into();
        assert!(matches!(write(&p.tools["write"], &args), Err(Failure::Refused(_))));
        std::fs::remove_dir_all(d).unwrap();
    }
}
