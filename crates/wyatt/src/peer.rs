//! Who is on the other end of a Unix socket, according to the kernel.
//!
//! `SO_PEERCRED` gives the pid, uid and gid captured at `connect()`. The
//! executable comes from `/proc/<pid>/exe`, which is racy on its own: the
//! peer could exit and its pid be reused before we read the link. On Linux
//! 6.5+ we also take `SO_PEERPIDFD`, a handle that always refers to the
//! original process, and check it is still alive after reading the link. If
//! it is not, the executable is reported as unknown, and an agent bound to an
//! `exe` pattern is refused.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use wyatt_core::policy::Peer;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
const SO_PEERPIDFD: Option<libc::c_int> = Some(77);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
const SO_PEERPIDFD: Option<libc::c_int> = None;
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;

fn getsockopt<T>(s: &UnixStream, opt: libc::c_int, out: &mut T) -> io::Result<()> {
    let mut len = std::mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `out` points to a T of `len` bytes; the kernel writes at most that.
    let r = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, opt, (out as *mut T).cast(), &mut len) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pidfd(s: &UnixStream) -> Option<OwnedFd> {
    let mut fd: libc::c_int = -1;
    getsockopt(s, SO_PEERPIDFD?, &mut fd).ok()?;
    // SAFETY: on success the kernel handed us a new pidfd.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn alive(pidfd: &OwnedFd) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    let r = unsafe {
        libc::syscall(SYS_PIDFD_SEND_SIGNAL, pidfd.as_raw_fd(), 0, std::ptr::null::<libc::siginfo_t>(), 0u32)
    };
    r == 0
}

pub fn identify(s: &UnixStream) -> io::Result<Peer> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    getsockopt(s, libc::SO_PEERCRED, &mut cred)?;
    let handle = pidfd(s);
    let mut exe = std::fs::read_link(format!("/proc/{}/exe", cred.pid)).ok().map(|p| p.to_string_lossy().into_owned());
    if let Some(h) = &handle
        && !alive(h)
    {
        exe = None;
    }
    Ok(Peer { pid: cred.pid, uid: cred.uid, gid: cred.gid, exe })
}

pub fn group_id(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 16384];
    // SAFETY: zeroed group is a valid out-parameter for getgrnam_r.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the given sizes.
    let r = unsafe { libc::getgrnam_r(name.as_ptr(), &mut gr, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
    (r == 0 && !out.is_null()).then_some(gr.gr_gid)
}

pub fn username(uid: u32) -> String {
    let mut buf = vec![0u8; 4096];
    // SAFETY: zeroed passwd is a valid out-parameter for getpwuid_r.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the given sizes.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return format!("uid:{uid}");
    }
    // SAFETY: on success pw_name points into `buf` and is NUL-terminated.
    unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let p = identify(&a).unwrap();
        assert_eq!(p.pid as u32, std::process::id());
        // SAFETY: getuid has no preconditions.
        assert_eq!(p.uid, unsafe { libc::getuid() });
        assert_eq!(p.exe.as_deref(), std::env::current_exe().ok().as_deref().and_then(|p| p.to_str()));
        assert!(!username(p.uid).is_empty());
    }
}
