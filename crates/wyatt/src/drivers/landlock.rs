//! Minimal Landlock bindings for sandboxing `proc` tools.
//!
//! The ruleset is built in the daemon before `fork`, because building it
//! needs allocation and file opens. The child then only calls
//! `prctl(PR_SET_NO_NEW_PRIVS)` and `landlock_restrict_self`, two plain
//! syscalls that are safe between `fork` and `exec`.
//!
//! What it covers depends on the kernel's Landlock ABI: file access since
//! ABI 1, TCP bind and connect since ABI 4, abstract Unix sockets and
//! signals since ABI 6. UDP is not covered by Landlock at all.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;
const RULE_NET_PORT: u32 = 2;

const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_TRUNCATE: u64 = 1 << 14;
const FS_IOCTL_DEV: u64 = 1 << 15;
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

/// Rights that apply to a regular file (the rest only make sense on directories).
const FILE_RIGHTS: u64 = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

/// What TCP the sandboxed process may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tcp {
    Deny,
    Any,
    /// Connect to these ports only; never bind.
    Connect(Vec<u16>),
}

pub fn abi() -> i32 {
    // SAFETY: the version query takes no pointers.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if v < 0 { 0 } else { v as i32 }
}

fn fs_rights(abi: i32) -> u64 {
    let mut all = (1u64 << 13) - 1; // ABI 1: execute .. make_sym
    if abi >= 2 {
        all |= 1 << 13; // refer
    }
    if abi >= 3 {
        all |= FS_TRUNCATE;
    }
    if abi >= 5 {
        all |= FS_IOCTL_DEV;
    }
    all
}

pub struct Ruleset {
    fd: OwnedFd,
    pub abi: i32,
}

/// Paths a process needs to start at all: the loader, libraries and binaries.
pub const BASE_READ: &[&str] = &[
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/localtime",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
];
pub const BASE_WRITE: &[&str] = &["/dev/null"];

impl Ruleset {
    /// `read` and `write` are (path, required) pairs. A missing required
    /// path is an error; a missing base path is skipped.
    pub fn build(read: &[(&str, bool)], write: &[(&str, bool)], tcp: &Tcp) -> io::Result<Ruleset> {
        let abi = abi();
        if abi < 1 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "Landlock is not available on this kernel"));
        }
        if abi < 4 && *tcp != Tcp::Any {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Landlock ABI {abi} cannot restrict TCP (needs 4, Linux 6.7+)"),
            ));
        }
        let handled = fs_rights(abi);
        let attr = RulesetAttr {
            handled_access_fs: handled,
            handled_access_net: if abi >= 4 && *tcp != Tcp::Any { NET_BIND_TCP | NET_CONNECT_TCP } else { 0 },
            scoped: if abi >= 6 { SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL } else { 0 },
        };
        // Older kernels reject attribute fields they do not know, so pass only
        // the prefix this ABI understands.
        let size = match abi {
            1..=3 => 8,
            4 | 5 => 16,
            _ => std::mem::size_of::<RulesetAttr>(),
        };
        // SAFETY: attr is a valid, initialised struct of at least `size` bytes.
        let fd = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, size, 0u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel returned a new fd that we now own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        let rs = Ruleset { fd, abi };
        let read_rights = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE;
        for (p, required) in read {
            rs.allow(p, read_rights, *required)?;
        }
        for (p, required) in write {
            rs.allow(p, handled, *required)?;
        }
        if let Tcp::Connect(ports) = tcp {
            for port in ports {
                let attr = NetPortAttr { allowed_access: NET_CONNECT_TCP, port: u64::from(*port) };
                // SAFETY: valid ruleset fd, rule type and a pointer to an initialised attr.
                let r = unsafe {
                    libc::syscall(
                        libc::SYS_landlock_add_rule,
                        rs.fd.as_raw_fd(),
                        RULE_NET_PORT,
                        &attr as *const NetPortAttr,
                        0u32,
                    )
                };
                if r < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(rs)
    }

    fn allow(&self, path: &str, rights: u64, required: bool) -> io::Result<()> {
        let file = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_CLOEXEC).open(path)
        {
            Ok(f) => f,
            Err(e) if !required && e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io::Error::new(e.kind(), format!("sandbox path {path}: {e}"))),
        };
        let is_dir = file.metadata().map(|m| m.is_dir()).unwrap_or(false);
        let attr = PathBeneathAttr {
            allowed_access: if is_dir { rights } else { rights & FILE_RIGHTS & fs_rights(self.abi) },
            parent_fd: file.as_raw_fd(),
        };
        // SAFETY: valid ruleset fd, rule type and a pointer to an initialised attr.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            )
        };
        if r < 0 {
            return Err(io::Error::new(io::Error::last_os_error().kind(), format!("sandbox rule for {path} failed")));
        }
        Ok(())
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Called in the child between fork and exec. Only async-signal-safe calls.
///
/// # Safety
/// `fd` must be a Landlock ruleset fd that is open in this process.
pub unsafe fn restrict_self(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain syscalls with integer arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
