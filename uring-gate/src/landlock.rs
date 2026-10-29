//! Minimal Landlock helpers (create / add path_beneath / restrict_self).
//!
//! Landlock is the kernel-enforced layer that makes io_uring `OPENAT` obey the
//! same filesystem policy as a direct `openat`: the kernel calls
//! `security_file_open` on both paths, so a Landlock ruleset that denies a
//! directory is honoured whether the open came from a syscall or an SQE.

use libc::{c_int, c_void, syscall, PR_SET_NO_NEW_PRIVS};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;

const SYS_LANDLOCK_CREATE_RULESET: c_int = 444;
const SYS_LANDLOCK_ADD_RULE: c_int = 445;
const SYS_LANDLOCK_RESTRICT_SELF: c_int = 446;
const LANDLOCK_RULE_PATH_BENEATH: c_int = 1;
const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1 << 0;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Landlock ABI version supported by the running kernel (>= 1), or an error.
pub fn abi_version() -> io::Result<i32> {
    let rc = unsafe {
        syscall(
            SYS_LANDLOCK_CREATE_RULESET as _,
            std::ptr::null::<c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as i32)
    }
}

pub struct Ruleset {
    fd: OwnedFd,
}

impl Ruleset {
    pub fn create(handled_fs: u64) -> io::Result<Self> {
        let attr = RulesetAttr {
            handled_access_fs: handled_fs,
            handled_access_net: 0,
            scoped: 0,
        };
        let rc = unsafe {
            syscall(
                SYS_LANDLOCK_CREATE_RULESET as _,
                &attr as *const _ as *const c_void,
                std::mem::size_of::<RulesetAttr>(),
                0u64,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(rc as c_int) },
        })
    }

    pub fn allow_path(&self, path: &str, allowed: u64) -> io::Result<()> {
        let c = CString::new(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let pfd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if pfd < 0 {
            return Err(io::Error::last_os_error());
        }
        let rule = PathBeneathAttr {
            allowed_access: allowed,
            parent_fd: pfd,
        };
        let rc = unsafe {
            syscall(
                SYS_LANDLOCK_ADD_RULE as _,
                self.fd.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const _ as *const c_void,
                0u32,
            )
        };
        unsafe { libc::close(pfd) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn restrict_self(self) -> io::Result<()> {
        if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe { syscall(SYS_LANDLOCK_RESTRICT_SELF as _, self.fd.as_raw_fd(), 0u32) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
