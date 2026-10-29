//! Kernel-feature probes used by the CLI and tests.
//!
//! The key question for this project: does Landlock already cover io_uring
//! `OPENAT`? If it does, filesystem policy needs no io_uring-specific work and
//! the remaining gaps are non-file ops (connect/socket/uring_cmd) and the
//! opcode allowlist. We measure it rather than assume it.

use crate::landlock::{
    abi_version, Ruleset, LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE,
};
use crate::uring::Ring;
use std::ffi::CString;
use std::io::{self, Write};

/// Whether `bpf` is in the active LSM list (required for the BPF-LSM backstop).
pub fn bpf_in_lsm() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|l| l.trim() == "bpf"))
        .unwrap_or(false)
}

pub fn lsm_list() -> String {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}

pub fn io_uring_disabled() -> String {
    std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}

/// `true` outcome = the open was denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LandlockUringResult {
    pub abi: i32,
    pub syscall_denied: bool,
    pub uring_denied: bool,
}

impl LandlockUringResult {
    /// Landlock covers io_uring openat iff both paths are denied the same way.
    pub fn covers_uring(&self) -> bool {
        self.syscall_denied && self.uring_denied
    }
}

/// Child body: Landlock-deny a directory, then try to open a file in it both
/// ways. Prints `syscall=<0|1> uring=<0|1>` (1 = denied).
fn landlock_child(denied_dir: &str) -> io::Result<()> {
    let abi = abi_version()?;
    // Allow only a sibling temp root for reads; the denied_dir is not added, so
    // opening under it must fail once restrict_self is called.
    let rs = Ruleset::create(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)?;
    // Grant read on /usr so the process can still function, but not denied_dir.
    rs.allow_path(
        "/usr",
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
    )?;
    rs.restrict_self()?;

    let target = format!("{denied_dir}/secret.txt");
    let cpath = CString::new(target.as_str()).unwrap();

    let sfd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            cpath.as_ptr(),
            libc::O_RDONLY,
        )
    };
    let syscall_denied = sfd < 0;
    if sfd >= 0 {
        unsafe { libc::close(sfd as i32) };
    }

    let mut ring = Ring::setup(8)?;
    let ures = ring.openat(libc::AT_FDCWD, &cpath, libc::O_RDONLY)?;
    let uring_denied = ures < 0;
    if ures >= 0 {
        unsafe { libc::close(ures) };
    }

    println!(
        "abi={} syscall={} uring={}",
        abi, syscall_denied as u8, uring_denied as u8
    );
    io::stdout().flush()?;
    Ok(())
}

/// Public entry for the hidden `--child-landlock <dir>` CLI mode.
pub fn run_landlock_child(denied_dir: &str) -> io::Result<()> {
    landlock_child(denied_dir)
}

/// Resolve this binary for re-exec of the hidden `child-landlock` mode.
fn self_exe() -> io::Result<std::path::PathBuf> {
    if let Ok(p) = std::env::var("URING_GATE_BIN") {
        return Ok(p.into());
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_uring-gate") {
        return Ok(p.into());
    }
    std::env::current_exe()
}

/// Measure Landlock coverage of io_uring openat by re-exec of this binary as
/// the sandboxed child (Landlock is irreversible per process).
pub fn landlock_covers_uring_openat() -> io::Result<LandlockUringResult> {
    let dir = std::env::temp_dir().join(format!("uring-gate-ll-{}", std::process::id()));
    let denied = dir.join("denied");
    std::fs::create_dir_all(&denied)?;
    std::fs::write(denied.join("secret.txt"), b"top secret")?;

    let exe = self_exe()?;
    let out = std::process::Command::new(&exe)
        .args(["child-landlock", denied.to_str().unwrap()])
        .output()?;
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "child-landlock failed: {:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut abi = 0;
    let mut sc = false;
    let mut ur = false;
    for tok in text.split_whitespace() {
        if let Some(v) = tok.strip_prefix("abi=") {
            abi = v.parse().unwrap_or(0);
        }
        if let Some(v) = tok.strip_prefix("syscall=") {
            sc = v == "1";
        }
        if let Some(v) = tok.strip_prefix("uring=") {
            ur = v == "1";
        }
    }
    Ok(LandlockUringResult {
        abi,
        syscall_denied: sc,
        uring_denied: ur,
    })
}
