//! The bypass suite: N known ways to get an operation past a seccomp-only
//! sandbox by issuing it as an io_uring SQE instead of a syscall.
//!
//! For every technique we re-exec this binary as a child process (so each
//! sandbox stays contained in its own process):
//!
//! - **baseline**: seccomp blocks the *syscall*, io_uring is left open. The
//!   SQE is expected to go through -> the sandbox is bypassed.
//! - **gated** (uring-gate): same seccomp, plus a ring created with
//!   `IORING_REGISTER_RESTRICTIONS` whose allowlist omits the opcode. The SQE
//!   is expected to return `-EACCES` -> the bypass is closed.
//!
//! Acceptance target: every technique bypasses the baseline and 0 bypass the
//! gate.

use crate::uring::{Ring, IORING_OP_CLOSE, IORING_OP_NOP, IORING_OP_READ};
use std::ffi::CString;
use std::io;

/// The forbidden operation a technique tries to smuggle through io_uring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Technique {
    /// Open a file the syscall layer forbids.
    Openat,
    /// Create a socket the syscall layer forbids.
    Socket,
    /// Connect a socket the syscall layer forbids.
    Connect,
}

impl Technique {
    pub fn name(self) -> &'static str {
        match self {
            Technique::Openat => "openat",
            Technique::Socket => "socket",
            Technique::Connect => "connect",
        }
    }

    pub const ALL: [Technique; 3] = [Technique::Openat, Technique::Socket, Technique::Connect];

    /// Syscalls blocked by the seccomp baseline for this technique.
    fn blocked_syscalls(self) -> Vec<libc::c_int> {
        match self {
            Technique::Openat => vec![libc::SYS_openat as _, libc::SYS_openat2 as _],
            Technique::Socket => vec![libc::SYS_socket as _],
            Technique::Connect => vec![libc::SYS_connect as _],
        }
    }

    /// Opcodes the gated ring allows (benign ops only; never this technique's).
    fn gate_allowlist(self) -> Vec<u8> {
        // A realistic agent ring: NOP, READ, CLOSE are fine; OPENAT/SOCKET/
        // CONNECT/URING_CMD are not. The suite never adds the tested opcode.
        vec![IORING_OP_NOP, IORING_OP_READ, IORING_OP_CLOSE]
    }
}

/// Outcome of one io_uring attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The op ran (resource created or the call reached past the policy).
    Escaped,
    /// The op was refused by policy (`-EACCES`/`-EPERM`).
    Blocked,
    /// The op failed for an unrelated reason.
    Error,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Escaped => "escaped",
            Outcome::Blocked => "blocked",
            Outcome::Error => "error",
        }
    }
    fn parse(s: &str) -> Outcome {
        match s {
            "escaped" => Outcome::Escaped,
            "blocked" => Outcome::Blocked,
            _ => Outcome::Error,
        }
    }
}

fn classify(res: i32) -> Outcome {
    if res >= 0 {
        return Outcome::Escaped;
    }
    match -res {
        libc::EACCES | libc::EPERM => Outcome::Blocked,
        // The op reached the fs/net layer (policy let it through) but failed
        // for a benign reason: that is still an escape past the sandbox.
        libc::ECONNREFUSED | libc::ENOENT | libc::ETIMEDOUT | libc::ENETUNREACH => Outcome::Escaped,
        _ => Outcome::Error,
    }
}

/// Run one io_uring attempt inside the current (already-sandboxed) process.
fn attempt(tech: Technique, ring: &mut Ring) -> io::Result<Outcome> {
    match tech {
        Technique::Openat => {
            let path = CString::new("/etc/hostname").unwrap();
            let res = ring.openat(libc::AT_FDCWD, &path, libc::O_RDONLY)?;
            if res >= 0 {
                // Clean up the leaked fd via the ring (CLOSE is allowlisted).
                let _ = ring.submit(crate::uring::Sqe {
                    opcode: IORING_OP_CLOSE,
                    fd: res,
                    ..Default::default()
                });
            }
            Ok(classify(res))
        }
        Technique::Socket => {
            let res = ring.socket(libc::AF_INET, libc::SOCK_STREAM, 0)?;
            if res >= 0 {
                unsafe { libc::close(res) };
            }
            Ok(classify(res))
        }
        Technique::Connect => {
            // A real socket is needed first; `socket()` is not blocked for the
            // connect technique, so make it directly.
            let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if sock < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as u16;
            addr.sin_port = 1u16.to_be(); // tcpmux: almost always refused
            addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let sa = unsafe { &*(&addr as *const libc::sockaddr_in as *const libc::sockaddr) };
            let res = ring.connect(sock, sa, std::mem::size_of::<libc::sockaddr_in>() as u32);
            unsafe { libc::close(sock) };
            Ok(classify(res?))
        }
    }
}

/// Body run in the child: sandbox, attempt, return `(direct, uring)`.
///
/// `gated` selects uring-gate (restricted ring) vs the baseline (plain ring).
pub fn child_run(tech: Technique, gated: bool) -> io::Result<(Outcome, Outcome)> {
    // Install the seccomp baseline (both modes share it: the point is that the
    // syscall is blocked and the question is only whether io_uring escapes).
    crate::seccomp::block_syscalls(&tech.blocked_syscalls())?;

    // Direct syscall attempt (should be blocked by seccomp).
    let direct = direct_attempt(tech);

    // io_uring attempt.
    let mut ring = if gated {
        Ring::setup_restricted(8, &tech.gate_allowlist())?
    } else {
        Ring::setup(8)?
    };
    let uring = attempt(tech, &mut ring)?;
    Ok((direct, uring))
}

fn direct_attempt(tech: Technique) -> Outcome {
    let res = unsafe {
        match tech {
            Technique::Openat => {
                let p = CString::new("/etc/hostname").unwrap();
                libc::syscall(libc::SYS_openat, libc::AT_FDCWD, p.as_ptr(), libc::O_RDONLY) as i32
            }
            Technique::Socket => {
                libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0) as i32
            }
            Technique::Connect => {
                let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                if s < 0 {
                    return Outcome::Error;
                }
                let mut addr: libc::sockaddr_in = std::mem::zeroed();
                addr.sin_family = libc::AF_INET as u16;
                addr.sin_port = 1u16.to_be();
                addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
                libc::syscall(
                    libc::SYS_connect,
                    s,
                    &addr as *const _,
                    std::mem::size_of::<libc::sockaddr_in>(),
                ) as i32
            }
        }
    };
    if res >= 0 {
        Outcome::Escaped
    } else {
        classify(-(io::Error::last_os_error().raw_os_error().unwrap_or(0)))
    }
}

/// Result of one technique under one mode.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub tech: Technique,
    pub gated: bool,
    pub direct: Outcome,
    pub uring: Outcome,
}

/// Full suite report.
#[derive(Clone, Debug)]
pub struct Report {
    pub rows: Vec<Row>,
}

impl Report {
    /// Techniques that escaped the baseline (should equal the total count).
    pub fn baseline_escapes(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| !r.gated && r.uring == Outcome::Escaped)
            .count()
    }
    /// Techniques that escaped the gate (acceptance target: 0).
    pub fn gated_escapes(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.gated && r.uring == Outcome::Escaped)
            .count()
    }
    pub fn techniques(&self) -> usize {
        Technique::ALL.len()
    }
}

/// Resolve this binary so the suite can re-exec itself as the sandboxed child
/// (fork() in cargo's multithreaded test harness can deadlock the allocator).
fn self_exe() -> io::Result<std::path::PathBuf> {
    if let Ok(p) = std::env::var("URING_GATE_BIN") {
        return Ok(p.into());
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_uring-gate") {
        return Ok(p.into());
    }
    std::env::current_exe()
}

/// Spawn `uring-gate child-bypass <tech> <mode>` and collect its outcomes.
fn spawn_child(tech: Technique, gated: bool) -> io::Result<(Outcome, Outcome)> {
    let exe = self_exe()?;
    let mode = if gated { "gated" } else { "baseline" };
    let out = std::process::Command::new(&exe)
        .args(["child-bypass", tech.name(), mode])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "child {} {mode} failed: {:?} stderr={}",
            tech.name(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    parse_line(&String::from_utf8_lossy(&out.stdout))
}

/// Body of the hidden `child-bypass` subcommand: sandbox, attempt, print.
pub fn child_cli(tech: Technique, gated: bool) -> io::Result<()> {
    let (direct, uring) = child_run(tech, gated)?;
    use std::io::Write;
    println!("direct={} uring={}", direct.as_str(), uring.as_str());
    io::stdout().flush()
}

fn parse_line(s: &str) -> io::Result<(Outcome, Outcome)> {
    let mut direct = Outcome::Error;
    let mut uring = Outcome::Error;
    for tok in s.split_whitespace() {
        if let Some(v) = tok.strip_prefix("direct=") {
            direct = Outcome::parse(v);
        }
        if let Some(v) = tok.strip_prefix("uring=") {
            uring = Outcome::parse(v);
        }
    }
    Ok((direct, uring))
}

/// Parse a technique name for the CLI child.
pub fn technique_from_name(name: &str) -> Option<Technique> {
    Technique::ALL.into_iter().find(|t| t.name() == name)
}

/// Run the whole suite (baseline + gated for every technique).
pub fn run_suite() -> io::Result<Report> {
    let mut rows = Vec::new();
    for tech in Technique::ALL {
        for gated in [false, true] {
            let (direct, uring) = spawn_child(tech, gated)?;
            rows.push(Row {
                tech,
                gated,
                direct,
                uring,
            });
        }
    }
    Ok(Report { rows })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_roundtrip() {
        for o in [Outcome::Escaped, Outcome::Blocked, Outcome::Error] {
            assert_eq!(Outcome::parse(o.as_str()), o);
        }
    }

    #[test]
    fn eacces_is_blocked() {
        assert_eq!(classify(-libc::EACCES), Outcome::Blocked);
        assert_eq!(classify(-libc::EPERM), Outcome::Blocked);
        assert_eq!(classify(0), Outcome::Escaped);
        assert_eq!(classify(5), Outcome::Escaped);
        // reaching the net layer but refused is still an escape past the sandbox
        assert_eq!(classify(-libc::ECONNREFUSED), Outcome::Escaped);
    }

    #[test]
    fn every_technique_has_a_name() {
        for t in Technique::ALL {
            assert_eq!(technique_from_name(t.name()), Some(t));
        }
        assert_eq!(technique_from_name("nope"), None);
    }
}
