//! BPF-LSM backstop runner (feature `lsm`, root only).
//!
//! `measure` loads the LSM programs, puts a sandboxed child in a target cgroup,
//! and checks that an io_uring `OPENAT` from that cgroup is denied just like the
//! direct syscall, while a control process outside the cgroup is unaffected.
//!
//! It exits non-zero (never skips) if `bpf` is not in the active LSM list, so
//! the `enforce` workflow fails visibly on a kernel without BPF-LSM.

use clap::{Parser, Subcommand};
use std::ffi::CString;
use std::io::Write;
use uring_gate::lsm::{self, Backstop};
use uring_gate::uring::Ring;

#[derive(Parser)]
#[command(
    name = "uring-gate-lsm",
    about = "BPF-LSM backstop for uring-gate (root)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Load, arm against a fresh cgroup, and measure io_uring vs syscall denial.
    Measure,
    /// Hidden: child that joins `dir` cgroup then attempts both opens.
    #[command(hide = true)]
    ChildCgroup { dir: String },
    /// Hidden: control child that attempts both opens without joining a cgroup.
    #[command(hide = true)]
    ChildControl,
}

fn main() {
    std::process::exit(match Cli::parse().cmd {
        Cmd::Measure => cmd_measure(),
        Cmd::ChildCgroup { dir } => child_attempts(Some(&dir)),
        Cmd::ChildControl => child_attempts(None),
    });
}

/// Returns `(direct, uring)` as `allowed`/`denied` and prints them.
fn child_attempts(cgroup_dir: Option<&str>) -> i32 {
    if let Some(dir) = cgroup_dir {
        // Join the target cgroup by writing our pid to cgroup.procs. This open
        // happens before membership, so the LSM hook does not deny it.
        let procs = format!("{dir}/cgroup.procs");
        match std::fs::OpenOptions::new().write(true).open(&procs) {
            Ok(mut f) => {
                if let Err(e) = write!(f, "{}", std::process::id()) {
                    eprintln!("join cgroup: {e}");
                    return 2;
                }
            }
            Err(e) => {
                eprintln!("open {procs}: {e}");
                return 2;
            }
        }
    }
    // Direct openat.
    let path = CString::new("/etc/hostname").unwrap();
    let d = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_RDONLY,
        )
    };
    let direct = if d >= 0 {
        unsafe { libc::close(d as i32) };
        "allowed"
    } else {
        "denied"
    };
    // io_uring openat on an unrestricted ring (the app we "do not control").
    let uring =
        match Ring::setup(8).and_then(|mut r| r.openat(libc::AT_FDCWD, &path, libc::O_RDONLY)) {
            Ok(res) if res >= 0 => {
                unsafe { libc::close(res) };
                "allowed"
            }
            Ok(_) => "denied",
            Err(e) => {
                eprintln!("ring: {e}");
                "error"
            }
        };
    // Report via stdout write (not a path open).
    let line = format!("direct={direct} uring={uring}\n");
    let _ = std::io::stdout().write_all(line.as_bytes());
    0
}

fn run_child(args: &[&str]) -> std::io::Result<(String, String)> {
    let exe = std::env::current_exe()?;
    let out = std::process::Command::new(exe).args(args).output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "child {args:?} failed: {:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut d = String::from("error");
    let mut u = String::from("error");
    for tok in text.split_whitespace() {
        if let Some(v) = tok.strip_prefix("direct=") {
            d = v.to_string();
        }
        if let Some(v) = tok.strip_prefix("uring=") {
            u = v.to_string();
        }
    }
    Ok((d, u))
}

/// Outcome of one cgroup measurement with the backstop attached and armed.
struct CgroupResult {
    s_direct: String,
    s_uring: String,
    c_direct: String,
    c_uring: String,
    denied: u64,
}

/// Arm `bs` against a fresh cgroup and run the sandboxed + control children.
fn run_cgroup(bs: &mut Backstop) -> Result<CgroupResult, String> {
    let dir = format!("/sys/fs/cgroup/uring-gate-{}", std::process::id());
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
    let res = (|| -> Result<CgroupResult, String> {
        let cid = lsm::cgroup_id(&dir).map_err(|e| e.to_string())?;
        bs.arm(cid, true).map_err(|e| e.to_string())?;
        println!("cgroup        {dir} (id={cid})");
        let (s_direct, s_uring) = run_child(&["child-cgroup", &dir]).map_err(|e| e.to_string())?;
        let (c_direct, c_uring) = run_child(&["child-control"]).map_err(|e| e.to_string())?;
        let denied = bs
            .counter(lsm::slot::FILE_OPEN_DENIED)
            .map_err(|e| e.to_string())?;
        Ok(CgroupResult {
            s_direct,
            s_uring,
            c_direct,
            c_uring,
            denied,
        })
    })();
    let _ = std::fs::remove_dir(&dir);
    res
}

fn print_result(r: &CgroupResult) {
    println!("sandboxed     direct={} uring={}", r.s_direct, r.s_uring);
    println!("control       direct={} uring={}", r.c_direct, r.c_uring);
}

/// Full enforcement measurement; requires `bpf` to be an active LSM.
fn cmd_measure() -> i32 {
    let mut bs = match Backstop::load() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return 1;
        }
    };
    match run_cgroup(&mut bs) {
        Ok(r) => {
            print_result(&r);
            println!(
                "MEASURE lsm_file_open_denied={} sandboxed_uring={} sandboxed_direct={} control_uring={}",
                r.denied, r.s_uring, r.s_direct, r.c_uring
            );
            let ok = r.s_direct == "denied"
                && r.s_uring == "denied"
                && r.c_direct == "allowed"
                && r.c_uring == "allowed"
                && r.denied >= 2;
            if ok {
                println!("OK: BPF-LSM denies io_uring OPENAT for the sandboxed cgroup exactly like the syscall; control unaffected");
                0
            } else {
                eprintln!("FAIL: expected sandboxed denied (both) and control allowed (both) with >=2 denials");
                1
            }
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            2
        }
    }
}
