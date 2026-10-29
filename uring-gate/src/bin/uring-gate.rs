//! uring-gate CLI.
//!
//! Subcommands:
//!   probe    print kernel features relevant to io_uring sandboxing
//!   bypass   run the bypass suite (baseline must all escape, gate must be 0)
//!   bench    run the throughput benchmark (gate must keep >= min-ratio)
//!   run      apply a Landlock filesystem policy and exec a command

use clap::{Parser, Subcommand};
use std::ffi::CString;
use uring_gate::bypass::{self, Outcome};
use uring_gate::landlock::{
    Ruleset, LANDLOCK_ACCESS_FS_EXECUTE, LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE,
    LANDLOCK_ACCESS_FS_WRITE_FILE,
};
use uring_gate::{bench, probe};

#[derive(Parser)]
#[command(
    name = "uring-gate",
    about = "Sandbox io_uring with restrictions + seccomp + Landlock instead of banning it"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print kernel features and whether Landlock covers io_uring openat.
    Probe,
    /// Run the bypass suite and exit non-zero if any gated technique escapes.
    Bypass {
        /// Emit machine-readable lines (one per row).
        #[arg(long)]
        raw: bool,
    },
    /// Throughput benchmark: restricted ring vs native ring.
    Bench {
        #[arg(long, default_value_t = 200_000)]
        iters: u64,
        #[arg(long, default_value_t = 0.85)]
        min_ratio: f64,
    },
    /// Apply a Landlock read/exec policy over `paths` and exec a command.
    Run {
        /// Directories granted read + execute (repeatable).
        #[arg(long = "ro", value_name = "DIR")]
        ro: Vec<String>,
        /// Directories granted read + write (repeatable).
        #[arg(long = "rw", value_name = "DIR")]
        rw: Vec<String>,
        /// The command and its arguments (after `--`).
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Hidden: sandboxed child that measures Landlock io_uring coverage.
    #[command(hide = true)]
    ChildLandlock { dir: String },
    /// Hidden: sandboxed child that runs one bypass technique.
    #[command(hide = true)]
    ChildBypass { tech: String, mode: String },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Probe => cmd_probe(),
        Cmd::Bypass { raw } => cmd_bypass(raw),
        Cmd::Bench { iters, min_ratio } => cmd_bench(iters, min_ratio),
        Cmd::Run { ro, rw, argv } => cmd_run(ro, rw, argv),
        Cmd::ChildLandlock { dir } => match probe::run_landlock_child(&dir) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("child error: {e}");
                2
            }
        },
        Cmd::ChildBypass { tech, mode } => match bypass::technique_from_name(&tech) {
            None => {
                eprintln!("unknown technique {tech}");
                2
            }
            Some(t) => match bypass::child_cli(t, mode == "gated") {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("child error: {e}");
                    2
                }
            },
        },
    };
    std::process::exit(code);
}

fn cmd_probe() -> i32 {
    println!("kernel        {}", kernel_release());
    println!("lsm           {}", probe::lsm_list());
    println!("bpf_in_lsm    {}", probe::bpf_in_lsm());
    println!("io_uring_disabled {}", probe::io_uring_disabled());
    match uring_gate::landlock::abi_version() {
        Ok(v) => println!("landlock_abi  {v}"),
        Err(e) => println!("landlock_abi  unavailable ({e})"),
    }
    match probe::landlock_covers_uring_openat() {
        Ok(r) => {
            println!(
                "landlock_covers_uring_openat {}  (syscall_denied={}, uring_denied={})",
                r.covers_uring(),
                r.syscall_denied,
                r.uring_denied
            );
        }
        Err(e) => println!("landlock_covers_uring_openat error ({e})"),
    }
    0
}

fn oc(o: Outcome) -> &'static str {
    match o {
        Outcome::Escaped => "ESCAPED",
        Outcome::Blocked => "blocked",
        Outcome::Error => "error",
    }
}

fn cmd_bypass(raw: bool) -> i32 {
    let report = match bypass::run_suite() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bypass suite failed: {e}");
            return 2;
        }
    };
    if raw {
        for r in &report.rows {
            println!(
                "tech={} mode={} direct={} uring={}",
                r.tech.name(),
                if r.gated { "gated" } else { "baseline" },
                oc(r.direct),
                oc(r.uring)
            );
        }
    } else {
        println!(
            "{:<10} {:<10} {:<10} {:<10}",
            "technique", "mode", "direct", "io_uring"
        );
        for r in &report.rows {
            println!(
                "{:<10} {:<10} {:<10} {:<10}",
                r.tech.name(),
                if r.gated { "gated" } else { "baseline" },
                oc(r.direct),
                oc(r.uring)
            );
        }
    }
    let total = report.techniques();
    let base = report.baseline_escapes();
    let gated = report.gated_escapes();
    println!("\nMEASURE baseline_escapes={base}/{total} gated_escapes={gated}/{total}");
    if base != total {
        eprintln!("FAIL: baseline did not reproduce all {total} bypasses (got {base})");
        return 1;
    }
    if gated != 0 {
        eprintln!("FAIL: {gated} technique(s) escaped uring-gate");
        return 1;
    }
    println!("OK: all {total} techniques bypass seccomp-only; 0 bypass uring-gate");
    0
}

fn cmd_bench(iters: u64, min_ratio: f64) -> i32 {
    match bench::run(iters) {
        Ok(r) => {
            println!("iters         {}", r.iters);
            println!("native        {:.0} ops/s", r.native_ops_s());
            println!("gated         {:.0} ops/s", r.gated_ops_s());
            println!(
                "MEASURE throughput_ratio={:.4} (target >= {:.2})",
                r.ratio(),
                min_ratio
            );
            if r.ratio() >= min_ratio {
                println!(
                    "OK: restricted ring keeps {:.1}% of native throughput",
                    r.ratio() * 100.0
                );
                0
            } else {
                eprintln!("FAIL: ratio {:.4} below target {:.2}", r.ratio(), min_ratio);
                1
            }
        }
        Err(e) => {
            eprintln!("bench failed: {e}");
            2
        }
    }
}

fn cmd_run(ro: Vec<String>, rw: Vec<String>, argv: Vec<String>) -> i32 {
    let rs = match Ruleset::create(
        LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_EXECUTE,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("landlock create failed: {e}");
            return 2;
        }
    };
    for d in &ro {
        if let Err(e) = rs.allow_path(
            d,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE,
        ) {
            eprintln!("landlock ro {d}: {e}");
            return 2;
        }
    }
    for d in &rw {
        if let Err(e) = rs.allow_path(
            d,
            LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_READ_DIR
                | LANDLOCK_ACCESS_FS_WRITE_FILE,
        ) {
            eprintln!("landlock rw {d}: {e}");
            return 2;
        }
    }
    if let Err(e) = rs.restrict_self() {
        eprintln!("landlock restrict_self failed: {e}");
        return 2;
    }
    let prog = CString::new(argv[0].as_str()).unwrap();
    let cargs: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe {
        libc::execvp(prog.as_ptr(), ptrs.as_ptr());
    }
    eprintln!("execvp {}: {}", argv[0], std::io::Error::last_os_error());
    127
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}
