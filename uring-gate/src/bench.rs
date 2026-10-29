//! Throughput benchmark: does wrapping a ring in
//! `IORING_REGISTER_RESTRICTIONS` cost throughput?
//!
//! We run the same io_uring file-read workload twice: once on a plain ring
//! (native), once on a ring whose allowlist includes `READ`. The acceptance
//! target is that the restricted ring keeps >= 85% of native throughput (vs
//! 0% if io_uring were banned outright).
//!
//! This measures the opcode-allowlist overhead, which is the cost uring-gate
//! adds in the unprivileged path. If a local `uring-http` server is present it
//! is used read-only as a reference workload; otherwise this self-contained
//! file benchmark stands in and the README says so.

use crate::uring::{Ring, IORING_OP_CLOSE, IORING_OP_NOP, IORING_OP_OPENAT, IORING_OP_READ};
use std::io::{self, Write};
use std::time::Instant;

pub struct BenchResult {
    pub iters: u64,
    pub native_ns: u128,
    pub gated_ns: u128,
}

impl BenchResult {
    pub fn native_ops_s(&self) -> f64 {
        self.iters as f64 / (self.native_ns as f64 / 1e9)
    }
    pub fn gated_ops_s(&self) -> f64 {
        self.iters as f64 / (self.gated_ns as f64 / 1e9)
    }
    /// Gated throughput as a fraction of native.
    pub fn ratio(&self) -> f64 {
        self.gated_ops_s() / self.native_ops_s()
    }
}

fn make_file(bytes: usize) -> io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("uring-gate-bench-{}.bin", std::process::id()));
    let mut f = std::fs::File::create(&path)?;
    let buf = vec![0xabu8; bytes];
    f.write_all(&buf)?;
    f.sync_all()?;
    Ok(path)
}

fn run_reads(ring: &mut Ring, fd: i32, iters: u64) -> io::Result<u128> {
    let mut buf = [0u8; 4096];
    let start = Instant::now();
    for _ in 0..iters {
        let res = ring.read(fd, &mut buf)?;
        if res < 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }
    }
    Ok(start.elapsed().as_nanos())
}

/// Benchmark `iters` reads on a native vs restricted ring.
pub fn run(iters: u64) -> io::Result<BenchResult> {
    let path = make_file(4096)?;
    let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Warm up.
    {
        let mut r = Ring::setup(8)?;
        run_reads(&mut r, fd, 1000)?;
    }

    let mut native = Ring::setup(8)?;
    let native_ns = run_reads(&mut native, fd, iters)?;

    let allow = [
        IORING_OP_NOP,
        IORING_OP_READ,
        IORING_OP_OPENAT,
        IORING_OP_CLOSE,
    ];
    let mut gated = Ring::setup_restricted(8, &allow)?;
    let gated_ns = run_reads(&mut gated, fd, iters)?;

    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(&path);
    Ok(BenchResult {
        iters,
        native_ns,
        gated_ns,
    })
}
