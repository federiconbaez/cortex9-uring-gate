//! Embed the eBPF LSM object when `URING_GATE_EBPF_OBJ` points at a built one.
//!
//! Without it the crate still builds on stable (no bpf-linker needed); the
//! `uring-gate-lsm` binary then reports the object is missing and the CI
//! `lsm` job, which sets the variable, fails visibly instead of skipping.
use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(embedded_ebpf)");
    println!("cargo::rerun-if-env-changed=URING_GATE_EBPF_OBJ");
    if let Ok(path) = std::env::var("URING_GATE_EBPF_OBJ") {
        if Path::new(&path).is_file() {
            println!("cargo::rerun-if-changed={path}");
            println!("cargo::rustc-cfg=embedded_ebpf");
        } else {
            println!("cargo::warning=URING_GATE_EBPF_OBJ={path} does not exist; not embedding");
        }
    }
}
