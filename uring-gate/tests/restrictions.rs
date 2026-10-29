//! Acceptance tests for the unprivileged core (IORING_REGISTER_RESTRICTIONS +
//! seccomp + Landlock). These run without root and must pass on the box and on
//! CI runners. A kernel without io_uring or Landlock makes them FAIL (never a
//! silent skip): that is the intended behaviour per the project rules.

use uring_gate::bypass::{self, Outcome};
use uring_gate::probe;
use uring_gate::uring::{Ring, IORING_OP_NOP, IORING_OP_OPENAT};

#[test]
fn restricted_ring_denies_disallowed_opcode() {
    // Allow only NOP; OPENAT must come back as -EACCES.
    let mut ring = Ring::setup_restricted(8, &[IORING_OP_NOP]).expect("restricted ring");
    assert_eq!(ring.nop().expect("nop"), 0, "NOP must be allowed");
    let path = std::ffi::CString::new("/etc/hostname").unwrap();
    let res = ring
        .openat(libc::AT_FDCWD, &path, libc::O_RDONLY)
        .expect("submit");
    assert_eq!(
        res,
        -libc::EACCES,
        "disallowed OPENAT must be -EACCES, got {res}"
    );
}

#[test]
fn plain_ring_allows_openat() {
    // Sanity: without restrictions the same OPENAT succeeds (the bypass the
    // gate closes). Guards against a test that passes for the wrong reason.
    let mut ring = Ring::setup(8).expect("plain ring");
    let path = std::ffi::CString::new("/etc/hostname").unwrap();
    let res = ring
        .openat(libc::AT_FDCWD, &path, libc::O_RDONLY)
        .expect("submit");
    assert!(
        res >= 0,
        "plain-ring OPENAT should open the file, got {res}"
    );
    let _ = ring.submit(uring_gate::uring::Sqe {
        opcode: uring_gate::uring::IORING_OP_CLOSE,
        fd: res,
        ..Default::default()
    });
    let _ = IORING_OP_OPENAT; // keep the import meaningful
}

#[test]
fn bypass_suite_acceptance() {
    let report = bypass::run_suite().expect("bypass suite");
    let total = report.techniques();
    assert!(total >= 3, "expected >=3 techniques, got {total}");
    // Every technique must bypass seccomp-only...
    assert_eq!(
        report.baseline_escapes(),
        total,
        "baseline must reproduce all {total} io_uring bypasses"
    );
    // ...and none must bypass uring-gate.
    assert_eq!(report.gated_escapes(), 0, "a technique escaped uring-gate");
    // The direct syscall must be blocked by seccomp in every row.
    for r in &report.rows {
        assert_eq!(
            r.direct,
            Outcome::Blocked,
            "direct {} syscall should be seccomp-blocked",
            r.tech.name()
        );
    }
}

#[test]
fn landlock_covers_io_uring_openat() {
    // Documented finding: on this kernel Landlock's security_file_open hook is
    // called for io_uring OPENAT too, so a denied directory is denied on both
    // paths. If a future kernel regressed this, the test would FAIL and flag it.
    let r = probe::landlock_covers_uring_openat().expect("landlock probe");
    assert!(r.abi >= 1, "Landlock must be available, abi={}", r.abi);
    assert!(r.syscall_denied, "syscall openat should be Landlock-denied");
    assert!(
        r.uring_denied,
        "io_uring openat should be Landlock-denied too (coverage)"
    );
}
