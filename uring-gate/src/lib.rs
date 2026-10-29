//! uring-gate: sandbox io_uring instead of banning it.
//!
//! The library is split into independent layers; the CLI wires them together:
//!
//! - [`uring`]: a minimal io_uring driver with opcode allowlisting via
//!   `IORING_REGISTER_RESTRICTIONS` (the kernel-enforced core, unprivileged).
//! - [`seccomp`]: the weak syscall-only baseline uring-gate exists to fix.
//! - [`landlock`]: filesystem policy the kernel applies to both syscall and
//!   io_uring opens (`security_file_open`).
//! - [`bypass`]: the bypass suite that measures the acceptance criterion.
//! - [`bench`]: the throughput benchmark.
//!
//! The optional [`lsm`] module (feature `lsm`) is the BPF-LSM backstop: a
//! program on `file_open`/`uring_cmd` that needs root and `bpf` in the active
//! LSM list, exercised by a dedicated CI job.

pub mod bench;
pub mod bypass;
pub mod landlock;
#[cfg(feature = "lsm")]
pub mod lsm;
pub mod probe;
pub mod seccomp;
pub mod uring;
