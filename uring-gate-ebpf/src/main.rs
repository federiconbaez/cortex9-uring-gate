//! eBPF LSM backstop of uring-gate.
//!
//! The opcode allowlist (`IORING_REGISTER_RESTRICTIONS`) only protects a ring
//! the application itself created restricted. For a process you do not control
//! that opens an unrestricted ring, the LSM layer is the backstop: the kernel
//! calls `security_file_open` for io_uring `OPENAT` just as for the syscall, so
//! a hook there applies one policy to both paths.
//!
//! Filtering is by **cgroup id**, not comm/pid: io_uring work may run in an
//! `io-wq` worker thread, which does not share the submitter's comm but does
//! share its cgroup. `bpf_get_current_cgroup_id()` therefore matches both the
//! inline and the punted path.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_cgroup_id,
    macros::{lsm, map},
    maps::Array,
    programs::LsmContext,
};
use uring_gate_common::{config, counters};

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(config::LEN, 0);

#[map]
static COUNTERS: Array<u64> = Array::with_max_entries(counters::LEN, 0);

#[inline(always)]
fn cfg(slot: u32) -> u64 {
    CONFIG.get(slot).copied().unwrap_or(0)
}

#[inline(always)]
fn bump(slot: u32) {
    if let Some(p) = COUNTERS.get_ptr_mut(slot) {
        unsafe { *p += 1 };
    }
}

#[inline(always)]
fn sandboxed() -> bool {
    if cfg(config::ACTIVE) == 0 {
        return false;
    }
    let target = cfg(config::TARGET_CGROUP);
    target != 0 && unsafe { bpf_get_current_cgroup_id() } == target
}

/// `security_file_open(struct file *file)`: deny for the sandboxed cgroup.
///
/// This fires for both a direct `openat` and an io_uring `IORING_OP_OPENAT`,
/// which is the coverage the project set out to show.
#[lsm(hook = "file_open")]
pub fn file_open(_ctx: LsmContext) -> i32 {
    if sandboxed() {
        bump(counters::FILE_OPEN_DENIED);
        return -1; // -EPERM
    }
    bump(counters::FILE_OPEN_SEEN);
    0
}

/// `security_uring_cmd(struct io_uring_cmd *ioucmd)`: deny the pass-through
/// `IORING_OP_URING_CMD` for the sandboxed cgroup (opcode restrictions on an
/// app's own ring cannot cover an app you do not control).
#[lsm(hook = "uring_cmd")]
pub fn uring_cmd(_ctx: LsmContext) -> i32 {
    if sandboxed() && cfg(config::DENY_URING_CMD) != 0 {
        bump(counters::URING_CMD_DENIED);
        return -1; // -EPERM
    }
    bump(counters::URING_CMD_SEEN);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
