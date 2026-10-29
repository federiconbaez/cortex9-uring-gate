//! Types shared between the userspace loader and the eBPF LSM program.
//!
//! Kept `no_std` so the same definitions compile for `bpfel-unknown-none`.
#![no_std]

/// Length of a `comm` (task name) as the kernel reports it.
pub const COMM_LEN: usize = 16;

/// Slots of the `CONFIG` array map.
pub mod config {
    /// Number of `u64` slots.
    pub const LEN: u32 = 3;
    /// cgroup id (cgroup2 dir inode) of the sandboxed process; 0 disables.
    pub const TARGET_CGROUP: u32 = 0;
    /// 1 = deny `IORING_OP_URING_CMD` for the sandboxed cgroup, 0 = allow.
    pub const DENY_URING_CMD: u32 = 1;
    /// 1 = enforcement active, 0 = observe only (program loaded, returns 0).
    pub const ACTIVE: u32 = 2;
}

/// Counters written by the eBPF side and read back from userspace.
pub mod counters {
    /// Number of `u64` slots in the `COUNTERS` array map.
    pub const LEN: u32 = 4;
    /// `file_open` denials against the sandboxed cgroup.
    pub const FILE_OPEN_DENIED: u32 = 0;
    /// `file_open` calls seen for the sandboxed comm.
    pub const FILE_OPEN_SEEN: u32 = 1;
    /// `uring_cmd` denials.
    pub const URING_CMD_DENIED: u32 = 2;
    /// `uring_cmd` calls seen for the sandboxed comm.
    pub const URING_CMD_SEEN: u32 = 3;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_slots_within_len() {
        for slot in [
            config::TARGET_CGROUP,
            config::DENY_URING_CMD,
            config::ACTIVE,
        ] {
            assert!(slot < config::LEN);
        }
    }

    #[test]
    fn counter_slots_within_len() {
        for slot in [
            counters::FILE_OPEN_DENIED,
            counters::FILE_OPEN_SEEN,
            counters::URING_CMD_DENIED,
            counters::URING_CMD_SEEN,
        ] {
            assert!(slot < counters::LEN);
        }
    }
}
