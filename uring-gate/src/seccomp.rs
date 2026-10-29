//! A tiny seccomp-BPF installer (no libseccomp).
//!
//! This is the *weak* baseline that uring-gate exists to fix: a classic
//! syscall allowlist/denylist that never inspects io_uring submission queue
//! entries. A filter built here blocks the named syscalls with `EPERM` while
//! leaving `io_uring_setup`/`enter`/`register` allowed, so the same operation
//! issued as an SQE sails straight past it.

use libc::c_int;
use std::io;

const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_DATA_NR_OFFSET: u32 = 0; // offsetof(struct seccomp_data, nr)

// Classic BPF opcodes.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Install a seccomp filter that returns `EPERM` for each syscall number in
/// `block` and allows everything else. Sets `PR_SET_NO_NEW_PRIVS` first.
///
/// This is irreversible for the calling thread, so callers normally run it in
/// a child process.
pub fn block_syscalls(block: &[c_int]) -> io::Result<()> {
    let mut prog: Vec<SockFilter> = Vec::new();
    // A = seccomp_data.nr
    prog.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    });
    for &nr in block {
        // if (A == nr) return ERRNO(EPERM);
        prog.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: nr as u32,
        });
        prog.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0x0000_ffff),
        });
    }
    prog.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &fprog as *const _,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
