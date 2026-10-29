//! Minimal io_uring driver (no liburing) with optional
//! `IORING_REGISTER_RESTRICTIONS` opcode allowlisting.
//!
//! The ring can be created in two ways:
//!
//! - [`Ring::setup`]: a plain ring, all opcodes enabled (the baseline that a
//!   seccomp-only sandbox fails to cover).
//! - [`Ring::setup_restricted`]: `IORING_SETUP_R_DISABLED`, then
//!   `IORING_REGISTER_RESTRICTIONS` with an opcode allowlist, then
//!   `IORING_REGISTER_ENABLE_RINGS`. Opcodes outside the allowlist are
//!   rejected by the kernel with `-EACCES` at completion.

use libc::{c_int, c_void, syscall};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const SYS_IO_URING_SETUP: c_int = 425;
const SYS_IO_URING_ENTER: c_int = 426;
const SYS_IO_URING_REGISTER: c_int = 427;

const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_CQ_RING: i64 = 0x8000000;
const IORING_OFF_SQES: i64 = 0x10000000;
const IORING_ENTER_GETEVENTS: u32 = 1;

const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
const IORING_REGISTER_RESTRICTIONS: u32 = 11;
const IORING_REGISTER_ENABLE_RINGS: u32 = 12;
const IORING_RESTRICTION_SQE_OP: u16 = 1;

/// io_uring opcodes used by this crate (uapi `enum io_uring_op`).
pub const IORING_OP_NOP: u8 = 0;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_SOCKET: u8 = 45;
pub const IORING_OP_URING_CMD: u8 = 46;

#[repr(C)]
#[derive(Clone, Copy)]
struct SqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqringOffsets,
    cq_off: CqringOffsets,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Restriction {
    opcode: u16,
    arg: u8,
    resv: u8,
    resv2: [u32; 3],
}

/// One io_uring submission queue entry (uapi `struct io_uring_sqe`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub file_index: u32,
    pub addr3: u64,
    pub pad2: u64,
}

impl Default for Sqe {
    fn default() -> Self {
        // SAFETY: an all-zero SQE is a valid (NOP-shaped) entry.
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

pub struct Ring {
    fd: OwnedFd,
    sq: *mut u8,
    cq: *mut u8,
    sqes: *mut Sqe,
    sq_off: SqringOffsets,
    cq_off: CqringOffsets,
    sq_entries: u32,
    cq_entries: u32,
    sq_map_len: usize,
    cq_map_len: usize,
}

fn setup(flags: u32, entries: u32) -> io::Result<(OwnedFd, Params)> {
    let mut params: Params = unsafe { std::mem::zeroed() };
    params.flags = flags;
    let rc = unsafe {
        syscall(
            SYS_IO_URING_SETUP as _,
            entries as c_int,
            &mut params as *mut Params as *mut c_void,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((unsafe { OwnedFd::from_raw_fd(rc as c_int) }, params))
}

impl Ring {
    /// A plain ring with every opcode enabled.
    pub fn setup(entries: u32) -> io::Result<Self> {
        let (fd, params) = setup(0, entries)?;
        Self::map(fd, params)
    }

    /// A ring created disabled, restricted to `allow_ops`, then enabled.
    ///
    /// Any opcode not in `allow_ops` completes with `-EACCES`.
    pub fn setup_restricted(entries: u32, allow_ops: &[u8]) -> io::Result<Self> {
        let (fd, params) = setup(IORING_SETUP_R_DISABLED, entries)?;
        let restr: Vec<Restriction> = allow_ops
            .iter()
            .map(|&op| Restriction {
                opcode: IORING_RESTRICTION_SQE_OP,
                arg: op,
                resv: 0,
                resv2: [0; 3],
            })
            .collect();
        let rc = unsafe {
            syscall(
                SYS_IO_URING_REGISTER as _,
                fd.as_raw_fd(),
                IORING_REGISTER_RESTRICTIONS as c_int,
                restr.as_ptr() as *const c_void,
                restr.len() as c_int,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe {
            syscall(
                SYS_IO_URING_REGISTER as _,
                fd.as_raw_fd(),
                IORING_REGISTER_ENABLE_RINGS as c_int,
                std::ptr::null::<c_void>(),
                0 as c_int,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::map(fd, params)
    }

    fn map(fd: OwnedFd, params: Params) -> io::Result<Self> {
        let sq_len = (params.sq_off.array as usize) + (params.sq_entries as usize) * 4;
        let cq_len = (params.cq_off.cqes as usize)
            + (params.cq_entries as usize) * std::mem::size_of::<Cqe>();
        let mmap = |len: usize, off: i64| -> io::Result<*mut c_void> {
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd.as_raw_fd(),
                    off,
                )
            };
            if p == libc::MAP_FAILED {
                Err(io::Error::last_os_error())
            } else {
                Ok(p)
            }
        };
        let sq = mmap(sq_len, IORING_OFF_SQ_RING)?;
        let cq = mmap(cq_len, IORING_OFF_CQ_RING)?;
        let sqes = mmap(
            (params.sq_entries as usize) * std::mem::size_of::<Sqe>(),
            IORING_OFF_SQES,
        )?;
        Ok(Self {
            fd,
            sq: sq as *mut u8,
            cq: cq as *mut u8,
            sqes: sqes as *mut Sqe,
            sq_off: params.sq_off,
            cq_off: params.cq_off,
            sq_entries: params.sq_entries,
            cq_entries: params.cq_entries,
            sq_map_len: sq_len,
            cq_map_len: cq_len,
        })
    }

    /// Submit one SQE and block for its single completion; returns `cqe.res`.
    ///
    /// The ring is driven one in-flight op at a time, but the SQ tail and CQ
    /// head are advanced across calls so the same [`Ring`] can be reused in a
    /// loop (e.g. the benchmark).
    pub fn submit(&mut self, sqe: Sqe) -> io::Result<i32> {
        let sq_mask = self.sq_entries - 1;
        unsafe {
            let tailp = self.sq.add(self.sq_off.tail as usize) as *mut u32;
            let array = self.sq.add(self.sq_off.array as usize) as *mut u32;
            let tail = std::ptr::read_volatile(tailp);
            let idx = tail & sq_mask;
            std::ptr::write(self.sqes.add(idx as usize), sqe);
            std::ptr::write_volatile(array.add(idx as usize), idx);
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            std::ptr::write_volatile(tailp, tail.wrapping_add(1));
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        }
        let rc = unsafe {
            syscall(
                SYS_IO_URING_ENTER as _,
                self.fd.as_raw_fd(),
                1i32,
                1i32,
                IORING_ENTER_GETEVENTS as c_int,
                std::ptr::null::<c_void>(),
                0usize,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            let head = self.cq.add(self.cq_off.head as usize) as *mut u32;
            let tail = self.cq.add(self.cq_off.tail as usize) as *const u32;
            let h = std::ptr::read_volatile(head);
            let t = std::ptr::read_volatile(tail);
            if t == h {
                return Err(io::Error::other("no CQE produced"));
            }
            let cqes = self.cq.add(self.cq_off.cqes as usize) as *const Cqe;
            let idx = (h & (self.cq_entries - 1)) as isize;
            let cqe = std::ptr::read(cqes.offset(idx));
            std::ptr::write_volatile(head, h.wrapping_add(1));
            Ok(cqe.res)
        }
    }

    pub fn nop(&mut self) -> io::Result<i32> {
        self.submit(Sqe {
            opcode: IORING_OP_NOP,
            user_data: 0,
            ..Default::default()
        })
    }

    pub fn openat(&mut self, dfd: i32, path: &std::ffi::CStr, flags: i32) -> io::Result<i32> {
        self.submit(Sqe {
            opcode: IORING_OP_OPENAT,
            fd: dfd,
            addr: path.as_ptr() as u64,
            op_flags: flags as u32,
            user_data: 1,
            ..Default::default()
        })
    }

    pub fn read(&mut self, fd: i32, buf: &mut [u8]) -> io::Result<i32> {
        self.submit(Sqe {
            opcode: IORING_OP_READ,
            fd,
            addr: buf.as_mut_ptr() as u64,
            len: buf.len() as u32,
            off: u64::MAX, // use current file offset
            user_data: 2,
            ..Default::default()
        })
    }

    pub fn connect(&mut self, fd: i32, addr: &libc::sockaddr, addrlen: u32) -> io::Result<i32> {
        self.submit(Sqe {
            opcode: IORING_OP_CONNECT,
            fd,
            addr: addr as *const _ as u64,
            off: addrlen as u64,
            user_data: 3,
            ..Default::default()
        })
    }

    pub fn socket(&mut self, domain: i32, ty: i32, proto: i32) -> io::Result<i32> {
        self.submit(Sqe {
            opcode: IORING_OP_SOCKET,
            fd: domain,
            off: ty as u64,
            len: proto as u32,
            user_data: 4,
            ..Default::default()
        })
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.sq as *mut c_void, self.sq_map_len);
            libc::munmap(self.cq as *mut c_void, self.cq_map_len);
            libc::munmap(
                self.sqes as *mut c_void,
                (self.sq_entries as usize) * std::mem::size_of::<Sqe>(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqe_is_64_bytes() {
        // The uapi io_uring_sqe is 64 bytes; a wrong size corrupts submissions.
        assert_eq!(std::mem::size_of::<Sqe>(), 64);
    }

    #[test]
    fn restriction_is_16_bytes() {
        assert_eq!(std::mem::size_of::<Restriction>(), 16);
    }
}
