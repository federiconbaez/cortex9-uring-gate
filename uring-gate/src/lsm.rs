//! BPF-LSM backstop loader and measurement (feature `lsm`, needs root).
//!
//! Loads the `file_open` and `uring_cmd` LSM programs, points them at a target
//! cgroup, and measures that an io_uring `OPENAT` issued from that cgroup is
//! denied exactly like the direct syscall — the coverage `IORING_REGISTER_
//! RESTRICTIONS` cannot give for an application you do not control.
//!
//! Requires `bpf` in `/sys/kernel/security/lsm`. If it is absent this module
//! returns an error and the CI job fails (no silent skip).

use aya::maps::Array as AyaArray;
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use std::io;
use uring_gate_common::config;

#[cfg(embedded_ebpf)]
static EMBEDDED: Option<&[u8]> = Some(aya::include_bytes_aligned!(env!("URING_GATE_EBPF_OBJ")));
#[cfg(not(embedded_ebpf))]
static EMBEDDED: Option<&[u8]> = None;

const DEFAULT_OBJECT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../uring-gate-ebpf/target/bpfel-unknown-none/release/uring-gate-ebpf"
);

/// Error type with a dedicated variant for "BPF-LSM not available".
#[derive(Debug)]
pub enum LsmError {
    NoBpfLsm { lsm: String },
    MissingObject { path: String },
    Aya(String),
    Io(io::Error),
}

impl std::fmt::Display for LsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsmError::NoBpfLsm { lsm } => write!(
                f,
                "bpf is not in the active LSM list ('{lsm}'); BPF-LSM enforcement is unavailable"
            ),
            LsmError::MissingObject { path } => {
                write!(
                    f,
                    "eBPF object not found at {path}; build uring-gate-ebpf first"
                )
            }
            LsmError::Aya(s) => write!(f, "aya: {s}"),
            LsmError::Io(e) => write!(f, "io: {e}"),
        }
    }
}
impl std::error::Error for LsmError {}
impl From<io::Error> for LsmError {
    fn from(e: io::Error) -> Self {
        LsmError::Io(e)
    }
}

fn aya_err<E: std::fmt::Display>(e: E) -> LsmError {
    LsmError::Aya(e.to_string())
}

/// A loaded, attached backstop. Programs stay attached while this is alive.
pub struct Backstop {
    ebpf: Ebpf,
}

impl Backstop {
    /// Load the object and attach both LSM hooks.
    pub fn load() -> Result<Self, LsmError> {
        let lsm = crate::probe::lsm_list();
        if !crate::probe::bpf_in_lsm() {
            return Err(LsmError::NoBpfLsm { lsm });
        }
        let bytes = read_object()?;
        let mut ebpf = Ebpf::load(&bytes).map_err(aya_err)?;
        let btf = Btf::from_sys_fs().map_err(aya_err)?;
        for hook in ["file_open", "uring_cmd"] {
            let prog: &mut Lsm = ebpf
                .program_mut(hook)
                .ok_or_else(|| LsmError::Aya(format!("program {hook} not found in object")))?
                .try_into()
                .map_err(aya_err)?;
            prog.load(hook, &btf).map_err(aya_err)?;
            prog.attach().map_err(aya_err)?;
        }
        Ok(Self { ebpf })
    }

    fn config(&mut self) -> Result<AyaArray<&mut aya::maps::MapData, u64>, LsmError> {
        AyaArray::try_from(
            self.ebpf
                .map_mut("CONFIG")
                .ok_or_else(|| LsmError::Aya("CONFIG map missing".into()))?,
        )
        .map_err(aya_err)
    }

    /// Point the hooks at `cgroup_id` and activate enforcement.
    pub fn arm(&mut self, cgroup_id: u64, deny_uring_cmd: bool) -> Result<(), LsmError> {
        let mut c = self.config()?;
        c.set(config::TARGET_CGROUP, cgroup_id, 0)
            .map_err(aya_err)?;
        c.set(config::DENY_URING_CMD, deny_uring_cmd as u64, 0)
            .map_err(aya_err)?;
        c.set(config::ACTIVE, 1, 0).map_err(aya_err)?;
        Ok(())
    }

    /// Read a counter slot.
    pub fn counter(&self, slot: u32) -> Result<u64, LsmError> {
        let arr: AyaArray<_, u64> = AyaArray::try_from(
            self.ebpf
                .map("COUNTERS")
                .ok_or_else(|| LsmError::Aya("COUNTERS map missing".into()))?,
        )
        .map_err(aya_err)?;
        arr.get(&slot, 0).map_err(aya_err)
    }
}

/// Just parse and load the object + maps into the kernel (runs no attach).
/// Proves the eBPF object is valid on this kernel even where BPF-LSM is off.
pub fn object_loads() -> Result<(), LsmError> {
    let bytes = read_object()?;
    Ebpf::load(&bytes).map_err(aya_err)?;
    Ok(())
}

/// Try the full load + attach and return the detailed error if it fails.
pub fn attempt_attach() -> Result<(), LsmError> {
    let bytes = read_object()?;
    let mut ebpf = Ebpf::load(&bytes).map_err(aya_err)?;
    let btf = Btf::from_sys_fs().map_err(aya_err)?;
    for hook in ["file_open", "uring_cmd"] {
        let prog: &mut Lsm = ebpf
            .program_mut(hook)
            .ok_or_else(|| LsmError::Aya(format!("program {hook} not found")))?
            .try_into()
            .map_err(aya_err)?;
        prog.load(hook, &btf).map_err(aya_err)?;
        prog.attach().map_err(aya_err)?;
    }
    Ok(())
}

fn read_object() -> Result<Vec<u8>, LsmError> {
    match EMBEDDED {
        Some(b) => Ok(b.to_vec()),
        None => {
            if !std::path::Path::new(DEFAULT_OBJECT).is_file() {
                return Err(LsmError::MissingObject {
                    path: DEFAULT_OBJECT.to_string(),
                });
            }
            Ok(std::fs::read(DEFAULT_OBJECT)?)
        }
    }
}

/// cgroup id of a cgroup2 directory (its kernfs inode number).
pub fn cgroup_id(dir: &str) -> io::Result<u64> {
    let md = std::fs::metadata(dir)?;
    use std::os::unix::fs::MetadataExt;
    Ok(md.ino())
}

/// Counter slots re-exported for the binary.
pub mod slot {
    pub use uring_gate_common::counters::*;
}
