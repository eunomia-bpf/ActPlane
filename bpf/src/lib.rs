// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//
//! ActPlane eBPF loader (aya).
//!
//! Loads the prebuilt CO-RE object `process.bpf.o` (compiled from the untouched
//! kernel C in this directory), installs the compiled policy into `.rodata`,
//! attaches the enforcer, and surfaces `TAINT_VIOLATION` events. This is the
//! pure-Rust replacement for the C `process` loader: same behavior, but loaded
//! in-process via aya with no libbpf/clang at runtime.
//!
//! The config blob is exactly the `struct taint_config` the collector's DSL
//! compiler already produces (the same bytes the C loader read from `--config`).

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};

// ---- prebuilt eBPF object, 8-byte aligned for aya's ELF parser ----
#[repr(align(8))]
struct Aligned<T: ?Sized>(T);
static OBJECT: &Aligned<[u8]> =
    &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/process.bpf.o")));
fn object_bytes() -> &'static [u8] {
    &OBJECT.0
}

// ===================== ABI mirrors (must match bpf/taint.h) =====================
// Identical to collector/src/dsl/lower.rs; guarded by abi_size_matches() below.
const PAT: usize = 64;
const ARG: usize = 24;
const MAX_SOURCES: usize = 128;
const MAX_RULES: usize = 128;
const MAX_XFORMS: usize = 64;
const MAX_GATES: usize = 64;
const MAX_INVALS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct CSource {
    kind: u8,
    m: u8,
    pat: [u8; PAT],
    label: u64,
    ipv4: u32,
    ipv4_mask: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CRule {
    op: u8,
    m: u8,
    cond_kind: u8,
    cond_neg: u8,
    cond_match: u8,
    effect: u8,
    target: [u8; PAT],
    arg: [u8; ARG],
    cond_pat: [u8; PAT],
    req: u64,
    forbid: u64,
    gate: u64,
    rule_id: u32,
    ipv4: u32,
    ipv4_mask: u32,
    cond_ipv4: u32,
    cond_ipv4_mask: u32,
    gate_idx: u32,
    since_mask: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CXform {
    m: u8,
    add: u8,
    gate: [u8; PAT],
    label: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CGate {
    m: u8,
    pat: [u8; PAT],
    bit: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CInval {
    op: u8,
    m: u8,
    pat: [u8; PAT],
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CConfig {
    n_sources: u32,
    n_rules: u32,
    n_xforms: u32,
    n_gates: u32,
    n_invals: u32,
    sources: [CSource; MAX_SOURCES],
    rules: [CRule; MAX_RULES],
    xforms: [CXform; MAX_XFORMS],
    gates: [CGate; MAX_GATES],
    invals: [CInval; MAX_INVALS],
}

// proc_state seed (bpf/taint_engine.bpf.h: { u64 labels; u64 lin_gates; }).
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcState {
    labels: u64,
    lin_gates: u64,
}

unsafe impl aya::Pod for CSource {}
unsafe impl aya::Pod for CRule {}
unsafe impl aya::Pod for CXform {}
unsafe impl aya::Pod for CGate {}
unsafe impl aya::Pod for CInval {}
unsafe impl aya::Pod for ProcState {}

// ringbuf event (bpf/process.h: struct event).
const EVENT_TYPE_TAINT_VIOLATION: i32 = 3;
const COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 127;

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    etype: i32,
    pid: i32,
    ppid: i32,
    blocked: u32,
    killed: u32,
    effect: u32,
    timestamp_ns: u64,
    comm: [u8; COMM_LEN],
    filename: [u8; FILENAME_LEN],
    taint_rule_id: u32,
    conn_ip: u32,
    taint_label: u64,
    matched_label: u64,
    prov_label: u64,
    prov_timestamp_ns: u64,
    prov_pid: i32,
    prov_op: u32,
    prov_ip: u32,
    prov_target: [u8; FILENAME_LEN],
}

/// Provenance for the label that caused a policy violation.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub label: u64,
    pub timestamp_ns: u64,
    pub pid: i32,
    pub op: u32,
    pub target: String,
}

/// A policy violation reported by the kernel.
#[derive(Debug, Clone)]
pub struct Violation {
    pub effect: u32, // 0 audit, 1 block, 2 kill
    pub blocked: bool,
    pub killed: bool,
    pub comm: String,
    pub pid: i32,
    pub ppid: i32,
    pub target: String, // exe/path, or "a.b.c.d" for connect
    pub rule_id: u32,
    pub label: u64,
    pub matched_label: u64,
    pub provenance: Option<Provenance>,
    pub timestamp_ns: u64,
}

/// Tracepoint programs: (fn name, category, event). Always attached.
const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("handle_fork", "sched", "sched_process_fork"),
    ("handle_exec", "sched", "sched_process_exec"),
    ("handle_exit", "sched", "sched_process_exit"),
    ("trace_openat", "syscalls", "sys_enter_openat"),
    ("trace_openat_exit", "syscalls", "sys_exit_openat"),
    ("trace_open", "syscalls", "sys_enter_open"),
    ("trace_open_exit", "syscalls", "sys_exit_open"),
    ("trace_openat2", "syscalls", "sys_enter_openat2"),
    ("trace_openat2_exit", "syscalls", "sys_exit_openat2"),
    ("trace_creat", "syscalls", "sys_enter_creat"),
    ("trace_creat_exit", "syscalls", "sys_exit_creat"),
    ("trace_truncate", "syscalls", "sys_enter_truncate"),
    ("trace_truncate_exit", "syscalls", "sys_exit_truncate"),
    ("trace_unlink", "syscalls", "sys_enter_unlink"),
    ("trace_unlinkat", "syscalls", "sys_enter_unlinkat"),
    ("trace_rename", "syscalls", "sys_enter_rename"),
    ("trace_renameat", "syscalls", "sys_enter_renameat"),
    ("trace_renameat2", "syscalls", "sys_enter_renameat2"),
    ("trace_connect", "syscalls", "sys_enter_connect"),
];

/// LSM programs: (fn name, hook). Attached only when BPF LSM is active.
const LSM_PROGS: &[(&str, &str)] = &[
    ("enforce_bprm_check_security", "bprm_check_security"),
    ("enforce_file_open", "file_open"),
    ("enforce_file_permission", "file_permission"),
    ("enforce_file_truncate", "file_truncate"),
    ("enforce_path_truncate", "path_truncate"),
    ("enforce_path_unlink", "path_unlink"),
    ("enforce_path_rename", "path_rename"),
    ("enforce_socket_connect", "socket_connect"),
];

/// True if `bpf` appears in the active LSM list (enables pre-op `block`).
pub fn bpf_lsm_active() -> bool {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open("/sys/kernel/security/lsm") {
        let _ = f.read_to_string(&mut s);
    }
    s.split(',').any(|x| x.trim() == "bpf")
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.into())
}

pub struct Loader {
    bpf: Ebpf,
    enforce: bool,
}

impl Loader {
    /// `config_blob` is the raw `struct taint_config` produced by the collector.
    pub fn load(config_blob: &[u8]) -> io::Result<Self> {
        if config_blob.len() != std::mem::size_of::<CConfig>() {
            return Err(err(format!(
                "config size mismatch: got {}, expected {}",
                config_blob.len(),
                std::mem::size_of::<CConfig>()
            )));
        }
        // Owned, aligned copy so we can borrow fields for set_global.
        let cfg: Box<CConfig> =
            Box::new(unsafe { std::ptr::read_unaligned(config_blob.as_ptr() as *const CConfig) });

        let enforce = bpf_lsm_active();
        let enforce_mode: u32 = if enforce { 1 } else { 0 };

        let mut loader = EbpfLoader::new();
        loader
            .set_global("enforce_mode", &enforce_mode, true)
            .set_global("n_sources", &cfg.n_sources, true)
            .set_global("n_rules", &cfg.n_rules, true)
            .set_global("n_xforms", &cfg.n_xforms, true)
            .set_global("n_gates", &cfg.n_gates, true)
            .set_global("n_invals", &cfg.n_invals, true)
            .set_global("taint_sources", &cfg.sources[..], true)
            .set_global("taint_rules", &cfg.rules[..], true)
            .set_global("taint_xforms", &cfg.xforms[..], true)
            .set_global("taint_gates", &cfg.gates[..], true)
            .set_global("taint_invals", &cfg.invals[..], true);

        let mut bpf = loader
            .load(object_bytes())
            .map_err(|e| err(format!("Ebpf::load: {e}")))?;

        // Loop counts in a (non-frozen) map so the verifier analyzes each
        // bpf_loop callback once. Slots: 0=rules 1=sources 2=xforms 3=gates 4=invals.
        {
            let mut counts: Array<_, u32> = Array::try_from(
                bpf.map_mut("ts_counts")
                    .ok_or_else(|| err("map ts_counts missing"))?,
            )
            .map_err(|e| err(format!("ts_counts: {e}")))?;
            let vals = [
                cfg.n_rules,
                cfg.n_sources,
                cfg.n_xforms,
                cfg.n_gates,
                cfg.n_invals,
            ];
            for (i, v) in vals.iter().enumerate() {
                counts
                    .set(i as u32, *v, 0)
                    .map_err(|e| err(format!("ts_counts[{i}]: {e}")))?;
            }
        }

        // Attach tracepoints (always) then LSM programs (only with BPF LSM).
        for (name, cat, event) in TRACEPOINTS {
            let p: &mut TracePoint = bpf
                .program_mut(name)
                .ok_or_else(|| err(format!("program {name} missing")))?
                .try_into()
                .map_err(|e| err(format!("{name} not a tracepoint: {e}")))?;
            p.load().map_err(|e| err(format!("{name}.load: {e}")))?;
            p.attach(cat, event)
                .map_err(|e| err(format!("{name}.attach: {e}")))?;
        }
        if enforce {
            let btf = Btf::from_sys_fs().map_err(|e| err(format!("btf: {e}")))?;
            for (name, hook) in LSM_PROGS {
                let p: &mut Lsm = bpf
                    .program_mut(name)
                    .ok_or_else(|| err(format!("program {name} missing")))?
                    .try_into()
                    .map_err(|e| err(format!("{name} not an lsm: {e}")))?;
                p.load(hook, &btf)
                    .map_err(|e| err(format!("{name}.load: {e}")))?;
                p.attach().map_err(|e| err(format!("{name}.attach: {e}")))?;
            }
        }

        Ok(Loader { bpf, enforce })
    }

    pub fn enforce_mode(&self) -> bool {
        self.enforce
    }

    /// Seed `pid` (and its future descendants) as the AGENT root with `label`.
    pub fn seed_agent(&mut self, pid: i32, label: u64) -> io::Result<()> {
        if pid <= 0 || label == 0 {
            return Err(err("agent pid and label must both be set"));
        }
        {
            let mut proc: HashMap<_, i32, ProcState> = HashMap::try_from(
                self.bpf
                    .map_mut("ts_proc")
                    .ok_or_else(|| err("ts_proc missing"))?,
            )
            .map_err(|e| err(format!("ts_proc: {e}")))?;
            proc.insert(
                pid,
                ProcState {
                    labels: label,
                    lin_gates: 0,
                },
                0,
            )
            .map_err(|e| err(format!("seed ts_proc: {e}")))?;
        }
        {
            let mut root: HashMap<_, i32, i32> = HashMap::try_from(
                self.bpf
                    .map_mut("ts_root")
                    .ok_or_else(|| err("ts_root missing"))?,
            )
            .map_err(|e| err(format!("ts_root: {e}")))?;
            root.insert(pid, pid, 0)
                .map_err(|e| err(format!("seed ts_root: {e}")))?;
        }
        Ok(())
    }

    /// Poll the ring buffer until `stop` is set, delivering each violation.
    pub fn run(&mut self, stop: &AtomicBool, mut on: impl FnMut(Violation)) -> io::Result<()> {
        let mut ring = RingBuf::try_from(self.bpf.map_mut("rb").ok_or_else(|| err("rb missing"))?)
            .map_err(|e| err(format!("rb: {e}")))?;
        let fd = ring.as_raw_fd();

        while !stop.load(Ordering::Relaxed) {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let r = unsafe { libc::poll(&mut pfd, 1, 100) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < std::mem::size_of::<Event>() {
                    continue;
                }
                let e: Event = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const Event) };
                if e.etype != EVENT_TYPE_TAINT_VIOLATION {
                    continue;
                }
                on(decode(&e));
            }
        }
        Ok(())
    }
}

fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn decode(e: &Event) -> Violation {
    let target = if e.conn_ip != 0 {
        let ip = e.conn_ip; // network order: bytes are a.b.c.d in memory
        format!(
            "{}.{}.{}.{}",
            ip & 0xff,
            (ip >> 8) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 24) & 0xff
        )
    } else {
        cstr(&e.filename)
    };
    let provenance = if e.prov_label != 0 {
        let target = if e.prov_ip != 0 {
            let ip = e.prov_ip;
            format!(
                "{}.{}.{}.{}",
                ip & 0xff,
                (ip >> 8) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 24) & 0xff
            )
        } else {
            cstr(&e.prov_target)
        };
        Some(Provenance {
            label: e.prov_label,
            timestamp_ns: e.prov_timestamp_ns,
            pid: e.prov_pid,
            op: e.prov_op,
            target,
        })
    } else {
        None
    };
    Violation {
        effect: e.effect,
        blocked: e.blocked != 0,
        killed: e.killed != 0,
        comm: cstr(&e.comm),
        pid: e.pid,
        ppid: e.ppid,
        target,
        rule_id: e.taint_rule_id,
        label: e.taint_label,
        matched_label: e.matched_label,
        provenance,
        timestamp_ns: e.timestamp_ns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Rust ABI mirror must match the C struct sizes the object was built
    // with. These are the documented sizes from bpf/taint.h.
    #[test]
    fn abi_sizes() {
        assert_eq!(std::mem::size_of::<ProcState>(), 16);
        // CConfig = 5 u32 (+pad) + the five arrays; just assert it is non-trivial
        // and 8-aligned so set_global offsets line up.
        assert_eq!(std::mem::align_of::<CConfig>(), 8);
        assert!(std::mem::size_of::<CConfig>() > 0);
    }

    #[test]
    fn object_is_aligned_elf() {
        let b = object_bytes();
        assert_eq!(b.as_ptr() as usize % 8, 0, "object must be 8-aligned");
        assert_eq!(&b[..4], b"\x7fELF");
    }
}
