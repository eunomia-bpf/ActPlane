// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Userspace policy simulator for the lowered kernel tables.
//!
//! This is a **test oracle**, not a second enforcement engine. It replays a
//! trace of [SimEvent]s against the lowered update/rule tables a policy
//! compiles to ([crate::lower::Compiled::tables]) and reports the [SimHit]s
//! the tracepoint-mode kernel engine would have emitted. Every path mirrors
//! the non-legacy kernel bodies in `bpf/taint_engine.bpf.h` /
//! `bpf/process.bpf.c` (domain 0 only), so a mismatch between the sim and
//! the live engine is a fidelity bug to chase, not a second source of truth.

use std::collections::{HashMap, HashSet};

use super::lower::{CRule, CUpdate, Compiled};

// ABI constant values, byte-identical to bpf/taint.h (pinned by the ABI
// guards in lower.rs / bpf/test_taint.c). The sim matches against the
// lowered table values, so it must use the same discriminants.
const M_EXACT: u8 = 0;
const M_PREFIX: u8 = 1;
const M_SUFFIX: u8 = 2;
const M_ANY: u8 = 3;
const M_CONTAINS: u8 = 4;

const OP_EXEC: u8 = 0;
const OP_OPEN: u8 = 1;
const OP_WRITE: u8 = 2;
const OP_CONNECT: u8 = 3;
const OP_RECV: u8 = 4;

const COND_NONE: u8 = 0;
const COND_LINEAGE: u8 = 1;
const COND_AFTER: u8 = 2;
const COND_TARGET: u8 = 3;

const EFFECT_NOTIFY: u8 = 0;
const EFFECT_BLOCK: u8 = 1;
const EFFECT_KILL: u8 = 2;
const EFFECT_UNSUPPORTED: u8 = 3;

const GATE_IMMEDIATE: i32 = -1;

/// TAINT_SUF_MAX: the kernel caps suffix/contains literals at 16 bytes
/// (bpf/taint.h). The compiler already enforces the cap, but the matcher
/// mirrors it for fidelity.
const SUF_MAX: usize = 16;

/// TE_POLICY_* feature bits (bpf/capability.bpf.h). Only the bits that gate
/// the tracepoint path are consulted by the sim; the BLOCK_* bits gate LSM
/// hook attachment and never gate the tracepoint scan.
const FEAT_PATH_CONTAINS: u32 = 1 << 0;
const FEAT_PATH_SUFFIX: u32 = 1 << 1;
const FEAT_OPEN_RULES: u32 = 1 << 2;
const FEAT_WRITE_RULES: u32 = 1 << 3;
const FEAT_CONNECT: u32 = 1 << 4;
const FEAT_RECV: u32 = 1 << 5;
const FEAT_FILE_FLOW: u32 = 1 << 6;

/// `config_features` in bpf/process.c, ported verbatim over the lowered
/// tables. The loader uses the same value to decide which hooks attach and
/// which tracepoint branches are reachable; the sim uses it to gate the
/// same branches (connect/recv tracepoint calls, open/write rule passes,
/// file flows).
pub fn policy_features(c: &Compiled) -> u32 {
    let (updates, rules) = c.tables();
    let mut features: u32 = 0;

    for u in updates {
        if u.op == OP_OPEN || u.op == OP_WRITE {
            features |= FEAT_FILE_FLOW | path_match_features(u.m);
        }
        if u.op == OP_CONNECT {
            features |= FEAT_CONNECT;
        }
        if u.op == OP_RECV {
            features |= FEAT_RECV;
        }
    }
    for r in rules {
        if r.effect == EFFECT_BLOCK {
            // TE_POLICY_BLOCK_EXEC / BLOCK_FILE / BLOCK_CONNECT: LSM-only
            // bits, set but never consulted by the tracepoint sim.
            // (kept as a comment branch so the port is auditable)
        }
        if r.op == OP_OPEN {
            features |= FEAT_OPEN_RULES | path_match_features(r.m);
            if r.cond_kind == COND_TARGET {
                features |= path_match_features(r.cond_match);
            }
        }
        if r.op == OP_WRITE {
            features |= FEAT_FILE_FLOW | FEAT_WRITE_RULES | path_match_features(r.m);
            if r.cond_kind == COND_TARGET {
                features |= path_match_features(r.cond_match);
            }
        }
        if r.op == OP_CONNECT {
            features |= FEAT_CONNECT;
        }
        if r.op == OP_RECV {
            features |= FEAT_RECV;
        }
    }
    features
}

fn path_match_features(m: u8) -> u32 {
    match m {
        M_CONTAINS => FEAT_PATH_CONTAINS,
        M_SUFFIX => FEAT_PATH_SUFFIX,
        _ => 0,
    }
}

/// One OS event in a simulated trace. All events are per-pid; a pid must be
/// created by a [SimEvent::Seed] (the enforcer's seed pid) or a
/// [SimEvent::Fork] whose parent is active, mirroring `te_pid_active`.
#[derive(Debug, Clone, PartialEq)]
pub enum SimEvent {
    /// Enforcer attach: `ts_proc[pid] = {labels: 0}`, `ts_root[pid] = pid`.
    Seed { pid: u32 },
    /// fork: the child inherits labels + lineage gates; root carries down.
    Fork { parent: u32, child: u32 },
    /// exec: `comm` is the task comm (basename, the match target); `argv`
    /// supplies the argv token slots for `@arg` matching (argv[1..]).
    Exec {
        pid: u32,
        comm: String,
        argv: Vec<String>,
    },
    /// Open for read (the sim's read access; open-rule pass + read flow).
    Read { pid: u32, path: String },
    /// Open for write: handle_open_exit materializes the file source, then
    /// the write-rule pass + write flow.
    Write { pid: u32, path: String },
    /// Unlink: the kernel fires this as a WRITE-access file event, so the
    /// write-rule pass + write flow run (but handle_open_exit's source
    /// materialize does not).
    Unlink { pid: u32, path: String },
    /// connect(2) to a numeric IPv4 peer (network-byte-order octets).
    Connect { pid: u32, ip: [u8; 4] },
    /// Recv-side ingress from a numeric IPv4 peer.
    Recv { pid: u32, ip: [u8; 4] },
    /// exit: the raw status is `code << 8` (a plain exit, not a signal).
    Exit { pid: u32, code: u8 },
}

/// A violation the kernel engine would have emitted for one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimHit {
    /// The task comm at the event.
    pub comm: String,
    /// Rendered target: dotted-quad IP for connect/recv, the path for file
    /// events, the comm for exec.
    pub target: String,
    /// The effect of the matched rule in tracepoint mode: NOTIFY(0) or
    /// KILL(2). BLOCK rules never fire in tracepoint mode.
    pub effect: u8,
    /// The lowered rule's `rule_id`.
    pub rule_id: u32,
}

#[derive(Clone)]
struct PidState {
    labels: u64,
    lin_gates: u64,
    comm: String,
}

#[derive(Clone)]
struct Sess {
    gate_bits: u64,
    epoch: u32,
    gate_epoch: [u32; 64],
    inval_epoch: [u32; 64],
}

impl Default for Sess {
    fn default() -> Self {
        Self {
            gate_bits: 0,
            epoch: 0,
            gate_epoch: [0; 64],
            inval_epoch: [0; 64],
        }
    }
}

struct SimState {
    features: u32,
    /// cap_task_bound: the pids the engine tracks.
    active: HashSet<u32>,
    /// ts_root: pid -> root pid (one session per test unless re-rooted).
    root: HashMap<u32, u32>,
    proc: HashMap<u32, PidState>,
    /// ts_sess, keyed by root pid; created lazily on the first tick.
    sess: HashMap<u32, Sess>,
    /// ts_file (domain 0): path -> stored labels.
    file: HashMap<String, u64>,
    /// ts_endp (domain 0): ip -> labels.
    endp: HashMap<u32, u64>,
    /// ts_exit_gates: pid -> (pending gates, exec epoch).
    exit_gates: HashMap<u32, (u64, u32)>,
    updates: Vec<CUpdate>,
    rules: Vec<CRule>,
    hits: Vec<SimHit>,
}

/// Replay `events` against the policy `c` and return the hits the
/// tracepoint-mode kernel engine would have emitted, in event order.
///
/// The sim models domain 0 in tracepoint mode (supported effects
/// NOTIFY + KILL), the exact mode the loader runs in without BPF LSM.
pub fn simulate(c: &Compiled, events: &[SimEvent]) -> Vec<SimHit> {
    let (updates, rules) = c.tables();
    let mut s = SimState {
        features: policy_features(c),
        active: HashSet::new(),
        root: HashMap::new(),
        proc: HashMap::new(),
        sess: HashMap::new(),
        file: HashMap::new(),
        endp: HashMap::new(),
        exit_gates: HashMap::new(),
        updates: updates.to_vec(),
        rules: rules.to_vec(),
        hits: Vec::new(),
    };
    for ev in events {
        match ev {
            SimEvent::Seed { pid } => s.seed(*pid),
            SimEvent::Fork { parent, child } => s.fork(*parent, *child),
            SimEvent::Exec { pid, comm, argv } => s.exec(*pid, comm, argv),
            SimEvent::Read { pid, path } => s.read_file(*pid, path),
            SimEvent::Write { pid, path } => s.write_file(*pid, path, true),
            SimEvent::Unlink { pid, path } => s.write_file(*pid, path, false),
            SimEvent::Connect { pid, ip } => s.connect(*pid, ip),
            SimEvent::Recv { pid, ip } => s.recv(*pid, ip),
            SimEvent::Exit { pid, code } => s.exit(*pid, *code),
        }
    }
    s.hits
}

impl SimState {
    fn seed(&mut self, pid: u32) {
        // seed_initial_label in bpf/process.c: active, 0 labels, own root.
        self.active.insert(pid);
        self.root.insert(pid, pid);
        self.proc.insert(
            pid,
            PidState {
                labels: 0,
                lin_gates: 0,
                comm: "bash".into(),
            },
        );
    }

    fn fork(&mut self, parent: u32, child: u32) {
        // te_fork: no-op unless the parent is active; copies proc state,
        // carries the root down.
        if !self.active.contains(&parent) {
            return;
        }
        if let Some(p) = self.proc.get(&parent).cloned() {
            self.proc.insert(child, p);
        }
        self.active.insert(child);
        self.root
            .insert(child, self.root.get(&parent).copied().unwrap_or(parent));
    }

    fn comm(&self, pid: u32) -> String {
        self.proc
            .get(&pid)
            .map(|p| p.comm.clone())
            .unwrap_or_default()
    }

    fn kill(&mut self, pid: u32) {
        // bpf_send_signal(SIGKILL): the pid is gone; later events naming it
        // are no-ops via te_pid_active.
        self.active.remove(&pid);
        self.proc.remove(&pid);
        self.exit_gates.remove(&pid);
    }

    fn tick(&mut self, root: u32) -> u32 {
        // te_tick: lazily create the session (absent = all-zero), epoch += 1.
        let s = self.sess.entry(root).or_default();
        s.epoch += 1;
        s.epoch
    }

    fn stamp(&mut self, root: u32, ep: u32, gate_hits: u64, inval_hits: u64) {
        // te_stamp: no-op unless ep != 0 and something fired; gate bits
        // latch into gate_bits, both epoch arrays record at ep.
        if ep == 0 || (gate_hits == 0 && inval_hits == 0) {
            return;
        }
        let s = self.sess.entry(root).or_default();
        s.gate_bits |= gate_hits;
        for i in 0..64u32 {
            if gate_hits & (1u64 << i) != 0 {
                s.gate_epoch[i as usize] = ep;
            }
            if inval_hits & (1u64 << i) != 0 {
                s.inval_epoch[i as usize] = ep;
            }
        }
    }

    fn after_satisfied(&self, r: &CRule, pid: u32) -> bool {
        // te_after_satisfied over the root session: latching when
        // since_mask == 0, freshness (gate epoch > last inval epoch)
        // otherwise.
        let Some(&rt) = self.root.get(&pid) else {
            return false;
        };
        let Some(s) = self.sess.get(&rt) else {
            return false;
        };
        if r.since_mask == 0 {
            return (s.gate_bits & r.gate) != 0;
        }
        let ge = s.gate_epoch[r.gate_idx as usize];
        if ge == 0 {
            return false;
        }
        let mut last_inval = 0u32;
        for i in 0..64u32 {
            if r.since_mask & (1u64 << i) != 0 {
                last_inval = last_inval.max(s.inval_epoch[i as usize]);
            }
        }
        ge > last_inval
    }

    /// exec-update collection mirroring te_exec_update_simple_cb +
    /// te_exec_update_prefix_cb: the simple pass collects ANY/EXACT rows
    /// (with the arg check), the prefix pass collects every other row via
    /// taint_exec_match. `comm` is the match target (the task comm).
    fn collect_exec_updates(&self, comm: &str, argv: &[String]) -> (u64, u64, u64, u64, u64) {
        let mut add = 0u64;
        let mut del = 0u64;
        let mut gates = 0u64;
        let mut exit_gates = 0u64;
        let mut invals = 0u64;
        for u in self
            .updates
            .iter()
            .filter(|u| u.op == OP_EXEC && u.domain_id == 0)
        {
            let m = if u.m == M_EXACT || u.m == M_ANY {
                exec_simple_match(u.m, comm, u.pat())
            } else {
                exec_match(u.m, comm, u.pat())
            };
            if !m || !arg_match(argv, u.arg_str()) {
                continue;
            }
            add |= u.add;
            del |= u.del;
            if u.gate_exit_code == GATE_IMMEDIATE {
                gates |= u.gates;
            } else {
                exit_gates |= u.gates;
            }
            invals |= u.invals;
        }
        (add, del, gates, exit_gates, invals)
    }

    fn exec(&mut self, pid: u32, comm: &str, argv: &[String]) {
        // handle_exec_args tail chain: guard on activity, collect simple,
        // collect prefix, apply, scan simple, scan complex, finish.
        if !self.active.contains(&pid) {
            return;
        }
        // Collect the update deltas before taking the mutable proc slot,
        // matching the kernel's read order (the update scan is pure).
        let (add, del, gates, exit_gates, invals) = self.collect_exec_updates(comm, argv);

        let Some(p) = self.proc.get_mut(&pid) else {
            return;
        };
        p.comm = comm.to_string();

        // apply: labels = (labels | add) & ~del; lin_gates |= gates;
        // tick + stamp when anything latched; store or clear exit-gates.
        p.labels = (p.labels | add) & !del;
        p.lin_gates |= gates;
        let rt = self.root.get(&pid).copied().unwrap_or(pid);
        let labels_after = p.labels;
        if gates != 0 || exit_gates != 0 || invals != 0 {
            let ep = self.tick(rt);
            if gates != 0 || invals != 0 {
                self.stamp(rt, ep, gates, invals);
            }
            if exit_gates != 0 {
                self.exit_gates.insert(pid, (exit_gates, ep));
            } else {
                self.exit_gates.remove(&pid);
            }
        } else {
            self.exit_gates.remove(&pid);
        }

        // Two-pass rule merge (exec_pipe_scan_rules + exec_pipe_merge_rule):
        // the simple pass (ANY/EXACT, cond NONE) records the best; if it
        // already found KILL the complex pass is skipped. The rule scan
        // reads the labels AFTER update application, matching
        // exec_pipe_scan_rules.
        let mut best_rule = -1i32;
        let mut best_index = -1i32;
        let mut best_effect: i32 = EFFECT_NOTIFY as i32;
        for (idx, r) in self.rules.iter().enumerate() {
            let eff = self.exec_simple_effect(r, labels_after, comm, argv);
            if eff < 0 {
                continue;
            }
            if best_rule < 0 || eff > best_effect {
                best_rule = r.rule_id as i32;
                best_index = idx as i32;
                best_effect = eff;
                if best_effect == EFFECT_KILL as i32 {
                    break;
                }
            }
        }
        if best_effect != EFFECT_KILL as i32 {
            for (idx, r) in self.rules.iter().enumerate() {
                let eff = self.exec_complex_effect(r, labels_after, comm, argv, pid);
                if eff < 0 {
                    continue;
                }
                // exec_pipe_merge_rule: replace on higher effect, or on the
                // same effect with the lower rule index.
                if best_rule < 0
                    || eff > best_effect
                    || (eff == best_effect && (best_index < 0 || (idx as i32) < best_index))
                {
                    best_rule = r.rule_id as i32;
                    best_index = idx as i32;
                    best_effect = eff;
                }
            }
        }

        if best_rule >= 0 && effect_mode(best_effect as u8) != EFFECT_UNSUPPORTED {
            self.hits.push(SimHit {
                comm: comm.to_string(),
                target: comm.to_string(),
                effect: best_effect as u8,
                rule_id: best_rule as u32,
            });
            if best_effect == EFFECT_KILL as i32 {
                self.kill(pid);
            }
        }
    }

    /// te_rule_effect_exec_simple: requires cond NONE, matches ANY/EXACT
    /// only, then the arg check. Returns the effect, or -1.
    fn exec_simple_effect(&self, r: &CRule, labels: u64, comm: &str, argv: &[String]) -> i32 {
        if r.op != OP_EXEC || r.cond_kind != COND_NONE {
            return -1;
        }
        let eff = effect_mode(r.effect);
        if eff == EFFECT_UNSUPPORTED || (eff != EFFECT_KILL && eff != EFFECT_NOTIFY) {
            // tracepoint effect_mask = NOTIFY | KILL.
            return -1;
        }
        if !mask_ok(labels, r.req, r.forbid) {
            return -1;
        }
        if !exec_simple_match(r.m, comm, r.pat()) {
            return -1;
        }
        if !arg_match(argv, r.arg_str()) {
            return -1;
        }
        eff as i32
    }

    /// te_rule_effect_exec_complex: the simple pass already covered
    /// EXACT/ANY rows with cond NONE, so skip those; every other row uses
    /// taint_exec_match + arg + the condition.
    fn exec_complex_effect(
        &self,
        r: &CRule,
        labels: u64,
        comm: &str,
        argv: &[String],
        pid: u32,
    ) -> i32 {
        if r.op != OP_EXEC {
            return -1;
        }
        if (r.m == M_EXACT || r.m == M_ANY) && r.cond_kind == COND_NONE {
            return -1;
        }
        let eff = effect_mode(r.effect);
        if eff == EFFECT_UNSUPPORTED || (eff != EFFECT_KILL && eff != EFFECT_NOTIFY) {
            return -1;
        }
        if !mask_ok(labels, r.req, r.forbid) {
            return -1;
        }
        if !exec_match(r.m, comm, r.pat()) {
            return -1;
        }
        if !arg_match(argv, r.arg_str()) {
            return -1;
        }
        if self.cond_satisfied(r, pid, None, None) {
            return -1;
        }
        eff as i32
    }

    /// OR of the add of matching file-source update rows (te_update_add_file_domain).
    fn file_source(&self, path: &str) -> u64 {
        let mut add = 0u64;
        for u in self
            .updates
            .iter()
            .filter(|u| u.op == OP_OPEN && u.domain_id == 0)
        {
            if path_match(u.m, path, u.pat(), self.features) {
                add |= u.add;
            }
        }
        add
    }

    fn file_stored(&self, path: &str) -> u64 {
        *self.file.get(path).unwrap_or(&0)
    }

    /// te_file_labels_domain: stored labels OR the path's source labels.
    fn file_labels(&self, path: &str) -> u64 {
        self.file_stored(path) | self.file_source(path)
    }

    /// Open for read: handle_open_exit materializes the file source (gated
    /// on FILE_FLOW), then the open-rule pass (gated on OPEN_RULES, seeing
    /// the proc labels plus the file's labels when FILE_FLOW is on), then
    /// the read flow (gated on FILE_FLOW). Tracepoint-mode KILL is async
    /// (the kernel's SIGKILL lands after the syscall completes), so the
    /// flow tail still runs after a KILL hit and the kill is applied only
    /// after it.
    fn read_file(&mut self, pid: u32, path: &str) {
        if !self.active.contains(&pid) {
            return;
        }
        // handle_open_exit materializes the path's source labels into the
        // file-object state so later reads inherit them.
        if self.features & FEAT_FILE_FLOW != 0 {
            let src = self.file_source(path);
            if src != 0 {
                *self.file.entry(path.to_string()).or_insert(0) |= src;
            }
        }
        let labels = self.proc.get(&pid).map(|p| p.labels).unwrap_or(0);
        // te_handle_file_event folds the file's labels (stored + source)
        // into the rule-check labels for read access when FILE_FLOW is on.
        let include = self.features & FEAT_FILE_FLOW != 0;
        let kill = if self.features & FEAT_OPEN_RULES != 0 {
            matches!(
                self.rule_pass(pid, OP_OPEN, labels, Some(path), None, include),
                Some(EFFECT_KILL)
            )
        } else {
            false
        };
        if self.features & FEAT_FILE_FLOW != 0 {
            // te_read: proc absorbs the file's labels (stored + source);
            // stamp any matched open-update gates/invals at this epoch.
            let fl = self.file_labels(path);
            if let Some(p) = self.proc.get_mut(&pid) {
                p.labels |= fl;
            }
            let (gates, invals) = self.update_stamp(OP_OPEN, path);
            if gates != 0 || invals != 0 {
                let rt = self.root.get(&pid).copied().unwrap_or(pid);
                let ep = self.tick(rt);
                self.stamp(rt, ep, gates, invals);
            }
        }
        if kill {
            self.kill(pid);
        }
    }

    /// Write-open or unlink access, both of which the kernel delivers to
    /// te_handle_file_event as a WRITE-access event: the write-rule pass
    /// (gated on WRITE_RULES, proc labels only since include_file_labels is
    /// read-only) then the write flow (gated on FILE_FLOW). Only a real
    /// open (write-open) additionally runs handle_open_exit's source
    /// materialize; the unlink tracepoint path has no materialize step.
    /// As with reads, the flow runs even after a KILL hit.
    fn write_file(&mut self, pid: u32, path: &str, is_write_open: bool) {
        if !self.active.contains(&pid) {
            return;
        }
        if is_write_open && self.features & FEAT_FILE_FLOW != 0 {
            let src = self.file_source(path);
            if src != 0 {
                *self.file.entry(path.to_string()).or_insert(0) |= src;
            }
        }
        let labels = self.proc.get(&pid).map(|p| p.labels).unwrap_or(0);
        let kill = if self.features & FEAT_WRITE_RULES != 0 {
            matches!(
                self.rule_pass(pid, OP_WRITE, labels, Some(path), None, false),
                Some(EFFECT_KILL)
            )
        } else {
            false
        };
        if self.features & FEAT_FILE_FLOW != 0 {
            // te_write_flow: tick + stamp even when the proc carries no
            // labels (editing an unlabeled file still invalidates a prior
            // gate); the file absorbs the labels only when pl != 0.
            let (gates, invals) = self.update_stamp(OP_WRITE, path);
            if gates != 0 || invals != 0 || labels != 0 {
                let rt = self.root.get(&pid).copied().unwrap_or(pid);
                let ep = self.tick(rt);
                if gates != 0 || invals != 0 {
                    self.stamp(rt, ep, gates, invals);
                }
                if labels != 0 {
                    *self.file.entry(path.to_string()).or_insert(0) |= labels;
                }
            }
        }
        if kill {
            self.kill(pid);
        }
    }

    fn connect(&mut self, pid: u32, ip: &[u8; 4]) {
        if !self.active.contains(&pid) {
            return;
        }
        // The connect tracepoint reaches te_handle_net_ip only when the
        // loader attached it, i.e. policy_features & TE_POLICY_CONNECT.
        if self.features & FEAT_CONNECT == 0 {
            return;
        }
        let ip32 = ip_to_u32(ip);
        // te_handle_event ORs the connect source into the labels before the
        // rule check.
        let conn_src = self.endpoint_source(OP_CONNECT, ip32);
        let labels = self.proc.get(&pid).map(|p| p.labels).unwrap_or(0) | conn_src;
        let kill = matches!(
            self.rule_pass(pid, OP_CONNECT, labels, None, Some(ip32), false),
            Some(EFFECT_KILL)
        );
        // te_connect_flow: proc absorbs the connect source; the endpoint
        // records the (now updated) proc labels. The flow runs even after a
        // KILL hit; the kill lands after it.
        if let Some(p) = self.proc.get_mut(&pid) {
            p.labels |= conn_src;
            if p.labels != 0 {
                *self.endp.entry(ip32).or_insert(0) |= p.labels;
            }
        }
        if kill {
            self.kill(pid);
        }
    }

    fn recv(&mut self, pid: u32, ip: &[u8; 4]) {
        if !self.active.contains(&pid) {
            return;
        }
        if self.features & FEAT_RECV == 0 {
            return;
        }
        let ip32 = ip_to_u32(ip);
        let stored = *self.endp.get(&ip32).unwrap_or(&0);
        let src = self.endpoint_source(OP_RECV, ip32);
        let rcv = stored | src;
        let labels = self.proc.get(&pid).map(|p| p.labels).unwrap_or(0) | rcv;
        let kill = matches!(
            self.rule_pass(pid, OP_RECV, labels, None, Some(ip32), false),
            Some(EFFECT_KILL)
        );
        // te_recv_flow: proc absorbs the endpoint's labels. The flow runs
        // even after a KILL hit; the kill lands after it.
        if rcv != 0 {
            if let Some(p) = self.proc.get_mut(&pid) {
                p.labels |= rcv;
            }
        }
        if kill {
            self.kill(pid);
        }
    }

    fn endpoint_source(&self, op: u8, ip32: u32) -> u64 {
        let mut add = 0u64;
        for u in self
            .updates
            .iter()
            .filter(|u| u.op == op && u.domain_id == 0)
        {
            if (ip32 & u.ipv4_mask) == u.ipv4 {
                add |= u.add;
            }
        }
        add
    }

    /// OR of the update gates/invals matching this event's op+target; used
    /// for the read/write flow stamping (te_read_domain /
    /// te_write_flow_domain).
    fn update_stamp(&self, op: u8, path: &str) -> (u64, u64) {
        let mut gates = 0u64;
        let mut invals = 0u64;
        for u in self
            .updates
            .iter()
            .filter(|u| u.op == op && u.domain_id == 0)
        {
            if !path_match(u.m, path, u.pat(), self.features) {
                continue;
            }
            if u.gate_exit_code == GATE_IMMEDIATE {
                gates |= u.gates;
            }
            invals |= u.invals;
        }
        (gates, invals)
    }

    /// The non-exec rule pass: one scan with te_better_match semantics
    /// (replace on strictly better effect, break on KILL). Records the hit
    /// and returns the winning effect; it does not kill, so the caller
    /// runs the event's flow tail first and applies `kill` only on a KILL
    /// hit, matching the kernel's async SIGKILL in tracepoint mode.
    fn rule_pass(
        &mut self,
        pid: u32,
        op: u8,
        labels: u64,
        target: Option<&str>,
        ip: Option<u32>,
        include_file_labels: bool,
    ) -> Option<u8> {
        let mut best_rule = -1i32;
        let mut best_effect = EFFECT_NOTIFY;
        for r in self.rules.iter().filter(|r| r.op == op && r.domain_id == 0) {
            let eff = effect_mode(r.effect);
            if eff == EFFECT_UNSUPPORTED || (eff != EFFECT_KILL && eff != EFFECT_NOTIFY) {
                continue;
            }
            let mut l = labels;
            if include_file_labels {
                if let Some(t) = target {
                    l |= self.file_stored(t);
                }
            }
            if !mask_ok(l, r.req, r.forbid) {
                continue;
            }
            if let Some(ip32) = ip {
                if (ip32 & r.ipv4_mask) != r.ipv4 {
                    continue;
                }
            } else {
                let target = target.unwrap_or("");
                if !path_match(r.m, target, r.pat(), self.features) {
                    continue;
                }
            }
            if self.cond_satisfied(r, pid, target, ip) {
                continue;
            }
            if best_rule < 0 || eff > best_effect {
                best_rule = r.rule_id as i32;
                best_effect = eff;
                if best_effect == EFFECT_KILL {
                    break;
                }
            }
        }
        if best_rule < 0 {
            return None;
        }
        let target_str = match ip {
            Some(ip32) => ip_to_str(ip32),
            None => target.map(|t| t.to_string()).unwrap_or_default(),
        };
        self.hits.push(SimHit {
            comm: self.comm(pid),
            target: target_str,
            effect: best_effect,
            rule_id: best_rule as u32,
        });
        Some(best_effect)
    }

    fn cond_satisfied(&self, r: &CRule, pid: u32, target: Option<&str>, ip: Option<u32>) -> bool {
        // te_cond_satisfied: a satisfied condition suppresses the rule.
        match r.cond_kind {
            COND_NONE => false,
            COND_LINEAGE => {
                let Some(p) = self.proc.get(&pid) else {
                    return false;
                };
                (p.lin_gates & r.gate) != 0
            }
            COND_AFTER => self.after_satisfied(r, pid),
            COND_TARGET => {
                let m = match ip {
                    Some(ip32) => (ip32 & r.cond_ipv4_mask) == r.cond_ipv4,
                    None => match r.op {
                        OP_EXEC => exec_match(r.cond_match, target.unwrap_or(""), r.cond_pat_str()),
                        _ => path_match(
                            r.cond_match,
                            target.unwrap_or(""),
                            r.cond_pat_str(),
                            self.features,
                        ),
                    },
                };
                if r.cond_neg != 0 { !m } else { m }
            }
            _ => false,
        }
    }

    fn exit(&mut self, pid: u32, code: u8) {
        // te_exit: settle any pending exit gates at their original epoch,
        // then delete the pid.
        if !self.active.contains(&pid) {
            return;
        }
        let raw = (code as i32) << 8;
        if let Some((pending, epoch)) = self.exit_gates.remove(&pid) {
            if pending != 0 {
                let mut hits = 0u64;
                for u in self
                    .updates
                    .iter()
                    .filter(|u| u.op == OP_EXEC && u.domain_id == 0)
                {
                    let matched = pending & u.gates;
                    if matched == 0 || u.gate_exit_code == GATE_IMMEDIATE {
                        continue;
                    }
                    // te_exit_status_matches against raw = code << 8.
                    if raw & 0x7f == 0
                        && (((raw >> 8) & 0xff) as u8) == (u.gate_exit_code & 0xff) as u8
                    {
                        hits |= matched;
                    }
                }
                if hits != 0 {
                    let rt = self.root.get(&pid).copied().unwrap_or(pid);
                    self.stamp(rt, epoch, hits, 0);
                }
            }
        }
        self.kill(pid);
    }
}

// --- matchers, ported from bpf/taint.h (non-BPF fallbacks) --------------

fn streq(text: &str, pat: &str) -> bool {
    text == pat
}

fn prefix(text: &str, pre: &str) -> bool {
    !pre.is_empty() && text.starts_with(pre)
}

fn suffix(text: &str, suf: &str) -> bool {
    !suf.is_empty() && suf.len() <= SUF_MAX && text.ends_with(suf)
}

fn contains(text: &str, pat: &str) -> bool {
    !pat.is_empty() && text.contains(pat)
}

/// taint_match with the feature gating (te_path_match): SUFFIX/CONTAINS
/// matchers only run when their feature bit is set.
fn path_match(m: u8, text: &str, pat: &str, features: u32) -> bool {
    match m {
        M_PREFIX => prefix(text, pat),
        M_ANY => true,
        M_SUFFIX => (features & FEAT_PATH_SUFFIX != 0) && suffix(text, pat),
        M_CONTAINS => (features & FEAT_PATH_CONTAINS != 0) && contains(text, pat),
        _ => streq(text, pat),
    }
}

/// te_exec_rule_match / taint_exec_match: PREFIX runs the prefix matcher,
/// ANY matches everything, anything else is an exact comm comparison
/// (SUFFIX/CONTAINS are unsupported on exec and fall back to exact).
fn exec_match(m: u8, comm: &str, pat: &str) -> bool {
    match m {
        M_PREFIX => prefix(comm, pat),
        M_ANY => true,
        _ => streq(comm, pat),
    }
}

/// te_exec_simple_match: only ANY/EXACT in the simple pass.
fn exec_simple_match(m: u8, comm: &str, pat: &str) -> bool {
    match m {
        M_ANY => true,
        M_EXACT => streq(comm, pat),
        _ => false,
    }
}

fn mask_ok(labels: u64, req: u64, forbid: u64) -> bool {
    (labels & req) == req && (labels & forbid) == 0
}

/// taint_arg_match over the tokenized argv: an empty token matches,
/// otherwise some argv slot must equal it.
fn arg_match(argv: &[String], tok: &str) -> bool {
    tok.is_empty() || argv.iter().any(|a| a == tok)
}

/// te_effect_mode in tracepoint mode (NOTIFY=0): NOTIFY->NOTIFY,
/// KILL->KILL, BLOCK->UNSUPPORTED (never fires without BPF LSM).
fn effect_mode(effect: u8) -> u8 {
    match effect {
        EFFECT_NOTIFY => EFFECT_NOTIFY,
        EFFECT_KILL => EFFECT_KILL,
        _ => EFFECT_UNSUPPORTED,
    }
}

fn ip_to_u32(o: &[u8; 4]) -> u32 {
    // The kernel's in-memory IPv4 is the network-byte-order octets read as
    // a little-endian u32: the first octet in the low byte.
    u32::from_le_bytes([o[0], o[1], o[2], o[3]])
}

fn ip_to_str(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip & 0xff) as u8,
        ((ip >> 8) & 0xff) as u8,
        ((ip >> 16) & 0xff) as u8,
        ((ip >> 24) & 0xff) as u8
    )
}

trait CUpdateExt {
    fn pat(&self) -> &str;
    fn arg_str(&self) -> &str;
}

impl CUpdateExt for CUpdate {
    fn pat(&self) -> &str {
        cstr(&self.target)
    }
    fn arg_str(&self) -> &str {
        cstr(&self.arg)
    }
}

trait CRuleExt {
    fn pat(&self) -> &str;
    fn arg_str(&self) -> &str;
    fn cond_pat_str(&self) -> &str;
}

impl CRuleExt for CRule {
    fn pat(&self) -> &str {
        cstr(&self.target)
    }
    fn arg_str(&self) -> &str {
        cstr(&self.arg)
    }
    fn cond_pat_str(&self) -> &str {
        cstr(&self.cond_pat)
    }
}

fn cstr(buf: &[u8]) -> &str {
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..n]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile_str;

    const EP: [u8; 4] = [10, 0, 0, 7];

    fn sim(policy: &str, events: &[SimEvent]) -> Vec<SimHit> {
        let c = compile_str(policy).expect("policy must compile");
        simulate(&c, events)
    }

    /// Defect 1: the kernel delivers unlink to the engine as a WRITE-access
    /// file event (`trace_unlink`/`trace_unlinkat` -> `te_handle_file(
    /// TE_REF_USER_PATH, path, 0, TE_ACCESS_WRITE, ...)`), so the WRITE rule
    /// pass must fire on Unlink, not only on a write-open. Before the fix,
    /// `write_file` gated the rule pass on `is_write_open`, so an Unlink
    /// produced zero hits.
    #[test]
    fn unlink_runs_the_write_rule_pass() {
        let hits = sim(
            r#"
            source S = exec "taint"
            rule w:
              notify write file "/out" if S
              because "write sink"
            "#,
            &[
                SimEvent::Seed { pid: 1 },
                SimEvent::Fork {
                    parent: 1,
                    child: 2,
                },
                SimEvent::Exec {
                    pid: 2,
                    comm: "taint".into(),
                    argv: vec![],
                },
                SimEvent::Unlink {
                    pid: 2,
                    path: "/out".into(),
                },
            ],
        );
        assert!(
            hits.iter()
                .any(|h| h.target == "/out" && h.effect == EFFECT_NOTIFY),
            "the unlink event must fire the WRITE rule pass: {hits:?}"
        );
    }

    /// Defect 2 (file flow): a KILL hit in tracepoint (NOTIFY) mode is
    /// asynchronous, so the write-flow tail still runs and ORs the process's
    /// labels into the shared file map. A later sibling that reads the file
    /// absorbs the label, and its connect rule then fires. Before the fix,
    /// the caller returned early on the KILL hit, the write flow was
    /// skipped, the file map stayed empty, and the sibling's connect rule
    /// never fired.
    #[test]
    fn flow_runs_after_kill_hit_file() {
        let hits = sim(
            r#"
            source S = exec "taint"
            rule w:
              kill write file "/out" if S
              because "write sink"
            rule c:
              notify connect endpoint "10.0.0.7" if S
              because "connect sink"
            "#,
            &[
                SimEvent::Seed { pid: 1 },
                SimEvent::Fork {
                    parent: 1,
                    child: 2,
                },
                SimEvent::Exec {
                    pid: 2,
                    comm: "taint".into(),
                    argv: vec![],
                },
                SimEvent::Write {
                    pid: 2,
                    path: "/out".into(),
                },
                SimEvent::Fork {
                    parent: 1,
                    child: 3,
                },
                // Exec a *different* comm so the label reaches pid 3 only
                // through the post-KILL file flow, not through exec.
                SimEvent::Exec {
                    pid: 3,
                    comm: "sh".into(),
                    argv: vec![],
                },
                SimEvent::Read {
                    pid: 3,
                    path: "/out".into(),
                },
                SimEvent::Connect { pid: 3, ip: EP },
            ],
        );
        assert!(
            hits.iter()
                .any(|h| h.target == "10.0.0.7" && h.effect == EFFECT_NOTIFY),
            "the post-KILL write flow must reach the sibling's connect rule: {hits:?}"
        );
    }

    /// Defect 2 (net flow): the connect-flow tail records the process's labels
    /// into the shared endpoint map even after a KILL hit. A later sibling's
    /// recv from that endpoint absorbs the label and its recv rule fires.
    /// Before the fix the caller returned early on the KILL hit, the connect
    /// flow was skipped, the endpoint map stayed empty, and the sibling's
    /// recv rule never fired.
    #[test]
    fn flow_runs_after_kill_hit_net() {
        let hits = sim(
            r#"
            source S = exec "taint"
            rule k:
              kill connect endpoint "10.0.0.7" if S
              because "connect kill"
            rule r:
              notify recv endpoint "10.0.0.7" if S
              because "recv sink"
            "#,
            &[
                SimEvent::Seed { pid: 1 },
                SimEvent::Fork {
                    parent: 1,
                    child: 2,
                },
                SimEvent::Exec {
                    pid: 2,
                    comm: "taint".into(),
                    argv: vec![],
                },
                SimEvent::Connect { pid: 2, ip: EP },
                SimEvent::Fork {
                    parent: 1,
                    child: 3,
                },
                SimEvent::Exec {
                    pid: 3,
                    comm: "sh".into(),
                    argv: vec![],
                },
                SimEvent::Recv { pid: 3, ip: EP },
            ],
        );
        assert!(
            hits.iter()
                .any(|h| h.target == "10.0.0.7" && h.effect == EFFECT_NOTIFY),
            "the post-KILL connect flow must reach the sibling's recv rule: {hits:?}"
        );
    }
}
