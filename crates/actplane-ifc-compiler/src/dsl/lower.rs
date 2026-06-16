// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Lower a parsed Policy to the kernel ABI (struct taint_config, see
//! bpf/taint.h): assign label/gate bits, compile boolean exprs to req/forbid
//! masks (via DNF), and lower globs to the kernel's exact/prefix/suffix/any
//! match kinds.

use super::ast::*;
use std::collections::HashMap;

// must match bpf/taint.h
const PAT: usize = 64;
const ARG: usize = 24;
// Must match bpf/taint.h MAX_TAINT_* exactly (ABI). Sized for 100+ rules/policy.
const MAX_UPDATES: usize = 320;
const MAX_RULES: usize = 128;
const MAX_GATES: usize = 64;
const MAX_INVALS: usize = 64;

const M_EXACT: u8 = 0;
const M_PREFIX: u8 = 1;
const M_SUFFIX: u8 = 2;
const M_ANY: u8 = 3;
const M_CONTAINS: u8 = 4;
const MAX_CONTAINS_LITERAL: usize = 24; // mirrors TAINT_SUF_MAX in bpf/taint.h
const OP_EXEC: u8 = 0;
const OP_OPEN: u8 = 1;
const OP_WRITE: u8 = 2;
const OP_CONNECT: u8 = 3;
const OP_RECV: u8 = 4;
const C_NONE: u8 = 0;
const C_LINEAGE: u8 = 1;
const C_AFTER: u8 = 2;
const C_TARGET: u8 = 3;
const EFFECT_NOTIFY: u8 = 0;
const EFFECT_BLOCK: u8 = 1;
const EFFECT_KILL: u8 = 2;
const GATE_IMMEDIATE: i32 = -1;

#[repr(C)]
#[derive(Clone, Copy)]
struct CUpdate {
    op: u8,
    m: u8,
    target: [u8; PAT],
    arg: [u8; ARG],
    add: u64,
    del: u64,
    gates: u64,
    invals: u64,
    ipv4: u32,
    ipv4_mask: u32,
    gate_exit_code: i32,
    domain_id: u32,
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
    domain_id: u32,
    since_mask: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CConfig {
    n_updates: u32,
    n_rules: u32,
    updates: [CUpdate; MAX_UPDATES],
    rules: [CRule; MAX_RULES],
}

fn set_pat(dst: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&b[..n]);
    dst[n] = 0;
}

/// (match, literal) lowering for exec-side patterns (matched on comm).
fn lower_exec(pat: &str) -> (u8, String) {
    if pat == "*" || pat == "**" || pat == "**/*" {
        return (M_ANY, String::new());
    }
    let base = pat.rsplit('/').next().unwrap_or(pat);
    if let Some(stripped) = base.strip_suffix('*') {
        (M_PREFIX, stripped.to_string())
    } else {
        (M_EXACT, base.to_string())
    }
}

fn shorten_contains_literal(lit: &str) -> String {
    if lit.len() <= MAX_CONTAINS_LITERAL {
        return lit.to_string();
    }
    let trimmed = lit.trim_start_matches('/');
    if trimmed.len() <= MAX_CONTAINS_LITERAL {
        return trimmed.to_string();
    }
    for (idx, _) in trimmed.match_indices('/') {
        let candidate = &trimmed[idx + 1..];
        if !candidate.is_empty() && candidate.len() <= MAX_CONTAINS_LITERAL {
            return candidate.to_string();
        }
    }
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    if !last.is_empty() && last.len() <= MAX_CONTAINS_LITERAL {
        return last.to_string();
    }
    let start = trimmed.len().saturating_sub(MAX_CONTAINS_LITERAL);
    trimmed[start..].to_string()
}

fn shorten_repo_relative_exact_literal(path: &str) -> String {
    if path.len() <= MAX_CONTAINS_LITERAL {
        return path.to_string();
    }
    for (idx, _) in path.match_indices('/') {
        let candidate = &path[idx + 1..];
        if candidate.contains('/') && candidate.len() <= MAX_CONTAINS_LITERAL {
            return candidate.to_string();
        }
    }
    if let Some((parent, _base)) = path.rsplit_once('/') {
        return shorten_contains_literal(&format!("{}/", parent));
    }
    shorten_contains_literal(path)
}

/// (match, literal) lowering for path patterns.
fn lower_path(pat: &str) -> (u8, String) {
    if pat == "*" || pat == "**" || pat == "**/*" {
        return (M_ANY, String::new());
    }
    let repo_relative = !pat.starts_with('/');
    // **/middle/** → contains "/middle/" (substring search)
    if let Some(inner) = pat.strip_prefix("**/").and_then(|r| r.strip_suffix("/**")) {
        if !inner.contains('*') {
            return (M_CONTAINS, shorten_contains_literal(&format!("/{inner}/")));
        }
    }
    // **/middle/* → contains "/middle/" (files directly inside)
    if let Some(inner) = pat.strip_prefix("**/").and_then(|r| r.strip_suffix("/*")) {
        if !inner.contains('*') {
            return (M_CONTAINS, shorten_contains_literal(&format!("/{inner}/")));
        }
    }
    if let Some(inner) = pat.strip_prefix("**/") {
        if let Some(suffix) = inner.strip_prefix('*') {
            return (M_CONTAINS, shorten_contains_literal(suffix));
        }
        return (M_CONTAINS, shorten_contains_literal(inner));
    }
    if let Some(p) = pat.strip_suffix("/**") {
        if repo_relative {
            if !p.contains('*') {
                return (M_CONTAINS, shorten_contains_literal(&format!("{}/", p)));
            }
        } else {
            return (M_PREFIX, format!("{}/", p));
        }
    }
    if let Some(p) = pat.strip_suffix("**") {
        if repo_relative {
            if !p.contains('*') {
                return (M_CONTAINS, shorten_contains_literal(p));
            }
        } else {
            return (M_PREFIX, p.to_string());
        }
    }
    if let Some(p) = pat.strip_suffix("/*") {
        if repo_relative {
            if !p.contains('*') {
                return (M_CONTAINS, shorten_contains_literal(&format!("{}/", p)));
            }
        } else {
            return (M_PREFIX, format!("{}/", p));
        }
    }
    if let Some(p) = pat.strip_prefix('*') {
        if repo_relative {
            return (M_CONTAINS, shorten_contains_literal(p));
        }
        return (M_SUFFIX, p.to_string());
    }
    if let Some(idx) = pat.find('*') {
        if repo_relative {
            return (M_CONTAINS, shorten_contains_literal(&pat[..idx]));
        }
        return (M_PREFIX, pat[..idx].to_string());
    }
    if repo_relative && pat.contains('/') {
        return (M_CONTAINS, shorten_repo_relative_exact_literal(pat));
    }
    if repo_relative {
        return (M_CONTAINS, shorten_contains_literal(pat));
    }
    (M_EXACT, pat.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_relative_paths_match_absolute_runtime_paths() {
        assert_eq!(
            lower_path("pyproject.toml"),
            (M_CONTAINS, "pyproject.toml".into())
        );
        assert_eq!(
            lower_path("src/google/adk/agents/config_schemas/AgentConfig.json"),
            (M_CONTAINS, "agents/config_schemas/".into())
        );
        assert_eq!(
            lower_path("ui/src/i18n/locales/en.ts"),
            (M_CONTAINS, "src/i18n/locales/en.ts".into())
        );
        assert_eq!(
            lower_path("codex-rs/app-server-protocol/schema/typescript/v2/**"),
            (M_CONTAINS, "schema/typescript/v2/".into())
        );
        assert_eq!(
            lower_path("packages/oh-my-opencode-*/bin/**"),
            (M_CONTAINS, "packages/oh-my-opencode-".into())
        );
        assert_eq!(
            lower_path("src/browser_harness/**"),
            (M_CONTAINS, "src/browser_harness/".into())
        );
        assert_eq!(
            lower_path("ui/src/i18n/locales/*.ts"),
            (M_CONTAINS, "ui/src/i18n/locales/".into())
        );
        assert_eq!(lower_path("**/*.js"), (M_CONTAINS, ".js".into()));
        assert_eq!(lower_path("**/*"), (M_ANY, String::new()));
    }

    #[test]
    fn absolute_paths_keep_absolute_semantics() {
        assert_eq!(
            lower_path("/tmp/guarded/**"),
            (M_PREFIX, "/tmp/guarded/".into())
        );
        assert_eq!(
            lower_path("/tmp/guarded/file.txt"),
            (M_EXACT, "/tmp/guarded/file.txt".into())
        );
    }

    #[test]
    fn exec_wildcard_patterns_match_any_comm() {
        assert_eq!(lower_exec("*"), (M_ANY, String::new()));
        assert_eq!(lower_exec("**"), (M_ANY, String::new()));
        assert_eq!(lower_exec("**/*"), (M_ANY, String::new()));
    }

    #[test]
    fn endpoint_sources_lower_to_connect_and_recv_updates() {
        let pol = crate::dsl::parse::parse(r#"source NET = endpoint "127.0.0.1""#)
            .expect("parse endpoint source");
        let compiled = compile(&pol).expect("compile endpoint source");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(cfg.n_updates, 2);
        let ops = [cfg.updates[0].op, cfg.updates[1].op];
        assert!(ops.contains(&OP_CONNECT), "missing connect update: {ops:?}");
        assert!(ops.contains(&OP_RECV), "missing recv update: {ops:?}");
    }
}

/// Lower an IPv4 prefix/host pattern to (net, mask) in the same byte order as
/// the kernel's `sin_addr.s_addr` (octet k at bit 8*k). "*" -> match-any (0,0).
/// "10.0.0." -> /24, "10.0.0.5" -> /32. Non-IP hostnames -> (0, !0) = match-none
/// (hostname rules need userspace DNS; not matched numerically).
fn lower_ipv4(pat: &str) -> (u32, u32) {
    if pat == "*" {
        return (0, 0);
    }
    let body = pat.strip_suffix('.').unwrap_or(pat);
    let mut net: u32 = 0;
    let mut mask: u32 = 0;
    let mut k = 0u32;
    for tok in body.split('.') {
        if k >= 4 {
            break;
        }
        match tok.parse::<u8>() {
            Ok(o) => {
                net |= (o as u32) << (8 * k);
                mask |= 0xffu32 << (8 * k);
                k += 1;
            }
            Err(_) => return (0, u32::MAX), // not an IP -> matches nothing in-kernel
        }
    }
    (net, mask)
}

struct Ctx {
    labels: HashMap<String, u64>,
    used_labels: u64,
    updates: Vec<CUpdate>,
    gate_bits: HashMap<(u8, u8, String, Option<u8>), (u64, u32)>,
    next_gate: u32,
    inval_slots: HashMap<(u8, u8, String, String), u32>,
    next_inval: u32,
}
impl Ctx {
    fn add_update(&mut self, spec: UpdateSpec<'_>) -> Result<(), String> {
        for u in &mut self.updates {
            if u.op == spec.op
                && u.m == spec.m
                && u.ipv4 == spec.ipv4
                && u.ipv4_mask == spec.ipv4_mask
                && u.gate_exit_code == spec.gate_exit_code
                && pat_eq(&u.target, spec.target)
                && arg_eq(&u.arg, spec.arg)
            {
                u.add |= spec.add;
                u.del |= spec.del;
                u.gates |= spec.gates;
                u.invals |= spec.invals;
                return Ok(());
            }
        }
        if self.updates.len() >= MAX_UPDATES {
            return Err(format!(
                "too many event updates ({} > {})",
                self.updates.len() + 1,
                MAX_UPDATES
            ));
        }
        let mut u = CUpdate {
            op: spec.op,
            m: spec.m,
            target: [0; PAT],
            arg: [0; ARG],
            add: spec.add,
            del: spec.del,
            gates: spec.gates,
            invals: spec.invals,
            ipv4: spec.ipv4,
            ipv4_mask: spec.ipv4_mask,
            gate_exit_code: spec.gate_exit_code,
            domain_id: 0,
        };
        set_pat(&mut u.target, spec.target);
        if !spec.arg.is_empty() {
            set_pat(&mut u.arg, spec.arg);
        }
        self.updates.push(u);
        Ok(())
    }

    fn label_bit(&mut self, name: &str) -> Result<u64, String> {
        if let Some(b) = self.labels.get(name) {
            return Ok(*b);
        }
        let bit_idx = (0..64)
            .find(|idx| self.used_labels & (1u64 << idx) == 0)
            .ok_or_else(|| "too many labels (max 64)".to_string())?;
        let b = 1u64 << bit_idx;
        self.used_labels |= b;
        self.labels.insert(name.to_string(), b);
        Ok(b)
    }
    /// Returns (gate bit, gate slot index). The index is what the engine uses to
    /// look up the gate's epoch for staleness; the bit is the v1 latching mask.
    fn gate_bit(
        &mut self,
        gate_op: Op,
        pat: &str,
        gate_exit: Option<u8>,
    ) -> Result<(u64, u32), String> {
        let (low_op, m, lit) = match gate_op {
            Op::Exec => {
                let (m, l) = lower_exec(pat);
                (OP_EXEC, m, l)
            }
            Op::Read | Op::Open => {
                let (m, l) = lower_path(pat);
                (OP_OPEN, m, l)
            }
            Op::Write | Op::Unlink => {
                let (m, l) = lower_path(pat);
                (OP_WRITE, m, l)
            }
            other => {
                return Err(format!(
                    "`after {}` is not supported as a gate (use exec/read/write)",
                    op_name(other)
                ));
            }
        };
        if gate_exit.is_some() && low_op != OP_EXEC {
            return Err("`exits` is only valid on `after exec` gates".into());
        }
        let key = (low_op, m, lit.clone(), gate_exit);
        if let Some(b) = self.gate_bits.get(&key) {
            return Ok(*b);
        }
        if self.next_gate >= 64 || self.next_gate as usize >= MAX_GATES {
            return Err("too many gates".into());
        }
        let idx = self.next_gate;
        let b = 1u64 << idx;
        self.next_gate += 1;
        self.add_update(UpdateSpec {
            op: low_op,
            m,
            target: &lit,
            arg: "",
            add: 0,
            del: 0,
            gates: b,
            invals: 0,
            ipv4: 0,
            ipv4_mask: 0,
            gate_exit_code: gate_exit.map(i32::from).unwrap_or(GATE_IMMEDIATE),
        })?;
        self.gate_bits.insert(key, (b, idx));
        Ok((b, idx))
    }
    /// Allocate (or reuse) a `since` invalidator slot, returning its bit in the
    /// rule's `since_mask`. `op` is the lowered taint_op; the pattern is matched
    /// like a sink target (exec on comm, others on path).
    fn inval_slot(
        &mut self,
        op: u8,
        kind: Kind,
        pat: &str,
        arg: Option<&str>,
    ) -> Result<u64, String> {
        let (m, lit) = if op == OP_EXEC {
            lower_exec(pat)
        } else {
            lower_target(op, kind, pat)
        };
        let arg_s = arg.unwrap_or("");
        let key = (op, m, lit.clone(), arg_s.to_string());
        if let Some(i) = self.inval_slots.get(&key) {
            return Ok(1u64 << *i);
        }
        if self.next_inval >= 64 || self.next_inval as usize >= MAX_INVALS {
            return Err("too many `since` invalidators (max 64)".into());
        }
        let idx = self.next_inval;
        self.next_inval += 1;
        let bit = 1u64 << idx;
        self.add_update(UpdateSpec {
            op,
            m,
            target: &lit,
            arg: arg_s,
            add: 0,
            del: 0,
            gates: 0,
            invals: bit,
            ipv4: 0,
            ipv4_mask: 0,
            gate_exit_code: GATE_IMMEDIATE,
        })?;
        self.inval_slots.insert(key, idx);
        Ok(bit)
    }
}

struct UpdateSpec<'a> {
    op: u8,
    m: u8,
    target: &'a str,
    arg: &'a str,
    add: u64,
    del: u64,
    gates: u64,
    invals: u64,
    ipv4: u32,
    ipv4_mask: u32,
    gate_exit_code: i32,
}

fn pat_eq(buf: &[u8; PAT], s: &str) -> bool {
    let mut pat = [0u8; PAT];
    set_pat(&mut pat, s);
    *buf == pat
}

fn arg_eq(buf: &[u8; ARG], s: &str) -> bool {
    let mut a = [0u8; ARG];
    let b = s.as_bytes();
    let n = b.len().min(ARG);
    a[..n].copy_from_slice(&b[..n]);
    *buf == a
}

/// expr -> disjunction of (req_mask, forbid_mask)
fn dnf(e: &Expr, ctx: &mut Ctx) -> Result<Vec<(u64, u64)>, String> {
    Ok(match e {
        Expr::True => vec![(0, 0)],
        Expr::Label(l) => vec![(ctx.label_bit(l)?, 0)],
        Expr::Not(l) => vec![(0, ctx.label_bit(l)?)],
        Expr::Or(a, b) => {
            let mut v = dnf(a, ctx)?;
            v.extend(dnf(b, ctx)?);
            v
        }
        Expr::And(a, b) => {
            let (da, db) = (dnf(a, ctx)?, dnf(b, ctx)?);
            let mut v = Vec::new();
            for (ra, fa) in &da {
                for (rb, fb) in &db {
                    v.push((ra | rb, fa | fb));
                }
            }
            v
        }
    })
}

/// Human-readable verb for a DSL op, used in the feedback payload.
fn op_name(op: Op) -> &'static str {
    match op {
        Op::Exec => "exec",
        Op::Read => "read",
        Op::Open => "open",
        Op::Write => "write",
        Op::Unlink => "unlink",
        Op::Connect => "connect",
        Op::Recv => "recv",
    }
}

fn op_lowers(op: Op) -> Result<&'static [u8], String> {
    match op {
        Op::Exec => Ok(&[OP_EXEC]),
        Op::Read => Ok(&[OP_OPEN]),
        Op::Open => Ok(&[OP_OPEN]),
        Op::Write | Op::Unlink => Ok(&[OP_WRITE]),
        Op::Connect => Ok(&[OP_CONNECT]),
        Op::Recv => Ok(&[OP_RECV]),
    }
}

/// Lower a `since` event op to the single taint_op the engine stamps on. Only
/// read/write/exec can invalidate a gate.
fn inval_op(op: Op) -> Result<u8, String> {
    match op {
        Op::Read | Op::Open => Ok(OP_OPEN),
        Op::Write | Op::Unlink => Ok(OP_WRITE),
        Op::Exec => Ok(OP_EXEC),
        other => Err(format!(
            "`since {}` is not a valid invalidator (use exec/read/write/open/unlink)",
            op_name(other)
        )),
    }
}

fn lower_target(op: u8, kind: Kind, pat: &str) -> (u8, String) {
    let _ = kind;
    match op {
        OP_EXEC => lower_exec(pat),
        OP_CONNECT | OP_RECV => (M_ANY, String::new()),
        _ => lower_path(pat),
    }
}

fn lower_effect(effect: Effect) -> u8 {
    match effect {
        Effect::Notify => EFFECT_NOTIFY,
        Effect::Block => EFFECT_BLOCK,
        Effect::Kill => EFFECT_KILL,
    }
}

/// Per-lowered-rule metadata, indexed by `rule_id`, kept Rust-side for building
/// the corrective-feedback payload (docs/feedback-design.md §6).
#[derive(Clone)]
pub struct RuleMeta {
    pub name: String,
    pub reason: String,
    pub effect: Effect,
    /// Operations represented by this lowered rule. This is usually a single
    /// DSL op, kept as a list for compatibility with existing feedback code.
    pub ops: Vec<String>,
    pub clause_op: String,
    pub kernel_op: String,
    pub target_kind: Kind,
    pub target_pattern: String,
    pub target_arg: Option<String>,
    pub clause_source_index: usize,
    pub source: Option<RuleSourceMeta>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSourceMeta {
    pub source_ref: String,
    pub binding_mode: Option<String>,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    pub clause_start_line: Option<usize>,
    pub clause_end_line: Option<usize>,
    pub clause_text: Option<String>,
}

pub struct Compiled {
    pub bytes: Vec<u8>,
    pub reasons: Vec<String>, // indexed by lowered rule_id
    pub meta: Vec<RuleMeta>,  // indexed by lowered rule_id
    pub labels: HashMap<String, u64>,
}

fn collect_label_names(pol: &Policy) -> Vec<String> {
    let mut names = std::collections::BTreeSet::new();
    for s in &pol.sources {
        names.insert(s.label.clone());
    }
    for x in &pol.xforms {
        names.insert(x.label.clone());
    }
    for r in &pol.rules {
        for cl in &r.clauses {
            collect_expr_labels(&cl.when, &mut names);
        }
    }
    names.into_iter().collect()
}

fn validate_label_bindings(labels: &HashMap<String, u64>) -> Result<u64, String> {
    let mut used = 0u64;
    for (name, bit) in labels {
        if name.is_empty() {
            return Err("label names must not be empty".into());
        }
        if *bit == 0 || bit.count_ones() != 1 {
            return Err(format!("label `{name}` has invalid bit mask 0x{bit:x}"));
        }
        if used & *bit != 0 {
            return Err(format!("label bit 0x{bit:x} is assigned more than once"));
        }
        used |= *bit;
    }
    Ok(used)
}

fn collect_expr_labels(expr: &Expr, out: &mut std::collections::BTreeSet<String>) {
    match expr {
        Expr::Label(l) | Expr::Not(l) => {
            out.insert(l.clone());
        }
        Expr::And(a, b) | Expr::Or(a, b) => {
            collect_expr_labels(a, out);
            collect_expr_labels(b, out);
        }
        Expr::True => {}
    }
}

pub fn compile(pol: &Policy) -> Result<Compiled, String> {
    compile_with_labels(pol, &HashMap::new())
}

pub fn compile_with_labels(
    pol: &Policy,
    existing_labels: &HashMap<String, u64>,
) -> Result<Compiled, String> {
    let sorted_labels = collect_label_names(pol);
    let pre_labels = existing_labels.clone();
    let used_labels = validate_label_bindings(&pre_labels)?;

    let mut ctx = Ctx {
        used_labels,
        labels: pre_labels,
        updates: Vec::new(),
        gate_bits: HashMap::new(),
        next_gate: 0,
        inval_slots: HashMap::new(),
        next_inval: 0,
    };
    for name in &sorted_labels {
        ctx.label_bit(name)?;
    }
    let mut rules: Vec<CRule> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut meta: Vec<RuleMeta> = Vec::new();

    for s in &pol.sources {
        let bit = ctx.label_bit(&s.label)?;
        let (op, m, lit, ipv4, ipv4_mask) = match s.kind {
            Kind::Exec => {
                let (m, lit) = lower_exec(&s.pattern);
                (OP_EXEC, m, lit, 0, 0)
            }
            Kind::File => {
                let (m, lit) = lower_path(&s.pattern);
                (OP_OPEN, m, lit, 0, 0)
            }
            Kind::Endpoint => {
                let (n, mk) = lower_ipv4(&s.pattern);
                for op in [OP_CONNECT, OP_RECV] {
                    ctx.add_update(UpdateSpec {
                        op,
                        m: M_ANY,
                        target: "",
                        arg: "",
                        add: bit,
                        del: 0,
                        gates: 0,
                        invals: 0,
                        ipv4: n,
                        ipv4_mask: mk,
                        gate_exit_code: GATE_IMMEDIATE,
                    })?;
                }
                continue;
            }
        };
        ctx.add_update(UpdateSpec {
            op,
            m,
            target: &lit,
            arg: "",
            add: bit,
            del: 0,
            gates: 0,
            invals: 0,
            ipv4,
            ipv4_mask,
            gate_exit_code: GATE_IMMEDIATE,
        })?;
    }
    for x in &pol.xforms {
        let bit = ctx.label_bit(&x.label)?;
        let (m, lit) = lower_exec(&x.gate);
        ctx.add_update(UpdateSpec {
            op: OP_EXEC,
            m,
            target: &lit,
            arg: "",
            add: if x.endorse { bit } else { 0 },
            del: if x.endorse { 0 } else { bit },
            gates: 0,
            invals: 0,
            ipv4: 0,
            ipv4_mask: 0,
            gate_exit_code: GATE_IMMEDIATE,
        })?;
    }
    for rule in &pol.rules {
        for cl in &rule.clauses {
            for op in op_lowers(cl.op)? {
                let op = *op;
                let (tm, tlit) = lower_target(op, cl.target.kind, &cl.target.pattern);
                // endpoint ops: numeric IPv4 target
                let (ipv4, ipv4_mask) = if op == OP_CONNECT || op == OP_RECV {
                    lower_ipv4(&cl.target.pattern)
                } else {
                    (0, 0)
                };
                // condition
                let (mut ck, mut cneg, mut cm, mut clit, mut gate) =
                    (C_NONE, 0u8, M_EXACT, String::new(), 0u64);
                let (mut cipv4, mut cipv4_mask) = (0u32, 0u32);
                let mut gate_idx = 0u32;
                let mut since_mask = 0u64;
                match &cl.unless {
                    None => {}
                    Some(Cond::Target { negate, pattern }) => {
                        ck = C_TARGET;
                        cneg = *negate as u8;
                        if op == OP_CONNECT || op == OP_RECV {
                            let (n, mk) = lower_ipv4(pattern);
                            cipv4 = n;
                            cipv4_mask = mk;
                        } else {
                            let (m, l) = lower_target(op, cl.target.kind, pattern);
                            cm = m;
                            clit = l;
                        }
                    }
                    Some(Cond::LineageIncludes { exec }) => {
                        ck = C_LINEAGE;
                        let (b, _idx) = ctx.gate_bit(Op::Exec, exec, None)?;
                        gate = b;
                    }
                    Some(Cond::After {
                        gate_op,
                        gate_pattern,
                        gate_exit,
                        since,
                    }) => {
                        ck = C_AFTER;
                        let (b, idx) = ctx.gate_bit(*gate_op, gate_pattern, *gate_exit)?;
                        gate = b;
                        gate_idx = idx;
                        for (op, pat, arg) in since {
                            let iop = inval_op(*op)?;
                            since_mask |=
                                ctx.inval_slot(iop, cl.target.kind, pat, arg.as_deref())?;
                        }
                    }
                }
                for (req, forbid) in dnf(&cl.when, &mut ctx)? {
                    let rule_id = meta.len() as u32;
                    reasons.push(rule.reason.clone());
                    meta.push(RuleMeta {
                        name: rule.name.clone(),
                        reason: rule.reason.clone(),
                        effect: cl.effect,
                        ops: vec![op_name(cl.op).to_string()],
                        clause_op: op_name(cl.op).to_string(),
                        kernel_op: kernel_op_name(op).to_string(),
                        target_kind: cl.target.kind,
                        target_pattern: cl.target.pattern.clone(),
                        target_arg: cl.target.arg.clone(),
                        clause_source_index: cl.source_index,
                        source: None,
                    });
                    let mut cr = CRule {
                        op,
                        m: tm,
                        cond_kind: ck,
                        cond_neg: cneg,
                        cond_match: cm,
                        effect: lower_effect(cl.effect),
                        target: [0; PAT],
                        arg: [0; ARG],
                        cond_pat: [0; PAT],
                        req,
                        forbid,
                        gate,
                        rule_id,
                        ipv4,
                        ipv4_mask,
                        cond_ipv4: cipv4,
                        cond_ipv4_mask: cipv4_mask,
                        gate_idx,
                        domain_id: 0,
                        since_mask,
                    };
                    set_pat(&mut cr.target, &tlit);
                    if let Some(a) = &cl.target.arg {
                        set_pat(&mut cr.arg, a);
                    }
                    set_pat(&mut cr.cond_pat, &clit);
                    rules.push(cr);
                }
            }
        }
    }

    if rules.len() > MAX_RULES {
        return Err(format!(
            "too many compiled rules ({} > {})",
            rules.len(),
            MAX_RULES
        ));
    }

    // build the repr(C) config
    let mut cfg: CConfig = unsafe { std::mem::zeroed() };
    cfg.n_updates = ctx.updates.len() as u32;
    cfg.n_rules = rules.len() as u32;
    for (i, u) in ctx.updates.iter().enumerate() {
        cfg.updates[i] = *u;
    }
    for (i, r) in rules.iter().enumerate() {
        cfg.rules[i] = *r;
    }

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &cfg as *const CConfig as *const u8,
            std::mem::size_of::<CConfig>(),
        )
    }
    .to_vec();
    Ok(Compiled {
        bytes,
        reasons,
        meta,
        labels: ctx.labels,
    })
}

fn kernel_op_name(op: u8) -> &'static str {
    match op {
        OP_EXEC => "exec",
        OP_OPEN => "read",
        OP_WRITE => "write",
        OP_CONNECT => "connect",
        OP_RECV => "recv",
        _ => "op",
    }
}
