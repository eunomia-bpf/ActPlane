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
const MAX_SOURCES: usize = 32;
const MAX_RULES: usize = 32;
const MAX_XFORMS: usize = 16;
const MAX_GATES: usize = 16;

const M_EXACT: u8 = 0;
const M_PREFIX: u8 = 1;
const M_SUFFIX: u8 = 2;
const M_ANY: u8 = 3;
const SRC_EXEC: u8 = 0;
const SRC_FILE: u8 = 1;
const SRC_ENDPOINT: u8 = 2;
const OP_EXEC: u8 = 0;
const OP_OPEN: u8 = 1;
const OP_WRITE: u8 = 2;
const OP_CONNECT: u8 = 3;
const C_NONE: u8 = 0;
const C_LINEAGE: u8 = 1;
const C_AFTER: u8 = 2;
const C_TARGET: u8 = 3;

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
struct CConfig {
    n_sources: u32,
    n_rules: u32,
    n_xforms: u32,
    n_gates: u32,
    sources: [CSource; MAX_SOURCES],
    rules: [CRule; MAX_RULES],
    xforms: [CXform; MAX_XFORMS],
    gates: [CGate; MAX_GATES],
}

fn set_pat(dst: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&b[..n]);
    dst[n] = 0;
}

/// (match, literal) lowering for exec-side patterns (matched on comm).
fn lower_exec(pat: &str) -> (u8, String) {
    let base = pat.rsplit('/').next().unwrap_or(pat);
    if let Some(stripped) = base.strip_suffix('*') {
        (M_PREFIX, stripped.to_string())
    } else {
        (M_EXACT, base.to_string())
    }
}

/// (match, literal) lowering for path patterns.
fn lower_path(pat: &str) -> (u8, String) {
    if pat == "*" {
        return (M_ANY, String::new());
    }
    if let Some(p) = pat.strip_suffix("/**") {
        return (M_PREFIX, format!("{}/", p));
    }
    if let Some(p) = pat.strip_suffix("**") {
        return (M_PREFIX, p.to_string());
    }
    if let Some(p) = pat.strip_suffix("/*") {
        return (M_PREFIX, format!("{}/", p));
    }
    if let Some(p) = pat.strip_prefix("**/") {
        return (M_SUFFIX, p.to_string());
    }
    if let Some(p) = pat.strip_prefix('*') {
        return (M_SUFFIX, p.to_string());
    }
    if let Some(idx) = pat.find('*') {
        return (M_PREFIX, pat[..idx].to_string());
    }
    (M_EXACT, pat.to_string())
}

/// Lower an IPv4 prefix/host pattern to (net, mask) in the same byte order as
/// the kernel's `sin_addr.s_addr` (octet k at bit 8*k). "*" -> match-any (0,0).
/// "10.0.0." -> /24, "10.0.0.5" -> /32. Non-IP hostnames -> (0, !0) = match-none
/// (hostname rules need userspace DNS; not enforced numerically).
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
    next_label: u32,
    gates: Vec<CGate>,
    gate_bits: HashMap<(u8, String), u64>,
    next_gate: u32,
}
impl Ctx {
    fn label_bit(&mut self, name: &str) -> Result<u64, String> {
        if let Some(b) = self.labels.get(name) {
            return Ok(*b);
        }
        if self.next_label >= 64 {
            return Err("too many labels (max 64)".into());
        }
        let b = 1u64 << self.next_label;
        self.next_label += 1;
        self.labels.insert(name.to_string(), b);
        Ok(b)
    }
    fn gate_bit(&mut self, exec_pat: &str) -> Result<u64, String> {
        let (m, lit) = lower_exec(exec_pat);
        let key = (m, lit.clone());
        if let Some(b) = self.gate_bits.get(&key) {
            return Ok(*b);
        }
        if self.next_gate >= 64 || self.gates.len() >= MAX_GATES {
            return Err("too many gates".into());
        }
        let b = 1u64 << self.next_gate;
        self.next_gate += 1;
        let mut g = CGate {
            m,
            pat: [0; PAT],
            bit: b,
        };
        set_pat(&mut g.pat, &lit);
        self.gates.push(g);
        self.gate_bits.insert(key, b);
        Ok(b)
    }
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

fn op_lowers(op: Op) -> Result<&'static [u8], String> {
    match op {
        Op::Exec => Ok(&[OP_EXEC]),
        Op::Read => Ok(&[OP_OPEN]),
        Op::Open => Ok(&[OP_OPEN, OP_WRITE]),
        Op::Write | Op::Unlink => Ok(&[OP_WRITE]),
        Op::Connect => Ok(&[OP_CONNECT]),
        Op::Recv => Err("recv is a source, not a sink op".into()),
    }
}

fn lower_target(op: u8, kind: Kind, pat: &str) -> (u8, String) {
    let _ = kind;
    match op {
        OP_EXEC => lower_exec(pat),
        OP_CONNECT => (M_ANY, String::new()), // connect matches numerically (ipv4/mask)
        _ => lower_path(pat),
    }
}

pub struct Compiled {
    pub bytes: Vec<u8>,
    pub reasons: Vec<String>, // indexed by rule_id
}

pub fn compile(pol: &Policy) -> Result<Compiled, String> {
    let mut ctx = Ctx {
        labels: HashMap::new(),
        next_label: 0,
        gates: Vec::new(),
        gate_bits: HashMap::new(),
        next_gate: 0,
    };
    let mut sources: Vec<CSource> = Vec::new();
    let mut rules: Vec<CRule> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut xforms: Vec<CXform> = Vec::new();

    for s in &pol.sources {
        let bit = ctx.label_bit(&s.label)?;
        let (mut net, mut mask) = (0u32, 0u32);
        let (kind, (m, lit)) = match s.kind {
            Kind::Exec => (SRC_EXEC, lower_exec(&s.pattern)),
            Kind::File => (SRC_FILE, lower_path(&s.pattern)),
            Kind::Endpoint => {
                let (n, mk) = lower_ipv4(&s.pattern);
                net = n;
                mask = mk;
                (SRC_ENDPOINT, (M_ANY, String::new())) // matched numerically
            }
        };
        let mut cs = CSource {
            kind,
            m,
            pat: [0; PAT],
            label: bit,
            ipv4: net,
            ipv4_mask: mask,
        };
        set_pat(&mut cs.pat, &lit);
        sources.push(cs);
    }
    for x in &pol.xforms {
        let bit = ctx.label_bit(&x.label)?;
        let (m, lit) = lower_exec(&x.gate);
        let mut cx = CXform {
            m,
            add: x.endorse as u8,
            gate: [0; PAT],
            label: bit,
        };
        set_pat(&mut cx.gate, &lit);
        xforms.push(cx);
    }
    for (rid, rule) in pol.rules.iter().enumerate() {
        reasons.push(rule.reason.clone());
        for cl in &rule.clauses {
            for op in op_lowers(cl.op)? {
                let op = *op;
                let (tm, tlit) = lower_target(op, cl.target.kind, &cl.target.pattern);
                // connect: numeric IPv4 target
                let (ipv4, ipv4_mask) = if op == OP_CONNECT {
                    lower_ipv4(&cl.target.pattern)
                } else {
                    (0, 0)
                };
                // condition
                let (mut ck, mut cneg, mut cm, mut clit, mut gate) =
                    (C_NONE, 0u8, M_EXACT, String::new(), 0u64);
                let (mut cipv4, mut cipv4_mask) = (0u32, 0u32);
                match &cl.unless {
                    None => {}
                    Some(Cond::Target { negate, pattern }) => {
                        ck = C_TARGET;
                        cneg = *negate as u8;
                        if op == OP_CONNECT {
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
                        gate = ctx.gate_bit(exec)?;
                    }
                    Some(Cond::After { exec }) => {
                        ck = C_AFTER;
                        gate = ctx.gate_bit(exec)?;
                    }
                }
                for (req, forbid) in dnf(&cl.when, &mut ctx)? {
                    let mut cr = CRule {
                        op,
                        m: tm,
                        cond_kind: ck,
                        cond_neg: cneg,
                        cond_match: cm,
                        target: [0; PAT],
                        arg: [0; ARG],
                        cond_pat: [0; PAT],
                        req,
                        forbid,
                        gate,
                        rule_id: rid as u32,
                        ipv4,
                        ipv4_mask,
                        cond_ipv4: cipv4,
                        cond_ipv4_mask: cipv4_mask,
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

    if sources.len() > MAX_SOURCES {
        return Err("too many sources".into());
    }
    if rules.len() > MAX_RULES {
        return Err(format!(
            "too many compiled rules ({} > {})",
            rules.len(),
            MAX_RULES
        ));
    }
    if xforms.len() > MAX_XFORMS {
        return Err("too many xforms".into());
    }

    // build the repr(C) config
    let mut cfg: CConfig = unsafe { std::mem::zeroed() };
    cfg.n_sources = sources.len() as u32;
    cfg.n_rules = rules.len() as u32;
    cfg.n_xforms = xforms.len() as u32;
    cfg.n_gates = ctx.gates.len() as u32;
    for (i, s) in sources.iter().enumerate() {
        cfg.sources[i] = *s;
    }
    for (i, r) in rules.iter().enumerate() {
        cfg.rules[i] = *r;
    }
    for (i, x) in xforms.iter().enumerate() {
        cfg.xforms[i] = *x;
    }
    for (i, g) in ctx.gates.iter().enumerate() {
        cfg.gates[i] = *g;
    }

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &cfg as *const CConfig as *const u8,
            std::mem::size_of::<CConfig>(),
        )
    }
    .to_vec();
    Ok(Compiled { bytes, reasons })
}
