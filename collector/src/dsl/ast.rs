// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Parsed form of the ActPlane taint DSL (docs/taint-dsl.md §2).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Endpoint,
    Exec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Exec,
    Read,
    Write,
    Unlink,
    Connect,
    Recv,
    Open,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    pub label: String,
    pub kind: Kind,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub kind: Kind,
    pub pattern: String,
    pub arg: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    True,
    Label(String),
    Not(String),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cond {
    Target { negate: bool, pattern: String },
    LineageIncludes { exec: String },
    /// `after exec X [since EV ("or" EV)*]`. Each EV is an (op, pattern) event
    /// whose later occurrence makes the X gate stale. `since` empty = v1
    /// latching semantics (gate fired ever).
    After { exec: String, since: Vec<(Op, String)> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Clause {
    pub op: Op,
    pub target: Target,
    pub when: Expr,
    pub unless: Option<Cond>,
}

/// Rule result. This is compiled into the kernel rule table and is the source
/// of truth for what happens when the rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Report only; the operation proceeds.
    Audit,
    /// Hard block (LSM -EPERM) when BPF LSM is available.
    Block,
    /// Send SIGKILL to the current task.
    Kill,
}

impl Default for Effect {
    fn default() -> Self {
        Effect::Block
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub name: String,
    pub clauses: Vec<Clause>,
    pub reason: String,
    /// Optional actionable next step shown to the agent (docs/feedback-design.md §6).
    pub remediation: Option<String>,
    /// Action taken when this rule matches (default Block).
    pub effect: Effect,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Xform {
    pub endorse: bool,
    pub label: String,
    pub gate: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Policy {
    pub labels: Vec<String>,
    pub sources: Vec<Source>,
    pub rules: Vec<Rule>,
    pub xforms: Vec<Xform>,
}
