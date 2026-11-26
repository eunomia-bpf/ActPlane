// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Policy analysis for the unprivileged backend.
//!
//! The analysis walks the parsed policy (the same AST the eBPF lowering uses)
//! and decides, clause by clause, whether the clause maps exactly onto the
//! static tier: Landlock allow-lists plus seccomp filters installed by the
//! launcher before `execve`. A clause that needs per-process labels, event
//! history, argv inspection, or a non-blocking effect is reported as
//! unsupported, and a policy with any unsupported clause is refused as a whole.
//! Nothing is downgraded to a weaker effect.

use actplane_ifc_compiler::ast::{Clause, Cond, Effect, Expr, Kind, Op, Policy};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

/// Landlock ABI that controls `truncate(2)` and `O_TRUNC` (Linux 6.2). Write
/// confinement needs it, because earlier ABIs let a confined process truncate
/// files outside the allowed hierarchy.
pub const LANDLOCK_ABI_WRITE: i32 = 3;
/// Landlock ABI that controls TCP `connect(2)`/`bind(2)` (Linux 6.7).
pub const LANDLOCK_ABI_TCP: i32 = 4;
/// Landlock ABI that adds signal and abstract Unix socket scoping (Linux 6.12).
pub const LANDLOCK_ABI_SCOPE: i32 = 6;

/// File-system access classes the static tier confines with Landlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FsClass {
    /// `write` and `unlink` clauses. The compiler lowers both to the same
    /// kernel write op, so both confine every kind of modification.
    Write,
    /// `read` and `open` clauses (the compiler's open op).
    Read,
    /// `exec` clauses.
    Execute,
}

impl FsClass {
    pub fn name(self) -> &'static str {
        match self {
            FsClass::Write => "write",
            FsClass::Read => "read",
            FsClass::Execute => "execute",
        }
    }

    /// Smallest Landlock ABI that confines this class without a gap.
    pub fn min_abi(self) -> i32 {
        match self {
            FsClass::Write => LANDLOCK_ABI_WRITE,
            FsClass::Read | FsClass::Execute => 1,
        }
    }
}

/// What a clause leaves allowed for its access class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Allowed {
    /// Nothing: the class is denied on every path.
    Nothing,
    /// A directory and everything beneath it (`unless target "/dir/**"`).
    Beneath(PathBuf),
    /// One existing non-directory file (`unless target "/dir/file"`).
    File(PathBuf),
}

impl Allowed {
    pub fn describe(&self) -> String {
        match self {
            Allowed::Nothing => "nowhere".into(),
            Allowed::Beneath(dir) => format!("beneath {}", dir.display()),
            Allowed::File(file) => format!("on the file {}", file.display()),
        }
    }
}

/// One exact clause, lowered to a file-system constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsConstraint {
    pub class: FsClass,
    pub allowed: Allowed,
    pub rule: String,
    /// 1-based clause number within the rule.
    pub clause: usize,
}

/// The static sandbox a supported policy compiles to. Every constraint is an
/// independent restriction, and restrictions intersect: an access is allowed
/// only when every constraint of its class allows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxSpec {
    pub fs: Vec<FsConstraint>,
    /// A `block connect endpoint "*"` clause is present.
    pub deny_network: bool,
}

impl SandboxSpec {
    pub fn classes(&self) -> BTreeSet<FsClass> {
        self.fs.iter().map(|c| c.class).collect()
    }

    /// Smallest Landlock ABI the file-system constraints need (0 when the
    /// spec has none; network denial falls back to seccomp below ABI 4).
    pub fn landlock_min_abi(&self) -> i32 {
        self.fs.iter().map(|c| c.class.min_abi()).max().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClauseStatus {
    /// Enforced by the kernel with the same allow/deny decision on every path
    /// the clause names; divergences (all in the stricter direction, or on
    /// descriptors opened before the sandbox) are listed in the notes.
    Exact,
    /// Not expressible in the static tier. The backend refuses the policy.
    Unsupported,
}

impl ClauseStatus {
    pub fn name(self) -> &'static str {
        match self {
            ClauseStatus::Exact => "exact",
            ClauseStatus::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClauseReport {
    pub rule: String,
    /// 1-based clause number within the rule.
    pub clause: usize,
    pub text: String,
    pub status: ClauseStatus,
    /// For exact clauses, the enforcement mechanism; otherwise the reason the
    /// clause cannot be expressed and what would express it.
    pub detail: String,
    pub notes: Vec<String>,
}

/// Report for a `source`, `declassify`, or `endorse` declaration.
#[derive(Debug, Clone)]
pub struct DeclReport {
    pub text: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    /// Label `run` seeds on the launched process (`COMMAND`, else `AGENT`).
    pub runner_label: Option<String>,
    pub clauses: Vec<ClauseReport>,
    pub declarations: Vec<DeclReport>,
    spec: SandboxSpec,
}

impl Analysis {
    pub fn is_supported(&self) -> bool {
        self.clauses.iter().all(|c| c.status == ClauseStatus::Exact)
    }

    pub fn exact_count(&self) -> usize {
        self.clauses
            .iter()
            .filter(|c| c.status == ClauseStatus::Exact)
            .count()
    }

    pub fn unsupported(&self) -> impl Iterator<Item = &ClauseReport> {
        self.clauses
            .iter()
            .filter(|c| c.status == ClauseStatus::Unsupported)
    }

    /// The sandbox, only when every clause is exact.
    pub fn spec(&self) -> Option<&SandboxSpec> {
        self.is_supported().then_some(&self.spec)
    }

    /// Multi-line refusal listing every unsupported clause and its reason.
    pub fn rejection_message(&self) -> String {
        let mut out = String::new();
        let n = self.unsupported().count();
        let _ = writeln!(
            out,
            "the unprivileged backend cannot enforce {n} clause(s) of this policy exactly, so it refuses to run it:"
        );
        for c in self.unsupported() {
            let _ = writeln!(out, "  - rule {} clause {}: {}", c.rule, c.clause, c.text);
            let _ = writeln!(out, "    {}", c.detail);
        }
        let _ = write!(
            out,
            "Use the default bpf-lsm backend for this policy, or review `actplane compile --backend unprivileged --explain`."
        );
        out
    }
}

/// The label `run` seeds on the launched process: `COMMAND`, or `AGENT` for
/// older policies, exactly as the eBPF runner selects it.
pub fn runner_label(policy: &Policy) -> Option<String> {
    let names = label_names(policy);
    ["COMMAND", "AGENT"]
        .into_iter()
        .find(|name| names.contains(*name))
        .map(str::to_string)
}

fn label_names(policy: &Policy) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for s in &policy.sources {
        names.insert(s.label.clone());
    }
    for x in &policy.xforms {
        names.insert(x.label.clone());
    }
    for r in &policy.rules {
        for c in &r.clauses {
            expr_labels(&c.when, &mut names);
        }
    }
    names
}

fn expr_labels(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::True => {}
        Expr::Label(l) | Expr::Not(l) => {
            out.insert(l.clone());
        }
        Expr::And(a, b) | Expr::Or(a, b) => {
            expr_labels(a, out);
            expr_labels(b, out);
        }
    }
}

const SUPERVISOR: &str =
    "the seccomp user-notify supervisor (step 2 of docs/design/unprivileged-backend.md)";

/// Classify every clause of `policy` for the unprivileged backend.
pub fn analyze(policy: &Policy) -> Analysis {
    let runner = runner_label(policy);
    let runner_declassified = runner
        .as_deref()
        .is_some_and(|r| policy.xforms.iter().any(|x| !x.endorse && x.label == r));

    let mut clauses = Vec::new();
    let mut spec = SandboxSpec::default();
    let mut exec_reports = Vec::new();
    for rule in &policy.rules {
        for clause in &rule.clauses {
            let number = clause.source_index + 1;
            let text = render_clause(clause);
            let report = match classify(clause, runner.as_deref(), runner_declassified) {
                Ok(mapping) => {
                    let mut notes = mapping.notes;
                    if let Expr::Label(l) = &clause.when {
                        notes.insert(
                            0,
                            format!(
                                "`if {l}` holds for the whole launched tree: `run` seeds {l} on the launched process, children inherit it, and the policy never removes it"
                            ),
                        );
                    }
                    match mapping.target {
                        Target::Fs(class, allowed) => {
                            if class == FsClass::Execute {
                                exec_reports.push(clauses.len());
                            }
                            spec.fs.push(FsConstraint {
                                class,
                                allowed,
                                rule: rule.name.clone(),
                                clause: number,
                            });
                        }
                        Target::Network => spec.deny_network = true,
                    }
                    ClauseReport {
                        rule: rule.name.clone(),
                        clause: number,
                        text,
                        status: ClauseStatus::Exact,
                        detail: mapping.detail,
                        notes,
                    }
                }
                Err(reason) => ClauseReport {
                    rule: rule.name.clone(),
                    clause: number,
                    text,
                    status: ClauseStatus::Unsupported,
                    detail: reason,
                    notes: Vec::new(),
                },
            };
            clauses.push(report);
        }
    }

    // An execute allow-list is only meaningful when no allowed exec location is
    // writable: otherwise the agent writes a binary there and runs it.
    if !exec_reports.is_empty()
        && let Err(reason) = check_exec_not_writable(&spec)
    {
        for idx in exec_reports {
            let report = &mut clauses[idx];
            report.status = ClauseStatus::Unsupported;
            report.detail = reason.clone();
            report.notes.clear();
        }
        spec.fs.retain(|c| c.class != FsClass::Execute);
    }

    let declarations = declaration_reports(policy, runner.as_deref());
    Analysis {
        runner_label: runner,
        clauses,
        declarations,
        spec,
    }
}

enum Target {
    Fs(FsClass, Allowed),
    Network,
}

struct Mapping {
    target: Target,
    detail: String,
    notes: Vec<String>,
}

fn classify(
    clause: &Clause,
    runner: Option<&str>,
    runner_declassified: bool,
) -> Result<Mapping, String> {
    match clause.effect {
        Effect::Block => {}
        Effect::Notify => {
            return Err(format!(
                "`notify` reports the event and lets it proceed; the static tier has no per-event report channel, so this needs {SUPERVISOR}"
            ));
        }
        Effect::Kill => {
            return Err(format!(
                "`kill` terminates the task after a match; Landlock and seccomp filters can only refuse the operation, so this needs {SUPERVISOR}"
            ));
        }
    }

    match &clause.when {
        Expr::True => {}
        Expr::Label(l) if Some(l.as_str()) == runner && !runner_declassified => {}
        Expr::Label(l) if Some(l.as_str()) == runner => {
            return Err(format!(
                "`if {l}` depends on per-process labels because the policy can remove {l} with `declassify {l} by exec ...`; label tracking needs {SUPERVISOR}"
            ));
        }
        other => {
            return Err(format!(
                "`if {}` depends on information-flow labels that the static tier does not track; label propagation needs {SUPERVISOR}",
                render_expr(other)
            ));
        }
    }

    if let Some(arg) = &clause.target.arg {
        return Err(format!(
            "the argv token \"{arg}\" needs execve argument inspection, which only {SUPERVISOR} provides (checked, then continued)"
        ));
    }

    let allowed = match &clause.unless {
        None => Allowed::Nothing,
        Some(Cond::Target {
            negate: false,
            pattern,
        }) => {
            if clause.op == Op::Connect || clause.op == Op::Recv {
                return Err(format!(
                    "`unless target \"{pattern}\"` is an endpoint allow-list; matching addresses needs connect() inspection with pidfd_getfd in {SUPERVISOR}"
                ));
            }
            parse_root(pattern)?
        }
        Some(Cond::Target {
            negate: true,
            pattern,
        }) => {
            return Err(format!(
                "`unless target not \"{pattern}\"` refuses the operation only inside one region and allows it elsewhere; Landlock rules are allow-lists and cannot express a denied region"
            ));
        }
        Some(Cond::LineageIncludes { exec }) => {
            return Err(format!(
                "`unless lineage-includes exec \"{exec}\"` needs the exec ancestry of each process, which only {SUPERVISOR} records"
            ));
        }
        Some(Cond::After { gate_op, .. }) => {
            return Err(format!(
                "`unless after {} ...` is a temporal gate over exec/exit/write history, which only {SUPERVISOR} observes",
                op_name(*gate_op)
            ));
        }
    };

    match clause.op {
        Op::Write | Op::Unlink => {
            require_kind(clause, Kind::File)?;
            require_any_path(clause)?;
            Ok(fs_mapping(FsClass::Write, allowed, clause.op))
        }
        Op::Read | Op::Open => {
            require_kind(clause, Kind::File)?;
            require_any_path(clause)?;
            Ok(fs_mapping(FsClass::Read, allowed, clause.op))
        }
        Op::Exec => {
            require_kind(clause, Kind::Exec)?;
            if matches!(clause.target.pattern.as_str(), "**/**" | "/**") {
                return Err(format!(
                    "`exec \"{}\"` lowers to a command-name prefix that matches no program in the bpf-lsm backend; write `block exec \"*\"` to refuse every program",
                    display_exec_pattern(&clause.target.pattern)
                ));
            }
            if clause.target.pattern != "**/*" {
                return Err(format!(
                    "`exec \"{}\"` refuses one program and allows every other one; Landlock's execute right is an allow-list, so only `block exec \"*\"` (optionally with `unless target \"/dir/**\"`) maps exactly",
                    display_exec_pattern(&clause.target.pattern)
                ));
            }
            Ok(fs_mapping(FsClass::Execute, allowed, clause.op))
        }
        Op::Connect => {
            require_kind(clause, Kind::Endpoint)?;
            if clause.target.pattern != "*" {
                return Err(format!(
                    "`connect endpoint \"{}\"` refuses some endpoints and allows others; address matching needs connect() inspection with pidfd_getfd in {SUPERVISOR}",
                    clause.target.pattern
                ));
            }
            Ok(Mapping {
                target: Target::Network,
                detail: "Landlock refuses every TCP connect(2) and bind(2) (no port is allowed, ABI >= 4), and the seccomp filter refuses every IPv4/IPv6 socket that is not TCP plus TCP fast-open sends; below ABI 4 the seccomp filter refuses every IPv4/IPv6 socket".into(),
                notes: vec![
                    "stricter than the bpf-lsm backend, which mediates IPv4 connect(): IPv6, UDP, ICMP, SCTP, MPTCP, raw sockets, and TCP bind are refused too".into(),
                    "Unix-domain sockets stay usable; on Landlock ABI >= 6 abstract Unix sockets are scoped to the sandbox".into(),
                    "descriptors inherited from the launching environment (for example stdio that is already a connected socket) stay usable; only new connections are refused".into(),
                ],
            })
        }
        Op::Recv => Err(format!(
            "`recv` needs per-socket supervision of received data, which only {SUPERVISOR} provides"
        )),
    }
}

fn require_kind(clause: &Clause, kind: Kind) -> Result<(), String> {
    if clause.target.kind == kind {
        Ok(())
    } else {
        Err(format!(
            "`{} {}` is not a target kind the {} operation uses",
            kind_name(clause.target.kind),
            clause.target.pattern,
            op_name(clause.op)
        ))
    }
}

/// File-path targets that match every path in the compiler's lowering.
fn is_any_path(pattern: &str) -> bool {
    matches!(pattern, "*" | "**" | "**/*" | "/**")
}

fn require_any_path(clause: &Clause) -> Result<(), String> {
    if is_any_path(&clause.target.pattern) {
        return Ok(());
    }
    Err(format!(
        "`{} file \"{}\"` refuses one region and allows the rest; Landlock rules are allow-lists, so only `file \"/**\"` targets (optionally with `unless target \"/dir/**\"` or an exact absolute path) map exactly",
        op_name(clause.op),
        clause.target.pattern
    ))
}

/// Parse the allowed root of `unless target ROOT`: an absolute, normalized
/// path, either exact or followed by `/**`.
fn parse_root(pattern: &str) -> Result<Allowed, String> {
    let (body, beneath) = if pattern == "/**" {
        ("/", true)
    } else if let Some(dir) = pattern.strip_suffix("/**") {
        (dir, true)
    } else {
        (pattern, false)
    };
    let invalid = |why: &str| {
        Err(format!(
            "`unless target \"{pattern}\"` {why}; Landlock allow-lists take an absolute path, either exact (`/dir/file`) or a whole hierarchy (`/dir/**`)"
        ))
    };
    if !body.starts_with('/') {
        return invalid(
            "is not an absolute path (the compiler matches relative patterns as substrings)",
        );
    }
    if body.contains(['*', '?', '[', ']', '{', '}']) {
        return invalid("contains a glob other than a trailing `/**`");
    }
    if body.len() > 1 && body.ends_with('/') {
        return invalid("ends with `/`");
    }
    let path = Path::new(body);
    if body.contains("//")
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return invalid("is not a normalized path");
    }
    if beneath {
        Ok(Allowed::Beneath(path.to_path_buf()))
    } else {
        Ok(Allowed::File(path.to_path_buf()))
    }
}

fn fs_mapping(class: FsClass, allowed: Allowed, op: Op) -> Mapping {
    let mut notes = Vec::new();
    let detail = match class {
        FsClass::Write => {
            notes.push("Landlock checks rights when a file is opened, created, removed, renamed or truncated; descriptors the launcher passes in (stdin, stdout, stderr) stay usable".into());
            notes.push("creating directories, symlinks, sockets and FIFOs and removing directories count as writes, which is stricter than the bpf-lsm backend".into());
            notes.push("writes to the character devices /dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom, /dev/tty, /dev/ptmx and /dev/pts/* stay allowed, matching the bpf-lsm backend, whose file rules cover regular files and directories only; other device nodes and FIFOs outside the allowed region are refused".into());
            if op == Op::Unlink {
                notes.push("the compiler lowers `unlink` to the same kernel write op as `write`, so this clause confines every modification, as in the bpf-lsm backend".into());
            }
            format!(
                "Landlock write rights (write, truncate, create, remove, rename, link) are allowed {}",
                allowed.describe()
            )
        }
        FsClass::Read => {
            notes.push("Landlock checks opening files and listing directories; path lookup and stat stay allowed, and descriptors the launcher passes in stay usable".into());
            notes.push("reads of the character devices /dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom, /dev/tty, /dev/ptmx and /dev/pts/* stay allowed, matching the bpf-lsm backend's regular-file-and-directory scope".into());
            format!(
                "Landlock read rights (open for reading, list directory) are allowed {}",
                allowed.describe()
            )
        }
        FsClass::Execute => {
            notes.push("this backend matches the executable path; the bpf-lsm backend matches exec patterns on the command name, so `unless target` exec roots have no bpf-lsm equivalent".into());
            notes.push("the ELF interpreter (for example /lib64/ld-linux-x86-64.so.2) and every script must be inside the allowed region; code run by an allowed interpreter or loaded by the dynamic loader is not itself executed with execve".into());
            notes.push("the launched command itself is executed after the sandbox is applied, so it must be inside the allowed region".into());
            format!("Landlock execute right is allowed {}", allowed.describe())
        }
    };
    if let Allowed::File(file) = &allowed {
        notes.push(format!(
            "{} must exist at launch; it may be accessed, but creating, removing or renaming it stays refused",
            file.display()
        ));
    }
    Mapping {
        target: Target::Fs(class, allowed),
        detail,
        notes,
    }
}

/// Region reachable under every constraint of one class (constraints
/// intersect). `None` means no constraint of that class exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Region {
    Empty,
    Beneath(PathBuf),
    File(PathBuf),
}

pub(crate) fn intersect(a: &Region, b: &Region) -> Region {
    match (a, b) {
        (Region::Empty, _) | (_, Region::Empty) => Region::Empty,
        (Region::Beneath(x), Region::Beneath(y)) => {
            if x.starts_with(y) {
                Region::Beneath(x.clone())
            } else if y.starts_with(x) {
                Region::Beneath(y.clone())
            } else {
                Region::Empty
            }
        }
        (Region::Beneath(d), Region::File(f)) | (Region::File(f), Region::Beneath(d)) => {
            if f.starts_with(d) {
                Region::File(f.clone())
            } else {
                Region::Empty
            }
        }
        (Region::File(f), Region::File(g)) => {
            if f == g {
                Region::File(f.clone())
            } else {
                Region::Empty
            }
        }
    }
}

pub(crate) fn region_of(allowed: &Allowed) -> Region {
    match allowed {
        Allowed::Nothing => Region::Empty,
        Allowed::Beneath(p) => Region::Beneath(p.clone()),
        Allowed::File(p) => Region::File(p.clone()),
    }
}

pub(crate) fn class_region<'a>(constraints: impl Iterator<Item = &'a Allowed>) -> Option<Region> {
    let mut region: Option<Region> = None;
    for allowed in constraints {
        let next = region_of(allowed);
        region = Some(match region {
            None => next,
            Some(r) => intersect(&r, &next),
        });
    }
    region
}

fn overlaps(a: &Region, b: &Region) -> bool {
    intersect(a, b) != Region::Empty
}

/// Refuse an execute allow-list unless every allowed exec location is outside
/// the writable region, so the agent cannot write a program and run it.
pub(crate) fn exec_write_conflict(
    exec: impl Iterator<Item = (Allowed, String)>,
    write: Option<Region>,
) -> Result<(), String> {
    let exec: Vec<(Allowed, String)> = exec.collect();
    let exec_region = class_region(exec.iter().map(|(a, _)| a));
    let Some(exec_region) = exec_region else {
        return Ok(());
    };
    if exec_region == Region::Empty {
        // `block exec "*"` without an allowed region: nothing is executable.
        return Ok(());
    }
    let Some(write_region) = write else {
        return Err(format!(
            "an execute allow-list ({}) needs a write confinement clause (for example `block write file \"/**\" unless target \"/work/**\"`) in the same policy; without one every directory the user can write stays writable, so the agent could place a program inside the allowed exec region and run it",
            describe_region(&exec_region)
        ));
    };
    if overlaps(&exec_region, &write_region) {
        return Err(format!(
            "the execute allow-list ({}) overlaps the writable region ({}); the agent could write a program there and run it, so this backend refuses execute rights beneath writable hierarchies",
            describe_region(&exec_region),
            describe_region(&write_region)
        ));
    }
    Ok(())
}

fn describe_region(region: &Region) -> String {
    match region {
        Region::Empty => "nowhere".into(),
        Region::Beneath(p) => format!("beneath {}", p.display()),
        Region::File(p) => format!("the file {}", p.display()),
    }
}

fn check_exec_not_writable(spec: &SandboxSpec) -> Result<(), String> {
    let write = class_region(
        spec.fs
            .iter()
            .filter(|c| c.class == FsClass::Write)
            .map(|c| &c.allowed),
    );
    exec_write_conflict(
        spec.fs
            .iter()
            .filter(|c| c.class == FsClass::Execute)
            .map(|c| (c.allowed.clone(), c.rule.clone())),
        write,
    )
}

fn declaration_reports(policy: &Policy, runner: Option<&str>) -> Vec<DeclReport> {
    let mut used_by_rules = BTreeSet::new();
    for r in &policy.rules {
        for c in &r.clauses {
            expr_labels(&c.when, &mut used_by_rules);
        }
    }
    let label_detail = |label: &str, what: &str| -> String {
        if Some(label) == runner {
            format!(
                "{what} for the runner label {label}; `run` already applies {label} to the whole launched tree, so this declaration changes nothing in this backend"
            )
        } else if used_by_rules.contains(label) {
            format!(
                "{what} for {label}; label propagation is not available in this backend, and the clauses that test {label} are reported unsupported"
            )
        } else {
            format!("{what} for {label}; inert, because no clause tests {label}")
        }
    };
    let mut out = Vec::new();
    for s in &policy.sources {
        out.push(DeclReport {
            text: format!(
                "source {} = {} \"{}\"",
                s.label,
                kind_name(s.kind),
                s.pattern
            ),
            detail: label_detail(&s.label, "label source"),
        });
    }
    for x in &policy.xforms {
        let verb = if x.endorse { "endorse" } else { "declassify" };
        let detail = if !x.endorse && Some(x.label.as_str()) == runner {
            format!(
                "removes the runner label {} from processes that exec \"{}\", so clauses conditioned on {} are reported unsupported",
                x.label, x.gate, x.label
            )
        } else {
            label_detail(&x.label, "label transform")
        };
        out.push(DeclReport {
            text: format!("{verb} {} by exec \"{}\"", x.label, x.gate),
            detail,
        });
    }
    out
}

fn display_exec_pattern(pattern: &str) -> &str {
    pattern.strip_prefix("**/").unwrap_or(pattern)
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::File => "file",
        Kind::Endpoint => "endpoint",
        Kind::Exec => "exec",
    }
}

fn op_name(op: Op) -> &'static str {
    match op {
        Op::Exec => "exec",
        Op::Read => "read",
        Op::Write => "write",
        Op::Unlink => "unlink",
        Op::Connect => "connect",
        Op::Recv => "recv",
        Op::Open => "open",
    }
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Notify => "notify",
        Effect::Block => "block",
        Effect::Kill => "kill",
    }
}

fn render_expr(expr: &Expr) -> String {
    match expr {
        Expr::True => "true".into(),
        Expr::Label(l) => l.clone(),
        Expr::Not(l) => format!("not {l}"),
        Expr::And(a, b) => format!("{} and {}", render_expr(a), render_expr(b)),
        Expr::Or(a, b) => format!("{} or {}", render_expr(a), render_expr(b)),
    }
}

fn render_event(op: Op, pattern: &str, arg: Option<&str>) -> String {
    match arg {
        Some(arg) => format!("{} \"{}\" \"{}\"", op_name(op), pattern, arg),
        None => format!("{} \"{}\"", op_name(op), pattern),
    }
}

/// Render a clause back to DSL text (exec targets without their implicit
/// `**/` prefix).
pub fn render_clause(clause: &Clause) -> String {
    let mut out = format!("{} {}", effect_name(clause.effect), op_name(clause.op));
    match clause.target.kind {
        Kind::Exec => {
            let _ = write!(out, " \"{}\"", display_exec_pattern(&clause.target.pattern));
        }
        kind => {
            let _ = write!(out, " {} \"{}\"", kind_name(kind), clause.target.pattern);
        }
    }
    if let Some(arg) = &clause.target.arg {
        let _ = write!(out, " \"{arg}\"");
    }
    if clause.when != Expr::True {
        let _ = write!(out, " if {}", render_expr(&clause.when));
    }
    match &clause.unless {
        None => {}
        Some(Cond::Target { negate, pattern }) => {
            let not = if *negate { "not " } else { "" };
            let _ = write!(out, " unless target {not}\"{pattern}\"");
        }
        Some(Cond::LineageIncludes { exec }) => {
            let _ = write!(out, " unless lineage-includes exec \"{exec}\"");
        }
        Some(Cond::After {
            gate_op,
            gate_pattern,
            gate_exit,
            since,
        }) => {
            let _ = write!(
                out,
                " unless after {}",
                render_event(*gate_op, gate_pattern, None)
            );
            if let Some(code) = gate_exit {
                let _ = write!(out, " exits {code}");
            }
            for (i, (op, pat, arg)) in since.iter().enumerate() {
                let joiner = if i == 0 { " since " } else { " or " };
                let _ = write!(out, "{joiner}{}", render_event(*op, pat, arg.as_deref()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use actplane_ifc_compiler::parse;

    fn analyze_src(src: &str) -> Analysis {
        analyze(&parse::parse(src).expect("parse"))
    }

    fn only(a: &Analysis) -> &ClauseReport {
        assert_eq!(a.clauses.len(), 1, "{:#?}", a.clauses);
        &a.clauses[0]
    }

    #[test]
    fn read_only_domain_is_exact() {
        let a = analyze_src("rule ro:\n  block write file \"*\"\n  because \"read only\"\n");
        assert!(a.is_supported(), "{}", a.rejection_message());
        let spec = a.spec().expect("spec");
        assert_eq!(
            spec.fs,
            vec![FsConstraint {
                class: FsClass::Write,
                allowed: Allowed::Nothing,
                rule: "ro".into(),
                clause: 1,
            }]
        );
        assert!(!spec.deny_network);
        assert_eq!(spec.landlock_min_abi(), LANDLOCK_ABI_WRITE);
    }

    #[test]
    fn workspace_confinement_with_runner_label_is_exact() {
        let a = analyze_src(
            r#"
            source AGENT = exec "**/codex"
            rule confine-writes:
              block write  file "/**" if AGENT unless target "/work/**"
              block unlink file "/**" if AGENT unless target "/work/**"
              because "agent may only modify /work"
            "#,
        );
        assert!(a.is_supported(), "{}", a.rejection_message());
        assert_eq!(a.runner_label.as_deref(), Some("AGENT"));
        let spec = a.spec().unwrap();
        assert_eq!(spec.fs.len(), 2);
        for c in &spec.fs {
            assert_eq!(c.class, FsClass::Write);
            assert_eq!(c.allowed, Allowed::Beneath(PathBuf::from("/work")));
        }
        assert!(a.clauses[0].notes[0].contains("`if AGENT` holds for the whole launched tree"));
        assert!(
            a.clauses[1]
                .notes
                .iter()
                .any(|n| n.contains("lowers `unlink` to the same kernel write op"))
        );
        assert!(
            a.declarations[0].detail.contains("runner label AGENT"),
            "{:?}",
            a.declarations
        );
    }

    #[test]
    fn exact_file_root_and_read_confinement_map_to_landlock() {
        let a = analyze_src(
            r#"
            rule r:
              block write file "/**" unless target "/tmp/notes.txt"
              block read  file "**/*" unless target "/srv/data/**"
              block open  file "**"
              because "x"
            "#,
        );
        assert!(a.is_supported(), "{}", a.rejection_message());
        let spec = a.spec().unwrap();
        assert_eq!(
            spec.fs[0].allowed,
            Allowed::File(PathBuf::from("/tmp/notes.txt"))
        );
        assert_eq!(spec.fs[1].class, FsClass::Read);
        assert_eq!(
            spec.fs[1].allowed,
            Allowed::Beneath(PathBuf::from("/srv/data"))
        );
        assert_eq!(spec.fs[2].class, FsClass::Read);
        assert_eq!(spec.fs[2].allowed, Allowed::Nothing);
        assert_eq!(spec.landlock_min_abi(), LANDLOCK_ABI_WRITE);
    }

    #[test]
    fn deny_all_network_is_exact() {
        let a = analyze_src(
            "source COMMAND = exec \"**\"\nrule no-net:\n  block connect endpoint \"*\" if COMMAND\n  because \"offline\"\n",
        );
        assert!(a.is_supported(), "{}", a.rejection_message());
        let spec = a.spec().unwrap();
        assert!(spec.deny_network);
        assert!(spec.fs.is_empty());
        assert_eq!(spec.landlock_min_abi(), 0);
    }

    #[test]
    fn label_conditioned_clause_is_rejected() {
        let a = analyze_src(
            r#"
            source SECRET = file "**/.env"
            rule no-exfil:
              block connect endpoint "*" if SECRET
              because "secret data must not leave the host"
            "#,
        );
        assert!(!a.is_supported());
        assert!(a.spec().is_none());
        let c = only(&a);
        assert_eq!(c.status, ClauseStatus::Unsupported);
        assert!(c.detail.contains("`if SECRET`"), "{}", c.detail);
        let msg = a.rejection_message();
        assert!(msg.contains("rule no-exfil clause 1"), "{msg}");
        assert!(msg.contains("refuses to run it"), "{msg}");
        assert!(a.declarations[0].detail.contains("reported unsupported"));
    }

    #[test]
    fn declassified_runner_label_is_rejected() {
        let a = analyze_src(
            "source COMMAND = exec \"**\"\nrule r:\n  block write file \"/**\" if COMMAND\n  because \"x\"\ndeclassify COMMAND by exec \"**/sudo-ok\"\n",
        );
        let c = only(&a);
        assert_eq!(c.status, ClauseStatus::Unsupported);
        assert!(c.detail.contains("declassify COMMAND"), "{}", c.detail);
    }

    #[test]
    fn non_block_effects_are_rejected_not_downgraded() {
        for (verb, needle) in [("notify", "`notify`"), ("kill", "`kill`")] {
            let a = analyze_src(&format!(
                "rule r:\n  {verb} write file \"/**\"\n  because \"x\"\n"
            ));
            let c = only(&a);
            assert_eq!(c.status, ClauseStatus::Unsupported, "{verb}");
            assert!(c.detail.contains(needle), "{}", c.detail);
            assert!(a.spec().is_none());
        }
    }

    #[test]
    fn argv_and_temporal_and_lineage_clauses_are_rejected() {
        let cases = [
            ("block exec \"git\" \"push\"", "argv token"),
            (
                "block write file \"/**\" unless after exec \"**/pytest\"",
                "temporal gate",
            ),
            (
                "block open file \"/**\" unless lineage-includes exec \"**/migrate\"",
                "exec ancestry",
            ),
            (
                "block write file \"/**\" unless target not \"/etc/**\"",
                "denied region",
            ),
            ("block recv endpoint \"*\"", "`recv`"),
            ("block connect endpoint \"10.0.0.\"", "address matching"),
            (
                "block connect endpoint \"*\" unless target \"127.0.0.1\"",
                "endpoint allow-list",
            ),
        ];
        for (clause, needle) in cases {
            let a = analyze_src(&format!("rule r:\n  {clause}\n  because \"x\"\n"));
            let c = only(&a);
            assert_eq!(c.status, ClauseStatus::Unsupported, "{clause}");
            assert!(c.detail.contains(needle), "{clause}: {}", c.detail);
        }
    }

    #[test]
    fn deny_one_region_and_relative_globs_are_rejected() {
        let cases = [
            ("block write file \"**/.env\"", "allow-lists"),
            ("block write file \"/etc/**\"", "allow-lists"),
            (
                "block write file \"/**\" unless target \"src/**\"",
                "not an absolute path",
            ),
            (
                "block write file \"/**\" unless target \"/work/*.txt\"",
                "glob",
            ),
            ("block write file \"/**\" unless target \"/work/*\"", "glob"),
            (
                "block write file \"/**\" unless target \"/work/../etc/**\"",
                "normalized",
            ),
            (
                "block write file \"/**\" unless target \"/work/\"",
                "ends with",
            ),
            ("block exec \"git\"", "allow-list"),
            ("block exec \"/usr/bin/*\"", "allow-list"),
            ("block exec \"**\"", "matches no program"),
            ("block exec \"/**\"", "matches no program"),
        ];
        for (clause, needle) in cases {
            let a = analyze_src(&format!("rule r:\n  {clause}\n  because \"x\"\n"));
            let c = only(&a);
            assert_eq!(c.status, ClauseStatus::Unsupported, "{clause}");
            assert!(c.detail.contains(needle), "{clause}: {}", c.detail);
        }
    }

    #[test]
    fn exec_allow_list_needs_disjoint_write_confinement() {
        // No write confinement: every user-writable directory stays writable.
        let a =
            analyze_src("rule r:\n  block exec \"*\" unless target \"/usr/**\"\n  because \"x\"\n");
        let c = only(&a);
        assert_eq!(c.status, ClauseStatus::Unsupported);
        assert!(
            c.detail.contains("needs a write confinement clause"),
            "{}",
            c.detail
        );

        // Overlapping regions: a program written in /work could be executed.
        let a = analyze_src(
            "rule r:\n  block write file \"/**\" unless target \"/work/**\"\n  block exec \"*\" unless target \"/work/bin/**\"\n  because \"x\"\n",
        );
        assert_eq!(a.clauses[0].status, ClauseStatus::Exact);
        assert_eq!(a.clauses[1].status, ClauseStatus::Unsupported);
        assert!(a.clauses[1].detail.contains("overlaps the writable region"));
        assert!(a.spec().is_none());

        // Disjoint regions are exact.
        let a = analyze_src(
            "rule r:\n  block write file \"/**\" unless target \"/work/**\"\n  block exec \"*\" unless target \"/usr/**\"\n  because \"x\"\n",
        );
        assert!(a.is_supported(), "{}", a.rejection_message());
        let spec = a.spec().unwrap();
        assert_eq!(
            spec.classes().into_iter().collect::<Vec<_>>(),
            vec![FsClass::Write, FsClass::Execute]
        );

        // Denying every exec needs no write confinement.
        let a = analyze_src("rule r:\n  block exec \"*\"\n  because \"x\"\n");
        assert!(a.is_supported(), "{}", a.rejection_message());
    }

    #[test]
    fn intersecting_write_clauses_are_checked_against_exec_roots() {
        // Writes are allowed only where both clauses allow them (/a/b); /a/c is
        // not writable, so executing beneath it is fine.
        let a = analyze_src(
            "rule r:\n  block write file \"/**\" unless target \"/a/**\"\n  block write file \"/**\" unless target \"/a/b/**\"\n  block exec \"*\" unless target \"/a/c/**\"\n  because \"x\"\n",
        );
        assert!(a.is_supported(), "{}", a.rejection_message());
        // Disjoint write clauses leave nothing writable.
        let w = class_region([Allowed::Beneath("/a".into()), Allowed::Beneath("/b".into())].iter());
        assert_eq!(w, Some(Region::Empty));
    }

    #[test]
    fn policy_without_rules_is_supported_with_hardening_only() {
        let a = analyze_src("source SECRET = file \"**/.env\"\n");
        assert!(a.is_supported());
        assert_eq!(a.spec().unwrap(), &SandboxSpec::default());
        assert!(a.declarations[0].detail.contains("inert"));
    }

    #[test]
    fn mixed_policy_reports_every_clause() {
        let a = analyze_src(
            r#"
            source COMMAND = exec "**"
            rule confine:
              block write file "/**" if COMMAND unless target "/work/**"
              kill exec "git" "push" if COMMAND
              because "stay in /work"
            rule net:
              block connect endpoint "*"
              because "offline"
            "#,
        );
        assert_eq!(a.clauses.len(), 3);
        assert_eq!(a.exact_count(), 2);
        assert_eq!(a.clauses[1].status, ClauseStatus::Unsupported);
        assert_eq!(a.clauses[1].text, "kill exec \"git\" \"push\" if COMMAND");
        assert!(!a.is_supported());
        let msg = a.rejection_message();
        assert!(msg.contains("rule confine clause 2"), "{msg}");
        assert!(!msg.contains("rule net"), "{msg}");
    }

    #[test]
    fn render_clause_round_trips_conditions() {
        let a = analyze_src(
            "rule r:\n  block exec \"git\" \"commit\" if A and not B unless after exec \"**/pytest\" exits 0 since write \"src/**\" or exec \"git\" \"x\"\n  because \"x\"\n",
        );
        assert_eq!(
            only(&a).text,
            "block exec \"git\" \"commit\" if A and not B unless after exec \"**/pytest\" exits 0 since write \"src/**\" or exec \"git\" \"x\""
        );
    }
}
