// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Lower a parsed Policy to the kernel ABI (struct taint_config, see
//! bpf/taint.h): assign label/gate bits, compile boolean exprs to req/forbid
//! masks (via DNF), and lower globs to the kernel's exact/prefix/suffix/any
//! match kinds.

use super::ast::*;
use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};

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
const MAX_CONTAINS_LITERAL: usize = 16; // mirrors TAINT_SUF_MAX in bpf/taint.h
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

/// Copy `s` into a fixed kernel pattern buffer, truncating to `dst.len() - 1`.
///
/// Truncation is silent to the kernel: the stored literal is a prefix of the
/// intended one, so a rule meant to match a long path or comm instead matches
/// that prefix (an `EXACT` literal then never matches the intended target, and a
/// `PREFIX`/`SUFFIX` literal matches a broader set). Callers that want the
/// mismatch reported use [`set_pat_reported`], which records it in
/// `Compiled::pattern_warnings` for the CLI to surface.
fn set_pat(dst: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&b[..n]);
    dst[n] = 0;
}

/// [`set_pat`] plus, when the literal did not fit, a warning naming what was
/// truncated and the effective limit. The message is built here because this
/// module owns the buffer sizes.
fn set_pat_reported(dst: &mut [u8], s: &str, what: &str, out: &mut Vec<PatternWarning>) {
    if !s.is_empty() && s.len() > dst.len() - 1 {
        out.push(PatternWarning {
            code: PATTERN_TRUNCATED,
            message: format!(
                "{what} \"{s}\" is longer than the kernel pattern buffer ({} bytes) and was truncated to a prefix; the compiled rule matches that prefix, not the intended target. Shorten it, or use a wildcard form that lowers to a shorter literal.",
                dst.len() - 1
            ),
        });
    }
    set_pat(dst, s);
}

/// Report a literal that the kernel matcher cannot use, for a pattern.
///
/// * An empty literal for a non-`ANY` kind. `taint_streq`, `taint_prefix`, and
///   `taint_contains` all return 0 for an empty pattern (exact: the text would
///   have to be empty; prefix: `anynz` stays 0, and the comment on
///   `taint_prefix` states an empty prefix never matches; contains: `pn == 0`
///   is guarded directly). A pattern such as `exec "src/*"`, `exec "foo/"`, or
///   `exec "*g*t"` (whose concrete text the wildcard-literal cleanup discards,
///   leaving an empty span) lowers to an empty literal, so the rule never fires.
///   `ANY` is exempt by construction: its literal is meant to be empty and it
///   always matches.
/// * A `SUFFIX`/`CONTAINS` literal past `TAINT_SUF_MAX`. Both matchers return 0
///   when the pattern is longer than their fixed 16-byte tail/window copy, so
///   that matcher entry never matches. It is the *entry* that dies, not always
///   the pattern: a repo-relative `**/<name>` pattern also emits a bare `exact`
///   companion entry in an `open`/`write`/path-gate slot, and an `exact` literal
///   has no length bound, so the construct still matches the bare form.
///   `live_companion` is that companion's literal when the caller emitted one,
///   and `None` when the primary entry is the only one.
fn check_matcher_literal_bound(
    kind: u8,
    lit: &str,
    what: &str,
    live_companion: Option<&str>,
    out: &mut Vec<PatternWarning>,
) {
    if kind == M_ANY {
        return;
    }
    if lit.is_empty() {
        out.push(PatternWarning {
            code: PATTERN_EMPTY_LITERAL,
            message: format!(
                "{what} \"\" lowers to an empty {} literal, and the kernel matcher rejects an empty pattern, so this can never match. Use a concrete name, or `*` / `**/*` to match anything.",
                match_kind_name(kind)
            ),
        });
        return;
    }
    if matches!(kind, M_SUFFIX | M_CONTAINS) && lit.len() > MAX_CONTAINS_LITERAL {
        let consequence = match live_companion {
            None => "so the pattern can never match. Use a shorter basename pattern, or an absolute pattern with a wildcard.".to_string(),
            Some(companion) => format!(
                "so this {} entry can never match. The pattern also emits a companion `exact` entry for the bare form \"{companion}\", whose literal has no such bound, so the pattern still matches a bare path with no leading directory. Use a shorter basename pattern, or an absolute pattern with a wildcard.",
                match_kind_name(kind)
            ),
        };
        out.push(PatternWarning {
            code: PATTERN_MATCHER_LENGTH,
            message: format!(
                "{what} \"{lit}\" lowers to a {}-byte {} literal, but the kernel matcher rejects any literal longer than {} bytes, {consequence}",
                lit.len(),
                match_kind_name(kind),
                MAX_CONTAINS_LITERAL
            ),
        });
    }
}

/// Record a [`PATTERN_LITERAL_WIDENED`] warning when the wildcard-literal
/// cleanup dropped concrete text, so the compiled matcher matches strictly more
/// than the glob names. `pat` is the pattern as the policy wrote it, which is
/// what the reader needs to fix, not the folded literal. `widened` is false
/// when the cleanup kept an empty span, because then the literal matches
/// nothing at all and [`check_matcher_literal_bound`] reports the empty form;
/// the two warnings must not both fire, since one says "strictly more" and the
/// other "never".
fn warn_widened_literal(pat: &str, widened: bool, what: &str, out: &mut Vec<PatternWarning>) {
    if !widened {
        return;
    }
    out.push(PatternWarning {
        code: PATTERN_LITERAL_WIDENED,
        message: format!(
            "{what} \"{pat}\" has a wildcard inside its literal, and the kernel matcher compares bytes, so the concrete text around that wildcard was dropped to leave a usable matcher literal; the compiled matcher now matches strictly more than the glob names. Move the wildcard to an edge of the pattern (a trailing `*`, or a leading `*` form), or write the exact name."
        ),
    });
}

/// Record a [`PATTERN_CONTAINS_CAPPED`] warning when the 16-byte `contains`
/// window forced the literal to a contiguous proper substring of the natural
/// one, so the compiled matcher matches strictly more than the glob names.
/// `pat` is the pattern as the policy wrote it, which is what the reader needs
/// to fix, not the shortened literal.
fn warn_capped_literal(pat: &str, capped: bool, what: &str, out: &mut Vec<PatternWarning>) {
    if !capped {
        return;
    }
    out.push(PatternWarning {
        code: PATTERN_CONTAINS_CAPPED,
        message: format!(
            "{what} \"{pat}\" lowers to a `contains` literal longer than the kernel's {MAX_CONTAINS_LITERAL}-byte window, so the compiler shortened it to a contiguous substring of that literal; the compiled matcher now matches strictly more than the glob names. Use a shorter directory pattern so the literal fits, or match a distinct basename instead."
        ),
    });
}

/// Record a [`RULE_CONDITION_CONTRADICTION`] warning when a lowered DNF term
/// requires and forbids the same label bit. `taint_mask_ok` tests
/// `(labels & req) == req && (labels & forbid) == 0`, so an overlap is false for
/// every label state: that disjunct can never hold. The engine uses the same
/// predicate, so nothing is silently mis-enforced; the alternative is dead.
///
/// `when` is `A and not A` under `&&`, so the whole clause is often dead, but
/// `(A or B) and not A` leaves `B` alive: `all_terms_dead` distinguishes the
/// two, because the reader's fix differs (delete the rule vs. delete one side).
/// `labels` inverts the bit back to the name, which is what the policy wrote.
/// The warning is emitted once per clause, not once per dead disjunct, so
/// `(A or A) and not A` does not repeat itself.
fn warn_condition_contradiction(
    req: u64,
    forbid: u64,
    all_terms_dead: bool,
    labels: &HashMap<String, u64>,
    name: &str,
    out: &mut Vec<PatternWarning>,
) {
    let overlap = req & forbid;
    if overlap == 0 {
        return;
    }
    let mut names: Vec<&str> = labels
        .iter()
        .filter(|(_, b)| **b & overlap != 0)
        .map(|(n, _)| n.as_str())
        .collect();
    names.sort_unstable();
    let named = if names.is_empty() {
        // Reachable only if a bit lacks a name, which `label_bit` prevents.
        format!("{overlap:#x}")
    } else {
        names
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let what = if all_terms_dead {
        "the rule"
    } else {
        "one branch"
    };
    let fix = if all_terms_dead {
        "Drop one side, or replace the negated term with the label it should exclude."
    } else {
        "One disjunct under the `or` is unsatisfiable; delete that side to leave the branches that can fire."
    };
    out.push(PatternWarning {
        code: RULE_CONDITION_CONTRADICTION,
        message: format!(
            "rule `{name}` requires and forbids {named} at once, so no process state satisfies that condition and {what} never fires. Under `and`, a label appears both plain and negated, as in `A and not A`. {fix}"
        ),
    });
}

/// Does the kernel matcher `(kind, lit)` accept the concrete text `text`? Mirrors
/// `taint_match` in bpf/taint.h: `ANY` accepts everything, and the other kinds
/// reject an empty literal (an empty `exact` literal still accepts the empty
/// text, which is only reachable for an empty comm, so the asymmetry is kept).
fn matcher_hits(kind: u8, lit: &str, text: &str) -> bool {
    match kind {
        M_ANY => true,
        M_EXACT => lit == text,
        M_PREFIX => !lit.is_empty() && text.starts_with(lit),
        M_SUFFIX => !lit.is_empty() && text.ends_with(lit),
        M_CONTAINS => !lit.is_empty() && text.contains(lit),
        _ => false,
    }
}

/// True when the matcher `(kind, lit)` has an empty text set, so it never fires:
/// the kernel's `prefix`/`suffix`/`contains` all return 0 for an empty literal.
/// `EXACT` is excluded because it accepts the empty text.
fn matcher_is_dead(kind: u8, lit: &str) -> bool {
    lit.is_empty() && matches!(kind, M_PREFIX | M_SUFFIX | M_CONTAINS)
}

/// `L(tm, tlit) ⊆ L(cm, clit)`: every text the rule's target matcher accepts is
/// also accepted by the condition matcher. Used for `unless target PAT`, where
/// the kernel suppresses the rule whenever the condition holds.
fn target_subset_of_condition(tm: u8, tlit: &str, cm: u8, clit: &str) -> bool {
    if cm == M_ANY || matcher_is_dead(tm, tlit) {
        return true;
    }
    if matcher_is_dead(cm, clit) {
        // The condition matches nothing, so it never suppresses.
        return false;
    }
    match tm {
        // A singleton: test the literal itself against the condition.
        M_EXACT => matcher_hits(cm, clit, tlit),
        M_PREFIX => match cm {
            M_PREFIX => tlit.starts_with(clit),
            M_CONTAINS => tlit.contains(clit),
            _ => false,
        },
        M_SUFFIX => match cm {
            M_SUFFIX => tlit.ends_with(clit),
            M_CONTAINS => tlit.contains(clit),
            _ => false,
        },
        M_CONTAINS => cm == M_CONTAINS && tlit.contains(clit),
        // `ANY` accepts every text, so it is a subset only of `ANY`, handled above.
        _ => false,
    }
}

/// `L(tm, tlit) ∩ L(cm, clit) = ∅`: no text is accepted by both matchers. Used
/// for `unless target not PAT`, where the rule fires only where the condition
/// matcher is false, so an empty intersection means it never fires.
fn target_disjoint_from_condition(tm: u8, tlit: &str, cm: u8, clit: &str) -> bool {
    if matcher_is_dead(tm, tlit) || matcher_is_dead(cm, clit) {
        // An empty target or condition set intersects nothing.
        return true;
    }
    if cm == M_ANY || tm == M_ANY {
        // `ANY` is the whole line, so it intersects every non-empty set.
        return false;
    }
    // A singleton is disjoint from the other matcher exactly when the other
    // matcher rejects its literal.
    if tm == M_EXACT {
        return !matcher_hits(cm, clit, tlit);
    }
    if cm == M_EXACT {
        return !matcher_hits(tm, tlit, clit);
    }
    // Both sets are then infinite. Any prefix/suffix/contains pair intersects
    // (the concatenation `p + s` has prefix `p`, suffix `s`, and contains both).
    // Two prefixes intersect iff one is a prefix of the other: if neither is,
    // the shorter diverges before the longer ends, so no text has both.
    if tm == M_PREFIX && cm == M_PREFIX {
        return !tlit.starts_with(clit) && !clit.starts_with(tlit);
    }
    false
}

/// Whether a `unless target` condition leaves the rule's target matcher dead.
/// `negate` is `target not PAT`; without it the rule fires only where the
/// condition is false, so it dies when the target is a subset of the condition.
fn condition_covers_target(tm: u8, tlit: &str, cm: u8, clit: &str, negate: bool) -> bool {
    if negate {
        target_disjoint_from_condition(tm, tlit, cm, clit)
    } else {
        target_subset_of_condition(tm, tlit, cm, clit)
    }
}

/// Endpoint form of [`condition_covers_target`]. The entry matches when
/// `(ip & tmask) == taddr` and the condition when `(ip & cmask) == caddr`
/// (bpf/taint.h `te_cond_satisfied`).
fn endpoint_condition_covers_target(
    taddr: u32,
    tmask: u32,
    caddr: u32,
    cmask: u32,
    negate: bool,
) -> bool {
    if negate {
        // Disjoint: the two masked equalities cannot hold at once, which is
        // exactly when they disagree on the bits both constrain. (No bit is a
        // free bit of both, so agreement on the shared mask decides it.)
        (taddr & cmask) != (caddr & tmask)
    } else {
        // The condition must accept every address the target accepts. Those
        // addresses range only over the target's free bits, so the condition
        // may constrain only bits the target already fixes, and its fixed
        // values must agree with the target's.
        cmask & !tmask == 0 && (taddr & cmask) == caddr
    }
}

/// Record a [`RULE_CONDITION_COVERS_TARGET`] warning when an `unless target`
/// condition is satisfied by every event the rule's own target accepts, so the
/// kernel's `te_cond_satisfied` gate (`return -1`, bpf/taint_engine.bpf.h)
/// suppresses the rule before it can fire.
///
/// `all_rows_dead` distinguishes a wholly dead rule from a target pattern that
/// also emits a repo-relative companion entry the exception does not cover, as
/// `open file "**/secret" unless target "**/secret"` does: the suffix entry is
/// suppressed, the bare-name companion still fires. The reader's fix differs,
/// so the wording does too.
fn warn_condition_covers_target(
    target_pat: &str,
    cond_pat: &str,
    negate: bool,
    all_rows_dead: bool,
    name: &str,
    out: &mut Vec<PatternWarning>,
) {
    let why = if negate {
        // `target not PAT` is satisfied exactly where the `PAT` matcher is
        // false. Disjointness means `PAT` is false for every text the target
        // accepts, so the condition holds everywhere and suppresses them all.
        format!(
            "the exception `unless target not \"{cond_pat}\"` holds for every event the rule's own target \"{target_pat}\" accepts, because the `\"{cond_pat}\"` matcher rejects all of them, and the kernel suppresses a rule whose `target` condition holds"
        )
    } else {
        format!(
            "the exception `unless target \"{cond_pat}\"` holds for every event the rule's own target \"{target_pat}\" accepts, and the kernel suppresses a rule whose `target` condition holds"
        )
    };
    let what = if all_rows_dead {
        "so the rule can never fire"
    } else {
        "so one of the rule's target matcher entries can never fire (the target pattern also emits a companion entry this exception does not cover)"
    };
    out.push(PatternWarning {
        code: RULE_CONDITION_COVERS_TARGET,
        message: format!(
            "rule `{name}`: {why}, {what}. Remove the `unless target` clause, or make it narrower than the target (a sub-path the target names)."
        ),
    });
}

/// Human-readable name of a kernel match kind, for warnings.
fn match_kind_name(kind: u8) -> &'static str {
    match kind {
        M_EXACT => "exact",
        M_PREFIX => "prefix",
        M_SUFFIX => "suffix",
        M_ANY => "any",
        M_CONTAINS => "contains",
        _ => "unknown",
    }
}

/// Record a [`RULE_CONDITION_LABEL_WITHOUT_PRODUCER`] warning when a clause's
/// `when` references a label that nothing in this policy (or an earlier delta,
/// via `existing_labels`) ever sets.
///
/// `label_bit` allocates a bit for a label the moment it is seen, whether from a
/// source, an xform, or a condition reference, so a policy that only ever
/// *names* a label still compiles to a rule whose `req`/`forbid` mask holds that
/// bit. Nothing then sets it: a `source` adds the bit and an `endorse` xform
/// adds it, but a `declassify` xform *clears* it (`del = bit`), so a policy whose
/// only mention of the label is a `declassify` still has no producer. The bit is
/// then zero in every process state, so `taint_mask_ok` rejects the plain form
/// (`req` unmet, the rule never fires) and accepts the negated form (`forbid`
/// clear, the rule fires on every event its target accepts).
///
/// `produced` holds the names an adding update defines, plus the labels an
/// earlier delta already allocated, since that bit is live in the domain even
/// though no local update writes it. [`RUNTIME_SEEDED_LABELS`] are exempt: the
/// runner seeds them into the protected pid itself.
///
/// Emitted once per clause, naming every such label, because the fix is the
/// same for each reference in the clause: declare a producer, or drop the term.
fn warn_condition_label_without_producer(
    when: &Expr,
    produced: &BTreeSet<&str>,
    name: &str,
    out: &mut Vec<PatternWarning>,
) {
    let mut referenced = BTreeSet::new();
    collect_expr_labels(when, &mut referenced);
    let mut missing: Vec<&str> = referenced
        .iter()
        .map(String::as_str)
        .filter(|name| !produced.contains(name) && !RUNTIME_SEEDED_LABELS.contains(name))
        .collect();
    missing.sort_unstable();
    let Some(label) = missing.first() else {
        return;
    };
    let also = if missing.len() > 1 {
        format!(
            " (also {})",
            missing[1..]
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        String::new()
    };
    out.push(PatternWarning {
        code: RULE_CONDITION_LABEL_WITHOUT_PRODUCER,
        message: format!(
            "rule `{name}`: the condition references label `{label}`{also}, which nothing in this policy sets, so no update ever puts its bit in a label mask. The plain form `if {label}` never fires, and the negated form `if not {label}` fires on every event the rule's target accepts. Declare a `source {label} = ...` for it (an `endorse` xform also sets it, but a `declassify` clears it), or drop the term."
        ),
    });
}

/// (match, literal) lowering for exec-side patterns (matched on comm). The
/// compact form the unit tests assert on; callers use [`lower_exec_reported`]
/// so the widening warning reaches `Compiled::pattern_warnings`.
#[cfg(test)]
fn lower_exec(pat: &str) -> (u8, String) {
    let l = lower_exec_reported(pat);
    (l.kind, l.lit)
}

/// [`lower_exec`] plus whether the wildcard-literal cleanup dropped concrete
/// text, which makes the compiled matcher match strictly more than the glob.
fn lower_exec_reported(pat: &str) -> Lowered {
    if pat == "*" || pat == "**" || pat == "**/*" {
        return Lowered {
            kind: M_ANY,
            lit: String::new(),
            widened: false,
            capped: false,
        };
    }
    let base = pat.rsplit('/').next().unwrap_or(pat);
    // A basename that is the recursive wildcard matches any comm. Without this
    // the parser's `exec "**"` normalization to `**/**`, and a written
    // `exec "src/**"`, both reduce to a `PREFIX "*"` literal, and no comm starts
    // with `*`, so the rule silently never fires. `exec "*"` already reaches
    // the ANY branch above.
    if base == "**" {
        return Lowered {
            kind: M_ANY,
            lit: String::new(),
            widened: false,
            capped: false,
        };
    }
    let lowered = if let Some(stripped) = base.strip_suffix('*') {
        (M_PREFIX, stripped.to_string())
    } else {
        (M_EXACT, base.to_string())
    };
    let (kind, lit, widened) = strip_wildcard_literal_widening(lowered.0, lowered.1);
    Lowered {
        kind,
        lit,
        widened,
        capped: false,
    }
}

/// One pattern's lowering plus the two independent ways the compiled matcher
/// can end up wider than the glob the policy wrote. Each has its own warning
/// code, so they are tracked separately: [`PATTERN_LITERAL_WIDENED`] for the
/// wildcard-literal cleanup, [`PATTERN_CONTAINS_CAPPED`] for the 16-byte
/// `contains` window.
struct Lowered {
    /// Kernel match kind.
    kind: u8,
    /// Literal that reaches the matcher table.
    lit: String,
    /// The wildcard-literal cleanup dropped concrete text.
    widened: bool,
    /// The `contains` cap shortened the literal to a proper substring.
    capped: bool,
}

/// Remove any `*` left in a matcher literal, widening to the concrete span the
/// matcher can actually use, and report whether that widened the match. The
/// kernel compares bytes, so a literal containing `*` only ever matches a real
/// asterisk byte and the rule silently never fires (`exec "g*t"` lowered to
/// `exact("g*t")`). Each match kind has an exact superset that keeps the
/// concrete text: a prefix keeps everything before the first wildcard, a suffix
/// everything after the last, and a substring test the run leading up to the
/// first. The result can be empty (a wildcard in the head or tail position),
/// which the caller reports as an empty-literal warning.
///
/// The cleanup keeps the span the byte matcher can use and drops the rest, so
/// the result is always a superset of the glob. It is a *strict* superset, and
/// worth warning about, exactly when a discarded byte is not itself a `*`: then
/// the glob required concrete text the matcher no longer checks. A purely
/// wildcard tail (`deploy*` to `prefix("deploy")`, or `g**`) discards nothing
/// concrete and is exact. An *empty* kept span is a strict **subset**, not a
/// superset: every non-`ANY` matcher rejects an empty literal, so the entry
/// matches nothing at all. The kept span being empty therefore also clears
/// `widened`, because claiming the matcher "matches strictly more" while the
/// same literal is reported as one that "can never match" is a contradiction;
/// the caller's empty-literal check states the true consequence.
fn strip_wildcard_literal_widening(kind: u8, lit: String) -> (u8, String, bool) {
    if kind == M_ANY || !lit.contains('*') {
        return (kind, lit, false);
    }
    if kind == M_SUFFIX {
        let cut = lit.rfind('*').unwrap();
        let kept = lit[cut + 1..].to_string();
        let widened = !kept.is_empty() && lit[..cut].bytes().any(|b| b != b'*');
        return (kind, kept, widened);
    }
    let cut = lit.find('*').unwrap();
    let kept = lit[..cut].to_string();
    let widened = !kept.is_empty() && lit[cut + 1..].bytes().any(|b| b != b'*');
    let kind = if kind == M_EXACT { M_PREFIX } else { kind };
    (kind, kept, widened)
}

/// Shorten a `contains` literal to fit the kernel's 16-byte window
/// (`MAX_CONTAINS_LITERAL`), returning the literal and whether the window
/// forced a shortening.
///
/// Every branch past the length check returns a contiguous proper substring of
/// the natural literal (`lit`), so the kernel's substring test matches a strict
/// superset of the glob: the glob required bytes the matcher no longer checks.
/// Unlike the wildcard cleanup the discarded text can be entirely concrete, so
/// the caller warns whenever the boolean is true.
fn shorten_contains_literal(lit: &str) -> (String, bool) {
    if lit.len() <= MAX_CONTAINS_LITERAL {
        return (lit.to_string(), false);
    }
    let trimmed = lit.trim_start_matches('/');
    if trimmed.len() <= MAX_CONTAINS_LITERAL {
        return (trimmed.to_string(), true);
    }
    for (idx, _) in trimmed.match_indices('/') {
        let candidate = &trimmed[idx + 1..];
        if !candidate.is_empty() && candidate.len() <= MAX_CONTAINS_LITERAL {
            return (candidate.to_string(), true);
        }
    }
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    if !last.is_empty() && last.len() <= MAX_CONTAINS_LITERAL {
        return (last.to_string(), true);
    }
    // A pattern may contain multi-byte UTF-8 (the kernel compares bytes), so
    // the byte offset can land inside a character. Advance to the next
    // boundary: that is the longest suffix that still fits the window, and the
    // result is a contiguous proper substring as the other branches are.
    let mut start = trimmed.len() - MAX_CONTAINS_LITERAL;
    while !trimmed.is_char_boundary(start) {
        start += 1;
    }
    (trimmed[start..].to_string(), true)
}

/// The repo-relative exact-path companion of [`shorten_contains_literal`]: the
/// same window, walked from the front and then falling back to the parent
/// directory. Every branch returns a contiguous proper substring of `path`, so
/// the result is likewise a strict widening of the glob and reported the same.
fn shorten_repo_relative_exact_literal(path: &str) -> (String, bool) {
    if path.len() <= MAX_CONTAINS_LITERAL {
        return (path.to_string(), false);
    }
    for (idx, _) in path.match_indices('/') {
        let candidate = &path[idx + 1..];
        if candidate.contains('/') && candidate.len() <= MAX_CONTAINS_LITERAL {
            return (candidate.to_string(), true);
        }
    }
    if let Some((parent, _base)) = path.rsplit_once('/') {
        let (lit, _) = shorten_contains_literal(&format!("{}/", parent));
        return (lit, true);
    }
    shorten_contains_literal(path)
}

/// The bare root-level companion for a repo-relative `**/<name>` pattern (a
/// globstar, a slash, and a wildcard-free basename). The `suffix("/<name>")`
/// form requires a leading slash, so it misses a top-level file addressed from
/// the repository root (`write .env`); pairing it with an `exact("<name>")`
/// covers that case without over-matching (`foo.env` is not a match). Emitting
/// an extra table entry is verifier-free because the update and rule scans run
/// in `bpf_loop` callbacks (verified once), unlike a new matcher kind or an edit
/// inside an inlined matcher, either of which pushed the file-event hooks over
/// the 1,000,000-instruction limit on the CI kernel.
fn lower_path_bare(pat: &str) -> Option<String> {
    let inner = pat.strip_prefix("**/")?;
    (!inner.is_empty() && !inner.contains('*')).then(|| inner.to_string())
}

/// The first-segment-relative companion for a repo-relative `**/<dir>/**` or
/// `**/<dir>/*` pattern. The primary lowering is `contains("/<dir>/")`, whose
/// literal needs a slash before the directory, so it misses a path that begins
/// at the pattern's directory (`dist/x.js`). The `prefix("<dir>/")` form covers
/// exactly that case: a leading segment equal to the directory. Like the
/// bare-name companion below, this is an existing match kind and adds only a
/// table entry, so the file-event hooks are unaffected.
fn lower_path_relative_prefix(pat: &str) -> Option<String> {
    let dir = pat
        .strip_prefix("**/")
        .and_then(|r| r.strip_suffix("/**").or_else(|| r.strip_suffix("/*")))?;
    (!dir.is_empty() && !dir.contains('*')).then(|| format!("{dir}/"))
}

/// All repo-relative companion matchers for a path pattern, in the order they
/// should follow the primary lowering. A repo-relative pattern's primary form
/// assumes an absolute runtime path, which does not hold in tracepoint mode
/// where the kernel matches the userspace path argument verbatim. Emitting the
/// extra table entries is verifier-free because the update and rule scans run
/// in `bpf_loop` callbacks (verified once), unlike a new matcher kind or an
/// edit inside an inlined matcher.
fn lower_path_companions(pat: &str) -> Vec<(u8, String)> {
    let mut out = Vec::new();
    if let Some(bare) = lower_path_bare(pat) {
        out.push((M_EXACT, bare));
    }
    if let Some(prefix) = lower_path_relative_prefix(pat) {
        out.push((M_PREFIX, prefix));
    }
    out
}

/// The companion literal that keeps a repo-relative path pattern alive when its
/// primary matcher dies on the kernel's 16-byte window. Companions are `exact`
/// (bare form) or `prefix` (first-segment-relative form), and neither has that
/// window, so the pattern still matches whenever one is emitted.
fn live_path_companion(pat: &str) -> Option<String> {
    lower_path_companions(pat)
        .into_iter()
        .find(|(m, _)| !matches!(*m, M_SUFFIX | M_CONTAINS))
        .map(|(_, lit)| lit)
}

/// True when a repo-relative path pattern's primary matcher misses a form that
/// the kernel's single `cond_kind`/`cond_pat` pair cannot also cover: a
/// `**/<name>` basename (bare root-level file) or a `**/<dir>/**` / `**/<dir>/*`
/// directory (first-segment-relative path). A rule *target* covers both forms by
/// emitting a companion table entry, but an `unless target` **condition** has
/// only one cond slot, so the exception cannot express the disjunction and
/// mis-matches on the uncovered form (a positive condition over-fires there,
/// a negated one under-fires).
///
/// Callers use this to warn that the exception is approximate; the engine is not
/// changed. Absolute patterns and pure wildcard forms have no companion and
/// return `false`.
pub fn repo_relative_condition_is_partial(pattern: &str) -> bool {
    !pattern.starts_with('/') && !lower_path_companions(pattern).is_empty()
}

/// (match, literal) lowering for path patterns. The raw lowering can leave a
/// `*` in the literal (an interior wildcard, e.g. `**/a*b` to `contains("a*b")`);
/// [`strip_wildcard_literal_widening`] removes it so the kernel byte
/// comparison can match. The compact form the unit tests assert on; callers use
/// [`lower_path_reported`] so the widening warning is recorded.
#[cfg(test)]
fn lower_path(pat: &str) -> (u8, String) {
    let l = lower_path_reported(pat);
    (l.kind, l.lit)
}

/// [`lower_path`] plus whether the wildcard-literal cleanup widened the matcher.
fn lower_path_reported(pat: &str) -> Lowered {
    let (kind, lit, capped) = lower_path_raw(pat);
    let (kind, lit, widened) = strip_wildcard_literal_widening(kind, lit);
    Lowered {
        kind,
        lit,
        widened: widened || absolute_prefix_widens(pat),
        capped,
    }
}

/// The absolute branch of [`lower_path_raw`] cuts at the first wildcard, so a
/// concrete byte after it leaves the pattern without ever entering a literal
/// (`/tmp/*b/*` lowers to `prefix("/tmp/")`, which matches any path under
/// `/tmp`). The same test as the literal cleanup applies, on the pattern: the
/// cut is a strict widening exactly when the discarded tail is not all `*`.
/// `/tmp/guarded/**` discards only wildcards and stays exact.
fn absolute_prefix_widens(pat: &str) -> bool {
    if !pat.starts_with('/') {
        return false;
    }
    match pat.find('*') {
        Some(idx) => pat[idx + 1..].bytes().any(|b| b != b'*'),
        None => false,
    }
}

/// Path-pattern lowering before the wildcard-literal cleanup in [`lower_path`].
fn lower_path_raw(pat: &str) -> (u8, String, bool) {
    if pat == "*" || pat == "**" || pat == "**/*" {
        return (M_ANY, String::new(), false);
    }
    let repo_relative = !pat.starts_with('/');
    // A repo-relative pattern made only of wildcard and separator characters
    // has no literal for a PREFIX/SUFFIX/EXACT/CONTAINS matcher to hold, so the
    // `*` would be matched as an ordinary byte and the rule would silently
    // never fire (`**/**` lowered to `suffix("*")`, `*/*` to `contains("/*")`).
    // Every such form contains an interior `/` (a lone `*` or `**`, and `**/*`,
    // are caught by the ANY guard above), and every path it can match has a
    // separator, so `contains("/")` is the exact approximation.
    if repo_relative && pat.chars().all(|c| c == '*' || c == '/') {
        return (M_CONTAINS, "/".to_string(), false);
    }
    // An absolute pattern is a genuine prefix match whose literal is everything
    // before the first wildcard. Handling it here keeps a `*` out of the
    // literal: the suffix branches below would otherwise return `PREFIX
    // "/tmp/**/"` for `/tmp/**/*`, and that literal requires a real `**` byte.
    if !repo_relative {
        return match pat.find('*') {
            Some(idx) => (M_PREFIX, pat[..idx].to_string(), false),
            None => (M_EXACT, pat.to_string(), false),
        };
    }
    // **/middle/** → contains "/middle/" (substring search)
    if let Some(inner) = pat.strip_prefix("**/").and_then(|r| r.strip_suffix("/**")) {
        if !inner.contains('*') {
            let (lit, capped) = shorten_contains_literal(&format!("/{inner}/"));
            return (M_CONTAINS, lit, capped);
        }
    }
    // **/middle/* → contains "/middle/" (files directly inside)
    if let Some(inner) = pat.strip_prefix("**/").and_then(|r| r.strip_suffix("/*")) {
        if !inner.contains('*') {
            let (lit, capped) = shorten_contains_literal(&format!("/{inner}/"));
            return (M_CONTAINS, lit, capped);
        }
    }
    if let Some(inner) = pat.strip_prefix("**/") {
        if let Some(suffix) = inner.strip_prefix('*') {
            return (M_SUFFIX, suffix.to_string(), false);
        }
        if !inner.contains('*') {
            return (M_SUFFIX, format!("/{inner}"), false);
        }
        let (lit, capped) = shorten_contains_literal(inner);
        return (M_CONTAINS, lit, capped);
    }
    if let Some(p) = pat.strip_suffix("/**") {
        if !p.contains('*') {
            let (lit, capped) = shorten_contains_literal(&format!("{}/", p));
            return (M_CONTAINS, lit, capped);
        }
    }
    if let Some(p) = pat.strip_suffix("**") {
        if !p.contains('*') {
            let (lit, capped) = shorten_contains_literal(p);
            return (M_CONTAINS, lit, capped);
        }
    }
    if let Some(p) = pat.strip_suffix("/*") {
        if !p.contains('*') {
            let (lit, capped) = shorten_contains_literal(&format!("{}/", p));
            return (M_CONTAINS, lit, capped);
        }
    }
    if let Some(p) = pat.strip_prefix('*') {
        let (lit, capped) = shorten_contains_literal(p);
        return (M_CONTAINS, lit, capped);
    }
    if let Some(idx) = pat.find('*') {
        let (lit, capped) = shorten_contains_literal(&pat[..idx]);
        return (M_CONTAINS, lit, capped);
    }
    if pat.contains('/') {
        let (lit, capped) = shorten_repo_relative_exact_literal(pat);
        return (M_CONTAINS, lit, capped);
    }
    let (lit, capped) = shorten_contains_literal(pat);
    (M_CONTAINS, lit, capped)
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
            (M_CONTAINS, "config_schemas/".into())
        );
        assert_eq!(
            lower_path("ui/src/i18n/locales/en.ts"),
            (M_CONTAINS, "locales/en.ts".into())
        );
        assert_eq!(
            lower_path("codex-rs/app-server-protocol/schema/typescript/v2/**"),
            (M_CONTAINS, "typescript/v2/".into())
        );
        assert_eq!(
            lower_path("packages/oh-my-opencode-*/bin/**"),
            (M_CONTAINS, "oh-my-opencode-".into())
        );

        assert_eq!(
            lower_path("src/browser_harness/**"),
            (M_CONTAINS, "browser_harness/".into())
        );
        assert_eq!(
            lower_path("ui/src/i18n/locales/*.ts"),
            (M_CONTAINS, "i18n/locales/".into())
        );
        // The repo-relative literals above are longer than the 16-byte
        // `contains` window and are shortened, which is a strict widening of the
        // glob. The caller warns, so pin the boolean alongside the literal.
        assert!(
            lower_path_reported("src/google/adk/agents/config_schemas/AgentConfig.json").capped
        );
        assert!(lower_path_reported("codex-rs/app-server-protocol/schema/typescript/v2/**").capped);
        assert!(lower_path_reported("ui/src/i18n/locales/*.ts").capped);
        assert!(lower_path_reported("packages/oh-my-opencode-*/bin/**").capped);

        assert_eq!(lower_path("**/*.js"), (M_SUFFIX, ".js".into()));
        assert_eq!(lower_path("**/sec.env"), (M_SUFFIX, "/sec.env".into()));
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
    fn globstar_basename_gets_a_bare_exact_companion() {
        // `**/<name>` lowers to suffix("/<name>"), which needs a leading slash;
        // the bare root-level form is covered by a companion exact matcher.
        assert_eq!(lower_path_bare("**/sec.env"), Some("sec.env".into()));
        assert_eq!(lower_path_bare("**/.env"), Some(".env".into()));
        assert_eq!(
            lower_path_bare("**/specs/AGENTS.md"),
            Some("specs/AGENTS.md".into())
        );
        // The wildcard form and absolute/relative non-globstar patterns have no
        // bare companion (they are already suffix/prefix/contains, not "/name").
        assert_eq!(lower_path_bare("**/*.js"), None);
        assert_eq!(lower_path_bare("/tmp/x/**"), None);
        assert_eq!(lower_path_bare("src/**"), None);
        assert_eq!(lower_path_bare("**/"), None);
    }

    #[test]
    fn globstar_basename_source_emits_suffix_and_exact_updates() {
        let pol =
            crate::dsl::parse::parse(r#"source SECRET = file "**/.env""#).expect("parse source");
        let compiled = compile(&pol).expect("compile source");
        let cfg = unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let updates = &cfg.updates[..cfg.n_updates as usize];
        let txt = |raw: &[u8]| -> String {
            String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())])
                .into_owned()
        };
        let pairs: Vec<(u8, u8, String)> = updates
            .iter()
            .map(|u| (u.op, u.m, txt(&u.target)))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (OP_OPEN, M_SUFFIX, "/.env".to_string()),
                (OP_OPEN, M_EXACT, ".env".to_string()),
            ]
        );
    }

    #[test]
    fn globstar_basename_sink_emits_suffix_and_exact_rules() {
        let pol = crate::dsl::parse::parse(
            r#"rule r:
                 notify write file "**/.env"
                 because "bare-relative dotfile guard"
               "#,
        )
        .expect("parse rule");
        let compiled = compile(&pol).expect("compile rule");
        let cfg = unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let rules = &cfg.rules[..cfg.n_rules as usize];
        let txt = |raw: &[u8]| -> String {
            String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())])
                .into_owned()
        };
        let targets: Vec<(u8, String)> = rules.iter().map(|r| (r.m, txt(&r.target))).collect();
        assert_eq!(
            targets,
            vec![
                (M_SUFFIX, "/.env".to_string()),
                (M_EXACT, ".env".to_string()),
            ]
        );
    }

    #[test]
    fn globstar_dir_gets_a_relative_prefix_companion() {
        // `**/<dir>/**` and `**/<dir>/*` lower to contains("/<dir>/"), whose
        // literal needs a slash before the directory and so misses a path that
        // starts at the directory; the prefix("<dir>/") form covers it.
        assert_eq!(
            lower_path_relative_prefix("**/dist/**"),
            Some("dist/".into())
        );
        assert_eq!(
            lower_path_relative_prefix("**/src/lib/**"),
            Some("src/lib/".into())
        );
        assert_eq!(
            lower_path_relative_prefix("**/middle/*"),
            Some("middle/".into())
        );
        // Wildcard directories, the `**/<name>` basename form, and absolute
        // patterns have no first-segment companion.
        assert_eq!(lower_path_relative_prefix("**/*.js"), None);
        assert_eq!(lower_path_relative_prefix("**/sec.env"), None);
        assert_eq!(lower_path_relative_prefix("/tmp/x/**"), None);
        assert_eq!(lower_path_relative_prefix("src/**"), None);
    }

    #[test]
    fn globstar_dir_source_emits_contains_and_prefix_updates() {
        let pol =
            crate::dsl::parse::parse(r#"source CLI = file "**/src/lib/**""#).expect("parse source");
        let compiled = compile(&pol).expect("compile source");
        let cfg = unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let updates = &cfg.updates[..cfg.n_updates as usize];
        let txt = |raw: &[u8]| -> String {
            String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())])
                .into_owned()
        };
        let pairs: Vec<(u8, u8, String)> = updates
            .iter()
            .map(|u| (u.op, u.m, txt(&u.target)))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (OP_OPEN, M_CONTAINS, "/src/lib/".to_string()),
                (OP_OPEN, M_PREFIX, "src/lib/".to_string()),
            ]
        );
    }

    #[test]
    fn globstar_dir_sink_emits_contains_and_prefix_rules() {
        let pol = crate::dsl::parse::parse(
            r#"rule r:
                 notify write file "**/dist/**"
                 because "first-segment-relative sink guard"
               "#,
        )
        .expect("parse rule");
        let compiled = compile(&pol).expect("compile rule");
        let cfg = unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let rules = &cfg.rules[..cfg.n_rules as usize];
        let txt = |raw: &[u8]| -> String {
            String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())])
                .into_owned()
        };
        let targets: Vec<(u8, String)> = rules.iter().map(|r| (r.m, txt(&r.target))).collect();
        assert_eq!(
            targets,
            vec![
                (M_CONTAINS, "/dist/".to_string()),
                (M_PREFIX, "dist/".to_string()),
            ]
        );
    }

    #[test]
    fn globstar_dir_exception_stays_single_condition() {
        // The `unless target` exception uses one cond_kind/cond_pat pair, which
        // cannot hold a disjunction; the sink target gains a companion but the
        // exception does not, so it keeps the absolute/nested form only.
        let pol = crate::dsl::parse::parse(
            r#"rule r:
                 notify write file "**/*.js" if AGENT unless target "**/dist/**"
                 because "js outside dist"
               "#,
        )
        .expect("parse rule");
        let compiled = compile(&pol).expect("compile rule");
        let cfg = unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let rules = &cfg.rules[..cfg.n_rules as usize];
        let txt = |raw: &[u8]| -> String {
            String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())])
                .into_owned()
        };
        let conds: Vec<(u8, u8, String)> = rules
            .iter()
            .map(|r| (r.cond_kind, r.cond_match, txt(&r.cond_pat)))
            .collect();
        assert_eq!(conds, vec![(C_TARGET, M_CONTAINS, "/dist/".to_string())]);
    }

    #[test]
    fn repo_relative_condition_is_partial_matches_companion_forms() {
        // Repo-relative basename and directory patterns carry a companion that a
        // single condition slot cannot express, so an `unless target` over them
        // is approximate.
        assert!(repo_relative_condition_is_partial("**/.env"));
        assert!(repo_relative_condition_is_partial("**/sec.env"));
        assert!(repo_relative_condition_is_partial("**/dist/**"));
        assert!(repo_relative_condition_is_partial("**/src/lib/**"));
        assert!(repo_relative_condition_is_partial("**/middle/*"));
        // Absolute patterns and pure wildcard forms have no companion.
        assert!(!repo_relative_condition_is_partial("/work/dist/**"));
        assert!(!repo_relative_condition_is_partial("**/*.js"));
        assert!(!repo_relative_condition_is_partial("/tmp/guarded/f.txt"));
        assert!(!repo_relative_condition_is_partial("src/**"));
    }

    #[test]
    fn exec_wildcard_patterns_match_any_comm() {
        assert_eq!(lower_exec("*"), (M_ANY, String::new()));
        assert_eq!(lower_exec("**"), (M_ANY, String::new()));
        assert_eq!(lower_exec("**/*"), (M_ANY, String::new()));
        // A recursive wildcard may appear only as the basename, after a
        // directory prefix. `exec "a/**"` means "a comm matching any basename
        // under `a`", and exec matching drops the directory, so it is ANY too.
        assert_eq!(lower_exec("a/**"), (M_ANY, String::new()));
        assert_eq!(lower_exec("a/b/**"), (M_ANY, String::new()));
        assert_eq!(lower_exec("**/a/**"), (M_ANY, String::new()));
    }

    /// The direct `lower_exec` inputs above skip the parser, which rewrites a
    /// slash-free exec pattern to `**/<pattern>` (parse.rs `P::target`). That
    /// rewrite turned a clause target `exec "**"` into `**/**` before lowering,
    /// so the whole-pattern ANY guard did not see it and the rule lowered to
    /// `PREFIX "*"`. No comm starts with `*`, so a valid catch-all silently
    /// never fired. Pin the parsed clause target's rule rows, not just the
    /// direct-call result.
    #[test]
    fn clause_exec_globstar_target_lowers_to_any() {
        for pattern in ["**", "**/**", "a/**"] {
            let src = format!("rule r:\n  kill exec \"{pattern}\"\n  because \"catch-all\"\n");
            let pol = crate::dsl::parse::parse(&src).expect("parse rule");
            let compiled = compile(&pol).expect("compile rule");
            let cfg =
                unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
            let rules = &cfg.rules[..cfg.n_rules as usize];
            assert_eq!(rules.len(), 1, "one rule per pattern: {pattern}");
            assert_eq!(
                (rules[0].m, String::new()),
                (M_ANY, String::new()),
                "clause exec {pattern} must lower to ANY, got m={}",
                rules[0].m
            );
        }
    }

    /// Exec patterns match a basename: the directory part is dropped, so
    /// `exec "/usr/bin/git"`, `exec "git"`, and `exec "**/git"` all lower to the
    /// same matcher. This is easy to misread as "a pattern with `/` is an exact
    /// path" (an earlier version of `docs/rule-language.md` said so), and a
    /// policy that relies on the directory would silently match a same-named
    /// executable elsewhere.
    #[test]
    fn exec_patterns_reduce_to_the_basename() {
        assert_eq!(lower_exec("/usr/bin/git"), (M_EXACT, "git".into()));
        assert_eq!(lower_exec("git"), (M_EXACT, "git".into()));
        assert_eq!(lower_exec("**/git"), (M_EXACT, "git".into()));
        assert_eq!(lower_exec("a/b/c"), (M_EXACT, "c".into()));
        // A trailing wildcard becomes a prefix over the basename.
        assert_eq!(lower_exec("**/deploy*"), (M_PREFIX, "deploy".into()));
        assert_eq!(lower_exec("/opt/bin/deploy*"), (M_PREFIX, "deploy".into()));
    }

    /// An interior wildcard must not survive into the matcher literal. The
    /// kernel compares bytes (`taint_streq`/`taint_prefix`/`taint_contains`),
    /// so `exact("g*t")` only matches a comm literally named `g*t`; the rule
    /// silently never fired. Keep the concrete span before the first wildcard
    /// as the widest matcher of the same kind.
    #[test]
    fn interior_wildcards_do_not_reach_the_matcher_literal() {
        assert_eq!(lower_exec("g*t"), (M_PREFIX, "g".into()));
        assert_eq!(lower_exec("g*t*"), (M_PREFIX, "g".into()));
        assert_eq!(lower_exec("g**"), (M_PREFIX, "g".into()));
        // A wildcard in the head position has no concrete prefix, so the
        // literal is empty and the caller reports `pattern_empty_literal`
        // rather than silently matching a `*` byte.
        assert_eq!(lower_exec("*g*t"), (M_PREFIX, String::new()));
        assert_eq!(lower_path("**/a*b"), (M_CONTAINS, "a".into()));
        assert_eq!(lower_path("**/*t"), (M_SUFFIX, "t".into()));
    }

    /// The cleanup that keeps the wildcard out of the literal drops the text
    /// after the wildcard, so the matcher matches a superset of the glob. When
    /// the discarded text is concrete, the superset is strict and the caller
    /// warns; a purely wildcard tail discards nothing concrete, so `deploy*`
    /// and `g**` stay exact and warning-free. Pin the boolean, not just the
    /// literal, because it is what decides whether the user is told. An empty
    /// kept span is the exception: the literal matches nothing, so the
    /// empty-literal check owns the consequence and the flag clears.
    #[test]
    fn wildcard_literal_cleanup_reports_only_a_strict_widening() {
        let widened = |pat: &str| lower_exec_reported(pat).widened;
        assert!(widened("g*t"), "the `t` after the wildcard is discarded");
        assert!(widened("g*t*"), "the `t` after the wildcard is discarded");
        assert!(widened("a*b"), "the `b` after the wildcard is discarded");
        // `*g*t` keeps an EMPTY head (the span before the first wildcard), so the
        // literal matches nothing at all: a strict subset, not a strict
        // superset. That is the empty-literal warning's claim, so the widening
        // flag clears to keep the two warnings from contradicting.
        assert!(!widened("*g*t"), "the kept head is empty");
        // Nothing concrete is dropped: the wildcard is the whole tail.
        assert!(!widened("deploy*"), "only the wildcard tail is dropped");
        assert!(!widened("**/deploy*"), "only the wildcard tail is dropped");
        assert!(
            !widened("g**"),
            "the head is `g`, the tail is all wildcards"
        );
        assert!(!widened("g"), "no wildcard at all");
        assert!(!widened("*"), "ANY has no literal");
        // Path patterns go through the same cleanup, including the SUFFIX kind,
        // which discards the head before the last wildcard.
        assert!(
            lower_path_reported("**/a*b").widened,
            "the `b` is discarded"
        );
        assert!(
            !lower_path_reported("**/*b/*").widened,
            "the `b/*` tail is discarded but the kept span is empty"
        );
        assert!(
            !lower_path_reported("**/*t").widened,
            "no concrete byte is dropped"
        );
        assert!(
            !lower_path_reported("/tmp/guarded/**").widened,
            "prefix keeps all text"
        );
        // An absolute pattern cuts at its first wildcard before any literal
        // cleanup, so the same criterion is applied to the pattern itself.
        assert!(
            lower_path_reported("/tmp/*b/*").widened,
            "the `b` tail is discarded"
        );
        assert!(
            lower_path_reported("/tmp/*/x").widened,
            "the `x` tail is discarded"
        );
        assert!(
            !lower_path_reported("/tmp/guarded/**").widened,
            "only wildcards are cut"
        );
        assert!(
            !lower_path_reported("/tmp/guarded").widened,
            "no wildcard to cut"
        );
    }

    /// The warning must reach `Compiled::pattern_warnings` through the parser
    /// and the whole compile path, not only from a direct lowering call: the
    /// parser rewrites a slash-free exec pattern to `**/<pattern>`, so a
    /// whole-pattern guard would never see the form the policy wrote. A widened
    /// `unless target` exception over-matches, so a positive one suppresses the
    /// rule where the policy did not except: silence here is the
    /// under-enforcement the warning closes.
    #[test]
    fn interior_wildcard_target_warns_through_the_compiler() {
        let src = "rule r:\n  kill exec \"g*t\"\n  because \"x\"\n";
        let pol = crate::dsl::parse::parse(src).expect("parse rule");
        let compiled = compile(&pol).expect("compile rule");
        assert!(
            compiled
                .pattern_warnings
                .iter()
                .any(|w| w.code == PATTERN_LITERAL_WIDENED),
            "expected {PATTERN_LITERAL_WIDENED}, got {:?}",
            compiled.pattern_warnings
        );
        // A trailing wildcard is the documented, exact form and must stay quiet.
        let quiet = "rule r:\n  kill exec \"**/deploy*\"\n  because \"x\"\n";
        let pol = crate::dsl::parse::parse(quiet).expect("parse rule");
        let compiled = compile(&pol).expect("compile rule");
        assert!(
            !compiled
                .pattern_warnings
                .iter()
                .any(|w| w.code == PATTERN_LITERAL_WIDENED),
            "a trailing wildcard discards no concrete text: {:?}",
            compiled.pattern_warnings
        );
    }

    /// The 16-byte `contains` window (`MAX_CONTAINS_LITERAL`) shortens a long
    /// repo-relative directory literal to a contiguous substring of it, and the
    /// kernel's substring test then matches a strict superset of the glob
    /// (`**/aaa/bbb/ccc/ddd/**` lowers to `contains("aaa/bbb/ccc/ddd/")`, which
    /// `abaaa/bbb/ccc/ddd/` also matches). Pin the boolean for the shortening
    /// branches, and pin silence when the natural literal already fits, because
    /// a false positive here would flag every ordinary policy.
    #[test]
    fn contains_window_shortening_reports_a_strict_widening() {
        let capped = |pat: &str| lower_path_reported(pat).capped;
        assert!(capped("**/aaa/bbb/ccc/ddd/**"), "the slash trim shortens");
        assert!(
            capped("**/alpha/beta/gamma/delta/**"),
            "the slash walk shortens"
        );
        assert!(
            capped("**/src/components/deep/nested/**"),
            "the slash walk shortens"
        );
        assert!(
            capped("src/google/adk/agents/config_schemas/AgentConfig.json"),
            "the last-segment walk shortens"
        );
        // The natural literal already fits the window: no shortening, no
        // warning, and the matcher is exactly the glob the policy wrote.
        assert!(!capped("**/a/b/**"), "`/a/b/` is 5 bytes");
        assert!(!capped("**/src/lib/**"), "`/src/lib/` is 9 bytes");
        // A suffix lowering is never passed through the contains shortener.
        assert!(!capped("**/*.js"), "suffix keeps its natural literal");
        assert!(!capped("**/sec.env"), "suffix keeps its natural literal");
    }

    /// The shortening warning must reach `Compiled::pattern_warnings` from a
    /// clause target, a file source, and an `unless target` condition, since
    /// each is lowered on a different path. A capped `unless target` exception
    /// in particular over-matches: it accepts a superset of the glob, so the
    /// rule is suppressed on paths the policy did not except and fails to fire
    /// there. Silence is an under-enforcement the warning closes.
    #[test]
    fn contains_window_shortening_warns_through_the_compiler() {
        let has_capped = |src: &str| {
            let pol = crate::dsl::parse::parse(src).expect("parse");
            let compiled = compile(&pol).expect("compile");
            compiled
                .pattern_warnings
                .iter()
                .any(|w| w.code == PATTERN_CONTAINS_CAPPED)
        };
        assert!(
            has_capped(
                "rule r:\n  kill read file \"**/src/components/deep/nested/**\"\n  because \"x\"\n"
            ),
            "a clause target is shortened"
        );
        assert!(
            has_capped(
                "source S = file \"**/alpha/beta/gamma/delta/**\"\nrule r:\n  kill read file \"**/z\" if S\n  because \"x\"\n"
            ),
            "a file source is shortened"
        );
        assert!(
            has_capped(
                "rule r:\n  kill read file \"**/src/lib/**\" unless target \"**/aaa/bbb/ccc/ddd/**\"\n  because \"x\"\n"
            ),
            "an `unless target` condition is shortened"
        );
        // A pattern whose literal fits the window stays quiet through the whole
        // compile path, so an ordinary policy does not gain a warning.
        assert!(
            !has_capped("rule r:\n  kill read file \"**/src/lib/**\"\n  because \"x\"\n"),
            "a short literal is not shortened"
        );
    }

    /// The terminal branch of [`shorten_contains_literal`] computes its offset
    /// from the byte length, so a multi-byte literal could put it inside a
    /// character. The offset must advance to the next boundary, keeping the
    /// result a valid, in-window suffix instead of panicking on the slice.
    #[test]
    fn contains_window_shortening_keeps_char_boundaries() {
        // `dir` is 16 bytes (`日` is three), so `/dir/` is 17 and no slash-segment
        // or last-segment candidate fits: only the byte-window branch runs, and
        // its offset (17 - 16 = 1) lands inside the first `日`.
        let (lit, capped) = shorten_contains_literal("/日日日日日a/");
        assert!(capped);
        assert_eq!(lit, "日日日日a/");
        assert!(lit.len() <= MAX_CONTAINS_LITERAL);
        assert!("/日日日日日a/".ends_with(&lit), "still a substring");
        // Every character is three bytes, so no 16-byte window is
        // character-aligned; the result stays in-window at 16 bytes.
        let (lit, capped) = shorten_contains_literal(&format!("/{}/", "日".repeat(20)));
        assert!(capped);
        assert_eq!(lit, "日日日日日/");
        assert!(lit.len() <= MAX_CONTAINS_LITERAL);
    }

    #[test]
    fn globstar_dir_gate_and_since_emit_companion_updates_with_shared_bits() {
        // A `**/dir/**` pattern in an `after` gate or a `since` invalidator goes
        // through the same lowering, so it must emit the same companion entry
        // and share one bit across both forms (one condition/invalidator).
        let pol = crate::dsl::parse::parse(
            r#"rule r:
                 notify exec "git" "commit" if AGENT unless after read "**/src/lib/**" since write "**/dist/**"
                 because "gate and invalidator over repo-relative dirs"
               "#,
        )
        .expect("parse rule");
        let compiled = compile(&pol).expect("compile rule");
        let cfg = unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let updates = &cfg.updates[..cfg.n_updates as usize];
        let txt = |raw: &[u8]| -> String {
            String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())])
                .into_owned()
        };
        // The read gate is OP_OPEN; the write invalidator is OP_WRITE. Each
        // pattern contributes a primary plus its first-segment companion.
        let gate_updates: Vec<(u8, String)> = updates
            .iter()
            .filter(|u| u.op == OP_OPEN)
            .map(|u| (u.m, txt(&u.target)))
            .collect();
        let inval_updates: Vec<(u8, String)> = updates
            .iter()
            .filter(|u| u.op == OP_WRITE)
            .map(|u| (u.m, txt(&u.target)))
            .collect();
        assert_eq!(
            gate_updates,
            vec![
                (M_CONTAINS, "/src/lib/".to_string()),
                (M_PREFIX, "src/lib/".to_string()),
            ]
        );
        assert_eq!(
            inval_updates,
            vec![
                (M_CONTAINS, "/dist/".to_string()),
                (M_PREFIX, "dist/".to_string()),
            ]
        );
        // One gate bit and one invalidator bit, shared by primary + companion.
        let gate_bits: Vec<u64> = updates
            .iter()
            .filter(|u| u.op == OP_OPEN)
            .map(|u| u.gates)
            .collect();
        let inval_bits: Vec<u64> = updates
            .iter()
            .filter(|u| u.op == OP_WRITE)
            .map(|u| u.invals)
            .collect();
        assert_eq!(gate_bits[0], gate_bits[1]);
        assert_ne!(gate_bits[0], 0);
        assert_eq!(inval_bits[0], inval_bits[1]);
        assert_ne!(inval_bits[0], 0);
    }

    #[test]
    fn exec_gate_arg_restricts_the_arming_token() {
        // `after exec "pnpm" "test"` must lower to an exec gate update whose
        // `arg` is "test", and a bare `after exec "pnpm"` gate must keep an
        // empty arg. The kernel matches `arg` against argv tokens
        // (taint_engine.bpf.h te_exec_update_* callbacks), so the two gates must
        // be distinct updates with distinct bits; sharing one would arm the
        // argv-restricted gate on every `pnpm` subcommand.
        let pol = crate::dsl::parse::parse(
            r#"rule narrow:
                 kill exec "git" "commit" if AGENT unless after exec "pnpm" "test"
                 because "only pnpm test arms this gate"
               rule broad:
                 kill exec "git" "commit" if AGENT unless after exec "pnpm"
                 because "any pnpm subcommand arms this gate"
               "#,
        )
        .expect("parse policy");
        let compiled = compile(&pol).expect("compile policy");
        let cfg = unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let updates = &cfg.updates[..cfg.n_updates as usize];
        let txt = |raw: &[u8]| -> String {
            String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())])
                .into_owned()
        };
        let gates: Vec<(String, u64)> = updates
            .iter()
            .filter(|u| u.op == OP_EXEC && u.gates != 0)
            .map(|u| (txt(&u.arg), u.gates))
            .collect();
        assert_eq!(gates.len(), 2, "one exec gate update per rule: {gates:?}");
        assert_eq!(gates[0], ("test".to_string(), gates[0].1));
        assert_eq!(gates[1], (String::new(), gates[1].1));
        assert_ne!(
            gates[0].1, gates[1].1,
            "argv-restricted and bare gates must not share a bit"
        );
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

    #[test]
    fn hostname_endpoint_sources_resolve_to_ipv4_updates() {
        let pol = crate::dsl::parse::parse(r#"source NET = endpoint "localhost""#)
            .expect("parse endpoint source");
        let compiled = compile(&pol).expect("compile endpoint source");
        assert_eq!(
            compiled.endpoint_resolutions.get("localhost"),
            Some(&vec!["127.0.0.1".to_string()])
        );

        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let (localhost, mask) = lower_ipv4("127.0.0.1");
        assert_eq!(cfg.n_updates, 2);
        for update in &cfg.updates[..cfg.n_updates as usize] {
            assert_eq!(update.ipv4, localhost);
            assert_eq!(update.ipv4_mask, mask);
        }
    }

    #[test]
    fn hostname_endpoint_rule_resolves_to_ipv4_matcher() {
        let pol = crate::dsl::parse::parse(
            r#"
            rule local:
              notify connect endpoint "localhost" if true
              because "local host"
            "#,
        )
        .expect("parse endpoint rule");
        let compiled = compile(&pol).expect("compile endpoint rule");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let (localhost, mask) = lower_ipv4("127.0.0.1");
        assert_eq!(cfg.n_rules, 1);
        assert_eq!(cfg.rules[0].ipv4, localhost);
        assert_eq!(cfg.rules[0].ipv4_mask, mask);
    }

    #[test]
    fn compiled_bytes_are_deterministic_and_padding_is_zeroed() {
        // The `repr(C)` update/rule structs are serialized as raw bytes over the
        // whole struct, so uninitialized padding leaks into the blob and makes
        // the same policy compile to different bytes (observed as 5 distinct
        // hashes in 5 release runs before the fix). This asserts the invariant:
        // two compiles are byte-identical and the pad bytes are zero. The
        // pre-fix failure is optimization-dependent uninitialized-read UB, so it
        // is not reproducible in a debug unit test; the release-level check is
        // `actplane ... compile` run twice on the same policy.
        let src = r#"
            source AGENT = exec "python3"
            rule probe_sink:
              notify write file "**/dist/**" if AGENT
              because "repo-relative dir sink"
        "#;
        let pol = crate::dsl::parse::parse(src).expect("parse policy");
        let a = compile(&pol).expect("compile once").bytes;
        let b = compile(&pol).expect("compile twice").bytes;
        assert_eq!(
            a, b,
            "same policy compiled twice must produce identical bytes"
        );
        let cfg: CConfig = unsafe { std::ptr::read_unaligned(a.as_ptr() as *const CConfig) };
        let upd_raw = unsafe {
            std::slice::from_raw_parts(
                cfg.updates.as_ptr() as *const u8,
                std::mem::size_of::<CUpdate>() * cfg.n_updates as usize,
            )
        };
        // Bytes 90..96 are the pad between `arg` and `add` in `taint_update`;
        // bytes 158..160 are the pad between `cond_pat` and `req` in
        // `taint_rule`.
        assert_eq!(&upd_raw[90..96], &[0u8; 6], "update padding must be zeroed");
        let rule_raw = unsafe {
            std::slice::from_raw_parts(
                cfg.rules.as_ptr() as *const u8,
                std::mem::size_of::<CRule>() * cfg.n_rules as usize,
            )
        };
        assert_eq!(
            &rule_raw[158..160],
            &[0u8; 2],
            "rule padding must be zeroed"
        );
    }

    /// The `repr(C)` structs here are byte-identical to `bpf/taint.h`; the blob is
    /// read directly into BPF rodata. `config_blob_is_fixed_size` pins only the
    /// total, so a field reorder of the same width would pass it while
    /// reinterpreting every field. Pin each field offset and size, matching the
    /// values `bpf/test_taint.c`'s `test_abi_layout` asserts from the C side; a
    /// change to either layout must update both.
    #[test]
    fn abi_layout_matches_the_c_header() {
        use std::mem::{offset_of, size_of};

        assert_eq!(offset_of!(CUpdate, op), 0);
        assert_eq!(offset_of!(CUpdate, m), 1);
        assert_eq!(offset_of!(CUpdate, target), 2);
        assert_eq!(offset_of!(CUpdate, arg), 66);
        assert_eq!(offset_of!(CUpdate, add), 96);
        assert_eq!(offset_of!(CUpdate, del), 104);
        assert_eq!(offset_of!(CUpdate, gates), 112);
        assert_eq!(offset_of!(CUpdate, invals), 120);
        assert_eq!(offset_of!(CUpdate, ipv4), 128);
        assert_eq!(offset_of!(CUpdate, ipv4_mask), 132);
        assert_eq!(offset_of!(CUpdate, gate_exit_code), 136);
        assert_eq!(offset_of!(CUpdate, domain_id), 140);
        assert_eq!(size_of::<CUpdate>(), 144);

        assert_eq!(offset_of!(CRule, op), 0);
        assert_eq!(offset_of!(CRule, m), 1);
        assert_eq!(offset_of!(CRule, cond_kind), 2);
        assert_eq!(offset_of!(CRule, cond_neg), 3);
        assert_eq!(offset_of!(CRule, cond_match), 4);
        assert_eq!(offset_of!(CRule, effect), 5);
        assert_eq!(offset_of!(CRule, target), 6);
        assert_eq!(offset_of!(CRule, arg), 70);
        assert_eq!(offset_of!(CRule, cond_pat), 94);
        assert_eq!(offset_of!(CRule, req), 160);
        assert_eq!(offset_of!(CRule, forbid), 168);
        assert_eq!(offset_of!(CRule, gate), 176);
        assert_eq!(offset_of!(CRule, rule_id), 184);
        assert_eq!(offset_of!(CRule, ipv4), 188);
        assert_eq!(offset_of!(CRule, ipv4_mask), 192);
        assert_eq!(offset_of!(CRule, cond_ipv4), 196);
        assert_eq!(offset_of!(CRule, cond_ipv4_mask), 200);
        assert_eq!(offset_of!(CRule, gate_idx), 204);
        assert_eq!(offset_of!(CRule, domain_id), 208);
        assert_eq!(offset_of!(CRule, since_mask), 216);
        assert_eq!(size_of::<CRule>(), 224);

        assert_eq!(offset_of!(CConfig, n_updates), 0);
        assert_eq!(offset_of!(CConfig, n_rules), 4);
        assert_eq!(offset_of!(CConfig, updates), 8);
        assert_eq!(offset_of!(CConfig, rules), 46088);
        assert_eq!(size_of::<CConfig>(), 74_760);
    }

    /// Constants shared with the kernel that do not appear in `taint_config`,
    /// so the offset/size assertions above do not transitively pin them. Each is
    /// load-bearing: the gate/invalidator epoch arrays are indexed by the
    /// compiler's slot number and masked with `N - 1` in the kernel (so `N` must
    /// stay a power of two that both sides agree on), and `MAX_CONTAINS_LITERAL`
    /// must equal `TAINT_SUF_MAX` or the matcher-length warning reports the wrong
    /// bound. `bpf/test_taint.c`'s `test_abi_constants` asserts the same values
    /// from the C side; keep the two in step with `bpf/taint.h`.
    #[test]
    fn abi_constants_match_the_c_header() {
        assert_eq!(PAT, 64, "TAINT_PAT_LEN");
        assert_eq!(ARG, 24, "TAINT_ARG_LEN");
        assert_eq!(MAX_UPDATES, 320, "MAX_TAINT_UPDATES");
        assert_eq!(MAX_RULES, 128, "MAX_TAINT_RULES");
        assert_eq!(MAX_GATES, 64, "MAX_TAINT_GATES");
        assert_eq!(MAX_INVALS, 64, "MAX_TAINT_INVALS");
        assert_eq!(MAX_CONTAINS_LITERAL, 16, "TAINT_SUF_MAX");
        assert!(
            MAX_GATES.is_power_of_two() && MAX_INVALS.is_power_of_two(),
            "the kernel masks gate/invalidator slot indices with `N - 1`"
        );
    }

    /// The enum discriminants below are written into the blob as `u8`/`i32`
    /// fields, so they are ABI values, not internal names. A drift here is
    /// silent and dangerous: making `M_CONTAINS` equal `M_ANY`'s 3 turns every
    /// `contains` matcher into match-anything, and changing an `OP_*` value
    /// makes the kernel index the wrong update/rule table. `bpf/test_taint.c`'s
    /// `test_abi_enum_values` asserts the same numbers from the C side.
    #[test]
    fn abi_enum_values_match_the_c_header() {
        assert_eq!(
            [M_EXACT, M_PREFIX, M_SUFFIX, M_ANY, M_CONTAINS],
            [0, 1, 2, 3, 4],
            "enum taint_match"
        );
        assert_eq!(
            [OP_EXEC, OP_OPEN, OP_WRITE, OP_CONNECT, OP_RECV],
            [0, 1, 2, 3, 4],
            "enum taint_op"
        );
        assert_eq!(
            [C_NONE, C_LINEAGE, C_AFTER, C_TARGET],
            [0, 1, 2, 3],
            "enum taint_cond"
        );
        assert_eq!(
            [EFFECT_NOTIFY, EFFECT_BLOCK, EFFECT_KILL],
            [0, 1, 2],
            "enum taint_effect"
        );
        assert_eq!(GATE_IMMEDIATE, -1, "TAINT_GATE_IMMEDIATE");
    }

    /// The DSL has four file ops but the kernel carries only two access kinds:
    /// `read`/`open` lower to `OP_OPEN`, `write`/`unlink` to `OP_WRITE`. That
    /// collapse is intentional (a policy that confines writes pairs `write` and
    /// `unlink` clauses deliberately), but it is a real semantic narrowing: an
    /// `unlink` clause also fires on writes to the same pattern and vice versa.
    /// Pin the mapping so a change is deliberate: routing `unlink` to `OP_OPEN`
    /// would put deletes on the read path, and swapping `write`/`unlink` would
    /// invert which access kind the kernel checks.
    #[test]
    fn dsl_file_ops_map_to_the_expected_kernel_access_kind() {
        assert_eq!(op_lowers(Op::Read).unwrap(), &[OP_OPEN]);
        assert_eq!(op_lowers(Op::Open).unwrap(), &[OP_OPEN]);
        assert_eq!(op_lowers(Op::Write).unwrap(), &[OP_WRITE]);
        assert_eq!(op_lowers(Op::Unlink).unwrap(), &[OP_WRITE]);
        assert_eq!(op_lowers(Op::Exec).unwrap(), &[OP_EXEC]);
        assert_eq!(op_lowers(Op::Connect).unwrap(), &[OP_CONNECT]);
        assert_eq!(op_lowers(Op::Recv).unwrap(), &[OP_RECV]);
        // The read side and the write side must not be cross-wired.
        assert_ne!(op_lowers(Op::Unlink).unwrap(), op_lowers(Op::Read).unwrap());
        assert_ne!(op_lowers(Op::Read).unwrap(), op_lowers(Op::Write).unwrap());
    }

    #[test]
    fn wildcard_hostnames_are_not_resolved_as_exact_hosts() {
        assert_eq!(hostname_candidate("*.internal"), None);
        assert_eq!(hostname_candidate("api.internal"), Some("api.internal"));
    }

    /// A fifth octet must not be truncated to the first four. The old `break`
    /// at `k >= 4` compiled `1.2.3.4.5` to a /32 on `1.2.3.4`, so the rule
    /// fired for `1.2.3.4` while `actplane doctor` (whose numeric predicate
    /// requires 1..=4 octets) reported the pattern as unsupported and
    /// non-firing. The two must agree, and the fail-closed `(0, u32::MAX)`
    /// matcher is what the doctor's "will not fire" claim describes.
    #[test]
    fn a_fifth_octet_is_not_truncated_to_a_numeric_ipv4_match() {
        assert_eq!(
            lower_numeric_ipv4("1.2.3.4"),
            lower_numeric_ipv4("1.2.3.4.")
        );
        assert_eq!(lower_numeric_ipv4("1.2.3.4.5"), None);
        assert!(!is_numeric_endpoint_pattern("1.2.3.4.5"));
        assert!(is_numeric_endpoint_pattern("1.2.3.4"));
        // `*` stays match-any, and a 4-octet pattern stays a /32.
        assert!(is_numeric_endpoint_pattern("*"));

        let pol = crate::dsl::parse::parse(
            r#"
            rule too_many_octets:
              kill connect endpoint "1.2.3.4.5"
              because "malformed numeric endpoint must fail closed"
            "#,
        )
        .expect("parse endpoint rule");
        let compiled = compile(&pol).expect("compile endpoint rule");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(cfg.n_rules, 1);
        // Fail closed: net 0 with a full mask is the literal `0.0.0.0`, not a
        // /32 on the truncated `1.2.3.4` (which would be 0x04030201).
        assert_eq!(cfg.rules[0].ipv4, 0);
        assert_eq!(cfg.rules[0].ipv4_mask, u32::MAX);
    }

    /// A negated endpoint condition whose pattern has no numeric matcher must
    /// lower to match-any before the kernel negates it, so `target not PAT`
    /// leaves the rule applying. Both the unresolved hostname and the
    /// unsupported-pattern paths previously returned a single `(0, u32::MAX)`
    /// from `endpoint_matches`, which the `len() == 1` early return passed
    /// through unchanged; the kernel then inverted that literal-`0.0.0.0`
    /// matcher to "true for every endpoint" and silently suppressed the rule,
    /// the opposite of the multi-address path and of the documented
    /// "fails closed" contract.
    #[test]
    fn a_negated_void_endpoint_condition_still_applies_the_rule() {
        fn cond(dsl: &str) -> (u8, u32, u32) {
            let pol = crate::dsl::parse::parse(dsl).expect("parse endpoint condition");
            let compiled = compile(&pol).expect("compile endpoint condition");
            let cfg: CConfig =
                unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
            let r = &cfg.rules[0];
            (r.cond_neg, r.cond_ipv4, r.cond_ipv4_mask)
        }

        // Unresolved hostname and unsupported wildcard: identical treatment.
        assert_eq!(
            cond(
                r#"
                rule r:
                  kill connect endpoint "10.0.0." unless target "void.invalid"
                  because "b"
                "#
            ),
            (0, 0, u32::MAX),
        );
        assert_eq!(
            cond(
                r#"
                rule r:
                  kill connect endpoint "10.0.0." unless target not "void.invalid"
                  because "b"
                "#
            ),
            (1, 0, 0),
        );
        assert_eq!(
            cond(
                r#"
                rule r:
                  kill connect endpoint "10.0.0." unless target not "*.internal"
                  because "b"
                "#
            ),
            (1, 0, 0),
        );
        // A single resolved address keeps its own matcher in both polarities.
        assert_eq!(
            cond(
                r#"
                rule r:
                  kill connect endpoint "10.0.0." unless target not "localhost"
                  because "b"
                "#
            ),
            (1, 0x0100_007f, u32::MAX),
        );
    }
}

fn ipv4_to_kernel(addr: Ipv4Addr) -> u32 {
    let octets = addr.octets();
    (octets[0] as u32)
        | ((octets[1] as u32) << 8)
        | ((octets[2] as u32) << 16)
        | ((octets[3] as u32) << 24)
}

fn kernel_ipv4_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        ip & 0xff,
        (ip >> 8) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 24) & 0xff
    )
}

fn looks_like_ipv4_prefix(pat: &str) -> bool {
    if pat == "*" {
        return true;
    }
    let body = pat.trim_end_matches('.');
    !body.is_empty()
        && body
            .split('.')
            .all(|tok| !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_digit()))
}

/// Lower an IPv4 prefix/host pattern to (net, mask) in the same byte order as
/// the kernel's `sin_addr.s_addr` (octet k at bit 8*k). "*" -> match-any (0,0).
/// "10.0.0." -> /24, "10.0.0.5" -> /32.
///
/// A fifth octet is rejected rather than truncated to the first four. The old
/// `break` at `k >= 4` made `1.2.3.4.5` compile to a /32 on `1.2.3.4`, so the
/// rule fired for `1.2.3.4`, while `actplane doctor` reported the same pattern
/// as unsupported and non-firing (its numeric predicate requires 1..=4
/// octets). Rejecting it routes through `hostname_candidate`
/// (`looks_like_ipv4_prefix` is true, so no hostname) to the `(0, u32::MAX)`
/// fail-closed matcher, matching the doctor/`--explain` claim exactly.
fn lower_numeric_ipv4(pat: &str) -> Option<(u32, u32)> {
    if pat == "*" {
        return Some((0, 0));
    }
    let body = pat.trim_end_matches('.');
    let mut net: u32 = 0;
    let mut mask: u32 = 0;
    let mut k = 0u32;
    for tok in body.split('.') {
        if k >= 4 {
            return None;
        }
        let Ok(o) = tok.parse::<u8>() else {
            return None;
        };
        net |= (o as u32) << (8 * k);
        mask |= 0xffu32 << (8 * k);
        k += 1;
    }
    if k == 0 { None } else { Some((net, mask)) }
}

/// True for a pattern the kernel can match as numeric IPv4 (or `"*"`). This is
/// the single source of truth for "is this endpoint pattern supported", shared
/// with `actplane doctor`, so the two cannot disagree: a pattern this rejects
/// (a hostname glob, IPv6, or a malformed numeric form such as `1.2.3.4.5`)
/// has no numeric matcher, so a rule using it does not fire for the endpoints
/// it names.
pub fn is_numeric_endpoint_pattern(pat: &str) -> bool {
    lower_numeric_ipv4(pat).is_some()
}

#[cfg(test)]
fn lower_ipv4(pat: &str) -> (u32, u32) {
    lower_numeric_ipv4(pat).unwrap_or((0, u32::MAX))
}

fn hostname_candidate(pat: &str) -> Option<&str> {
    if pat == "*" || pat.contains('*') || pat.contains(':') || looks_like_ipv4_prefix(pat) {
        return None;
    }
    let host = pat.trim_end_matches('.');
    if host.is_empty() || host.contains('/') {
        return None;
    }
    if host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Some(host)
    } else {
        None
    }
}

fn resolve_hostname_ipv4s(host: &str) -> Vec<u32> {
    if host.eq_ignore_ascii_case("localhost") {
        return vec![ipv4_to_kernel(Ipv4Addr::new(127, 0, 0, 1))];
    }
    let Ok(addrs) = (host, 0).to_socket_addrs() else {
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    for addr in addrs {
        if let SocketAddr::V4(v4) = addr {
            out.insert(ipv4_to_kernel(*v4.ip()));
        }
    }
    out.into_iter().collect()
}

struct Ctx {
    labels: HashMap<String, u64>,
    used_labels: u64,
    updates: Vec<CUpdate>,
    gate_bits: HashMap<(u8, u8, String, Option<String>, Option<u8>), (u64, u32)>,
    next_gate: u32,
    inval_slots: HashMap<(u8, u8, String, String), u32>,
    next_inval: u32,
    endpoint_cache: HashMap<String, Vec<(u32, u32)>>,
    endpoint_resolutions: HashMap<String, Vec<String>>,
    /// Pattern-lowering warnings from source/xform updates.
    warnings: Vec<PatternWarning>,
}
impl Ctx {
    /// Addresses a pattern lowers to, in the kernel's (net, mask) form.
    ///
    /// An empty vector means the pattern has no numeric matcher at all: an
    /// unresolved hostname, a hostname glob, IPv6, or a malformed numeric form
    /// such as `1.2.3.4.5`. Callers choose the sentinel, because the right one
    /// depends on position: a source/target fails closed with `(0, u32::MAX)`
    /// (the literal `0.0.0.0`, which no endpoint has), while a negated
    /// condition needs the opposite polarity (see `endpoint_condition_match`).
    fn endpoint_addresses(&mut self, pat: &str) -> Vec<(u32, u32)> {
        if let Some(matches) = self.endpoint_cache.get(pat) {
            return matches.clone();
        }
        let matches = if let Some(numeric) = lower_numeric_ipv4(pat) {
            vec![numeric]
        } else if let Some(host) = hostname_candidate(pat) {
            let addrs = resolve_hostname_ipv4s(host);
            self.endpoint_resolutions.insert(
                pat.to_string(),
                addrs
                    .iter()
                    .map(|addr| kernel_ipv4_to_string(*addr))
                    .collect(),
            );
            addrs.into_iter().map(|addr| (addr, u32::MAX)).collect()
        } else {
            Vec::new()
        };
        self.endpoint_cache.insert(pat.to_string(), matches.clone());
        matches
    }

    /// Addresses for a source or rule target. A pattern with no numeric
    /// matcher fails closed: `(0, u32::MAX)` matches only the literal
    /// `0.0.0.0`, so the update or rule never fires for a real endpoint.
    fn endpoint_matches(&mut self, pat: &str) -> Vec<(u32, u32)> {
        let matches = self.endpoint_addresses(pat);
        if matches.is_empty() {
            vec![(0, u32::MAX)]
        } else {
            matches
        }
    }

    fn endpoint_condition_match(&mut self, pat: &str, negate: bool) -> (u32, u32) {
        let matches = self.endpoint_addresses(pat);
        if matches.len() == 1 {
            return matches[0];
        }
        // At most one condition address fits the ABI, so zero addresses (a
        // pattern with no numeric matcher) and several addresses (a hostname
        // with multiple A records) share this path. Both are treated so the
        // rule still applies, which is the fail-closed outcome for an
        // exception that could not be expressed.
        //
        // A positive `unless target` uses `(0, u32::MAX)`, the literal
        // `0.0.0.0`, which no connect/recv target has: `m` is false, the
        // condition is unsatisfied, and the rule fires. `target not PAT` uses
        // match-any `(0, 0)`: `m` is true for every endpoint, and the kernel's
        // `cond_neg` inverts it to false, so the rule fires there too.
        if negate { (0, 0) } else { (0, u32::MAX) }
    }

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
        // Zero the whole struct first: the struct literal would leave the
        // `repr(C)` padding between `arg` and `add` uninitialized, and the blob
        // is serialized as raw bytes over the full struct, so that padding would
        // leak into the compiled config and make identical policies produce
        // different blobs (and hashes).
        let mut u: CUpdate = unsafe { std::mem::zeroed() };
        u.op = spec.op;
        u.m = spec.m;
        u.add = spec.add;
        u.del = spec.del;
        u.gates = spec.gates;
        u.invals = spec.invals;
        u.ipv4 = spec.ipv4;
        u.ipv4_mask = spec.ipv4_mask;
        u.gate_exit_code = spec.gate_exit_code;
        u.domain_id = 0;
        set_pat_reported(&mut u.target, spec.target, spec.what, &mut self.warnings);
        // Only a gate or an invalidator carries a non-empty arg, and both name
        // themselves in `what`, so the arg diagnostic follows it ("gate target"
        // -> "gate arg"). A source/xform arg is empty and never warns.
        let arg_what = spec.what.replacen("target", "arg", 1);
        set_pat_reported(&mut u.arg, spec.arg, &arg_what, &mut self.warnings);
        check_matcher_literal_bound(
            spec.m,
            spec.target,
            spec.what,
            spec.companion,
            &mut self.warnings,
        );
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
        arg: Option<&str>,
        gate_exit: Option<u8>,
    ) -> Result<(u64, u32), String> {
        let (low_op, m, lit, widened, capped) = match gate_op {
            Op::Exec => {
                let l = lower_exec_reported(pat);
                (OP_EXEC, l.kind, l.lit, l.widened, l.capped)
            }
            Op::Read | Op::Open => {
                let l = lower_path_reported(pat);
                (OP_OPEN, l.kind, l.lit, l.widened, l.capped)
            }
            Op::Write | Op::Unlink => {
                let l = lower_path_reported(pat);
                (OP_WRITE, l.kind, l.lit, l.widened, l.capped)
            }
            other => {
                return Err(format!(
                    "`after {}` is not supported as a gate (use exec/read/write)",
                    op_name(other)
                ));
            }
        };
        warn_widened_literal(pat, widened, "gate target", &mut self.warnings);
        warn_capped_literal(pat, capped, "gate target", &mut self.warnings);
        if arg.is_some() && low_op != OP_EXEC {
            return Err("a gate argument is only valid on `after exec` gates".into());
        }
        if gate_exit.is_some() && low_op != OP_EXEC {
            return Err("`exits` is only valid on `after exec` gates".into());
        }
        let key = (low_op, m, lit.clone(), arg.map(str::to_string), gate_exit);
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
            arg: arg.unwrap_or(""),
            add: 0,
            del: 0,
            gates: b,
            invals: 0,
            ipv4: 0,
            ipv4_mask: 0,
            gate_exit_code: gate_exit.map(i32::from).unwrap_or(GATE_IMMEDIATE),
            what: "gate target",
            companion: (low_op != OP_EXEC)
                .then(|| live_path_companion(pat))
                .flatten()
                .as_deref(),
        })?;
        // Gate companions: a repo-relative path gate also arms on the
        // companion forms (same bit, so the gate is one condition).
        if low_op != OP_EXEC {
            for (cm, clit) in lower_path_companions(pat) {
                self.add_update(UpdateSpec {
                    op: low_op,
                    m: cm,
                    target: &clit,
                    arg: "",
                    add: 0,
                    del: 0,
                    gates: b,
                    invals: 0,
                    ipv4: 0,
                    ipv4_mask: 0,
                    gate_exit_code: GATE_IMMEDIATE,
                    what: "gate companion target",
                    companion: None,
                })?;
            }
        }
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
        if arg.is_some() && op != OP_EXEC {
            return Err("a gate argument is only valid on `exec` gates".into());
        }
        let l = if op == OP_EXEC {
            lower_exec_reported(pat)
        } else {
            lower_target_reported(op, kind, pat)
        };
        let (m, lit, widened, capped) = (l.kind, l.lit, l.widened, l.capped);
        warn_widened_literal(pat, widened, "invalidator target", &mut self.warnings);
        warn_capped_literal(pat, capped, "invalidator target", &mut self.warnings);
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
            what: "invalidator target",
            companion: (op != OP_EXEC)
                .then(|| live_path_companion(pat))
                .flatten()
                .as_deref(),
        })?;
        // Invalidator companions: a repo-relative path `since` pattern also
        // stamps the companion forms (same bit, so one invalidator).
        if op != OP_EXEC {
            for (cm, clit) in lower_path_companions(pat) {
                self.add_update(UpdateSpec {
                    op,
                    m: cm,
                    target: &clit,
                    arg: arg_s,
                    add: 0,
                    del: 0,
                    gates: 0,
                    invals: bit,
                    ipv4: 0,
                    ipv4_mask: 0,
                    gate_exit_code: GATE_IMMEDIATE,
                    what: "invalidator companion target",
                    companion: None,
                })?;
            }
        }
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
    /// Construct the update came from, for the literal diagnostics. Named at
    /// each call site the way the widened/capped warnings already are, so a
    /// source, gate, xform, or invalidator literal reports which one it was
    /// rather than the generic "event target" all of them used to say.
    what: &'a str,
    /// The bare `exact` companion literal the caller also emits for a
    /// repo-relative path pattern, if any. A `SUFFIX`/`CONTAINS` primary past
    /// the kernel window is a dead matcher entry, but its `exact` companion has
    /// no length bound, so the pattern still matches the bare form and
    /// [`check_matcher_literal_bound`] must say so rather than "never matches".
    companion: Option<&'a str>,
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

/// Lower a target pattern for the given op, carrying both widening causes.
fn lower_target_reported(op: u8, kind: Kind, pat: &str) -> Lowered {
    let _ = kind;
    match op {
        OP_EXEC => lower_exec_reported(pat),
        OP_CONNECT | OP_RECV => Lowered {
            kind: M_ANY,
            lit: String::new(),
            widened: false,
            capped: false,
        },
        _ => lower_path_reported(pat),
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
/// the corrective-feedback payload (docs/design/feedback-design.md).
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

/// A pattern-lowering warning: the literal the compiler produced does not mean
/// what the policy wrote, so the rule either matches something else or can never
/// match. The compiler owns the message (it knows the buffer and matcher
/// bounds); `code` is the stable identifier the CLI reports.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatternWarning {
    pub code: &'static str,
    pub message: String,
}

/// Stable codes for [`PatternWarning`].
pub const PATTERN_TRUNCATED: &str = "pattern_literal_truncated";
pub const PATTERN_EMPTY_LITERAL: &str = "pattern_empty_literal";
pub const PATTERN_MATCHER_LENGTH: &str = "pattern_matcher_length_exceeded";
pub const PATTERN_LITERAL_WIDENED: &str = "pattern_literal_widened";
pub const PATTERN_CONTAINS_CAPPED: &str = "pattern_contains_capped";

/// Every pattern-lowering code the compiler can record, in one place.
///
/// A hand-written list of codes drifts: `pattern_empty_literal` was emitted but
/// missing from the CLI's doc-completeness guard, so its documentation could
/// have changed unnoticed. Callers that must enumerate the family (that guard)
/// read this instead of restating it, so a new code here is a compile-time
/// signal to update them.
pub const PATTERN_WARNING_CODES: [&str; 5] = [
    PATTERN_TRUNCATED,
    PATTERN_EMPTY_LITERAL,
    PATTERN_MATCHER_LENGTH,
    PATTERN_LITERAL_WIDENED,
    PATTERN_CONTAINS_CAPPED,
];

/// A clause whose `when` requires and forbids the same label bit, so the
/// kernel's `taint_mask_ok` can never hold and the rule never fires.
///
/// Distinct from the five `pattern_*` codes: those report a matcher that means
/// something other than the glob. A contradiction is not a matcher change; the
/// blob and the policy agree, and both are dead. Kept out of
/// [`PATTERN_WARNING_CODES`] for that reason, and reported through the same
/// `Compiled::pattern_warnings` channel so every surface prints it.
pub const RULE_CONDITION_CONTRADICTION: &str = "rule_condition_contradiction";

/// An `unless target` condition that is satisfied by every event the rule's own
/// target accepts, so the kernel's condition gate suppresses the rule and it
/// never fires.
///
/// Distinct from [`RULE_CONDITION_CONTRADICTION`] (the label mask is dead) and
/// from the five `pattern_*` codes (the matcher differs from the glob). Here the
/// target and the condition are each lowered correctly; it is their relationship
/// that kills the rule. Kept out of [`PATTERN_WARNING_CODES`] and reported
/// through the same `Compiled::pattern_warnings` channel.
pub const RULE_CONDITION_COVERS_TARGET: &str = "rule_condition_covers_target";

/// A condition that references a label no update in the policy ever *sets*, so
/// the compiled blob never puts that bit in a process's label mask.
///
/// `label_bit` assigns a bit on first sight, and a condition reference allocates
/// one too, but only a `source` or an `endorse` xform writes it. (`declassify`
/// lowers to `del`, so it clears the bit rather than setting it, and does not
/// make the label reachable.) With no such producer the plain form (`if L`)
/// never fires, and the negated form (`if not L`) is satisfied
/// for every event the clause's target accepts, so it fires on all of them.
///
/// Distinct from [`RULE_CONDITION_CONTRADICTION`] (a dead mask built from
/// labels that do exist) and from the `pattern_*` codes (a matcher that
/// differs from the glob). Kept out of [`PATTERN_WARNING_CODES`] and reported
/// through the same `Compiled::pattern_warnings` channel.
pub const RULE_CONDITION_LABEL_WITHOUT_PRODUCER: &str = "rule_condition_label_without_producer";

/// Labels the runtime seeds into a process directly, so a policy may reference
/// one without declaring a `source` for it.
///
/// `actplane run`/`watch`/auto-attach seed the launched (or attached) pid with
/// the `COMMAND` label, falling back to `AGENT` for older policies, before any
/// exec update runs (`runtime::runner_label`, and `templates.rs` tells users to
/// narrow `exec "**"` to their agent executable). A reference-only policy is
/// therefore enforceable, and warning about it would be a false positive.
pub const RUNTIME_SEEDED_LABELS: [&str; 2] = ["COMMAND", "AGENT"];

pub struct Compiled {
    pub bytes: Vec<u8>,
    pub reasons: Vec<String>, // indexed by lowered rule_id
    pub meta: Vec<RuleMeta>,  // indexed by lowered rule_id
    pub labels: HashMap<String, u64>,
    pub endpoint_resolutions: HashMap<String, Vec<String>>,
    /// Pattern-lowering warnings (sorted, deduplicated), for the CLI to surface.
    pub pattern_warnings: Vec<PatternWarning>,
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
        endpoint_cache: HashMap::new(),
        endpoint_resolutions: HashMap::new(),
        warnings: Vec::new(),
    };
    for name in &sorted_labels {
        ctx.label_bit(name)?;
    }
    let mut rules: Vec<CRule> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut meta: Vec<RuleMeta> = Vec::new();
    let mut warnings: Vec<PatternWarning> = Vec::new();

    for s in &pol.sources {
        let bit = ctx.label_bit(&s.label)?;
        let (op, m, lit, ipv4, ipv4_mask, widened, capped) = match s.kind {
            Kind::Exec => {
                let l = lower_exec_reported(&s.pattern);
                (OP_EXEC, l.kind, l.lit, 0, 0, l.widened, l.capped)
            }
            Kind::File => {
                let l = lower_path_reported(&s.pattern);
                (OP_OPEN, l.kind, l.lit, 0, 0, l.widened, l.capped)
            }
            Kind::Endpoint => {
                let endpoints = ctx.endpoint_matches(&s.pattern);
                for (n, mk) in endpoints {
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
                            what: "source target",
                            companion: None,
                        })?;
                    }
                }
                continue;
            }
        };
        warn_widened_literal(&s.pattern, widened, "source target", &mut ctx.warnings);
        warn_capped_literal(&s.pattern, capped, "source target", &mut ctx.warnings);
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
            what: "source target",
            companion: (op == OP_OPEN)
                .then(|| live_path_companion(&s.pattern))
                .flatten()
                .as_deref(),
        })?;
        // Repo-relative companions. The primary lowering assumes an absolute
        // runtime path; in tracepoint mode the kernel matches the userspace
        // path argument verbatim, which is relative when the caller passed a
        // relative path. Pair each primary form with its companion so both the
        // absolute/nested and the bare/first-segment-relative forms match.
        if op == OP_OPEN {
            for (cm, clit) in lower_path_companions(&s.pattern) {
                ctx.add_update(UpdateSpec {
                    op,
                    m: cm,
                    target: &clit,
                    arg: "",
                    add: bit,
                    del: 0,
                    gates: 0,
                    invals: 0,
                    ipv4: 0,
                    ipv4_mask: 0,
                    gate_exit_code: GATE_IMMEDIATE,
                    what: "source companion target",
                    companion: None,
                })?;
            }
        }
    }
    for x in &pol.xforms {
        let bit = ctx.label_bit(&x.label)?;
        let l = lower_exec_reported(&x.gate);
        let (m, lit, widened, capped) = (l.kind, l.lit, l.widened, l.capped);
        warn_widened_literal(&x.gate, widened, "transform gate", &mut ctx.warnings);
        warn_capped_literal(&x.gate, capped, "transform gate", &mut ctx.warnings);
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
            what: "transform gate",
            companion: None,
        })?;
    }
    // Labels an update in the blob (or an earlier delta in the same domain)
    // actually *sets*. A condition reference alone allocates a bit without
    // producing it, which is what the warning below reports.
    //
    // Only an `endorse` xform counts: `declassify` lowers to `del`, i.e. it
    // clears the bit, so `declassify L by exec G` does not make `if L` reachable
    // (it makes it less reachable). A source always adds.
    let produced: BTreeSet<&str> = pol
        .sources
        .iter()
        .map(|s| s.label.as_str())
        .chain(
            pol.xforms
                .iter()
                .filter(|x| x.endorse)
                .map(|x| x.label.as_str()),
        )
        .chain(existing_labels.keys().map(String::as_str))
        .collect();
    for rule in &pol.rules {
        for cl in &rule.clauses {
            // The condition's DNF is a property of the clause, not of the op or
            // the target matcher, so compute it once and reuse it below. A
            // contradicted term is dead in every rule the clause emits, so the
            // warning is per clause and names whether the whole clause or only
            // one `or` branch is unreachable.
            let terms = dnf(&cl.when, &mut ctx)?;
            if let Some((req, forbid)) = terms.iter().find(|(r, f)| r & f != 0) {
                let all_terms_dead = terms.iter().all(|(r, f)| r & f != 0);
                warn_condition_contradiction(
                    *req,
                    *forbid,
                    all_terms_dead,
                    &ctx.labels,
                    &rule.name,
                    &mut warnings,
                );
            }
            // A label the condition references but nothing produces is a dead
            // bit in the plain form and a free bit in the negated form. Checked
            // against the producers, not the allocated bits, because
            // `label_bit` has already assigned a bit to every referenced name.
            warn_condition_label_without_producer(&cl.when, &produced, &rule.name, &mut warnings);
            // An `unless target` condition is tested against the same event
            // text as the rule's own target, so a condition that covers the
            // target suppresses every event and kills the rule. Track coverage
            // across the row loop (a target pattern can emit a companion entry
            // the exception does not cover) and warn once per clause.
            let mut cond_rows_total = 0usize;
            let mut cond_rows_dead = 0usize;
            let mut cond_reported: Option<(String, bool)> = None;
            for op in op_lowers(cl.op)? {
                let op = *op;
                let target_matches = if op == OP_CONNECT || op == OP_RECV {
                    ctx.endpoint_matches(&cl.target.pattern)
                        .into_iter()
                        .map(|(ipv4, ipv4_mask)| (M_ANY, String::new(), ipv4, ipv4_mask, None))
                        .collect::<Vec<_>>()
                } else {
                    let l = lower_target_reported(op, cl.target.kind, &cl.target.pattern);
                    let (tm, tlit, widened, capped) = (l.kind, l.lit, l.widened, l.capped);
                    warn_widened_literal(&cl.target.pattern, widened, "rule target", &mut warnings);
                    warn_capped_literal(&cl.target.pattern, capped, "rule target", &mut warnings);
                    let mut v = vec![(
                        tm,
                        tlit,
                        0,
                        0,
                        (op == OP_OPEN || op == OP_WRITE)
                            .then(|| live_path_companion(&cl.target.pattern))
                            .flatten(),
                    )];
                    // Repo-relative companions for the sink target, mirroring
                    // the file source. An extra rule entry is verifier-free
                    // (the scans run in bpf_loop callbacks), and a companion
                    // that co-matches costs no extra verdict: the scan keeps a
                    // single best-effect match, so no event fires twice.
                    if op == OP_OPEN || op == OP_WRITE {
                        for (cm, clit) in lower_path_companions(&cl.target.pattern) {
                            v.push((cm, clit, 0, 0, None));
                        }
                    }
                    v
                };
                for (tm, tlit, ipv4, ipv4_mask, comp) in target_matches {
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
                                let (n, mk) = ctx.endpoint_condition_match(pattern, *negate);
                                cipv4 = n;
                                cipv4_mask = mk;
                            } else {
                                let lowered = lower_target_reported(op, cl.target.kind, pattern);
                                warn_widened_literal(
                                    pattern,
                                    lowered.widened,
                                    "rule condition pattern",
                                    &mut warnings,
                                );
                                warn_capped_literal(
                                    pattern,
                                    lowered.capped,
                                    "rule condition pattern",
                                    &mut warnings,
                                );
                                cm = lowered.kind;
                                clit = lowered.lit;
                            }
                        }
                        Some(Cond::LineageIncludes { exec }) => {
                            ck = C_LINEAGE;
                            let (b, _idx) = ctx.gate_bit(Op::Exec, exec, None, None)?;
                            gate = b;
                        }
                        Some(Cond::After {
                            gate_op,
                            gate_pattern,
                            gate_arg,
                            gate_exit,
                            since,
                        }) => {
                            ck = C_AFTER;
                            let (b, idx) = ctx.gate_bit(
                                *gate_op,
                                gate_pattern,
                                gate_arg.as_deref(),
                                *gate_exit,
                            )?;
                            gate = b;
                            gate_idx = idx;
                            for (op, pat, arg) in since {
                                let iop = inval_op(*op)?;
                                since_mask |=
                                    ctx.inval_slot(iop, cl.target.kind, pat, arg.as_deref())?;
                            }
                        }
                    }
                    if let Some(Cond::Target { negate, pattern }) = &cl.unless {
                        let dead = if op == OP_CONNECT || op == OP_RECV {
                            endpoint_condition_covers_target(
                                ipv4, ipv4_mask, cipv4, cipv4_mask, *negate,
                            )
                        } else {
                            condition_covers_target(tm, &tlit, cm, &clit, *negate)
                        };
                        cond_rows_total += 1;
                        cond_rows_dead += dead as usize;
                        if dead && cond_reported.is_none() {
                            cond_reported = Some((pattern.clone(), *negate));
                        }
                    }
                    for (req, forbid) in &terms {
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
                        // Zero-init so `repr(C)` padding does not leak into the
                        // serialized blob (see `add_update`).
                        let mut cr: CRule = unsafe { std::mem::zeroed() };
                        cr.op = op;
                        cr.m = tm;
                        cr.cond_kind = ck;
                        cr.cond_neg = cneg;
                        cr.cond_match = cm;
                        cr.effect = lower_effect(cl.effect);
                        cr.req = *req;
                        cr.forbid = *forbid;
                        cr.gate = gate;
                        cr.rule_id = rule_id;
                        cr.ipv4 = ipv4;
                        cr.ipv4_mask = ipv4_mask;
                        cr.cond_ipv4 = cipv4;
                        cr.cond_ipv4_mask = cipv4_mask;
                        cr.gate_idx = gate_idx;
                        cr.domain_id = 0;
                        cr.since_mask = since_mask;
                        set_pat_reported(&mut cr.target, &tlit, "rule target", &mut warnings);
                        check_matcher_literal_bound(
                            tm,
                            &tlit,
                            "rule target",
                            comp.as_deref(),
                            &mut warnings,
                        );
                        if let Some(a) = &cl.target.arg {
                            set_pat_reported(&mut cr.arg, a, "rule arg", &mut warnings);
                        }
                        // Only a `target` condition on a path/exec op stores a
                        // pattern; `connect`/`recv` store the condition as a
                        // numeric IPv4 (`cond_ipv4`), and every other condition
                        // kind leaves `cond_pat` empty by design.
                        if ck == C_TARGET && !matches!(op, OP_CONNECT | OP_RECV) {
                            set_pat_reported(
                                &mut cr.cond_pat,
                                &clit,
                                "rule condition pattern",
                                &mut warnings,
                            );
                            check_matcher_literal_bound(
                                cm,
                                &clit,
                                "rule condition pattern",
                                None,
                                &mut warnings,
                            );
                        }
                        rules.push(cr);
                    }
                }
            }
            if let Some((pattern, negate)) = cond_reported {
                warn_condition_covers_target(
                    &cl.target.pattern,
                    &pattern,
                    negate,
                    cond_rows_dead == cond_rows_total,
                    &rule.name,
                    &mut warnings,
                );
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
    warnings.extend(ctx.warnings);
    warnings.sort();
    warnings.dedup();
    Ok(Compiled {
        bytes,
        reasons,
        meta,
        labels: ctx.labels,
        endpoint_resolutions: ctx.endpoint_resolutions,
        pattern_warnings: warnings,
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
