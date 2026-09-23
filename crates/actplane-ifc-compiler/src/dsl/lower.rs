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

/// Report a literal that the kernel matcher cannot use, for a pattern that
/// therefore never matches. Two independent ways that happens:
///
/// * An empty literal for a non-`ANY` kind. `taint_streq` and `taint_prefix`
///   both return 0 for an empty pattern (exact: the text would have to be empty;
///   prefix: `anynz` stays 0, and the comment on `taint_prefix` states an empty
///   prefix never matches). A pattern such as `exec "src/*"` or `exec "foo/"`
///   lowers to an empty literal, so the rule never fires. `ANY` is exempt by
///   construction: its literal is meant to be empty and it always matches.
/// * A `SUFFIX`/`CONTAINS` literal past `TAINT_SUF_MAX`. Both matchers return 0
///   when the pattern is longer than their fixed 16-byte tail/window copy, so
fn check_matcher_literal_bound(kind: u8, lit: &str, what: &str, out: &mut Vec<PatternWarning>) {
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
        out.push(PatternWarning {
            code: PATTERN_MATCHER_LENGTH,
            message: format!(
                "{what} \"{lit}\" lowers to a {}-byte {} literal, but the kernel matcher rejects any literal longer than {} bytes, so the pattern can never match. Use a shorter basename pattern, or an absolute pattern with a wildcard.",
                lit.len(),
                match_kind_name(kind),
                MAX_CONTAINS_LITERAL
            ),
        });
    }
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

/// True when a repo-relative path pattern's primary matcher misses a form that
/// the kernel's single `cond_kind`/`cond_pat` pair cannot also cover: a
/// `**/<name>` basename (bare root-level file) or a `**/<dir>/**` / `**/<dir>/*`
/// directory (first-segment-relative path). A rule *target* covers both forms by
/// emitting a companion table entry, but an `unless target` **condition** has
/// only one cond slot, so the exception cannot express the disjunction and
/// mis-matches on the uncovered form (a negated condition over-fires there).
///
/// Callers use this to warn that the exception is approximate; the engine is not
/// changed. Absolute patterns and pure wildcard forms have no companion and
/// return `false`.
pub fn repo_relative_condition_is_partial(pattern: &str) -> bool {
    !pattern.starts_with('/') && !lower_path_companions(pattern).is_empty()
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
            return (M_SUFFIX, suffix.to_string());
        }
        if !inner.contains('*') {
            return (M_SUFFIX, format!("/{inner}"));
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
fn lower_numeric_ipv4(pat: &str) -> Option<(u32, u32)> {
    if pat == "*" {
        return Some((0, 0));
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
            Err(_) => return None,
        }
    }
    if k == 0 { None } else { Some((net, mask)) }
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
    fn endpoint_matches(&mut self, pat: &str) -> Vec<(u32, u32)> {
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
            if addrs.is_empty() {
                vec![(0, u32::MAX)]
            } else {
                addrs.into_iter().map(|addr| (addr, u32::MAX)).collect()
            }
        } else {
            vec![(0, u32::MAX)]
        };
        self.endpoint_cache.insert(pat.to_string(), matches.clone());
        matches
    }

    fn endpoint_condition_match(&mut self, pat: &str, negate: bool) -> (u32, u32) {
        let matches = self.endpoint_matches(pat);
        if matches.len() == 1 {
            return matches[0];
        }
        // `unless target PAT` should fail closed when a hostname expands to
        // several A records but the current ABI can store only one condition
        // address. For `target not PAT`, use match-any before negation so the
        // condition is false for every endpoint, and the rule still applies.
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
        set_pat_reported(
            &mut u.target,
            spec.target,
            "event target",
            &mut self.warnings,
        );
        set_pat_reported(&mut u.arg, spec.arg, "event arg", &mut self.warnings);
        check_matcher_literal_bound(spec.m, spec.target, "event target", &mut self.warnings);
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
                        })?;
                    }
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
                })?;
            }
        }
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
                let target_matches = if op == OP_CONNECT || op == OP_RECV {
                    ctx.endpoint_matches(&cl.target.pattern)
                        .into_iter()
                        .map(|(ipv4, ipv4_mask)| (M_ANY, String::new(), ipv4, ipv4_mask))
                        .collect::<Vec<_>>()
                } else {
                    let (tm, tlit) = lower_target(op, cl.target.kind, &cl.target.pattern);
                    let mut v = vec![(tm, tlit, 0, 0)];
                    // Repo-relative companions for the sink target, mirroring
                    // the file source. An extra rule entry is verifier-free
                    // (the scans run in bpf_loop callbacks), and a companion
                    // that co-matches costs no extra verdict: the scan keeps a
                    // single best-effect match, so no event fires twice.
                    if op == OP_OPEN || op == OP_WRITE {
                        for (cm, clit) in lower_path_companions(&cl.target.pattern) {
                            v.push((cm, clit, 0, 0));
                        }
                    }
                    v
                };
                for (tm, tlit, ipv4, ipv4_mask) in target_matches {
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
                                let (m, l) = lower_target(op, cl.target.kind, pattern);
                                cm = m;
                                clit = l;
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
                        // Zero-init so `repr(C)` padding does not leak into the
                        // serialized blob (see `add_update`).
                        let mut cr: CRule = unsafe { std::mem::zeroed() };
                        cr.op = op;
                        cr.m = tm;
                        cr.cond_kind = ck;
                        cr.cond_neg = cneg;
                        cr.cond_match = cm;
                        cr.effect = lower_effect(cl.effect);
                        cr.req = req;
                        cr.forbid = forbid;
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
                        check_matcher_literal_bound(tm, &tlit, "rule target", &mut warnings);
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
                                &mut warnings,
                            );
                        }
                        rules.push(cr);
                    }
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
