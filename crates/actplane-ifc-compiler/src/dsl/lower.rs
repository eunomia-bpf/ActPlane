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

    /// Compile a DSL source and read the kernel `CConfig` out of the fixed-size
    /// `bytes` blob, the same `read_unaligned` probe the endpoint tests above use.
    /// `CConfig`/`CRule`/`CUpdate` are module-private, so the probe must live in
    /// this module.
    fn compile_cfg(src: &str) -> CConfig {
        let pol = crate::dsl::parse::parse(src).expect("parse policy");
        let compiled = compile(&pol).expect("compile policy");
        unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
    }

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
    fn wildcard_hostnames_are_not_resolved_as_exact_hosts() {
        assert_eq!(hostname_candidate("*.internal"), None);
        assert_eq!(hostname_candidate("api.internal"), Some("api.internal"));
    }

    #[test]
    fn absolute_wildcard_paths_lower_to_prefix() {
        // An absolute path's leading `/` is a stable start anchor, so every
        // wildcard form lowers to M_PREFIX (the kernel does a start-anchored
        // prefix scan). M_CONTAINS (a substring scan) is only reachable for
        // repo-relative paths, which have no start anchor and so fall back to a
        // substring match. The in-tree `absolute_paths_keep_absolute_semantics`
        // test pins the `/**` -> M_PREFIX and no-wildcard -> M_EXACT forms; the
        // `/*`, internal-`*`, and trailing-`*` absolute branches below are what
        // a regression could quietly collapse to M_CONTAINS, silently turning a
        // start-anchored prefix into a substring match.
        assert_eq!(lower_path("/data/**"), (M_PREFIX, "/data/".into()));
        assert_eq!(lower_path("/data/x/*"), (M_PREFIX, "/data/x/".into()));
        assert_eq!(lower_path("/data/*/y"), (M_PREFIX, "/data/".into()));
        assert_eq!(lower_path("/data/x*"), (M_PREFIX, "/data/x".into()));
        // The repo-relative counterparts have no start anchor, so the same
        // wildcard shapes fall to a M_CONTAINS substring scan. This contrast is
        // what makes the absolute M_PREFIX branches load-bearing.
        assert_eq!(lower_path("data/x/*"), (M_CONTAINS, "data/x/".into()));
        assert_eq!(lower_path("data/*/y"), (M_CONTAINS, "data/".into()));
        assert_eq!(lower_path("data/x*"), (M_CONTAINS, "data/x".into()));
        // A bare `**` still lowers to M_ANY (match any), independent of the
        // prefix/contains split.
        assert_eq!(lower_path("**"), (M_ANY, String::new()));
    }

    #[test]
    fn an_absolute_path_with_an_interior_wildcard_lowers_to_a_prefix_match() {
        // An absolute path whose star is NOT at the terminal position
        // (`/var/log/*.log`, `/opt/**/*.conf`) is lowered through the
        // interior-wildcard arm to a prefix match on the substring up to the
        // first star. This is the `find('*')` branch (lower.rs:208-212),
        // distinct from the terminal `/*` suffix arm (lower.rs:193-200) that
        // the absolute single-star test pins. No base test asserts these
        // interior-star absolute lowerings.
        assert_eq!(lower_path("/var/log/*.log"), (M_PREFIX, "/var/log/".into()));
        // A `**` interior glob on an absolute path lowers to the prefix up
        // to the first star.
        assert_eq!(lower_path("/opt/**/*.conf"), (M_PREFIX, "/opt/".into()));
        // Control: an absolute path with no star is an exact match, not a
        // prefix.
        assert_eq!(lower_path("/opt/file"), (M_EXACT, "/opt/file".into()));
    }

    #[test]
    fn an_absolute_single_star_path_lowers_to_a_prefix_match() {
        // An absolute path with a single `*` segment (e.g. `/tmp/*.js`)
        // matches every file directly inside that directory. The `/*`
        // suffix lowers to a prefix match on the directory prefix (the
        // trailing `/` included), distinct from the absolute `/**` form
        // (recursive, also a prefix but reached via a different branch) and
        // from an exact absolute path.
        assert_eq!(lower_path("/tmp/*.js"), (M_PREFIX, "/tmp/".into()));
        assert_eq!(lower_path("/opt/*.bin"), (M_PREFIX, "/opt/".into()));
        // Control: a no-wildcard absolute path stays an exact match.
        assert_eq!(lower_path("/opt/file"), (M_EXACT, "/opt/file".into()));
    }

    #[test]
    fn an_after_gate_with_a_non_gateable_op_is_rejected() {
        // An `after` gate only supports exec/read/write: the gate's taint_op
        // is what the engine stamps as the epoch. `connect`/`recv` are not
        // gateable, and the restriction is a compile-time check in
        // `gate_bit`. The parser accepts any op word (`P::op`), so this is
        // reached only during lowering.
        use crate::dsl::parse::parse;
        // `connect` is not a valid gate op.
        let pol = parse("rule r:\n  block exec \"git\" unless after connect \"10.0.0.5\"\n")
            .expect("an after connect gate parses");
        match compile(&pol) {
            Ok(_) => panic!("an after connect gate must be rejected"),
            Err(err) => assert_eq!(
                err,
                "`after connect` is not supported as a gate (use exec/read/write)"
            ),
        }
        // `recv` is likewise not a valid gate op.
        let pol = parse("rule r:\n  block exec \"git\" unless after recv \"10.0.0.5\"\n")
            .expect("an after recv gate parses");
        match compile(&pol) {
            Ok(_) => panic!("an after recv gate must be rejected"),
            Err(err) => assert_eq!(
                err,
                "`after recv` is not supported as a gate (use exec/read/write)"
            ),
        }
        // Positive control: `exec` is a valid gate op and compiles.
        let pol = parse("rule r:\n  block exec \"git\" unless after exec \"/in\"\n")
            .expect("an after exec gate parses");
        compile(&pol).expect("an after exec gate compiles");
    }

    #[test]
    fn arg_eq_ignores_tail_bytes_beyond_the_arg_cap() {
        // `arg_eq` compares a `[u8; ARG]` buffer against a fresh buffer holding
        // the first `min(len, ARG)` bytes of the string, zero-padded. So the
        // predicate is insensitive to any string tail beyond `ARG`, and short
        // strings zero-pad against the trailing bytes. No base test pins this
        // truncation/padding invariant directly; it is only exercised
        // indirectly through rule lowering.
        let prefix = "a23456789012345678901234"; // exactly `ARG` bytes
        assert_eq!(prefix.len(), ARG);
        let mut buf = [0u8; ARG];
        buf[..ARG].copy_from_slice(prefix.as_bytes());

        // An exact-`ARG`-length string matches, and a string with the same
        // `ARG` prefix but a longer tail matches too (tail is dropped).
        assert!(arg_eq(&buf, prefix));
        assert!(arg_eq(&buf, "a23456789012345678901234more_tail_bytes"));

        // A string that differs on a byte within the `ARG` window does not.
        assert!(!arg_eq(&buf, "b23456789012345678901234"));

        // A zeroed buffer matches the empty string (nothing to copy) but not
        // a non-empty string whose first byte is nonzero.
        let zero = [0u8; ARG];
        assert!(arg_eq(&zero, ""));
        assert!(!arg_eq(&zero, "abc"));
    }

    #[test]
    fn positional_arg_truncates_to_the_kernel_arg_slot() {
        // The parse layer accepts an arbitrarily-long quoted positional arg token
        // (a `Tok::Str` with no length guard) and there is no arg-length compile
        // error, so a too-long arg is truncated rather than rejected. The kernel
        // stores it in a fixed `char arg[TAINT_ARG_LEN]` slot (TAINT_ARG_LEN = 24,
        // taint.h), so set_pat keeps the first ARG-1 = 23 bytes and NUL-pads the
        // rest. A regression that dropped that truncation -- or wrote past the
        // NUL -- would corrupt the C-ABI arg field the kernel's exec argv matcher
        // reads. #56 pins only the fitting short arg; the overflow boundary is
        // unclaimed.
        fn arg_field(kept: &str) -> [u8; ARG] {
            let mut out = [0u8; ARG];
            out[..kept.len()].copy_from_slice(kept.as_bytes());
            out
        }
        let config = |src: &str| -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        };

        // 22 chars fits inside the 23-char data region: stored verbatim.
        let cfg = config(
            "rule r:\n  block exec \"git\" \"abcdefghijklmnopqrstuv\" if true\n  because \"z\"\n",
        );
        assert_eq!(
            cfg.rules[0].arg,
            arg_field("abcdefghijklmnopqrstuv"),
            "a 22-char arg fits and is stored verbatim"
        );

        // 23 chars is the exact data region: the NUL lands on the slot's last byte.
        let cfg = config(
            "rule r:\n  block exec \"git\" \"abcdefghijklmnopqrstuvw\" if true\n  because \"z\"\n",
        );
        assert_eq!(
            cfg.rules[0].arg,
            arg_field("abcdefghijklmnopqrstuvw"),
            "a 23-char arg fills the data region, NUL on the last byte"
        );

        // 25 chars overflows: only the first 23 bytes survive, NUL at index 23.
        let cfg = config(
            "rule r:\n  block exec \"git\" \"abcdefghijklmnopqrstuvwxy\" if true\n  because \"z\"\n",
        );
        assert_eq!(
            cfg.rules[0].arg,
            arg_field("abcdefghijklmnopqrstuvw"),
            "a 25-char arg truncates to the first 23 bytes"
        );

        // 40 chars: the same boundary -- first 23 of 40 kept.
        let cfg = config(
            "rule r:\n  block exec \"git\" \"0123456789012345678901234567890123456789\" if true\n  because \"z\"\n",
        );
        assert_eq!(
            cfg.rules[0].arg,
            arg_field("01234567890123456789012"),
            "a 40-char arg truncates to the first 23 bytes"
        );

        // An absent arg leaves the slot all-zero (the kernel's \"ignore argv\" case).
        let cfg = config("rule r:\n  block exec \"git\" if true\n  because \"z\"\n");
        assert_eq!(
            cfg.rules[0].arg,
            arg_field(""),
            "an absent arg leaves the slot all-zero"
        );
    }

    #[test]
    fn numeric_ipv4_patterns_lower_to_prefix_masks() {
        assert_eq!(lower_numeric_ipv4("*"), Some((0, 0)));
        assert_eq!(
            lower_numeric_ipv4("10.0.0.5"),
            Some((ipv4_to_kernel("10.0.0.5".parse().unwrap()), u32::MAX))
        );
        assert_eq!(
            lower_numeric_ipv4("10.0.0."),
            Some((ipv4_to_kernel("10.0.0.0".parse().unwrap()), 0x00ff_ffff))
        );
        assert_eq!(lower_numeric_ipv4("10.0.0.256"), None);
        assert_eq!(lower_numeric_ipv4("not-an-ip"), None);
    }

    #[test]
    fn non_numeric_endpoint_patterns_lower_to_match_any() {
        assert_eq!(lower_ipv4("api.internal"), (0, u32::MAX));
    }

    #[test]
    fn existing_label_bits_are_validated_before_reuse() {
        let empty_name = HashMap::from([(String::new(), 1u64)]);
        assert_eq!(
            validate_label_bindings(&empty_name).unwrap_err(),
            "label names must not be empty"
        );

        let multi_bit = HashMap::from([("A".to_string(), 0b11u64)]);
        assert_eq!(
            validate_label_bindings(&multi_bit).unwrap_err(),
            "label `A` has invalid bit mask 0x3"
        );

        let zero_bit = HashMap::from([("A".to_string(), 0u64)]);
        assert_eq!(
            validate_label_bindings(&zero_bit).unwrap_err(),
            "label `A` has invalid bit mask 0x0"
        );

        let duplicate = HashMap::from([("A".to_string(), 0b10u64), ("B".to_string(), 0b10u64)]);
        assert_eq!(
            validate_label_bindings(&duplicate).unwrap_err(),
            "label bit 0x2 is assigned more than once"
        );
    }

    #[test]
    fn negated_nonconnect_target_not_keeps_its_pattern_in_the_path_region() {
        // A `target not P` on a file op must keep the negated condition in the
        // *path* cond region: the pattern is lowered by lower_path into
        // cond_match + cond_pat (exactly like the rule's own target), cond_neg
        // is set, and the connect-only cond_ipv4 fields stay zero. The kernel
        // uses cond_match/cond_pat for path rules but cond_ipv4 for connect
        // rules, so a negation regression that treated a path `not` like a
        // connect one would either zero the pattern or mis-route it into
        // cond_ipv4. #57 pinned only that `not` sets cond_neg (the negation
        // bit); #61 pinned the *plain* (cond_neg = 0) non-connect region.
        // Neither pins that the *negated* form still routes its pattern through
        // lower_path into cond_pat while leaving cond_ipv4 at zero.
        fn cfg(src: &str) -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        }

        // Absolute glob: `/work/**` lowers to M_PREFIX on the start-anchored
        // literal `/work/`. The negated form must carry that matcher + pattern
        // in the path region with cond_neg set and cond_ipv4 zero.
        let cr = &cfg(
            "rule r:\n block write file \"/**\" unless target not \"/work/**\" because \"deny writes under /work\"\n",
        )
        .rules[0];
        let (cm, clit) = lower_path("/work/**");
        let mut want_cond = [0u8; PAT];
        set_pat(&mut want_cond, &clit);
        assert_eq!(cr.op, OP_WRITE);
        assert_eq!(cr.cond_kind, C_TARGET, "target cond lowers to TCOND_TARGET");
        assert_eq!(cr.cond_neg, 1, "the `not` form sets cond_neg");
        assert_eq!(cr.cond_match, cm, "negated pattern lowers via lower_path");
        assert_eq!(
            cr.cond_match, M_PREFIX,
            "an absolute glob is start-anchored"
        );
        assert_eq!(
            cr.cond_pat, want_cond,
            "the negated pattern lands in cond_pat"
        );
        assert_eq!(cr.cond_ipv4, 0, "a path negation must not touch cond_ipv4");
        assert_eq!(
            cr.cond_ipv4_mask, 0,
            "a path negation must not touch cond_ipv4_mask"
        );

        // Same matcher, negation bit off: the plain form routes the identical
        // pattern into the same region with cond_neg = 0.
        let cr = &cfg(
            "rule r:\n block write file \"/**\" unless target \"/work/**\" because \"allow writes outside /work\"\n",
        )
        .rules[0];
        assert_eq!(cr.cond_neg, 0, "the plain form is not negated");
        assert_eq!(cr.cond_match, cm, "plain and negated share the matcher");
        assert_eq!(
            cr.cond_pat, want_cond,
            "plain and negated share the cond pattern"
        );

        // Repo-relative glob: `src/**` has no start anchor, so it lowers to
        // M_CONTAINS on `src/` -- the same lower_path dispatch the rule target
        // uses, and a negation must not change that dispatch.
        let cr = &cfg(
            "rule r:\n block open file \"/**\" unless target not \"src/**\" because \"deny opening under src\"\n",
        )
        .rules[0];
        let (cm, clit) = lower_path("src/**");
        let mut want_cond = [0u8; PAT];
        set_pat(&mut want_cond, &clit);
        assert_eq!(cr.op, OP_OPEN, "open lowers to OP_OPEN");
        assert_eq!(cr.cond_neg, 1);
        assert_eq!(cr.cond_match, cm, "repo-rel glob lowers to M_CONTAINS");
        assert_eq!(
            cr.cond_match, M_CONTAINS,
            "a repo-rel glob is a substring scan"
        );
        assert_eq!(
            cr.cond_pat, want_cond,
            "the repo-rel cond pattern lands in cond_pat"
        );
        assert_eq!(cr.cond_ipv4, 0);
    }

    #[test]
    fn a_long_contains_literal_shortens_to_the_shortest_fitting_segment() {
        // `shorten_contains_literal` caps a `M_CONTAINS` literal at
        // `MAX_CONTAINS_LITERAL` (16 chars, the kernel `TAINT_PAT_LEN`
        // headroom). It walks a preference chain: verbatim if already short,
        // else trim the leading '/', else keep the first `/`-segment that
        // fits, else the last segment, else a hard 16-char tail. No base
        // test pins this helper's cap-walk arms directly; they only surface
        // through full `lower_path` calls.
        // Within the cap: kept verbatim.
        assert_eq!(shorten_contains_literal("/var/log/"), "/var/log/");
        // Over the cap: trimming the leading '/' brings it to exactly the cap.
        assert_eq!(
            shorten_contains_literal("/aaaaaaaaaaaaaaaa"),
            "aaaaaaaaaaaaaaaa"
        );
        // Over the cap and still over after trimming: the first '/'-segment
        // that fits is kept, dropping the long leading prefix.
        assert_eq!(shorten_contains_literal("/aaaaaaaaaaaaaaaa/bbbb/"), "bbbb/");
        // A segment later in the walk, still within the cap, is kept even
        // when it is longer than a shorter earlier segment.
        assert_eq!(
            shorten_contains_literal("/opt/data/files/xy/"),
            "data/files/xy/"
        );
    }

    #[test]
    fn a_deep_repo_relative_path_shortens_to_the_first_in_range_segment() {
        // `lower_path` on a repo-relative exact path caps the kernel literal
        // at `MAX_CONTAINS_LITERAL` (16) via `shorten_repo_relative_exact_literal`,
        // which walks down past every `/`-suffixed candidate that is still
        // over the cap and returns the first one that fits. The base tests
        // only cover single-step shortenings, so the multi-skip walk is
        // unpinned.
        // 19 chars: the `b/...` suffix (17 chars) is over the cap and is
        // skipped; `c/d/e/f/g/h/i.js` (16 chars) fits and still contains a
        // slash, so it is returned.
        assert_eq!(
            lower_path("a/b/c/d/e/f/g/h/i.js"),
            (M_CONTAINS, "c/d/e/f/g/h/i.js".into())
        );
        // Two over-cap suffixes are skipped before landing on a fitting one.
        assert_eq!(
            lower_path("src/google/adk/agents/x.json"),
            (M_CONTAINS, "agents/x.json".into())
        );
        // Control: a repo-relative exact path already within the cap is used
        // verbatim, no shortening.
        assert_eq!(
            lower_path("pyproject.toml"),
            (M_CONTAINS, "pyproject.toml".into())
        );
    }

    #[test]
    fn contains_literals_are_bounded_by_taint_suf_max() {
        // bpf/taint.h: the kernel suffix/contains matchers reject any literal
        // longer than TAINT_SUF_MAX (`sn > TAINT_SUF_MAX` makes the match 0).
        // So a lowered M_CONTAINS literal must fit the 16-char window, or the
        // source silently never matches in-kernel.
        //
        // A fitting literal passes through unchanged.
        assert_eq!(lower_path("**/short/**"), (M_CONTAINS, "/short/".into()));

        // An over-cap literal is shortened to fit the kernel's window:
        // `**/abcdefghijklmno/**` -> `/abcdefghijklmno/` (17 chars) shortens
        // to the 16-char `abcdefghijklmno/`.
        assert_eq!(
            lower_path("**/abcdefghijklmno/**"),
            (M_CONTAINS, "abcdefghijklmno/".into())
        );

        // The hard cap: no matter how long the source path is, the lowered
        // literal never exceeds MAX_CONTAINS_LITERAL (= TAINT_SUF_MAX = 16).
        for p in [
            "**/very/long/segment/path/**",
            "**/a/b/c/d/e/f/g/**",
            "**/aaaaaaaaaaaaaaaa/**",
            "aaaaaaaaaaaaaaaaaaaa/**",
        ] {
            let (m, lit) = lower_path(p);
            assert!(
                m == M_CONTAINS,
                "{p} -> match byte {m}, expected M_CONTAINS"
            );
            let len = lit.len();
            assert!(
                len <= MAX_CONTAINS_LITERAL,
                "{p} -> {lit:?} ({len} chars) exceeds TAINT_SUF_MAX = {MAX_CONTAINS_LITERAL}"
            );
        }
    }

    #[test]
    fn an_out_of_vocabulary_declaration_is_rejected() {
        // The top-level declaration vocabulary is closed: the parser accepts
        // exactly `label` (which itself rejects as removed), `source`,
        // `endorse` / `declassify`, and `rule`; anything else hits the
        // catch-all `unknown declaration '{kw}'`. #104 pinned the removed
        // `label` keyword; nobody pinned the catch-all. A stray top-level
        // keyword must fail at parse time rather than be silently ignored.
        use crate::dsl::parse::parse;
        let err = parse("foo AGENT = exec \"/**/s\"\n")
            .expect_err("an unknown top-level declaration must be rejected");
        assert_eq!(err, "unknown declaration 'foo'");

        // Positive controls: each valid declaration keyword parses and
        // compiles.
        for pol in [
            "source S = file \"/**/s\"\n",
            "endorse S by exec \"/in\"\n",
            "declassify S by exec \"/in\"\n",
            "rule r:\n  block exec \"git\" because \"z\"\n",
        ] {
            let p = parse(pol).expect("a valid declaration parses");
            let _ = compile(&p).expect("a valid-declaration policy compiles");
        }
    }

    #[test]
    fn and_over_or_distributes_the_conjunct_across_every_disjunct() {
        // The `dnf` And arm is a cross-product: every disjunct of the left
        // operand is combined with every disjunct of the right. Because the
        // parser is a left-associative `and`/`or` chain, `A or B and C` is
        // `(A or B) and C`, so the conjunct `C` is distributed into *both*
        // `or` disjuncts, producing two rules whose `req` masks are
        // `A|C` and `B|C`. The kernel evaluates each disjunct `CRule`
        // independently, so a regression that collapsed the cross-product
        // (kept only one disjunct, or dropped the distributed conjunct)
        // would under-block.
        //
        // #55 pinned the flat `and` (one disjunct, a two-bit mask) and the
        // flat `or` (two single-bit disjuncts); neither pins that `and`
        // over an `or` multiplies the disjunct count and ORs the conjunct
        // into each one.
        use std::collections::HashMap;
        fn dsl(src: &str) -> CConfig {
            let labels = [
                ("A".to_string(), 1u64),
                ("B".to_string(), 2u64),
                ("C".to_string(), 4u64),
            ]
            .into_iter()
            .collect::<HashMap<_, _>>();
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile_with_labels(&pol, &labels).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        }

        // `(A or B) and C` -> the two `or` disjuncts each get `C` ORed in.
        let g = dsl("rule r:\n  block exec \"x\" if A or B and C\n  because \"z\"\n");
        assert_eq!(g.n_rules, 2, "the conjunct distributes into both `or` arms");
        let reqs: Vec<u64> = g.rules[..2].iter().map(|r| r.req).collect();
        assert!(reqs.contains(&5u64), "one disjunct is A|C = 0b101");
        assert!(reqs.contains(&6u64), "the other is B|C = 0b110");
        for r in &g.rules[..2] {
            assert_eq!(r.forbid, 0, "no disjunct forbids a label");
        }

        // A flat `and` stays a single disjunct: the cross-product of two
        // singletons is one mask, not two rules.
        let g = dsl("rule r:\n  block exec \"x\" if A and B\n  because \"z\"\n");
        assert_eq!(g.n_rules, 1, "a flat `and` is one disjunct");
        assert_eq!(g.rules[0].req, 3u64, "`A and B` requires both");
    }

    /// The kernel matcher denies an operation when
    /// `(mask & req) == req && (mask & forbid) == 0`, so a positive atom must
    /// lower into `req` and a `not` atom into `forbid`, and every DNF
    /// disjunct must stay internally disjoint. Pin the actual mask *content*
    /// (not just the disjunct count, which `mod.rs` covers) via explicit label
    /// bits, so a distribution bug that routes a `not` label into `req` --
    /// flipping a deny into an allow -- is caught.
    #[test]
    fn dnf_masks_route_not_into_forbid_and_keep_disjuncts_disjoint() {
        use std::collections::HashMap;
        let labels: HashMap<String, u64> = [("A".to_string(), 1u64), ("B".to_string(), 2u64)]
            .into_iter()
            .collect();
        let dsl = |src: &str| -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile_with_labels(&pol, &labels).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        };

        // `A and not B`: one disjunct; A required, B forbidden, disjoint.
        let cfg = dsl("rule r:\n  block exec \"x\" if A and not B\n  because \"z\"\n");
        assert_eq!(cfg.n_rules, 1);
        assert_eq!(cfg.rules[0].req, 1u64, "`A` must be a required label");
        assert_eq!(
            cfg.rules[0].forbid, 2u64,
            "`not B` must be a forbidden label"
        );
        assert_eq!(
            cfg.rules[0].req & cfg.rules[0].forbid,
            0,
            "a disjunct cannot require and forbid the same label"
        );

        // `A or not B`: `or` splits into two disjuncts, each still disjoint.
        let cfg = dsl("rule r:\n  block exec \"x\" if A or not B\n  because \"z\"\n");
        assert_eq!(cfg.n_rules, 2);
        assert_eq!(cfg.rules[0].req, 1u64);
        assert_eq!(cfg.rules[0].forbid, 0u64);
        assert_eq!(cfg.rules[1].req, 0u64);
        assert_eq!(cfg.rules[1].forbid, 2u64);
    }

    #[test]
    fn a_boolean_when_expr_expands_to_a_disjunction_of_label_masks() {
        // `dnf` lowers a boolean `when` expression to a disjunction of
        // `(req_mask, forbid_mask)` pairs. A label is a required bit, a
        // negated label is a forbidden bit, and an `And` crosses its two
        // operands' disjuncts (each pair's masks are OR'd together). The
        // base endpoint/exec tests never exercise this expansion directly.
        let mut ctx = Ctx {
            labels: HashMap::from([
                ("A".to_string(), 1u64),
                ("B".to_string(), 2u64),
                ("C".to_string(), 4u64),
            ]),
            used_labels: 0,
            updates: Vec::new(),
            gate_bits: HashMap::new(),
            next_gate: 0,
            inval_slots: HashMap::new(),
            next_inval: 0,
            endpoint_cache: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };
        // A single label is a one-requirement disjunct.
        assert_eq!(
            dnf(&Expr::Label("A".into()), &mut ctx).unwrap(),
            vec![(1, 0)]
        );
        // A negated label is a single forbidden bit.
        assert_eq!(dnf(&Expr::Not("B".into()), &mut ctx).unwrap(), vec![(0, 2)]);
        // `And(Or(A, Not B), C)` crosses the two disjuncts of the `Or`
        // with the single `C` disjunct: `A` -> (1|4, 0), `Not B` ->
        // (0|4, 2).
        assert_eq!(
            dnf(
                &Expr::And(
                    Box::new(Expr::Or(
                        Box::new(Expr::Label("A".into())),
                        Box::new(Expr::Not("B".into()))
                    )),
                    Box::new(Expr::Label("C".into()))
                ),
                &mut ctx
            )
            .unwrap(),
            vec![(5, 0), (4, 2)]
        );
    }

    #[test]
    fn and_forms_or_two_labels_into_a_single_two_bit_mask() {
        use std::collections::HashMap;
        let labels: HashMap<String, u64> = [("A".to_string(), 1u64), ("B".to_string(), 2u64)]
            .into_iter()
            .collect();
        let dsl = |src: &str| -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile_with_labels(&pol, &labels).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        };
        // `dnf`'s And arm ORs the two disjuncts' bits into one field
        // (`(ra | rb, fa | fb)`), so `A and B` is a single rule whose `req`
        // carries BOTH bits, not two single-bit rules. The kernel's
        // taint_mask_ok ANDs the node's label mask against `req`, so a node
        // must have every required bit set. #55 pinned only the single-bit
        // `not -> forbid` routing; #75 the sorted bit mapping. Nobody pins the
        // two-bit `req`/`forbid` mask that an `and` builds. A regression that
        // replaced the `|` with an overwrite (last label wins) would silently
        // drop a required/forbidden label.
        // `A and B`: one disjunct; req carries A|B = 0b11.
        let cfg = dsl("rule r:\n  notify write file \"/sink\" if A and B\n  because \"z\"\n");
        assert_eq!(cfg.n_rules, 1, "`and` joins, not splits: one disjunct");
        assert_eq!(cfg.rules[0].req, 0b11, "`A and B` -> req carries both bits");
        assert_eq!(cfg.rules[0].forbid, 0, "no `not` in this clause");
        // `not A and not B`: one disjunct; forbid carries A|B = 0b11.
        let cfg =
            dsl("rule r:\n  notify write file \"/sink\" if not A and not B\n  because \"z\"\n");
        assert_eq!(cfg.n_rules, 1, "`and` joins, not splits: one disjunct");
        assert_eq!(
            cfg.rules[0].req, 0,
            "no positive requirement in this clause"
        );
        assert_eq!(
            cfg.rules[0].forbid, 0b11,
            "`not A and not B` -> forbid carries both bits"
        );
        // The two mask fields of a single rule stay disjoint.
        for r in &cfg.rules[..1] {
            assert_eq!(
                r.req & r.forbid,
                0,
                "a rule cannot require and forbid one bit"
            );
        }
    }

    #[test]
    fn a_trailing_dot_dotted_prefix_lowers_to_a_subnet_mask() {
        // An IPv4 endpoint written as a dotted prefix (trailing dot, no CIDR
        // slash) matches an entire subnet: `10.0.0.` is /24, `10.0.` is /16,
        // `10.` is /8. `lower_numeric_ipv4` packs octet k at bit 8*k, so the
        // leading octet lands in the low byte and the mask sets the
        // corresponding low groups. The base endpoint tests pin only the
        // exact-host /32 form; this pins the dotted-prefix subnet form.
        // /24: `10.0.0.` -> net 10 (low byte), mask 0x00FFFFFF
        assert_eq!(lower_ipv4("10.0.0."), (10, 0x00FFFFFF));
        // /16: `10.0.` -> net 10, mask 0x0000FFFF
        assert_eq!(lower_ipv4("10.0."), (10, 0x0000FFFF));
        // /8: `10.` -> net 10, mask 0x000000FF
        assert_eq!(lower_ipv4("10."), (10, 0x000000FF));
        // Control: an exact host has all four octets set -> /32.
        assert_eq!(lower_ipv4("10.1.2.3"), (0x0302010A, 0xFFFFFFFF));
    }

    #[test]
    fn a_duplicate_rule_name_is_rejected() {
        // Two `rule` declarations sharing a name are rejected at parse time.
        // The name keys the corrective-feedback reason lookup: `Compiled.meta`
        // and `reasons` are indexed per lowered rule, and the name is what a
        // report uses to address a rule's reason. A regression that dropped
        // the duplicate guard would let two rules shadow one another and the
        // name-based feedback would resolve to the wrong (or first) rule.
        use crate::dsl::parse::parse;
        let err = parse(
            "rule r:\n  notify exec \"a\" because \"z\"\n\
             rule r:\n  notify exec \"b\" because \"z\"\n",
        )
        .expect_err("two rules sharing a name must be rejected");
        assert_eq!(err, "duplicate rule name `r`");

        // Positive control: distinct names parse into two rules and compile.
        let pol = parse(
            "rule a:\n  notify exec \"a\" because \"z\"\n\
                   rule b:\n  notify exec \"b\" because \"z\"\n",
        )
        .expect("two distinct rule names parse");
        assert_eq!(pol.rules.len(), 2);
        let _ = compile(&pol).expect("distinct-name policy compiles");
    }

    /// `lower_effect` copies the `Effect` verb into the `CRule.effect` byte, the
    /// exact kernel ABI `enum taint_effect` in `bpf/taint.h` (NOTIFY=0,
    /// BLOCK=1, KILL=2). The kernel decides corrective-feedback severity from
    /// this byte, so a renumbering drift in `lower.rs` (say, BLOCK/NOTIFY
    /// swapped) silently turns a hard deny into a no-op report -- or a report
    /// into a SIGKILL -- with no blob-size symptom. No test read this byte.
    ///
    /// Each rule is located by its target literal (order-independent via
    /// `pat_eq`), not by index, so the pin holds even if clause lowering order
    /// changes.
    #[test]
    fn rule_effect_bytes_match_the_kernel_abi() {
        let pol = crate::dsl::parse::parse(
            r#"
            source AGENT = exec "**/codex"
            rule n:
              notify write file "/a" if AGENT
              because "n"
            rule b:
              block write file "/b" if AGENT
              because "b"
            rule k:
              kill write file "/c" if AGENT
              because "k"
            "#,
        )
        .expect("parse effect policy");
        let cfg: CConfig = unsafe {
            std::ptr::read_unaligned(
                compile(&pol).expect("compile effect policy").bytes.as_ptr() as *const CConfig
            )
        };
        assert_eq!(cfg.n_rules, 3, "one lowered rule per clause");

        fn effect_for(cfg: &CConfig, target: &str) -> u8 {
            for r in &cfg.rules[..cfg.n_rules as usize] {
                if r.op == OP_WRITE && pat_eq(&r.target, target) {
                    return r.effect;
                }
            }
            panic!("no write rule for target {target}");
        }
        assert_eq!(
            effect_for(&cfg, "/a"),
            EFFECT_NOTIFY,
            "`notify` must lower to TEFFECT_NOTIFY"
        );
        assert_eq!(
            effect_for(&cfg, "/b"),
            EFFECT_BLOCK,
            "`block` must lower to TEFFECT_BLOCK"
        );
        assert_eq!(
            effect_for(&cfg, "/c"),
            EFFECT_KILL,
            "`kill` must lower to TEFFECT_KILL"
        );
    }

    #[test]
    fn a_clause_effect_lowers_to_its_kernel_effect_byte() {
        // `lower_effect` maps the three `Effect` variants to the kernel
        // effect bytes `EFFECT_NOTIFY`/`BLOCK`/`KILL` (0/1/2), the values the
        // engine stores in each matched rule's effect field. The base tests
        // only observe effects through full `compile` metadata; this pins the
        // mapping directly.
        assert_eq!(lower_effect(Effect::Notify), EFFECT_NOTIFY);
        assert_eq!(lower_effect(Effect::Block), EFFECT_BLOCK);
        assert_eq!(lower_effect(Effect::Kill), EFFECT_KILL);
        // The three bytes are distinct.
        let mut bytes = vec![
            lower_effect(Effect::Notify),
            lower_effect(Effect::Block),
            lower_effect(Effect::Kill),
        ];
        bytes.dedup();
        assert_eq!(bytes.len(), 3);
    }

    #[test]
    fn an_invalid_declassify_gate_syntax_is_rejected() {
        // `declassify`/`endorse` xforms have the fixed shape
        // `<verb> <label> by exec "<gate>"`. Two keyword positions are
        // matched literally by `P::eat`: the `by` between the label and the
        // op, and `exec` (the only valid invalidator op) after `by`. A
        // wrong word in either position must reject at parse time.
        use crate::dsl::parse::parse;
        fn err(src: &str) -> String {
            parse(src)
                .map(|_| "OK".to_string())
                .unwrap_or_else(|e| format!("Err({e})"))
        }
        // The `by` keyword position: `with` is not a recognized connector.
        assert_eq!(
            err("declassify A with exec \"/gate\"\n"),
            "Err(expected 'by', got Some(Word(\"with\")))"
        );
        // The op position: only `exec` may gate a `declassify`/`endorse`.
        assert_eq!(
            err("declassify A by read \"/gate\"\n"),
            "Err(expected 'exec', got Some(Word(\"read\")))"
        );
        // Positive control: the fixed `... by exec "..."` shape compiles.
        compile(&parse("declassify A by exec \"/gate\"\n").expect("a valid declassify parses"))
            .expect("a valid declassify compiles");
        compile(&parse("endorse B by exec \"/gate\"\n").expect("a valid endorse parses"))
            .expect("a valid endorse compiles");
    }

    #[test]
    fn endpoint_patterns_route_between_dns_and_numeric() {
        // Endpoint source patterns are routed before they are resolved:
        // looks_like_ipv4_prefix decides whether the pattern is treated as a
        // numeric prefix (and lowered to a net/mask), and hostname_candidate
        // decides which remaining patterns are sent to compile-time DNS
        // resolution. The two are the complementary halves of the routing,
        // so a regression in either one silently re-routes every endpoint
        // source.

        // looks_like_ipv4_prefix is purely syntactic (all-digit dotted body),
        // so it does NOT range-check: 999.999.999.999 and the 5-token form both
        // route as prefixes, and any later value check happens in
        // lower_numeric_ipv4, not here.
        assert!(looks_like_ipv4_prefix("10.0.0."));
        assert!(looks_like_ipv4_prefix("192.168.1"));
        assert!(looks_like_ipv4_prefix("1.2.3.4"));
        assert!(looks_like_ipv4_prefix("999.999.999.999"));
        assert!(looks_like_ipv4_prefix("1.2.3.4.5"));
        assert!(looks_like_ipv4_prefix("*"));
        // A CIDR suffix breaks the all-digit body, so it is NOT a prefix.
        assert!(!looks_like_ipv4_prefix("10.0.0.0/8"));
        // Non-numeric and empty-dot bodies are not prefixes.
        assert!(!looks_like_ipv4_prefix("abc"));
        assert!(!looks_like_ipv4_prefix("1..0"));

        // hostname_candidate: good hostnames are resolved, with a trailing dot
        // trimmed. The allowed charset is alnum plus . - _ .
        assert_eq!(hostname_candidate("api.internal."), Some("api.internal"));
        assert_eq!(hostname_candidate("my_host-1"), Some("my_host-1"));
        // Numeric forms are routed to the mask path, so they are NOT hostnames.
        assert_eq!(hostname_candidate("10.0.0.5"), None);
        assert_eq!(hostname_candidate("10.0.0."), None);
        // CIDR, colon, and path forms are rejected; so are wildcard and any
        // byte outside the allowed charset.
        assert_eq!(hostname_candidate("10.0.0.0/8"), None);
        assert_eq!(hostname_candidate("api:8080"), None);
        assert_eq!(hostname_candidate("my/host"), None);
        assert_eq!(hostname_candidate("bad#host"), None);
        assert_eq!(hostname_candidate("a b"), None);
    }

    #[test]
    fn a_bare_star_endpoint_lowers_to_match_any() {
        // A bare `*` endpoint pattern matches any address. `lower_numeric_ipv4`
        // lowers it to the match-any sentinel (net 0, mask 0) so the kernel
        // matcher accepts every endpoint. This is distinct from the exact-host
        // /32 and dotted-subnet forms the endpoint tests already pin.
        assert_eq!(lower_ipv4("*"), (0, 0));
        // Control: an exact host is a /32 match.
        assert_eq!(lower_ipv4("10.0.0.1"), (0x0100000A, 0xFFFFFFFF));
        // A non-numeric, non-`*` pattern (`**`) falls through to the
        // catch-all non-match (net 0, mask /32).
        assert_eq!(lower_ipv4("**"), (0, 0xFFFFFFFF));
    }

    /// A dotted-prefix endpoint (trailing dot, e.g. `"10.0.0."`) lowers to a
    /// *partial* IPv4 mask, not a full-IP `/32`. The kernel matches connect/recv
    /// targets and `unless target` conditions by `(ip & mask) == net`
    /// (`taint_mask_ok` in `bpf/taint.h`; the connect condition branch in
    /// `te_cond_satisfied`, `bpf/taint_engine.bpf.h`), so a lowerer that silently
    /// widens a `/24` target to `/32` (or drops the trailing-dot rule) changes
    /// exactly which hosts match -- a byte-diff that no blob-size check sees.
    /// The net/mask bytes are anchored on the documented contract
    /// (`"10.0.0."` -> /24, `"172.16."` -> /16, lower.rs and
    /// `docs/rule-language.md:113`), which is a host-independent `<< (8*k)`
    /// shift of each dotted octet -- so hardcoding them here is non-circular
    /// and would catch a regression in the mask-width rule.
    #[test]
    fn prefix_endpoint_lowers_to_a_partial_ipv4_mask() {
        let pol = crate::dsl::parse::parse(
            r#"
            rule egress-24:
              block connect endpoint "10.0.0." if true unless target "172.16."
              because "no egress into 10/24 or 172.16/16"
            "#,
        )
        .expect("parse prefix-egress policy");
        let compiled = compile(&pol).expect("compile prefix-egress policy");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(cfg.n_rules, 1, "a single numeric target lowers to one rule");
        let cr = &cfg.rules[0];
        assert_eq!(cr.op, OP_CONNECT);
        assert_eq!(
            cr.cond_kind, C_TARGET,
            "`unless target` must set TCOND_TARGET"
        );
        assert_eq!(cr.cond_neg, 0, "a plain `unless target` is not negated");

        // Target "10.0.0." is a /24: 3 dotted octets -> 24-bit mask.
        // net = 10, mask = 0x00ffffff.
        assert_eq!(
            cr.ipv4, 0x0000_000a,
            "a dotted prefix keeps the network base as the net field"
        );
        assert_eq!(
            cr.ipv4_mask, 0x00ff_ffff,
            "three dotted octets must give a 24-bit (/24) mask, not 0xffffffff"
        );

        // Condition "172.16." is a /16: 2 dotted octets -> 16-bit mask.
        // net = 172 | (16<<8) = 0x000010ac, mask = 0x0000ffff.
        assert_eq!(
            cr.cond_ipv4, 0x0000_10ac,
            "the condition prefix keeps its own network base in cond_ipv4"
        );
        assert_eq!(
            cr.cond_ipv4_mask, 0x0000_ffff,
            "two dotted octets must give a 16-bit (/16) mask, not 0xffffffff"
        );
        // The target and condition masks have *different widths* (24 vs 16 bits),
        // so a swap between the target and condition endpoint fields is observable.
        assert_ne!(
            cr.ipv4_mask, cr.cond_ipv4_mask,
            "the target and condition prefixes have different widths"
        );
    }

    /// The mask width is set *only* by the number of dotted octets: the trailing
    /// dot is the separator, not a data octet. This pins the contrast between a
    /// `/24` prefix (`"10.0.0."`), a full host (`"10.0.0.0"`, `/32`), and the
    /// match-any wildcard (`"*"` -> `0/0`). All three share no DNS lookup.
    #[test]
    fn endpoint_mask_width_depends_on_dotted_octet_count() {
        // "/24" vs "/32": same network base, different mask width.
        let c24: CConfig = unsafe {
            let p = crate::dsl::parse::parse(
                r#"
                    rule t24:
                      block connect endpoint "10.0.0." if true
                      because "a /24 net"
                    "#,
            )
            .expect("parse /24 policy");
            std::ptr::read_unaligned(compile(&p).expect("ok").bytes.as_ptr() as *const CConfig)
        };
        let c32: CConfig = unsafe {
            let p = crate::dsl::parse::parse(
                r#"
                    rule t32:
                      block connect endpoint "10.0.0.0" if true
                      because "a single host"
                    "#,
            )
            .expect("parse /32 policy");
            std::ptr::read_unaligned(compile(&p).expect("ok").bytes.as_ptr() as *const CConfig)
        };
        assert_eq!(
            c24.rules[0].ipv4, c32.rules[0].ipv4,
            "the same dotted network base yields the same net field"
        );
        assert_eq!(
            c24.rules[0].ipv4_mask, 0x00ff_ffff,
            "trailing dot -> /24 mask"
        );
        assert_eq!(
            c32.rules[0].ipv4_mask, 0xffff_ffff,
            "a fully-dotted address is a /32 (single host)"
        );

        // Match-any: "*" lowers to net 0, mask 0 (match any endpoint).
        let cstar: CConfig = unsafe {
            let p = crate::dsl::parse::parse(
                r#"
                    rule tany:
                      block connect endpoint "*" if true
                      because "any endpoint"
                    "#,
            )
            .expect("parse wildcard policy");
            std::ptr::read_unaligned(compile(&p).expect("ok").bytes.as_ptr() as *const CConfig)
        };
        assert_eq!(cstar.rules[0].ipv4, 0);
        assert_eq!(
            cstar.rules[0].ipv4_mask, 0,
            "`*` must be the match-any (0,0) pair, not a zero net with a /32 mask"
        );
    }

    #[test]
    fn endpoint_sources_emit_their_update_matcher_bytes() {
        // An `endpoint` source lowers to one connect and one recv update.
        // The kernel matches network edges against the numeric `ipv4` /
        // `ipv4_mask` byte pair (`ts_endp`), not a target string, so the
        // matcher region of each update is inert: `m = M_ANY`, empty
        // `target`, empty `arg`. #78 pinned the `ipv4` / `ipv4_mask`
        // resolution and the base test pinned the connect/recv `op` split,
        // but nobody pinned the `m` / `target` / `arg` region -- a
        // regression that stamped a target literal (or a non-M_ANY `m`)
        // onto the network-edge update would go uncaught here.
        fn cstr<const N: usize>(p: &[u8; N]) -> String {
            let end = p.iter().position(|b| *b == 0).unwrap_or(N);
            String::from_utf8_lossy(&p[..end]).into_owned()
        }
        let pol = crate::dsl::parse::parse(r#"source NET = endpoint "8.8.8.8""#)
            .expect("parse endpoint source");
        let compiled = compile(&pol).expect("compile endpoint source");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(cfg.n_updates, 2, "one connect + one recv update");
        let (ipv4, mask) = lower_ipv4("8.8.8.8");
        for u in &cfg.updates[..cfg.n_updates as usize] {
            match u.op {
                OP_CONNECT | OP_RECV => {}
                other => panic!("endpoint source update op {} not a network op", other),
            }
            assert_eq!(u.m, M_ANY, "network-edge update matches by ip, not target");
            assert_eq!(
                cstr(&u.target),
                "",
                "no target literal rides a network-edge update"
            );
            assert_eq!(cstr(&u.arg), "", "no arg rides a network-edge update");
            assert_eq!(u.ipv4, ipv4, "numeric endpoint lands in ipv4");
            assert_eq!(u.ipv4_mask, mask, "endpoint mask lands in ipv4_mask");
            assert_eq!(u.add, 1u64, "the source grants NET's label bit");
        }
    }

    #[test]
    fn a_nested_exec_path_lowers_to_its_basename_not_the_full_path() {
        // `lower_exec` matches on `comm` (the basename), so any nested path
        // -- relative or absolute -- is lowered through the `rsplit('/')`
        // basename arm (lower.rs:102) rather than kept as a full path. A
        // trailing star on the basename becomes a prefix on the stripped
        // name. No base test pins these multi-segment lowerings; the base
        // tests only cover single-component names.
        assert_eq!(lower_exec("bin/git"), (M_EXACT, "git".into()));
        assert_eq!(lower_exec("/usr/local/bin/ls"), (M_EXACT, "ls".into()));
        // A star on the basename lowers to a prefix on the stripped name.
        assert_eq!(lower_exec("bin/node*"), (M_PREFIX, "node".into()));
    }

    #[test]
    fn exec_patterns_lower_to_comm_basename() {
        // The kernel exec hook matches `comm` (process basename, <= 15 bytes),
        // never the full path. So `exec "/usr/bin/git"` and `exec "git"` must
        // lower to the same (match, literal). lower_exec canonicalizes by
        // taking the last '/'-segment.
        assert_eq!(lower_exec("git"), (M_EXACT, "git".into()));
        assert_eq!(
            lower_exec("/usr/bin/git"),
            lower_exec("git"),
            "full-path and bare-name exec patterns must canonicalize to the same comm match"
        );
        assert_eq!(lower_exec("/bin/echo"), (M_EXACT, "echo".into()));

        // A trailing '*' becomes a comm prefix match (e.g. `python*`), not an
        // exact match: the base is `python` and the `*` is stripped.
        assert_eq!(lower_exec("python*"), (M_PREFIX, "python".into()));
        assert_eq!(lower_exec("/usr/local/bin/pip*"), (M_PREFIX, "pip".into()));
    }

    #[test]
    fn a_star_suffixed_exec_pattern_lowers_to_a_prefix_match() {
        // An exec pattern with a `*` suffix matches any comm beginning with
        // the prefix. `lower_exec` strips the glob suffix and drops any path
        // prefix, so the kernel match is a prefix match on the basename: the
        // distinct case from the exact-basename `M_EXACT` lowering (which
        // drops no wildcard) and the full-wildcard `M_ANY` lowering.
        assert_eq!(lower_exec("git*"), (M_PREFIX, "git".into()));
        assert_eq!(lower_exec("/usr/bin/git*"), (M_PREFIX, "git".into()));
        assert_eq!(lower_exec("**/git*"), (M_PREFIX, "git".into()));
        // Control: no wildcard suffix -> exact match on the basename.
        assert_eq!(lower_exec("git"), (M_EXACT, "git".into()));
    }

    #[test]
    fn a_leading_wildcard_in_an_exec_pattern_is_preserved() {
        // `lower_exec` strips only a trailing `*` (turning the match into
        // `M_PREFIX`); a leading `*` is part of the basename and survives in
        // the literal, so `*git*` lowers to a prefix match on `*git`, not on
        // `git`. This is the case the `git*` trailing-wildcard test leaves
        // unpinned.
        // Trailing `*` stripped; leading `*` preserved in the prefix literal.
        assert_eq!(lower_exec("*git*"), (M_PREFIX, "*git".into()));
        // No trailing `*`: the leading `*` makes the whole literal exact.
        assert_eq!(lower_exec("*git"), (M_EXACT, "*git".into()));
        // A path prefix is still dropped regardless of the leading wildcard.
        assert_eq!(lower_exec("/bin/ls*"), (M_PREFIX, "ls".into()));
    }

    #[test]
    fn a_trailing_star_exec_pattern_keeps_the_prefix_up_to_the_star() {
        // `lower_exec` only treats a trailing `*` as a prefix match:
        // `base.strip_suffix('*')` yields the `M_PREFIX` literal. The literal
        // keeps every character before the star, including a dash, so a
        // hyphenated pattern lowers to a prefix on the whole `name-`
        // substring, not just the bare token. No base test pins a
        // trailing-star pattern with a trailing dash.
        assert_eq!(lower_exec("git-*"), (M_PREFIX, "git-".into()));
        assert_eq!(lower_exec("node-*"), (M_PREFIX, "node-".into()));
        // Control: a star directly on the token strips to the bare name.
        assert_eq!(lower_exec("git*"), (M_PREFIX, "git".into()));
    }

    #[test]
    fn an_exits_code_outside_the_u8_range_is_rejected() {
        // `exits N` carries the gate's exit-status match into the `u8`
        // `gate_exit_code` ABI byte. The parse layer validates `N` with
        // `N.parse::<u8>()`, so out-of-range or non-numeric literals are
        // rejected at parse time with the exact message
        // "expected exit code 0..255, got '{N}'". #57 pinned the valid
        // bytes (0 and 2) and #98 pinned the no-exits default (-1 /
        // GATE_IMMEDIATE); nobody pinned the *range* guard -- a regression
        // that silently wrapped a 9-bit literal into the byte would
        // mis-match the kernel's exit-status comparison.
        use crate::dsl::parse::parse;
        fn gate(src: &str) -> Result<String, String> {
            match parse(src) {
                Ok(_) => Ok(String::new()),
                Err(e) => Err(e),
            }
        }
        // Upper bound: 256 does not fit a u8.
        let err = gate(
            "rule r:\n  block exec \"git\" unless after exec \"/in\" exits 256\n  because \"z\"\n",
        )
        .expect_err("256 must be rejected");
        assert_eq!(err, "expected exit code 0..255, got '256'");
        // A clearly-out-of-range literal.
        let err = gate(
            "rule r:\n  block exec \"git\" unless after exec \"/in\" exits 300\n  because \"z\"\n",
        )
        .expect_err("300 must be rejected");
        assert_eq!(err, "expected exit code 0..255, got '300'");
        // A non-numeric literal.
        let err = gate(
            "rule r:\n  block exec \"git\" unless after exec \"/in\" exits abc\n  because \"z\"\n",
        )
        .expect_err("abc must be rejected");
        assert_eq!(err, "expected exit code 0..255, got 'abc'");
        // A negative literal (the lexer still tokenizes it as a word).
        let err = gate(
            "rule r:\n  block exec \"git\" unless after exec \"/in\" exits -1\n  because \"z\"\n",
        )
        .expect_err("-1 must be rejected");
        assert_eq!(err, "expected exit code 0..255, got '-1'");

        // Positive controls: the two inclusive bounds parse.
        let _ = gate(
            "rule r:\n  block exec \"git\" unless after exec \"/in\" exits 0\n  because \"z\"\n",
        )
        .expect("exits 0 parses");
        let _ = gate(
            "rule r:\n  block exec \"git\" unless after exec \"/in\" exits 255\n  because \"z\"\n",
        )
        .expect("exits 255 parses");
    }

    #[test]
    fn an_exits_clause_on_a_non_exec_gate_is_rejected() {
        // The `exits <code>` suffix is only meaningful on an `after exec`
        // gate: the engine records the child's exit code, but only an
        // exec'd process has one. The parser rejects `exits` on any other
        // gate op at parse time (distinct from the exit-code range guard,
        // which still applies once the gate is `exec`).
        use crate::dsl::parse::parse;
        fn err(src: &str) -> String {
            parse(src)
                .map(|_| "OK".to_string())
                .unwrap_or_else(|e| format!("Err({e})"))
        }
        // `read` is not a valid `exits` gate op.
        assert_eq!(
            err("rule r:\n  block exec \"git\" unless after read \"/x\" exits 1\n"),
            "Err(`exits` is only valid on `after exec` gates)"
        );
        // `write` is likewise not a valid `exits` gate op.
        assert_eq!(
            err("rule r:\n  block exec \"git\" unless after write \"/x\" exits 1\n"),
            "Err(`exits` is only valid on `after exec` gates)"
        );
        // Positive control: `exits` on an `after exec` gate parses.
        compile(
            &parse("rule r:\n  block exec \"git\" unless after exec \"/in\" exits 0\n")
                .expect("an after exec exits gate parses"),
        )
        .expect("an after exec exits gate compiles");
    }

    #[test]
    fn a_nonexec_gate_rejects_an_exits_clause() {
        // `exits N` stamps a gate with the exit code `N`, and the engine only
        // ever matches an exit status in the process-exit path
        // (`te_exit_status_matches` on `raw_status`, gated on the exec event
        // class). An `after open ... exits N` / `after write ... exits N`
        // gate could never match an exit status, so the parser rejects it
        // up front rather than compiling a silent no-op gate. This is the
        // mirror of #57's "gate carries the exit-code byte" surface: here the
        // byte is refused because the gate op is not exec.
        use crate::dsl::parse::parse;
        // Every gate op except exec must refuse the `exits` clause.
        for gate in ["read", "open", "write", "unlink", "connect", "recv"] {
            let pol = parse(&format!(
                "rule r:\n  block exec \"git\" unless after {gate} \"/pytest\" exits 0\n  because \"z\"\n"
            ));
            let err = pol.expect_err("a non-exec gate must reject `exits`");
            assert_eq!(
                err, "`exits` is only valid on `after exec` gates",
                "`after {gate} ... exits 0` must be rejected"
            );
        }
        // exec is the only gate op allowed to carry `exits`: the same rule
        // with an exec gate compiles cleanly.
        let pol = parse(
            "rule r:\n  block exec \"git\" unless after exec \"/pytest\" exits 0\n  because \"z\"\n",
        )
        .expect("an exec gate may carry `exits`");
        let _ = compile(&pol).expect("a valid exec-gate policy compiles");
    }

    #[test]
    fn a_non_word_identifier_is_rejected() {
        // Identifier positions (a source's label, a rule's name) must be
        // bare words; a quoted string or any other non-word token there is
        // a common authoring mistake that must reject at parse time. This
        // pins the `P::word()` guard (`expected word, got {tok}`),
        // distinct from the `expected string` pattern guard (#118) and the
        // `expected ':'`/`'='` guards (#109, #110).
        use crate::dsl::parse::parse;
        fn err(src: &str) -> String {
            parse(src)
                .map(|_| "OK".to_string())
                .unwrap_or_else(|e| format!("Err({e})"))
        }
        // A source label given as a quoted string.
        assert_eq!(
            err("source \"A\" = exec \"/x\"\n"),
            "Err(expected word, got Some(Str(\"A\")))"
        );
        // A rule name given as a quoted string.
        assert_eq!(
            err("rule \"r\":\n  block exec \"git\" because \"z\"\n"),
            "Err(expected word, got Some(Str(\"r\")))"
        );
        // Positive control: a well-formed source + rule parse and compile.
        let pol = parse("source A = exec \"/x\"\nrule r:\n  block exec \"git\" because \"z\"\n")
            .expect("a well-formed source and rule parse");
        compile(&pol).expect("a well-formed source and rule compile");
    }

    #[test]
    fn collect_expr_labels_walks_the_expression_tree_into_a_deduped_set() {
        // `collect_expr_labels` gathers every `Label`/`Not` name reachable in
        // an `Expr`, recursing through `And`/`Or`, ignoring `True`, and
        // deduplicating through the caller's set. No base test pins the
        // collector's arms directly; it is only exercised through
        // `collect_label_names`.
        use std::collections::BTreeSet;

        // A leaf `Label` and a leaf `Not` each contribute their name.
        let mut leaf: BTreeSet<String> = BTreeSet::new();
        collect_expr_labels(&Expr::Label("A".to_string()), &mut leaf);
        assert_eq!(leaf.iter().collect::<Vec<_>>(), &["A"]);
        let mut neg: BTreeSet<String> = BTreeSet::new();
        collect_expr_labels(&Expr::Not("B".to_string()), &mut neg);
        assert_eq!(neg.iter().collect::<Vec<_>>(), &["B"]);

        // `True` contributes no labels.
        let mut t: BTreeSet<String> = BTreeSet::new();
        collect_expr_labels(&Expr::True, &mut t);
        assert!(t.is_empty());

        // `And`/`Or` recurse into both branches.
        let tree = Expr::And(
            Box::new(Expr::Label("A".to_string())),
            Box::new(Expr::Or(
                Box::new(Expr::Label("B".to_string())),
                Box::new(Expr::Not("C".to_string())),
            )),
        );
        let mut reached: BTreeSet<String> = BTreeSet::new();
        collect_expr_labels(&tree, &mut reached);
        assert_eq!(reached.iter().collect::<Vec<_>>(), &["A", "B", "C"]);

        // The same name reached through several paths is recorded once.
        let dup = Expr::And(
            Box::new(Expr::Label("X".to_string())),
            Box::new(Expr::Or(
                Box::new(Expr::Label("X".to_string())),
                Box::new(Expr::Not("X".to_string())),
            )),
        );
        let mut deduped: BTreeSet<String> = BTreeSet::new();
        collect_expr_labels(&dup, &mut deduped);
        assert_eq!(deduped.iter().collect::<Vec<_>>(), &["X"]);

        // The collector fills a `BTreeSet`, so iteration is lexicographic even
        // when the tree lists the labels out of order.
        let out_of_order = Expr::Or(
            Box::new(Expr::Label("b".to_string())),
            Box::new(Expr::Or(
                Box::new(Expr::Label("c".to_string())),
                Box::new(Expr::Label("a".to_string())),
            )),
        );
        let mut sorted: BTreeSet<String> = BTreeSet::new();
        collect_expr_labels(&out_of_order, &mut sorted);
        assert_eq!(sorted.iter().collect::<Vec<_>>(), &["a", "b", "c"]);
    }

    #[test]
    fn op_name_and_kernel_op_name_pin_the_feedback_verbs() {
        // op_name maps each of the 7 DSL ops to the verb used in the corrective
        // feedback payload. Read and Open both lower to the same OP_OPEN kernel
        // byte (lower.rs:712-714), but the DSL side keeps distinct verbs, so a
        // regression that collapsed them in op_name would corrupt the feedback
        // text even though the engine behavior is unchanged.
        assert_eq!(op_name(Op::Exec), "exec");
        assert_eq!(op_name(Op::Read), "read");
        assert_eq!(op_name(Op::Open), "open");
        assert_eq!(op_name(Op::Write), "write");
        assert_eq!(op_name(Op::Unlink), "unlink");
        assert_eq!(op_name(Op::Connect), "connect");
        assert_eq!(op_name(Op::Recv), "recv");

        // kernel_op_name is the reverse mapping, kernel op byte -> verb, used
        // when a violation is reported back to the agent. It is deliberately
        // narrower than op_name because the kernel only stamps 5 bytes: read and
        // open share OP_OPEN (reported as "read") and write and unlink share
        // OP_WRITE (reported as "write"). An out-of-range byte falls back to the
        // generic "op" so a malformed report never surfaces a bogus verb.
        assert_eq!(kernel_op_name(OP_EXEC), "exec");
        assert_eq!(kernel_op_name(OP_OPEN), "read");
        assert_eq!(kernel_op_name(OP_WRITE), "write");
        assert_eq!(kernel_op_name(OP_CONNECT), "connect");
        assert_eq!(kernel_op_name(OP_RECV), "recv");
        assert_eq!(kernel_op_name(0xFF), "op");
    }

    #[test]
    fn after_gates_stamp_the_path_op_bytes() {
        // A `after <op>` gate arms a rule on that event class, so the gate
        // update must carry the kernel taint_op of the gating event. gate_bit
        // (lower.rs) consolidates the four path ops to two kernel op bytes:
        // `read` and `open` both arm on an open/read edge (OP_OPEN), `write`
        // and `unlink` both arm on a mutating edge (OP_WRITE). A wrong byte
        // would arm the rule on the wrong syscall class with no compile-time
        // or blob-size symptom. #57 pins the `after exec` gate row (OP_EXEC);
        // #82 pins the connect/recv gate reject; these accept bytes are not
        // pinned.
        let cases = [
            ("read", OP_OPEN),
            ("open", OP_OPEN),
            ("write", OP_WRITE),
            ("unlink", OP_WRITE),
        ];
        for (op_word, want_op) in cases {
            let pol = crate::dsl::parse::parse(&format!(
                "rule r:\n\
                 notify write file \"/sink\" unless after {op_word} \"/cfg\"\n\
                 because \"re-arm the guard when the file is touched\"\n",
            ))
            .expect("parse after gate rule");
            let compiled = compile(&pol).expect("compile after gate rule");
            let cfg: CConfig =
                unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
            assert_eq!(cfg.n_updates, 1, "a single gate update");
            assert_eq!(cfg.n_rules, 1, "one rule");
            // The gate update carries a non-zero `gates` bit; it is never an
            // invalidator (no `invals`) and arms the rule via `rule.gates`.
            let gate = cfg.updates[0];
            assert_eq!(gate.gates, 1u64, "single gate => bit 1<<0");
            assert_eq!(gate.invals, 0, "gate carries no inval bits");
            assert_eq!(
                gate.op, want_op,
                "after {op_word} must stamp taint_op byte {want_op}"
            );
            assert_eq!(gate.m, M_EXACT, "`/cfg` -> exact path");
            assert_eq!(&gate.target[..4], b"/cfg", "gate target literal is `/cfg`");
            assert_eq!(
                gate.gate_exit_code, GATE_IMMEDIATE,
                "a no-`exits` gate arms on any exit status"
            );
            // Cross-table: the rule references exactly the gate it allocated.
            assert_eq!(cfg.rules[0].gate, 1u64, "rule arms on gate slot 0");
            assert_eq!(cfg.rules[0].gate_idx, 0, "single gate lands in slot 0");
        }
    }

    /// Two clauses that share the *same* gate (`unless after exec "**/pytest"
    /// exits 0`) must dedupe to a single gate slot, and every rule that
    /// references the gate must carry the matching `gate` bit and `gate_idx`.
    /// The engine latches a gate by OR-ing its `gates` bit into the process
    /// lineage mask (`ns.lin_gates |= c.gates`, taint_engine.bpf.h:1611) and,
    /// for v2 staleness, looks the gate up by `gate_idx` (`te_after_satisfied`,
    /// taint_engine.bpf.h:1259) -- so a shifted bit, a wrong index, or a
    /// hardcoded exit code would silently break gate freshness with no
    /// compile-time or blob-size symptom. Pin the cross-table coherence.
    #[test]
    fn gate_bits_dedupe_and_stay_coherent_with_rules() {
        // One policy, three clauses: two share gate `exits 0`, one uses the
        // distinct gate `exits 2`. Both clauses must be covered by the gate
        // dedupe, and the distinct gate must land in the *next* slot.
        let cfg = compile_cfg(
            "rule r:\n\
             block exec \"git\" unless after exec \"**/pytest\" exits 0\n\
             block exec \"make\" unless after exec \"**/pytest\" exits 0\n\
             notify exec \"git\" unless after exec \"**/pytest\" exits 2\n\
             because \"run tests before committing/pushing\"\n",
        );
        // Three clauses, no `when` labels => one DNF disjunct each => three rules.
        assert_eq!(cfg.n_rules, 3, "one rule per clause");
        // `exits 0` (clauses 0+1) dedupe to slot 0; `exits 2` (clause 2) is slot 1.
        assert_eq!(cfg.n_updates, 2, "two distinct gates => two updates");

        // Slot 0: the `exits 0` gate. `**/pytest` lowers to the exact comm matcher.
        let u0 = &cfg.updates[0];
        assert_eq!(u0.op, OP_EXEC, "gate is an exec event");
        assert_eq!(u0.m, M_EXACT, "`**/pytest` -> exact comm `pytest`");
        assert_eq!(
            &u0.target[..6],
            "pytest".as_bytes(),
            "gate target literal is `pytest`"
        );
        assert_eq!(u0.gates, 1u64, "slot 0 => bit 1<<0");
        assert_eq!(u0.gate_exit_code, 0, "`exits 0` carries code 0");

        // Slot 1: the `exits 2` gate.
        let u1 = &cfg.updates[1];
        assert_eq!(u1.target, u0.target, "same gate literal in slot 1");
        assert_eq!(u1.gates, 2u64, "slot 1 => bit 1<<1");
        assert_eq!(
            u1.gate_exit_code, 2,
            "`exits 2` carries code 2, not a hardcoded 0/-1"
        );

        // Every rule must agree with the slot it references: matching bit AND index.
        assert_eq!(cfg.rules[0].cond_kind, C_AFTER, "clause 0 -> TCOND_AFTER");
        assert_eq!(cfg.rules[0].gate, 1u64, "clause 0 references slot 0");
        assert_eq!(cfg.rules[0].gate_idx, 0, "clause 0 -> index 0");
        assert_eq!(cfg.rules[1].cond_kind, C_AFTER, "clause 1 -> TCOND_AFTER");
        assert_eq!(cfg.rules[1].gate, 1u64, "clause 1 reuses slot 0 (dedup)");
        assert_eq!(cfg.rules[1].gate_idx, 0, "clause 1 -> index 0");
        assert_eq!(cfg.rules[2].cond_kind, C_AFTER, "clause 2 -> TCOND_AFTER");
        assert_eq!(cfg.rules[2].gate, 2u64, "clause 2 references slot 1");
        assert_eq!(cfg.rules[2].gate_idx, 1, "clause 2 -> index 1");
    }

    /// The kernel inverts a `TCOND_TARGET` match only when `cond_neg` is set
    /// (`return r->cond_neg ? !m : m`, taint_engine.bpf.h:2102). A flipped
    /// negation silently inverts the whole allow/deny decision, so pin both
    /// directions of the `target`/`target not` forms.
    #[test]
    fn target_cond_negation_flips_cond_neg() {
        let cfg = compile_cfg(
            "rule r:\n\
             block write file \"/**\" unless target \"/work/**\"\n\
             because \"allow writes outside the agent workspace\"\n",
        );
        assert_eq!(cfg.n_rules, 1, "one rule");
        assert_eq!(
            cfg.rules[0].cond_kind, C_TARGET,
            "target cond lowers to TCOND_TARGET"
        );
        assert_eq!(cfg.rules[0].cond_neg, 0, "plain `target P` is not negated");

        let cfg2 = compile_cfg(
            "rule r:\n\
             block write file \"/**\" unless target not \"/work/**\"\n\
             because \"deny writes inside the agent workspace\"\n",
        );
        assert_eq!(
            cfg2.rules[0].cond_kind, C_TARGET,
            "target cond lowers to TCOND_TARGET"
        );
        assert_eq!(cfg2.rules[0].cond_neg, 1, "`target not P` sets cond_neg");
    }

    #[test]
    fn a_gate_without_an_exits_clause_defaults_to_gate_immediate() {
        // `gate_exit_code` is how the engine knows which exit code stamps a
        // gate. `TAINT_GATE_IMMEDIATE` (-1) means the gate latches on any
        // matching event with no exit-code check, while a concrete code
        // (0..255) makes the engine wait for that specific exit code via
        // `te_exit_status_matches`. The compiler's `gate_bit` helper sets
        // `gate_exit_code` from the optional `exits` clause; when the clause
        // is absent, the byte must default to GATE_IMMEDIATE. #57 pinned
        // the explicit-code cases (`exits 0`, `exits 2`), but the no-exits
        // default is load-bearing: a regression that zeroed the default
        // would silently turn "gate on any matching event" into "gate on
        // exit code 0", changing the gate's fire condition for every rule
        // that omits `exits`.
        fn gate_code(src: &str) -> i32 {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            let g: CConfig =
                unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
            g.updates[..g.n_updates as usize]
                .iter()
                .find(|u| u.gates != 0)
                .map(|u| u.gate_exit_code)
                .expect("a gate update is allocated")
        }

        // No `exits` clause: the gate update's exit code defaults to the
        // kernel's GATE_IMMEDIATE sentinel, not zero.
        assert_eq!(
            gate_code(
                "source S = file \"/**/.env\"\n\
                 rule r:\n\
                   block exec \"git\" if S unless after exec \"/pytest\"\n\
                   because \"test before commit\"\n"
            ),
            GATE_IMMEDIATE,
            "no `exits` clause defaults to GATE_IMMEDIATE (-1)"
        );

        // `exits 0` is a *specific* exit code, not the immediate sentinel:
        // it must differ from the default, so an "latch on any event" rule
        // and a "latch on exit 0" rule compile to different gate bytes.
        assert_eq!(
            gate_code(
                "source S = file \"/**/.env\"\n\
                 rule r:\n\
                   block exec \"git\" if S unless after exec \"/pytest\" exits 0\n\
                   because \"test before commit\"\n"
            ),
            0,
            "`exits 0` carries the concrete exit code 0"
        );

        // And a non-zero exit code passes through verbatim.
        assert_eq!(
            gate_code(
                "source S = file \"/**/.env\"\n\
                 rule r:\n\
                   block exec \"git\" if S unless after exec \"/pytest\" exits 42\n\
                   because \"test before commit\"\n"
            ),
            42,
            "`exits 42` carries the concrete exit code 42"
        );
    }

    #[test]
    fn gate_updates_carry_no_label_movement() {
        // A gate update latches only the gate bit on the matching event; it
        // must not grant or strip any label, so `add` and `del` stay zero.
        // The contrast that makes this load-bearing: a `file` source in the
        // same policy grants its own bit via `add` on the open event, so a
        // regression that OR'd a source/grant bit into the gate's `add` (or a
        // `del` into the gate) would silently move a label when the gate fires
        // -- an information-flow violation the kernel would propagate. #57
        // pinned the gate *bit* coherence (slot bits match rule references)
        // and #87 the inval arg byte, but neither pinned that the gate update
        // keeps its `add`/`del` regions empty.
        let pol = crate::dsl::parse::parse(
            "source S = file \"/**/.env\"\n\
             rule r:\n\
               block exec \"git\" if S unless after exec \"/pytest\" exits 0\n\
               because \"test before commit\"\n",
        )
        .expect("parse policy");
        let compiled = compile(&pol).expect("compile policy");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let sbit = compiled.labels.get("S").copied().expect("S label bit");

        // Locate the gate update (the one carrying a non-zero gate bit) and
        // the source update (the one that grants S).
        let updates = &cfg.updates[..cfg.n_updates as usize];
        let gate = updates
            .iter()
            .find(|u| u.gates != 0)
            .expect("a gate update is allocated");
        let source = updates
            .iter()
            .find(|u| u.add == sbit)
            .expect("the S source update is allocated");

        // The gate update latches its gate bit and carries no exit code beyond
        // the `exits 0` byte, but it must not move any label.
        assert_eq!(gate.op, OP_EXEC, "the gate is an exec event");
        assert_eq!(gate.gates, 1u64, "the gate is slot 0");
        assert_eq!(gate.gate_exit_code, 0, "`exits 0` carries code 0");
        assert_eq!(gate.add, 0, "a gate update must not grant a label");
        assert_eq!(gate.del, 0, "a gate update must not strip a label");
        assert_eq!(gate.invals, 0, "a gate update is not a since invalidator");

        // The source update is the control that proves the `add` direction is
        // specific to label-granting events: it grants S and strips nothing.
        assert_eq!(source.op, OP_OPEN, "a file source is an open event");
        assert_eq!(source.add, sbit, "the source grants its own bit");
        assert_eq!(source.del, 0, "a source never strips a label");
        assert_eq!(source.gates, 0, "a source update is not a gate");
    }

    #[test]
    fn connect_and_recv_are_not_valid_gates() {
        // A `after <op>` gate arms a rule on that event class, so the gate
        // update must carry the kernel taint_op of the gating event. The
        // engine can only arm a gate from exec/read/write events (see
        // gate_bit in lower.rs), so `connect` and `recv` are rejected at
        // compile time. The parse layer accepts any op word after `after`, so
        // the rejection only surfaces during lowering; pin it here so the
        // error string and op set stay honest. #57 pins the `after exec`
        // accept row; #73 pins the equivalent `since` invalidator reject.
        let base = |op: &str| {
            crate::dsl::parse::parse(&format!(
                r#"rule sink:
                  notify write file "/sink" unless after {op} "/cfg""#
            ))
            .expect("parse gate rule")
        };
        for bad in ["connect", "recv"] {
            let pol = base(bad);
            match compile(&pol) {
                Ok(_) => panic!("after {bad} should not compile as a gate"),
                Err(e) => assert!(
                    e.contains("not supported as a gate"),
                    "unexpected error for after {bad}: {e}"
                ),
            }
        }
        // Positive control: `after read` IS a valid gate, so the same shape
        // compiles cleanly. This proves the rejection is specific to
        // connect/recv rather than to the whole `after` construction.
        let pol = base("read");
        let compiled = compile(&pol).expect("after read is a valid gate");
        assert!(!compiled.bytes.is_empty());
    }

    /// The kernel blob is a fixed-size rodata region holding at most
    /// MAX_GATES (64) gate slots. A policy whose clauses reference more
    /// distinct `after` gates than the blob can hold must be rejected at
    /// compile time, not silently dropped. Each distinct gate pattern lowers
    /// to a distinct gate slot, so 65 distinct `after exec` gates make the
    /// 65th allocation trip the guard. No label is needed, so the 64-label
    /// cap is never reached first; 65 rules stays under MAX_RULES.
    #[test]
    fn gate_overflow_beyond_max_gates_is_rejected() {
        // MAX_GATES = 64. i in 0..=64 gives 65 distinct gate slots, so the
        // 65th gate_bit sees next_gate == 64 and trips the guard.
        let mut src = String::from("rule overflow:\n");
        for i in 0..=MAX_GATES {
            src.push_str(&format!(
                "  notify write file \"/o{i}\" unless after exec \"/g{i}\"\n"
            ));
        }
        src.push_str("  because \"overflow\"\n");
        match crate::dsl::parse::parse(&src).and_then(|p| compile(&p)) {
            Ok(_) => panic!("compile must fail past MAX_GATES"),
            Err(err) => {
                assert!(err.contains("too many gates"), "wrong error: {err}");
            }
        }
    }

    #[test]
    fn non_exec_gates_route_their_target_through_lower_path() {
        // #57 pins the *exec* gate: `after exec "**/pytest"` lowers the pattern
        // through `lower_exec` (comm basename -> exact `pytest`). A non-exec
        // gate (`after read` / `after write`) instead lowers its target through
        // `lower_path`, and stamps the file-side taint_op. Nobody pins that
        // routing. A regression that forced every gate through `lower_exec`, or
        // mis-mapped the gate op to the wrong taint_op, would silently change
        // both the op byte and the target literal the kernel matches to arm the
        // gate -- the gate would arm on the wrong event.
        fn find_gate(cfg: &CConfig) -> CUpdate {
            cfg.updates[..cfg.n_updates as usize]
                .iter()
                .find(|u| u.gates != 0 && u.invals == 0)
                .cloned()
                .expect("an after clause allocates a gate update")
        }
        fn config(src: &str) -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        }
        fn target_field(lit: &str) -> [u8; PAT] {
            let mut out = [0u8; PAT];
            let n = lit.len().min(PAT - 1);
            out[..n].copy_from_slice(&lit.as_bytes()[..n]);
            out
        }

        // `after read "/cfg"`: an absolute exact path. lower_path("/cfg") is
        // M_EXACT; the gate stamps OP_OPEN (read maps to the open op).
        let cfg = config(
            "rule r:\n\
             notify write file \"/sink\" unless after read \"/cfg\"\n\
             because \"guard the sink until the cfg is read\"\n",
        );
        assert_eq!(
            cfg.n_updates, 1,
            "a single after clause, no since => one gate update"
        );
        let gate = find_gate(&cfg);
        assert_eq!(gate.op, OP_OPEN, "a read gate stamps OP_OPEN");
        assert_eq!(gate.m, M_EXACT, "lower_path(\"/cfg\") -> M_EXACT");
        assert_eq!(
            gate.target,
            target_field("/cfg"),
            "the read gate's target literal is the lowered path"
        );
        assert_eq!(gate.gates, 1u64, "slot 0 => bit 1<<0");
        assert_eq!(
            gate.gate_exit_code, GATE_IMMEDIATE,
            "a non-exec gate carries no exit status"
        );
        // The rule references the same slot: matching bit AND index.
        assert_eq!(
            cfg.rules[0].cond_kind, C_AFTER,
            "an after clause -> C_AFTER"
        );
        assert_eq!(cfg.rules[0].gate, 1u64, "the rule references slot 0's bit");
        assert_eq!(
            cfg.rules[0].gate_idx, 0,
            "the rule references slot 0's index"
        );

        // `after write "src/**"`: a repo-relative directory glob. lower_path
        // gives M_CONTAINS "src/"; the gate stamps OP_WRITE.
        let cfg = config(
            "rule r:\n\
             notify write file \"/sink\" unless after write \"src/**\"\n\
             because \"guard the sink until a source file is written\"\n",
        );
        let gate = find_gate(&cfg);
        assert_eq!(gate.op, OP_WRITE, "a write gate stamps OP_WRITE");
        assert_eq!(
            gate.m, M_CONTAINS,
            "lower_path(\"src/**\") -> M_CONTAINS \"src/\""
        );
        assert_eq!(
            gate.target,
            target_field("src/"),
            "the write gate's contains literal"
        );

        // The load-bearing contrast: the same `**/x` shape under a read gate goes
        // through lower_path (M_SUFFIX "/cfg.dat"), whereas under an exec gate it
        // would go through lower_exec (M_EXACT "cfg.dat"). Different literals
        // prove the routing, not just the op byte.
        let cfg = config(
            "rule r:\n\
             notify write file \"/sink\" unless after read \"**/cfg.dat\"\n\
             because \"guard the sink until the config is read back\"\n",
        );
        let gate = find_gate(&cfg);
        assert_eq!(gate.op, OP_OPEN, "a read gate stamps OP_OPEN");
        assert_eq!(
            gate.m, M_SUFFIX,
            "lower_path(\"**/cfg.dat\") -> M_SUFFIX, not lower_exec's M_EXACT"
        );
        assert_eq!(
            gate.target,
            target_field("/cfg.dat"),
            "the read gate's suffix literal is \"/cfg.dat\" (lower_path), not \"cfg.dat\" (lower_exec)"
        );
    }

    #[test]
    fn a_single_label_host_is_a_hostname_candidate_but_an_empty_one_is_not() {
        // `hostname_candidate` decides whether an endpoint pattern is a DNS
        // name (resolved to IPv4s) or treated as a literal. A single-label
        // host with no dot (`localhost`) is still a valid hostname candidate,
        // but an empty pattern is rejected. The base test pins only the
        // wildcard rejection and the two-label `api.internal` accept; these
        // boundaries are unpinned.
        assert_eq!(hostname_candidate("localhost"), Some("localhost"));
        assert_eq!(hostname_candidate(""), None);
    }

    #[test]
    fn since_invalidator_carries_its_own_exec_arg() {
        // A `since` invalidator is a full update the kernel matches to de-stale
        // a gate. For an `exec` invalidator, the positional arg token lands in
        // the inval update's `char arg[TAINT_ARG_LEN]` slot (taint.h), the same
        // byte the kernel's exec argv matcher reads to decide whether the exec
        // event actually de-stales the gate. #84 pins the inval op/m/target;
        // #81 the inval op byte; #59 the inval slot bits; #85 the rule-arg
        // truncation. Nobody pins the inval's own arg byte. A regression that
        // dropped it, or copied the gate's arg into the inval, would silently
        // change which exec events reset the gate.
        fn find_inval(cfg: &CConfig) -> CUpdate {
            cfg.updates[..cfg.n_updates as usize]
                .iter()
                .find(|u| u.invals != 0)
                .cloned()
                .expect("a since clause allocates an invalidator update")
        }
        fn arg_field(s: &str) -> [u8; ARG] {
            let mut out = [0u8; ARG];
            let n = s.len().min(ARG - 1);
            out[..n].copy_from_slice(&s.as_bytes()[..n]);
            out
        }
        let config = |src: &str| -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        };

        // An exec inval with a positional arg: the arg byte lands in the inval
        // update, not the gate.
        let cfg = config(
            "rule r:\n\
             notify write file \"/sink\" unless after exec \"/in\" since exec \"/make\" \"install\"\n\
             because \"stale when the build re-runs\"\n",
        );
        assert_eq!(cfg.n_updates, 2, "one gate update + one since invalidator");
        let inval = find_inval(&cfg);
        assert_eq!(inval.op, OP_EXEC, "an exec invalidator stamps OP_EXEC");
        assert_eq!(
            inval.arg,
            arg_field("install"),
            "the exec inval's positional arg lands in the inval arg slot"
        );

        // An absent inval arg leaves the slot all-zero (the kernel's
        // "ignore argv" case). This contrast is the mutation-catcher.
        let cfg = config(
            "rule r:\n\
             notify write file \"/sink\" unless after exec \"/in\" since exec \"/make\"\n\
             because \"stale when the build re-runs\"\n",
        );
        let inval = find_inval(&cfg);
        assert_eq!(inval.op, OP_EXEC, "an exec invalidator stamps OP_EXEC");
        assert_eq!(
            inval.arg,
            arg_field(""),
            "an absent inval arg leaves the slot all-zero"
        );
    }

    #[test]
    fn a_shared_since_invalidator_dedupes_across_rules() {
        // `inval_slot` is global across the whole compile: it keys the
        // allocated inval slots on (op, m, lit, arg), so two *separate rules*
        // that reference the same `since` invalidator must dedupe to one
        // inval update, with both rules' `since_mask` referencing the same
        // shared bit. #59 pinned within-rule coherence and #90 pinned
        // within-rule dedup (two `or` clauses), but nobody pinned the
        // cross-rule dedup: a regression that scoped `inval_slot` per rule
        // would double-allocate the shared invalidator and the two rules'
        // `since_mask`s would point at different slots, so the engine would
        // de-stale the gate on only one of the two argv events.
        fn inval_count(g: &CConfig) -> u32 {
            g.updates[..g.n_updates as usize]
                .iter()
                .filter(|u| u.invals != 0)
                .count() as u32
        }

        // Two separate rules sharing the identical `since` invalidator:
        // one shared inval update, both rules reference the same bit.
        let pol = crate::dsl::parse::parse(
            "source S = file \"/**/s\"\n\
             rule a:\n  block exec \"git\" if S unless after exec \"/in\" since exec \"/make\" \"install\"\n  because \"z\"\n\
             rule b:\n  block exec \"npm\" if S unless after exec \"/in\" since exec \"/make\" \"install\"\n  because \"z\"\n",
        )
        .expect("parse two-rule shared-since policy");
        let compiled = compile(&pol).expect("compile two-rule shared-since policy");
        let g: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(g.n_rules, 2, "one rule per policy clause");
        assert_eq!(
            inval_count(&g),
            1,
            "a shared since invalidator dedupes to one update"
        );
        // Both rules' since_mask reference the single shared inval bit.
        assert_eq!(
            g.rules[0].since_mask, 1u64,
            "rule 0 references the shared inval bit"
        );
        assert_eq!(
            g.rules[1].since_mask, 1u64,
            "rule 1 reuses the same shared inval bit"
        );
        // The deduped inval update carries the shared argv byte.
        let invals: Vec<&CUpdate> = g.updates[..g.n_updates as usize]
            .iter()
            .filter(|u| u.invals != 0)
            .collect();
        assert_eq!(invals.len(), 1);
        assert_eq!(
            cstr23(&invals[0].arg),
            "install",
            "the deduped update carries the shared argv"
        );

        // Contrast: the two rules carry *distinct* argv, so the dedupe key
        // differs and two inval updates are allocated; the rules' since_mask
        // bits then differ.
        let pol = crate::dsl::parse::parse(
            "source S = file \"/**/s\"\n\
             rule a:\n  block exec \"git\" if S unless after exec \"/in\" since exec \"/make\" \"install\"\n  because \"z\"\n\
             rule b:\n  block exec \"npm\" if S unless after exec \"/in\" since exec \"/make\" \"build\"\n  because \"z\"\n",
        )
        .expect("parse two-rule distinct-since policy");
        let compiled = compile(&pol).expect("compile two-rule distinct-since policy");
        let g: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(inval_count(&g), 2, "distinct argv -> two inval updates");
        let mut masks = [g.rules[0].since_mask, g.rules[1].since_mask];
        masks.sort_unstable();
        assert_eq!(
            masks,
            [1u64, 2u64],
            "the two rules reference two distinct bits"
        );
    }

    fn cstr23(p: &[u8; ARG]) -> String {
        let end = p.iter().position(|b| *b == 0).unwrap_or(ARG);
        String::from_utf8_lossy(&p[..end]).into_owned()
    }

    #[test]
    fn inval_slot_dedupe_key_includes_the_arg_dimension() {
        // inval_slot dedupes its allocated slots on (op, m, lit, arg). #59
        // pinned the target dimension (two distinct `write "src/**"` /
        // `write "tests/**"` invals -> two slots); #87 pinned the arg *byte*.
        // Nobody pins that the arg is a real key dimension: two since clauses
        // that share an op and target but differ in argv must allocate two
        // slots (so the kernel can de-stale the gate on either), and two
        // identical clauses must collapse to one. A regression that dropped
        // arg from the key would let the two distinct-argv invals share a slot,
        // so the engine would only de-stale the gate on the first argv.
        fn arg_field(s: &str) -> [u8; ARG] {
            let mut out = [0u8; ARG];
            let n = s.len().min(ARG - 1);
            out[..n].copy_from_slice(&s.as_bytes()[..n]);
            out
        }
        fn config(src: &str) -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        }
        fn inval_updates(cfg: &CConfig) -> Vec<CUpdate> {
            cfg.updates[..cfg.n_updates as usize]
                .iter()
                .filter(|u| u.invals != 0)
                .cloned()
                .collect()
        }

        // Same op + target `/make`, two distinct argv: two inval slots.
        let cfg = config(
            "rule r:\n\
             block exec \"git\" unless after exec \"/in\" since exec \"/make\" \"install\" or exec \"/make\" \"build\"\n\
             because \"stale when a build stage re-runs\"\n",
        );
        assert_eq!(
            cfg.n_updates, 3,
            "one gate + two distinct-argv inval updates"
        );
        let invals = inval_updates(&cfg);
        assert_eq!(invals.len(), 2, "two distinct argv -> two slots");
        assert_eq!(
            invals.iter().map(|u| u.arg).collect::<Vec<_>>(),
            vec![arg_field("install"), arg_field("build")],
            "each distinct argv gets its own inval arg byte"
        );
        assert_eq!(cfg.rules[0].since_mask, 0b11, "both inval slots referenced");

        // Two identical since clauses: collapse to one slot.
        let cfg = config(
            "rule r:\n\
             block exec \"git\" unless after exec \"/in\" since exec \"/make\" \"install\" or exec \"/make\" \"install\"\n\
             because \"stale when the build re-runs\"\n",
        );
        assert_eq!(cfg.n_updates, 2, "one gate + one deduped inval update");
        let invals = inval_updates(&cfg);
        assert_eq!(invals.len(), 1, "identical argv collapses to one slot");
        assert_eq!(
            cfg.rules[0].since_mask, 0b01,
            "the single slot is referenced"
        );
    }

    #[test]
    fn the_valid_since_event_ops_fold_to_three_kernel_op_bytes() {
        // `inval_op` lowers a `since` event op to the one `taint_op` byte that
        // may invalidate a gate. Unlike `op_lowers` (which accepts all seven
        // ops), only exec/read/write/open/unlink are valid here, and the
        // op pairs that share a byte fold: `Read`/`Open` -> `OP_OPEN` and
        // `Write`/`Unlink` -> `OP_WRITE`.
        // The positive-side folding is unpinned: #121 pinned the reject
        // (error) side; the valid-set byte mapping is a distinct surface.
        assert_eq!(inval_op(Op::Exec).unwrap(), OP_EXEC);
        assert_eq!(inval_op(Op::Read).unwrap(), OP_OPEN);
        assert_eq!(inval_op(Op::Open).unwrap(), OP_OPEN);
        assert_eq!(inval_op(Op::Write).unwrap(), OP_WRITE);
        assert_eq!(inval_op(Op::Unlink).unwrap(), OP_WRITE);
        // The two sharing pairs resolve to the same byte.
        assert_eq!(inval_op(Op::Read).unwrap(), inval_op(Op::Open).unwrap());
        assert_eq!(inval_op(Op::Write).unwrap(), inval_op(Op::Unlink).unwrap());
        // `Connect` and `Recv` are network ops that can never invalidate a
        // gate; both are rejected.
        assert!(inval_op(Op::Connect).is_err());
        assert!(inval_op(Op::Recv).is_err());
    }

    #[test]
    fn connect_and_recv_are_not_valid_since_invalidators() {
        // A `since <op>` clause must stamp a gate with the kernel taint_op of
        // the invalidating event. The engine can only invalidate a gate from
        // exec/read/write events (see inval_op in lower.rs), so `connect` and
        // `recv` are rejected at compile time. The parse layer accepts any op
        // word after `since`, so the rejection only surfaces during lowering;
        // pin it here so the error string and op set stay honest.
        let base = |op: &str| {
            crate::dsl::parse::parse(&format!(
                r#"rule sink:
                  notify write file "/sink" unless after exec "/in" since {op} "/cfg""#
            ))
            .expect("parse since rule")
        };
        for bad in ["connect", "recv"] {
            let pol = base(bad);
            match compile(&pol) {
                Ok(_) => panic!("since {bad} should not compile as an invalidator"),
                Err(e) => assert!(
                    e.contains("not a valid invalidator"),
                    "unexpected error for since {bad}: {e}"
                ),
            }
        }
        // Positive control: `since read` IS a valid invalidator, so the same
        // shape compiles cleanly. This proves the rejection is specific to
        // connect/recv rather than to the whole `since` construction.
        let pol = base("read");
        let compiled = compile(&pol).expect("since read is a valid invalidator");
        assert!(!compiled.bytes.is_empty());
    }

    /// The kernel blob is a fixed-size rodata region holding at most
    /// MAX_INVALS (64) `since` invalidator slots. A single clause whose
    /// `since` chain references more distinct invalidators than the blob
    /// can hold must be rejected at compile time, not silently dropped.
    /// Each distinct `since` pattern lowers to a distinct slot, so 65
    /// distinct `read` invalidators make the 65th allocation trip the
    /// guard. 1 rule / 1 gate / 66 updates stay well under their caps,
    /// so only the inval cap trips.
    #[test]
    fn inval_overflow_beyond_max_invals_is_rejected() {
        // MAX_INVALS = 64. i in 0..=MAX_INVALS gives 65 distinct `since`
        // invalidators, so the 65th inval_slot sees next_inval == 64 and
        // trips the guard.
        let mut since = String::new();
        for i in 0..=MAX_INVALS {
            if i > 0 {
                since.push_str(" or ");
            }
            since.push_str(&format!("read \"/s{i}\""));
        }
        let src = format!(
            "rule overflow:\n  notify write file \"/sink\" unless after exec \"/g\" since {since}\n  because \"overflow\"\n"
        );
        match crate::dsl::parse::parse(&src).and_then(|p| compile(&p)) {
            Ok(_) => panic!("compile must fail past MAX_INVALS"),
            Err(err) => {
                assert!(
                    err.contains("too many `since` invalidators"),
                    "wrong error: {err}"
                );
            }
        }
    }

    /// `since` invalidators and the rules that consume them are two separate
    /// kernel tables that must stay coherent. `inval_slot` dedupes each
    /// invalidator to a slot index `i` and allocates an *update* carrying
    /// `invals = 1<<i` (the bit the engine ORs into `inval_epoch` on a
    /// matching event, taint_engine.bpf.h:1194-1211); the rule that lists the
    /// invalidator under `since` carries `since_mask = OR of those bits` and,
    /// for v2 staleness, the engine reads `inval_epoch[i]` for every `i` set
    /// in `since_mask` (`te_after_satisfied`, taint_engine.bpf.h:1257-1273).
    /// A rule `since_mask` bit with no matching `invals` update -- or a wrong
    /// index -- would make the gate never/always go stale with no
    /// compile-time or blob-size symptom. Pin the cross-table coherence.
    #[test]
    fn since_inval_bits_stay_coherent_with_updates() {
        let pol = crate::dsl::parse::parse(
            "rule r:\n\
             block exec \"git\" unless after exec \"**/pytest\"\n\
               since write \"src/**\" or write \"tests/**\"\n\
             because \"tests must stay green before committing\"\n",
        )
        .expect("parse since policy");
        let compiled = compile(&pol).expect("compile since policy");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };

        // One gate update (`**/pytest`, no `exits`) plus two distinct inval
        // updates (`src/**`, `tests/**`) => three updates.
        assert_eq!(cfg.n_updates, 3, "one gate + two since invalidators");
        assert_eq!(cfg.n_rules, 1, "one rule");

        // The inval updates are exactly the ones with a non-zero `invals`
        // mask; they must NOT carry gate bits or an exit code.
        let inval_bits: Vec<u64> = cfg.updates[..cfg.n_updates as usize]
            .iter()
            .map(|u| (u.op, u.invals, u.gates, u.gate_exit_code))
            .filter(|&(_, invals, _, _)| invals != 0)
            .map(|(_, invals, _, _)| invals)
            .collect();
        assert_eq!(inval_bits, vec![1u64, 2u64], "inval slots 0 and 1");
        for u in &cfg.updates[..cfg.n_updates as usize] {
            if u.invals != 0 {
                assert_eq!(u.op, OP_WRITE, "both invalidators are write events");
                assert_eq!(u.gates, 0, "inval update must not carry gate bits");
                assert_eq!(
                    u.gate_exit_code, GATE_IMMEDIATE,
                    "inval update carries no exit code"
                );
            }
        }

        // The rule's `since_mask` must equal the OR of the allocated inval
        // bits, and agree with its v2 staleness lookup.
        let r = &cfg.rules[0];
        assert_eq!(r.since_mask, 3u64, "rule references inval slots 0 and 1");
        assert_eq!(r.cond_kind, C_AFTER, "unless-after lowers to TCOND_AFTER");
        assert_eq!(r.gate, 1u64, "gate is slot 0");
        assert_eq!(r.gate_idx, 0, "gate index 0");
        // Cross-table: every since_mask bit has a matching invals update.
        for i in 0..64 {
            if r.since_mask & (1u64 << i) != 0 {
                assert!(
                    cfg.updates[..cfg.n_updates as usize]
                        .iter()
                        .any(|u| u.invals == (1u64 << i)),
                    "since_mask bit {i} must have a matching inval update"
                );
            }
        }
    }

    /// Control: `after` with no `since` keeps v1 latching semantics --
    /// `since_mask == 0`, no inval updates, and the gate still latches by its
    /// single bit. This is the baseline that proves the v2 test above is about
    /// the `since` mask, not a side effect of adding the gate.
    #[test]
    fn since_free_after_gate_has_no_inval_updates() {
        let pol = crate::dsl::parse::parse(
            "rule r:\n\
             block exec \"git\" unless after exec \"**/pytest\"\n\
             because \"tests must run before committing\"\n",
        )
        .expect("parse after-only policy");
        let compiled = compile(&pol).expect("compile after-only policy");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };

        assert_eq!(cfg.n_rules, 1, "one rule");
        assert_eq!(cfg.rules[0].since_mask, 0, "no since => v1 latching");
        assert_eq!(cfg.rules[0].gate, 1u64, "gate still latches by slot 0");
        // No update carries an invals bit.
        assert!(
            cfg.updates[..cfg.n_updates as usize]
                .iter()
                .all(|u| u.invals == 0),
            "after-only policy allocates no inval updates"
        );
    }

    #[test]
    fn since_invalidators_carry_their_own_target_pattern() {
        // A `since` invalidator tells the kernel *which file de-stales the gate*.
        // That target is lowered by the same lower_path as any other path sink and
        // lands in the invalidator update's m/target fields. #81 pins the inval
        // op byte; #59 pins the inval slot bits; neither pins these target bytes.
        // A regression that zeroed or re-routed the inval target would make the
        // invalidator match no file, so the gate would never de-stale.
        let cases = [
            // (since-op word, inval taint_op, inval pattern, expected lower_path)
            ("read", OP_OPEN, "/cfg", (M_EXACT, "/cfg".to_string())),
            (
                "write",
                OP_WRITE,
                "src/**",
                (M_CONTAINS, "src/".to_string()),
            ),
            (
                "unlink",
                OP_WRITE,
                "cfg.dat",
                (M_CONTAINS, "cfg.dat".to_string()),
            ),
            (
                "open",
                OP_OPEN,
                "**/cfg.dat",
                (M_SUFFIX, "/cfg.dat".to_string()),
            ),
        ];
        for (op_word, want_op, inval_pat, (want_m, want_lit)) in cases {
            let pol = crate::dsl::parse::parse(&format!(
                "rule r:\n\
                 notify write file \"/sink\" unless after exec \"/in\" since {op_word} \"{inval_pat}\"\n\
                 because \"re-arm the guard when the file is touched\"\n",
            ))
            .expect("parse since rule");
            let compiled = compile(&pol).expect("compile since rule");
            let cfg: CConfig =
                unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
            assert_eq!(cfg.n_updates, 2, "one gate update + one since invalidator");
            let inval = cfg.updates[..cfg.n_updates as usize]
                .iter()
                .find(|u| u.invals != 0)
                .expect("a since clause allocates an invalidator update");
            assert_eq!(
                inval.op, want_op,
                "since {op_word} stamps taint_op {want_op}"
            );
            // The target the kernel substring-matches against is the lowered
            // pattern literal, routed to the invalidator update, not the gate.
            assert_eq!(inval.m, want_m, "since {op_word} \"inval_pat\" match byte");
            let mut want_buf = [0u8; PAT];
            set_pat(&mut want_buf, &want_lit);
            assert_eq!(
                inval.target, want_buf,
                "since {op_word} \"inval_pat\" must carry target \"want_lit\""
            );
            assert_eq!(inval.gates, 0, "a since invalidator carries no gate bits");
            assert_eq!(
                inval.gate_exit_code, GATE_IMMEDIATE,
                "a since invalidator stamps no exit status"
            );
        }
    }

    #[test]
    fn ipv4_kernel_packing_round_trips_through_the_string_form() {
        // `ipv4_to_kernel` packs octet `k` into bit `8*k` to match the
        // kernel's `sin_addr.s_addr` byte order; `kernel_ipv4_to_string` is
        // its documented inverse. Neither is asserted by the endpoint tests
        // (which only pin `lower_ipv4` results), so this pins the packing
        // order and the round-trip directly.
        let cases: [(&std::net::Ipv4Addr, u32); 4] = [
            (&std::net::Ipv4Addr::new(127, 0, 0, 1), 0x0100007F),
            (&std::net::Ipv4Addr::new(10, 0, 0, 1), 0x0100000A),
            (&std::net::Ipv4Addr::new(192, 168, 1, 254), 0xFE01A8C0),
            (&std::net::Ipv4Addr::new(0, 0, 0, 0), 0),
        ];
        for (addr, expected_kernel) in cases {
            let kernel = ipv4_to_kernel(*addr);
            assert_eq!(kernel, expected_kernel, "pack order for {addr}");
            assert_eq!(
                kernel_ipv4_to_string(kernel),
                addr.to_string(),
                "round-trip for {addr}"
            );
        }
    }

    #[test]
    fn a_kernel_packed_ipv4_reverses_to_its_dotted_quad_string() {
        // `kernel_ipv4_to_string` is the string inverse of `ipv4_to_kernel`:
        // it unpacks a kernel-packed little-endian IPv4 (octet 0 in the low
        // byte) back into its dotted-quad form. No base test pins this
        // unpack; the base tests only exercise the pack direction.
        assert_eq!(kernel_ipv4_to_string(0x0100007F), "127.0.0.1");
        assert_eq!(kernel_ipv4_to_string(0x08080808), "8.8.8.8");
        assert_eq!(kernel_ipv4_to_string(0x0000000A), "10.0.0.0");
        // Control: the zero pack is the all-zero quad.
        assert_eq!(kernel_ipv4_to_string(0), "0.0.0.0");
    }

    #[test]
    fn a_match_literal_is_truncated_to_the_kernel_buffer_cap() {
        // `set_pat` mirrors the kernel match-buffer ABI: it stores at most
        // `buf.len() - 1` bytes (leaving room for the NUL terminator) and
        // NUL-terminates at `buf[n]`. This is the same limit AGENTS.md flags
        // as "Match buffers must be >= TAINT_PAT_LEN". No base test pins
        // the truncation cap directly.
        // Within the cap: the NUL lands right after the last byte.
        let mut p = [0u8; PAT];
        set_pat(&mut p, "git");
        assert_eq!(p.iter().position(|&b| b == 0), Some("git".len()));
        // Over the PAT cap: truncated to `PAT - 1` stored bytes, NUL at the
        // last byte of the buffer.
        let long: String = std::iter::repeat('a').take(100).collect();
        let mut p2 = [0u8; PAT];
        set_pat(&mut p2, &long);
        let stored = String::from_utf8_lossy(&p2[..PAT - 1]).into_owned();
        assert_eq!(
            stored,
            std::iter::repeat('a').take(PAT - 1).collect::<String>()
        );
        assert_eq!(p2[PAT - 1], 0);
        // Over the ARG cap: truncated to `ARG - 1` stored bytes.
        let longarg: String = std::iter::repeat('b').take(100).collect();
        let mut a = [0u8; ARG];
        set_pat(&mut a, &longarg);
        let stored_arg = String::from_utf8_lossy(&a[..ARG - 1]).into_owned();
        assert_eq!(
            stored_arg,
            std::iter::repeat('b').take(ARG - 1).collect::<String>()
        );
        assert_eq!(a[ARG - 1], 0);
    }

    #[test]
    fn validate_label_bindings_rejects_bad_masks_and_duplicate_bits() {
        use std::collections::HashMap;
        // `validate_label_bindings` accepts each label only if its name is
        // non-empty, its mask is a single power of two, and that bit has not
        // been claimed by an earlier label. The `Ok` value is the OR of the
        // accepted bits. No base test pins these validation arms directly.
        // Two distinct power-of-two bits are accepted; `Ok` is their OR.
        let ok: HashMap<String, u64> = [("a".to_string(), 0b01u64), ("b".to_string(), 0b10u64)]
            .into_iter()
            .collect();
        assert_eq!(validate_label_bindings(&ok).unwrap(), 0b11);
        // An empty binding map is valid and uses no bits.
        let empty: HashMap<String, u64> = HashMap::new();
        assert_eq!(validate_label_bindings(&empty).unwrap(), 0);

        // A label with an empty name is rejected.
        let empty_name: HashMap<String, u64> = [(String::new(), 0b01u64)].into_iter().collect();
        assert_eq!(
            validate_label_bindings(&empty_name).err().as_deref(),
            Some("label names must not be empty")
        );

        // A mask that is not a single power of two (zero, or multi-bit) is
        // rejected with the offending bit printed in hex.
        let zero: HashMap<String, u64> = [("z".to_string(), 0u64)].into_iter().collect();
        assert_eq!(
            validate_label_bindings(&zero).err().as_deref(),
            Some("label `z` has invalid bit mask 0x0")
        );
        let multi: HashMap<String, u64> = [("n".to_string(), 0b101u64)].into_iter().collect();
        assert_eq!(
            validate_label_bindings(&multi).err().as_deref(),
            Some("label `n` has invalid bit mask 0x5")
        );

        // Two labels claiming the same bit are rejected.
        let dup: HashMap<String, u64> = [("x".to_string(), 0b100u64), ("y".to_string(), 0b100u64)]
            .into_iter()
            .collect();
        assert_eq!(
            validate_label_bindings(&dup).err().as_deref(),
            Some("label bit 0x4 is assigned more than once")
        );
    }

    #[test]
    fn two_labels_sharing_a_single_bit_are_rejected() {
        // `compile_with_labels` accepts a pre-supplied label -> bit map.
        // Each bit must be assigned to at most one label; if two labels
        // share a bit, `validate_label_bindings` rejects with "label bit
        // 0x{bit:x} is assigned more than once". This is load-bearing: a
        // shared bit would silently merge two distinct information-flow
        // labels into one, so a rule that forbids label `A` would also
        // forbid `B` without the author's intent.
        // The empty-name and invalid-mask guards are separate surfaces.
        use std::collections::HashMap;
        fn map(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
            pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
        }
        let pol = crate::dsl::parse::parse("rule r:\n  block exec \"git\" because \"z\"\n")
            .expect("the rule parses");

        match compile_with_labels(&pol, &map(&[("A", 1u64), ("B", 1u64)])) {
            Ok(_) => panic!("two labels on one bit must be rejected"),
            Err(err) => assert_eq!(err, "label bit 0x1 is assigned more than once"),
        }

        // Positive control: distinct single bits for two labels compile.
        compile_with_labels(&pol, &map(&[("A", 1u64), ("B", 2u64)]))
            .expect("distinct label bits compile");
    }

    #[test]
    fn label_bits_are_assigned_in_sorted_name_order() {
        // Label -> bit assignment is a pure function of the *sorted* label-name
        // set (collect_label_names, lower.rs:812), not the order the author
        // wrote the `source` lines. So A, B, C hold bits 0, 1, 2 regardless of
        // source order, and the kernel req/forbid/add masks are reproducible.
        // The engine matches on these masks, so a regression that assigned bits
        // by first-encounter would silently move which operations each rule
        // covers. To make the ordering observable, the sources are declared in
        // reverse-sorted order (B, C, A); declaration-encounter assignment would
        // put B=0x1, C=0x2, A=0x4, while the sorted order below pins B=0x2,
        // C=0x4, A=0x1.
        let pol = crate::dsl::parse::parse(
            r#"
            source B = exec "b"
            source C = exec "c"
            source A = exec "a"
            rule r:
              notify write file "/sink" if B or C or A
            "#,
        )
        .expect("parse sources");
        let compiled = compile(&pol).expect("compile sources");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(cfg.n_rules, 3);
        // `or` is left-associative (parse.rs:150), so the three disjunct rules
        // are B, C, A; sorted bits A=0x1, B=0x2, C=0x4 put them at 0x2, 0x4, 0x1.
        assert_eq!(cfg.rules[0].req, 0x2, "B should hold bit 1");
        assert_eq!(cfg.rules[1].req, 0x4, "C should hold bit 2");
        assert_eq!(cfg.rules[2].req, 0x1, "A should hold bit 0");
        for r in &cfg.rules[..3] {
            assert_eq!(r.forbid, 0, "these disjuncts only require, never forbid");
        }
        // The three source updates carry the same sorted bits (as a set, since
        // the updates table is emitted in source-line order).
        let mut add: Vec<u64> = cfg.updates[..cfg.n_updates as usize]
            .iter()
            .map(|u| u.add)
            .collect();
        add.sort();
        assert_eq!(add, vec![0x1, 0x2, 0x4]);
    }

    #[test]
    fn a_label_with_an_empty_name_is_rejected() {
        // `compile_with_labels` accepts a pre-supplied label -> bit map. An
        // empty label name is a degenerate map key that would silently
        // shadow every rule referring to `""`; the guard rejects it before
        // any bit is consumed. This completes the `validate_label_bindings`
        // trio alongside #114 (duplicate bit) and #115 (invalid bit mask).
        use std::collections::HashMap;
        fn map(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
            pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
        }
        let pol = crate::dsl::parse::parse("rule r:\n  block exec \"git\" because \"z\"\n")
            .expect("the rule parses");

        // An empty name is rejected.
        match compile_with_labels(&pol, &map(&[("", 1u64)])) {
            Ok(_) => panic!("an empty label name must be rejected"),
            Err(err) => assert_eq!(err, "label names must not be empty"),
        }

        // The rejection fires even when an empty name sits among valid ones.
        match compile_with_labels(&pol, &map(&[("A", 1u64), ("", 2u64)])) {
            Ok(_) => panic!("an empty label name must be rejected"),
            Err(err) => assert_eq!(err, "label names must not be empty"),
        }

        // Positive control: a valid single name compiles.
        compile_with_labels(&pol, &map(&[("A", 1u64)])).expect("a valid label name compiles");
    }

    #[test]
    fn a_label_with_an_invalid_bit_mask_is_rejected() {
        // `compile_with_labels` accepts a pre-supplied label -> bit map. Each
        // label's bit must be a *single* bit: a zero mask produces a label
        // that can never propagate, and a multi-bit mask occupies several
        // slots at once, colliding with the per-label single-bit invariant
        // that `label_bit` and `inval_slot` assign one bit each. The guard
        // rejects both. #114 pinned the duplicate-bit (two labels, one bit)
        // guard; this is the distinct per-label mask-shape guard.
        use std::collections::HashMap;
        fn map(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
            pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
        }
        let pol = crate::dsl::parse::parse("rule r:\n  block exec \"git\" because \"z\"\n")
            .expect("the rule parses");

        // A zero mask is invalid.
        match compile_with_labels(&pol, &map(&[("A", 0u64)])) {
            Ok(_) => panic!("a zero label mask must be rejected"),
            Err(err) => assert_eq!(err, "label `A` has invalid bit mask 0x0"),
        }

        // A multi-bit mask (two bits) is invalid.
        match compile_with_labels(&pol, &map(&[("A", 3u64)])) {
            Ok(_) => panic!("a multi-bit label mask must be rejected"),
            Err(err) => assert_eq!(err, "label `A` has invalid bit mask 0x3"),
        }

        // Positive control: a single bit compiles.
        compile_with_labels(&pol, &map(&[("A", 1u64)])).expect("a single-bit label mask compiles");
    }

    #[test]
    fn the_legacy_label_keyword_is_rejected_in_favor_of_source() {
        // The DSL descends from AgentSight, whose source declaration was the
        // `label` keyword. ActPlane renamed it to `source`; the parser keeps
        // an explicit rejection for the legacy spelling so a stray `label`
        // fails with a migration hint rather than a generic "unknown
        // declaration". #58 pinned label *binding* rejection; nobody pinned
        // the legacy-keyword migration guard.
        use crate::dsl::parse::parse;
        let err = parse("label AGENT = exec \"/**/agent\"\n")
            .expect_err("the legacy `label` keyword must be rejected");
        assert_eq!(
            err,
            "the `label` keyword has been removed; use `source` instead (e.g. `source AGENT = exec \"**/your-agent\"`)"
        );

        // Positive control: the modern `source` spelling parses one source.
        let pol = parse("source AGENT = exec \"/**/agent\"\n")
            .expect("the modern `source` keyword parses");
        assert_eq!(pol.sources.len(), 1);
    }

    #[test]
    fn collect_label_names_dedupes_across_sources_xforms_and_rules() {
        // `collect_label_names` gathers label names from every source, every
        // xform, and every rule clause's `when` expression, deduplicating and
        // sorting through a `BTreeSet`. No base test pins the collector's
        // cross-source dedup directly; it is only exercised through
        // `compile_with_labels`.
        use crate::dsl::ast::{
            Clause, Effect, Expr, Kind, Op, Policy, Rule, Source, Target, Xform,
        };

        let src = |label: &str| Source {
            label: label.to_string(),
            kind: Kind::File,
            pattern: "/tmp/x".to_string(),
        };
        let xf = |endorse: bool, label: &str| Xform {
            endorse,
            label: label.to_string(),
            gate: "git".to_string(),
        };
        let clause = |when: Expr| Clause {
            op: Op::Exec,
            target: Target {
                kind: Kind::Exec,
                pattern: "git".to_string(),
                arg: None,
            },
            when,
            unless: None,
            effect: Effect::Notify,
            source_index: 0,
        };

        // "A" is claimed by a source, a xform, and a rule clause; "B" by a
        // source; "C" by a rule clause. Dedup collapses the three "A"s.
        let pol = Policy {
            labels: Vec::new(),
            sources: vec![src("B"), src("A")],
            xforms: vec![xf(false, "A")],
            rules: vec![Rule {
                name: "r".to_string(),
                clauses: vec![clause(Expr::And(
                    Box::new(Expr::Label("C".to_string())),
                    Box::new(Expr::Label("A".to_string())),
                ))],
                reason: String::new(),
            }],
        };
        assert_eq!(
            collect_label_names(&pol),
            vec!["A".to_string(), "B".to_string(), "C".to_string()]
        );

        // A default (empty) policy names no labels.
        assert!(collect_label_names(&Policy::default()).is_empty());
    }

    /// The kernel blob is a fixed-size rodata region holding the label set as
    /// a u64 mask (at most 64 label bits), not a const-capped table. A policy
    /// that names more distinct labels than the mask can hold must be
    /// rejected at compile time, not silently dropped. The label pre-pass
    /// allocates a bit for every source/xform/`when` label, so 65 distinct
    /// source labels make the 65th allocation trip the guard. 65 file
    /// sources add 65 updates, staying under MAX_UPDATES (320), and no
    /// rule/gate/invalidator is involved, so only the label cap trips.
    #[test]
    fn label_overflow_beyond_max_labels_is_rejected() {
        // 65 distinct labels L0..L64. The 65th label_bit sees no free bit in
        // the (0..64) u64 scan and trips "too many labels (max 64)".
        let mut src = String::new();
        for i in 0..=64 {
            src.push_str(&format!("source L{i} = file \"/p{i}\"\n"));
        }
        match crate::dsl::parse::parse(&src).and_then(|p| compile(&p)) {
            Ok(_) => panic!("compile must fail past the 64-label cap"),
            Err(err) => {
                assert!(
                    err.contains("too many labels (max 64)"),
                    "wrong error: {err}"
                );
            }
        }
    }

    #[test]
    fn lineage_cond_lowers_to_c_lineage() {
        // `lineage-includes` is the last uncovered value of the kernel
        // `cond_kind` enum (TCOND_LINEAGE = 1): the deny is relaxed only if the
        // gate bit was set in an *ancestor* process mask. #57 pins C_AFTER and
        // C_TARGET; this pins the LINEAGE byte and the gate it stamps.
        let pol = crate::dsl::parse::parse(
            "rule r:\n\
             block exec \"git\" unless lineage-includes exec \"**/pytest\"\n\
             because \"allow commits once the test suite has run\"\n",
        )
        .expect("parse lineage policy");
        let compiled = compile(&pol).expect("compile lineage policy");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(cfg.n_rules, 1, "one clause, no labels => one rule");
        assert_eq!(cfg.n_updates, 1, "one lineage gate => one update");
        assert_eq!(
            cfg.rules[0].cond_kind, C_LINEAGE,
            "`lineage-includes` lowers to TCOND_LINEAGE"
        );
        assert_eq!(cfg.rules[0].cond_neg, 0, "lineage cond carries no negation");
        assert_eq!(cfg.rules[0].gate, 1u64, "lineage gate is the slot-0 bit");
        assert_eq!(cfg.rules[0].gate_idx, 0, "lineage gate sits in slot 0");
        // A lineage gate latches on ancestry, not on a matching exit status,
        // so it stamps TAINT_GATE_IMMEDIATE (-1), never a concrete code.
        assert_eq!(cfg.updates[0].op, OP_EXEC, "lineage gate is an exec event");
        assert_eq!(
            cfg.updates[0].m, M_EXACT,
            "`**/pytest` -> exact comm `pytest`"
        );
        assert_eq!(
            &cfg.updates[0].target[..6],
            "pytest".as_bytes(),
            "lineage gate target literal"
        );
        assert_eq!(
            cfg.updates[0].gate_exit_code, GATE_IMMEDIATE,
            "lineage gate stamps immediate (-1), not an exit status"
        );
        assert_eq!(cfg.updates[0].gates, 1u64, "slot 0 => bit 1<<0");
        // Contrast: a clause with no `unless` leaves cond_kind at TCOND_NONE and
        // produces no gate update at all.
        let pol2 = crate::dsl::parse::parse(
            "rule r:\n\
             block exec \"git\"\n\
             because \"deny commits outright\"\n",
        )
        .expect("parse label-free policy");
        let cfg2: CConfig = unsafe {
            std::ptr::read_unaligned(
                compile(&pol2)
                    .expect("compile label-free policy")
                    .bytes
                    .as_ptr() as *const CConfig,
            )
        };
        assert_eq!(cfg2.n_rules, 1);
        assert_eq!(cfg2.n_updates, 0, "no cond => no gate update");
        assert_eq!(
            cfg2.rules[0].cond_kind, C_NONE,
            "no `unless` leaves cond_kind at TCOND_NONE"
        );
    }

    #[test]
    fn localhost_resolves_to_the_loopback_ipv4_kernel_value() {
        // `resolve_hostname_ipv4s` special-cases `localhost` (case-insensitive)
        // to the loopback address instead of doing a DNS lookup, so the
        // lowering is fully deterministic. No base test pins this value
        // directly; it only surfaces through a full `compile` of an endpoint
        // rule targeting `localhost`.
        let loopback = ipv4_to_kernel(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(resolve_hostname_ipv4s("localhost"), vec![loopback]);
        // The special-case is case-insensitive.
        assert_eq!(resolve_hostname_ipv4s("LocalHost"), vec![loopback]);
    }

    #[test]
    fn middle_segment_globs_lower_to_contains() {
        // A middle-segment directory glob `**/mid/**` (any depth under `mid`)
        // and `**/mid/*` (files directly inside `mid`) both lower to a
        // M_CONTAINS substring search for `"/mid/"`, not a suffix match. The
        // kernel matcher for M_CONTAINS is a substring scan, so the two glob
        // forms are equivalent for the engine (both mean "a `mid` directory in
        // the path"); the distinction from `**/mid` (M_SUFFIX `/mid`, an
        // end-of-path match) is what a regression could quietly erase. The
        // in-tree path test pins the leaf/suffix forms (`**/*.js`,
        // `**/sec.env` -> M_SUFFIX) but not these directory-contains forms.
        assert_eq!(lower_path("**/mid/**"), (M_CONTAINS, "/mid/".into()));
        assert_eq!(lower_path("**/mid/*"), (M_CONTAINS, "/mid/".into()));
        // Contrast: with no trailing star the middle segment is a suffix, so
        // it is an end-of-path match, not a contains scan.
        assert_eq!(lower_path("**/mid"), (M_SUFFIX, "/mid".into()));
    }

    #[test]
    fn prefix_glob_internal_star_lowers_to_contains() {
        // The `**/`-prefix arm of `lower_path` splits on the inner token:
        //   `**/mid/**`, `**/mid/*` -> M_CONTAINS "/mid/"   (midseg slash-wrap, #74)
        //   `**/*.so`               -> M_SUFFIX   ".so"     (leading star, in-tree)
        //   `**/lib-*.so`           -> M_CONTAINS "lib-*.so" (internal star, THIS test)
        // The internal-star case is the unclaimed one: the inner token is neither a
        // `/**`/`/*` midseg suffix nor a leading star, so it falls to the generic
        // `**/` fallback, which emits M_CONTAINS with the raw inner literal -- the
        // `*` byte is KEPT, because `taint_contains` (taint.h) is a literal
        // substring scan, not a glob. A regression that collapsed this arm to
        // M_SUFFIX, or stripped the star, would silently change what the kernel
        // matches.
        assert_eq!(lower_path("**/lib-*.so"), (M_CONTAINS, "lib-*.so".into()));
        // A long inner token: `shorten_contains_literal` truncates to the 16-char
        // cap, but the star still survives inside the kept window.
        assert_eq!(
            lower_path("**/verylonglibname-*.so"),
            (M_CONTAINS, "longlibname-*.so".into())
        );
        // Contrast: a `**/` token whose star is LEADING is an M_SUFFIX end-match,
        // not a M_CONTAINS substring scan. This sibling is what keeps the split
        // real: the same arm must route an internal star to M_CONTAINS and a
        // leading star to M_SUFFIX.
        assert_eq!(lower_path("**/*.so"), (M_SUFFIX, ".so".into()));
    }

    #[test]
    fn a_non_exec_target_requires_an_explicit_node_kind() {
        // An `exec` target may omit its kind (the op implies it), but a
        // non-exec op (`open`, `write`, `connect`, `recv`) must name the
        // node kind its target refers to: the parser cannot infer it. A
        // missing kind is rejected with "expected node kind in target".
        // Without this guard a `block open "/etc/passwd"` would silently
        // parse as if the pattern were the target node, with no kind.
        // #105 pinned the wrong-kind-word rejection ("expected kind in
        // target, got '{w}'"); nobody pinned the missing-kind guard.
        use crate::dsl::parse::parse;
        let err = parse("rule r:\n  block open \"/etc/passwd\"\n")
            .expect_err("a non-exec target without a node kind must be rejected");
        assert_eq!(err, "expected node kind in target");

        let err = parse("rule r:\n  block connect \"8.8.8.8\"\n")
            .expect_err("a connect target without a node kind must be rejected");
        assert_eq!(err, "expected node kind in target");

        // Positive controls: the two non-exec ops that carry a valid node
        // kind parse and compile.
        for pol in [
            "rule r:\n  block open file \"/etc/passwd\"\n",
            "rule r:\n  block connect endpoint \"8.8.8.8\"\n",
        ] {
            let p = parse(pol).expect("a non-exec target with a node kind parses");
            let _ = compile(&p).expect("a valid non-exec target compiles");
        }
    }

    #[test]
    fn a_non_word_top_level_token_is_rejected() {
        // A policy is a list of declarations, each starting with a word
        // (`source`, `rule`, `declassify`, `endorse`, or the removed
        // `label` keyword). A top-level non-word token -- a string literal,
        // `=`, or `:` -- is not a declaration keyword, so the parser must
        // reject it rather than mis-parse the body. The most common real
        // mistake is opening a policy with a bare string (an author forgot
        // the `rule r:` header).
        use crate::dsl::parse::parse;
        fn err(src: &str) -> String {
            parse(src)
                .map(|_| "OK".to_string())
                .unwrap_or_else(|e| format!("Err({e})"))
        }
        assert_eq!(
            err("\"git\""),
            "Err(expected declaration, got Str(\"git\"))"
        );
        assert_eq!(err("= x"), "Err(expected declaration, got Eq)");
        assert_eq!(err(": x"), "Err(expected declaration, got Colon)");
        // Positive control: a well-formed rule still parses.
        parse("rule r:\n  block exec \"git\" because \"z\"\n").expect("a valid rule parses");
    }

    #[test]
    fn a_numeric_ipv4_pattern_packs_a_net_mask_or_returns_none() {
        // `lower_numeric_ipv4` returns the `(net, mask)` pair only when the
        // pattern's leading tokens are all octets; a non-numeric leading
        // token (`api.internal`) or an empty string yields `None` (falling
        // through to the `lower_ipv4` match-any default). Octets are packed
        // little-endian: octet `k` into bit `8*k`. No base test pins the
        // `None` returns or the partial/overflow packing.
        // A hostname that merely contains dots is not a numeric IPv4.
        assert_eq!(lower_numeric_ipv4("api.internal"), None);
        // An empty pattern has no octets.
        assert_eq!(lower_numeric_ipv4(""), None);
        // A 3-octet prefix packs three octets into a 3-byte mask.
        assert_eq!(lower_numeric_ipv4("1.2.3"), Some((0x00030201, 0x00FFFFFF)));
        // Exactly four octets pack into a full /32.
        assert_eq!(
            lower_numeric_ipv4("1.2.3.4"),
            Some((0x04030201, 0xFFFFFFFF))
        );
        // Tokens beyond the fourth are ignored, so a 6-token pattern packs
        // identically to its first four octets.
        assert_eq!(
            lower_numeric_ipv4("1.2.3.4.5.6"),
            lower_numeric_ipv4("1.2.3.4")
        );
    }

    #[test]
    fn op_lowers_maps_each_dsl_op_to_its_single_taint_op_byte() {
        // `op_lowers` maps each DSL op to the single `taint_op` byte the
        // engine stamps on the event. The non-obvious claim worth pinning is
        // that `Write` and `Unlink` share one op (`OP_WRITE`): an unlink is
        // modeled as a write, and `Read`/`Open` likewise share `OP_OPEN`.
        // No base test asserts this mapping directly (the op byte only
        // surfaces through full `compile` calls).
        let cases: [(Op, &[u8]); 7] = [
            (Op::Exec, &[OP_EXEC]),
            (Op::Read, &[OP_OPEN]),
            (Op::Open, &[OP_OPEN]),
            (Op::Write, &[OP_WRITE]),
            (Op::Unlink, &[OP_WRITE]),
            (Op::Connect, &[OP_CONNECT]),
            (Op::Recv, &[OP_RECV]),
        ];
        for (op, expected) in cases {
            assert_eq!(*op_lowers(op).unwrap(), *expected, "op_lowers({op:?})");
        }
        // The two sharing pairs resolve to the same byte.
        assert_eq!(
            *op_lowers(Op::Write).unwrap(),
            *op_lowers(Op::Unlink).unwrap()
        );
        assert_eq!(*op_lowers(Op::Read).unwrap(), *op_lowers(Op::Open).unwrap());
    }

    #[test]
    fn the_connect_family_ops_lower_to_their_own_kernel_op_bytes() {
        // `op_lowers` maps a single-op `Op` to its kernel op byte. The
        // connect-family ops each lower to their own distinct byte rather
        // than collapsing onto a shared one (in contrast to the write
        // family, where `Write` and `Unlink` share `OP_WRITE`). No base
        // test pins the single-op arms directly.
        assert_eq!(op_lowers(Op::Exec).unwrap(), &[OP_EXEC]);
        assert_eq!(op_lowers(Op::Connect).unwrap(), &[OP_CONNECT]);
        assert_eq!(op_lowers(Op::Recv).unwrap(), &[OP_RECV]);
        // Control: the two write-family ops collapse onto the same byte.
        assert_eq!(op_lowers(Op::Write).unwrap(), &[OP_WRITE]);
        assert_eq!(op_lowers(Op::Unlink).unwrap(), &[OP_WRITE]);
    }

    #[test]
    fn clause_ops_lower_to_kernel_op_bytes() {
        // The kernel engine switches on CRule.op to pick its propagation
        // path (exec comm vs open path vs write vs connect vs recv), so the
        // stored byte must equal bpf/taint.h's `enum taint_op`. Pin the
        // whole op_lowers table in one policy: seven distinct clause ops,
        // one single-clause rule each, in declaration order. `read` and
        // `open` share OP_OPEN; `write` and `unlink` share OP_WRITE, so a
        // table that forgot either alias collapses these two assertions.
        let pol = crate::dsl::parse::parse(
            r#"
            rule r_exec:
              notify exec file "/bin/true"
            rule r_read:
              notify read file "/in"
            rule r_open:
              notify open file "/in"
            rule r_write:
              notify write file "/out"
            rule r_unlink:
              notify unlink file "/out"
            rule r_connect:
              notify connect endpoint "127.0.0.1"
            rule r_recv:
              notify recv endpoint "127.0.0.1"
            "#,
        )
        .expect("parse op rules");
        let compiled = compile(&pol).expect("compile op rules");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(cfg.n_rules, 7);
        let ops = [
            cfg.rules[0].op,
            cfg.rules[1].op,
            cfg.rules[2].op,
            cfg.rules[3].op,
            cfg.rules[4].op,
            cfg.rules[5].op,
            cfg.rules[6].op,
        ];
        assert_eq!(
            ops,
            [
                OP_EXEC, OP_OPEN, OP_OPEN, OP_WRITE, OP_WRITE, OP_CONNECT, OP_RECV
            ]
        );
    }

    #[test]
    fn an_out_of_vocabulary_op_or_kind_is_rejected() {
        // The op and kind vocabularies are closed: `P::op` maps exactly the
        // seven kernel op tokens (exec/read/write/unlink/connect/recv/open)
        // and `P::kind` maps the three node kinds (file/endpoint/exec);
        // anything else is a parse error carrying the offending token. A
        // regression that silently accepted a stray op or kind token (or
        // mapped it to a wrong kernel op byte) would miscompile the rule,
        // and nobody pinned the closed-vocabulary guard.
        use crate::dsl::parse::parse;
        // An out-of-vocabulary op token is rejected with the token in the
        // message.
        let err = parse("rule r:\n  block fork \"a\" because \"z\"\n")
            .expect_err("an unknown op must be rejected");
        assert_eq!(err, "unknown op 'fork'");
        // An out-of-vocabulary source-kind token is rejected the same way.
        let err =
            parse("source S = proc \"/**/s\"\n").expect_err("an unknown kind must be rejected");
        assert_eq!(err, "unknown kind 'proc'");

        // Positive controls: a valid op and a valid source kind parse and
        // compile.
        let pol =
            parse("rule r:\n  block exec \"git\" because \"z\"\n").expect("a valid op parses");
        let _ = compile(&pol).expect("a valid-op policy compiles");
        let pol = parse("source S = endpoint \"8.8.8.8\"\n").expect("a valid source kind parses");
        let _ = compile(&pol).expect("a valid-kind policy compiles");
    }

    /// A positional target arg (`block exec "git" "commit"`) must be lowered
    /// into `CRule.arg`; the kernel's `taint_arg_match` treats an all-zero `arg`
    /// token as "ignore the argv" (taint.h:134), so dropping the arg silently
    /// widens an argv-specific rule to match every invocation of the target.
    /// The existing test (`positional_args_work`) only asserts the clause
    /// effect, never the arg bytes. Pin the actual `arg`/`target`/matcher bytes
    /// via a `read_unaligned` probe of `CConfig`, and contrast the no-arg form,
    /// whose `arg` stays all-zero.
    #[test]
    fn positional_target_arg_lowered_into_crule_arg() {
        // Build a NUL-padded fixed-width byte field the way `set_pat` does.
        fn nuls<const N: usize>(s: &str) -> [u8; N] {
            let mut out = [0u8; N];
            let n = s.len().min(N - 1);
            out[..n].copy_from_slice(&s.as_bytes()[..n]);
            out
        }
        // Probe `rules[i].arg` / `.target` out of the compiled blob (the
        // `CConfig`/`CRule` structs are module-private, same pattern as the
        // endpoint tests above).
        fn config(src: &str) -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        }

        // `block exec "git" "commit"`: basename `git` (no `/`) normalizes to
        // `**/git`, lowers to the exact matcher with literal `git`; the
        // positional arg `commit` must land in the 24-byte kernel `arg` slot.
        let cfg = config("rule r:\n  block exec \"git\" \"commit\" if true\n  because \"z\"\n");
        assert_eq!(cfg.n_rules, 1, "one rule expected");
        let r = &cfg.rules[0];
        assert_eq!(r.op, OP_EXEC, "exec rule");
        assert_eq!(r.m, M_EXACT, "`git` has no glob -> exact matcher");
        assert_eq!(
            r.target,
            nuls::<PAT>("git"),
            "basename `git` lowers to the exact target literal"
        );
        assert_eq!(
            r.arg,
            nuls::<ARG>("commit"),
            "positional arg `commit` must be stored in the kernel arg slot"
        );

        // The no-arg form must leave `arg` all-zero (the kernel's "ignore argv"
        // case, taint.h:134). This contrast is the mutation-catcher: a lowering
        // bug that writes garbage into a missing arg, or drops a present one,
        // flips one of these two assertions.
        let cfg = config("rule r:\n  block exec \"git\" if true\n  because \"z\"\n");
        assert_eq!(
            cfg.rules[0].arg,
            nuls::<ARG>(""),
            "absent positional arg must leave the arg slot all-zero"
        );
    }

    #[test]
    fn a_long_repo_relative_exact_literal_shortens_to_a_fitting_subsegment() {
        // `shorten_repo_relative_exact_literal` keeps an exact repo-relative
        // path verbatim when it fits the `M_CONTAINS` cap, otherwise walks
        // down to the first sub-segment (a tail still containing `/`) that
        // fits, and finally falls back to the parent-dir `/<parent>/` form.
        // No base test pins these cap-walk arms directly; they only surface
        // through full `lower_path` calls.
        // Within the cap: kept verbatim.
        assert_eq!(
            shorten_repo_relative_exact_literal("src/main.rs"),
            "src/main.rs"
        );
        // Over the cap: the first sub-segment that still fits is kept,
        // dropping the long leading prefix.
        assert_eq!(
            shorten_repo_relative_exact_literal("docs/api/types/v2/mod.rs"),
            "types/v2/mod.rs"
        );
        // Over the cap with no sub-segment that fits: fall back to the
        // parent directory form.
        assert_eq!(
            shorten_repo_relative_exact_literal("vendor/libtool-main"),
            "vendor/"
        );
    }

    #[test]
    fn a_repo_relative_path_with_an_interior_wildcard_lowers_to_a_contains_literal() {
        // A repo-relative path whose star is NOT at the terminal position
        // (`config/*.toml`, `src/*/main.rs`) is lowered through the
        // interior-wildcard arm to a contains-match on the substring up to
        // the first star. This is the repo-relative `find('*')` branch
        // (lower.rs:182-183), the counterpart of the absolute arm pinned by
        // the absolute interior-star test. No base test asserts these
        // interior-star repo-relative lowerings.
        assert_eq!(lower_path("config/*.toml"), (M_CONTAINS, "config/".into()));
        assert_eq!(lower_path("src/*/main.rs"), (M_CONTAINS, "src/".into()));
        // Control: a repo-relative exact path with no star is lowered through
        // the exact-literal arm, not the interior-wildcard arm.
        assert_eq!(
            lower_path("config/toml"),
            (M_CONTAINS, "config/toml".into())
        );
    }

    #[test]
    fn a_repo_relative_exact_path_with_no_in_range_suffix_falls_back_to_parent() {
        // `shorten_repo_relative_exact_literal` caps the kernel literal at
        // `MAX_CONTAINS_LITERAL` (16). Before the last-resort parent
        // fallback it walks every `/`-suffixed candidate looking for one that
        // still contains a slash and fits under the cap (the multi-skip walk
        // pinned by the in-range-segment test). When no such candidate
        // exists - a single-slash path whose leaf has no further slash - it
        // falls back to the `<parent>/` form.
        // 18 chars: the only slash-split candidate is `leaf`, which has no
        // slash of its own, so the walk finds nothing and the fallback
        // yields `longerparentx/`.
        assert_eq!(
            lower_path("longerparentx/leaf"),
            (M_CONTAINS, "longerparentx/".into())
        );
        // A path of exactly the cap length with a slash is used verbatim, no
        // shortening.
        assert_eq!(
            lower_path("node_modules/foo"),
            (M_CONTAINS, "node_modules/foo".into())
        );
    }

    #[test]
    fn rule_ids_track_lowered_rule_position_not_clause_index() {
        // `CRule.rule_id` is the index the kernel uses to look up the
        // human-readable reason for a violation: `taint_engine.bpf.h` records
        // `e->matched_rule = rp->rule_id` and the loader indexes the `reasons`
        // table by that id. It is set to `meta.len()` -- the lowered rule's
        // own position in the reasons/meta tables -- not the clause index.
        //
        // On a DNF split this matters: a clause like `B or C` lowers to two
        // disjunct rules that must carry two distinct, consecutive
        // `rule_id`s (1 and 2), not the same clause index. A regression that
        // emitted the clause index (or reset the counter per clause) would
        // desync `rule_id` from the reasons table, and the kernel would
        // surface the wrong reason (or read past the table) on a violation.
        use std::collections::HashMap;
        let labels = [
            ("A".to_string(), 1u64),
            ("B".to_string(), 2u64),
            ("C".to_string(), 4u64),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();
        let s = "source A = file \"/**/a\"\n\
                 source B = file \"/**/b\"\n\
                 source C = file \"/**/c\"\n\
                 rule r:\n\
                   block exec \"git\" if A\n\
                   notify exec \"git\" if B or C\n\
                   because \"z\"\n";
        let pol = crate::dsl::parse::parse(s).expect("parse policy");
        let compiled = compile_with_labels(&pol, &labels).expect("compile policy");
        let g: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };

        // Clause 0 (`A`) -> 1 rule; clause 1 (`B or C`) -> 2 disjunct rules.
        assert_eq!(g.n_rules, 3, "one disjunct for `A`, two for `B or C`");
        // The kernel indexes reasons by `rule_id`, so the table and the ids
        // must stay in lockstep: three reasons for three lowered rules.
        assert_eq!(
            compiled.reasons.len(),
            3,
            "one reason entry per lowered rule"
        );
        let ids: Vec<u32> = g.rules[..g.n_rules as usize]
            .iter()
            .map(|r| r.rule_id)
            .collect();
        assert_eq!(ids, vec![0u32, 1, 2], "`rule_id` is the lowered position");

        // The two rules from the same `B or C` clause get distinct
        // consecutive ids (1 and 2), not a duplicated clause index: the
        // second rule is `C`'s disjunct and must not reuse the first's id.
        let by_req: Vec<u32> = g.rules[..g.n_rules as usize]
            .iter()
            .filter(|r| r.req == 2u64 || r.req == 4u64)
            .map(|r| r.rule_id)
            .collect();
        assert!(
            by_req.contains(&1) && by_req.contains(&2),
            "`B or C` -> ids 1 and 2"
        );
        // Every id bounds the reasons table the kernel will index into.
        for r in &g.rules[..g.n_rules as usize] {
            assert!(
                (r.rule_id as usize) < compiled.reasons.len(),
                "`rule_id` {id} must index a reason entry",
                id = r.rule_id
            );
        }
    }

    #[test]
    fn a_rule_declaration_requires_a_colon_after_the_name() {
        // A `rule` declaration is `rule <name> : <clauses...>`. After the
        // name the parser demands a `:` token; anything else is rejected
        // with "expected ':' after rule name, got {tok}". Without the guard,
        // a stray word or `=` after the name would be silently swallowed and
        // misparsed as a clause keyword rather than a structural error.
        // Nobody pinned the rule-name colon guard.
        use crate::dsl::parse::parse;
        let err = parse("rule r block exec \"git\" because \"z\"\n")
            .expect_err("a missing colon after the rule name must be rejected");
        assert!(
            err.starts_with("expected ':' after rule name, got "),
            "the error names the offending token: {err}"
        );
        let err = parse("rule r = block exec \"git\" because \"z\"\n")
            .expect_err("a wrong token after the rule name must be rejected");
        assert!(
            err.starts_with("expected ':' after rule name, got "),
            "the error names the offending token: {err}"
        );

        // Positive control: a rule with the colon parses and compiles.
        let pol = parse("rule r:\n  block exec \"git\" because \"z\"\n")
            .expect("a colon-terminated rule parses");
        let _ = compile(&pol).expect("a valid rule compiles");
    }

    /// The kernel blob is a fixed-size rodata region holding at most
    /// MAX_RULES (128) rule slots. A policy that lowers to more rules than
    /// the blob can hold must be rejected at compile time, not silently
    /// truncated (which would drop rules the engine depends on). Each of 129
    /// clauses lowers to exactly one rule, so the 129th trips the guard;
    /// `if true` needs no label, so the 64-label cap is never reached first.
    #[test]
    fn rule_overflow_beyond_max_rules_is_rejected() {
        // MAX_RULES = 128. i in 0..=128 gives 129 clauses => 129 rules > 128.
        let mut src = String::from("rule overflow:\n");
        for i in 0..=MAX_RULES {
            src.push_str(&format!("  notify write file \"/o{i}\"\n"));
        }
        src.push_str("  because \"overflow\"\n");
        match crate::dsl::parse::parse(&src).and_then(|p| compile(&p)) {
            Ok(_) => panic!("compile must fail past MAX_RULES"),
            Err(err) => {
                assert!(
                    err.contains("too many compiled rules"),
                    "wrong error: {err}"
                );
            }
        }
    }

    #[test]
    fn file_rules_emit_their_rule_level_target_matcher_bytes() {
        // The kernel matches each rule's event on CRule.m + CRule.target
        // (the matching predicates in bpf/taint.h), so the emitted byte pair
        // is what the engine compares against at runtime. #78 pinned
        // lower_target's *return values*; #76 pinned lower_path's *returns*
        // directly. Neither pins the CRule.target / CRule.m bytes a file-op
        // rule actually writes into the blob, which is a distinct ABI field:
        // an emission regression (a CRule loop that dropped m, or a set_pat
        // that mis-truncated target) would break these without breaking the
        // function-level tests.
        //
        // The load-bearing decision pinned here: the same glob shape lowers to
        // M_CONTAINS when repo-relative (no start anchor -> substring scan)
        // but M_PREFIX when absolute (start-anchored /data/ -> prefix scan).
        // A regression that dropped the repo_relative check in lower_path
        // would emit M_PREFIX for the repo-relative glob and silently turn a
        // substring match into a start-anchored prefix match at the rule level.
        fn target_str(t: &[u8; PAT]) -> String {
            let end = t.iter().position(|b| *b == 0).unwrap_or(PAT);
            String::from_utf8_lossy(&t[..end]).into_owned()
        }
        fn cfg(src: &str) -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        }

        // Repo-relative directory glob: substring scan on "data/".
        let r = &cfg("rule r:\n block write file \"data/**\" because \"z\"\n").rules[0];
        assert_eq!(r.op, OP_WRITE, "write op");
        assert_eq!(r.m, M_CONTAINS, "repo-rel glob -> substring scan");
        assert_eq!(target_str(&r.target), "data/", "trailing slash retained");

        // Absolute directory glob: start-anchored prefix scan on "/data/".
        let r = &cfg("rule r:\n block write file \"/data/**\" because \"z\"\n").rules[0];
        assert_eq!(r.op, OP_WRITE);
        assert_eq!(r.m, M_PREFIX, "absolute glob -> start-anchored prefix");
        assert_eq!(target_str(&r.target), "/data/");

        // The repo-relative vs absolute split is the crux: `data/**` (above)
        // is M_CONTAINS, `/data/**` (above) is M_PREFIX. A bare repo-relative
        // name with no wildcard still falls to M_CONTAINS (no start anchor).
        let r = &cfg("rule r:\n block write file \"src\" because \"z\"\n").rules[0];
        assert_eq!(r.m, M_CONTAINS, "repo-rel bare name -> substring scan");
        assert_eq!(target_str(&r.target), "src");

        // An absolute exact path has no wildcard and a start anchor, so it
        // lowers to M_EXACT on the full path.
        let r = &cfg("rule r:\n block write file \"/a/b\" because \"z\"\n").rules[0];
        assert_eq!(r.m, M_EXACT, "absolute exact path -> exact match");
        assert_eq!(target_str(&r.target), "/a/b");
    }

    #[test]
    fn a_since_invalidator_with_a_non_invalidator_op_is_rejected() {
        // `since` gates only invalidate on exec/read/write/open/unlink. The
        // parser accepts any op word (`P::op`), so the restriction is a
        // compile-time check in `inval_op`. A `connect`/`recv` invalidator
        // must reject rather than silently map to the wrong taint_op.
        use crate::dsl::parse::parse;
        // `connect` is not a valid invalidator op.
        let pol = parse(
            "rule r:\n  block exec \"git\" unless after exec \"/in\" since connect \"10.0.0.5\"\n",
        )
        .expect("a since connect rule parses");
        match compile(&pol) {
            Ok(_) => panic!("a since connect invalidator must be rejected"),
            Err(err) => assert_eq!(
                err,
                "`since connect` is not a valid invalidator (use exec/read/write/open/unlink)"
            ),
        }
        // `recv` is likewise not a valid invalidator op.
        let pol = parse(
            "rule r:\n  block exec \"git\" unless after exec \"/in\" since recv \"10.0.0.5\"\n",
        )
        .expect("a since recv rule parses");
        match compile(&pol) {
            Ok(_) => panic!("a since recv invalidator must be rejected"),
            Err(err) => assert_eq!(
                err,
                "`since recv` is not a valid invalidator (use exec/read/write/open/unlink)"
            ),
        }
        // Positive control: `exec` is a valid invalidator op and compiles.
        let pol =
            parse("rule r:\n  block exec \"git\" unless after exec \"/in\" since exec \"/in\"\n")
                .expect("a since exec rule parses");
        compile(&pol).expect("a since exec invalidator compiles");
    }

    #[test]
    fn a_rule_exceeding_the_sixty_four_since_invalidator_cap_is_rejected() {
        // `since` invalidators occupy a global 64-bit slot table
        // (`inval_slots` / `next_inval` on the compile `Ctx`), shared across
        // the whole policy. Exceeding the cap must reject at compile time
        // rather than overflow a `since_mask` `u64` or silently drop an
        // invalidator. #101 pinned cross-rule dedup of the shared slot;
        // nobody pinned the cap itself.
        use crate::dsl::parse::parse;
        // Build a single rule carrying `n` distinct `since` invalidators
        // (`exec "/i{n}"`), joined with `or`.
        fn build(n: usize) -> String {
            let since: Vec<String> = (0..n).map(|i| format!("exec \"/i{i}\"")).collect();
            let since = since.join(" or ");
            format!("rule r:\n  block exec \"git\" unless after exec \"/in\" since {since}\n")
        }

        // Boundary: 64 distinct invalidators is exactly the cap and compiles.
        let pol = parse(&build(64)).expect("64 distinct since invalidators parse");
        compile(&pol).expect("64 distinct since invalidators compile");

        // 65 distinct invalidators trip the global cap.
        let pol = parse(&build(65)).expect("65 distinct since invalidators parse");
        match compile(&pol) {
            Ok(_) => panic!("more than 64 since invalidators must be rejected"),
            Err(err) => assert_eq!(err, "too many `since` invalidators (max 64)"),
        }

        // Dedup control: repeated identical invalidators do not consume new
        // slots, so a duplicate list stays well under the cap.
        let pol =
            parse("rule r:\n  block exec \"git\" unless after exec \"/in\" since exec \"/i0\" or exec \"/i0\"\n")
                .expect("a duplicated since invalidator parses");
        compile(&pol).expect("duplicated since invalidators dedup and compile");
    }

    #[test]
    fn since_invalidators_stamp_the_valid_op_bytes() {
        // A `since <op>` clause de-stales the gate on that event class, so the
        // invalidator update must carry the kernel taint_op of the op. inval_op
        // (lower.rs) consolidates the five valid ops to three kernel op bytes:
        // `read` and `open` both mark an open/read edge (OP_OPEN), `write` and
        // `unlink` both mark a mutating edge (OP_WRITE), and `exec` stays
        // OP_EXEC. A wrong byte would de-stale the gate on the wrong syscall
        // class with no compile-time or blob-size symptom. #73 pins the
        // connect/recv *reject*; #59 pins the `invals` slot bits; neither
        // pins these accept bytes.
        let cases = [
            ("exec", OP_EXEC),
            ("read", OP_OPEN),
            ("open", OP_OPEN),
            ("write", OP_WRITE),
            ("unlink", OP_WRITE),
        ];
        for (op_word, want_op) in cases {
            let pol = crate::dsl::parse::parse(&format!(
                "rule r:\n\
                 notify write file \"/sink\" unless after exec \"/in\" since {op_word} \"/cfg\"\n\
                 because \"re-arm the guard when the file is touched\"\n",
            ))
            .expect("parse since rule");
            let compiled = compile(&pol).expect("compile since rule");
            let cfg: CConfig =
                unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
            assert_eq!(cfg.n_updates, 2, "one gate update + one since invalidator");
            // The invalidator is the update carrying a non-zero `invals` bit.
            let inval = cfg.updates[..cfg.n_updates as usize]
                .iter()
                .find(|u| u.invals != 0)
                .expect("a since clause allocates an invalidator update");
            assert_eq!(
                inval.op, want_op,
                "since {op_word} must stamp taint_op byte {want_op}"
            );
            // An invalidator never carries gate bits or a matching exit code.
            assert_eq!(inval.gates, 0, "since invalidator carries no gate bits");
            assert_eq!(
                inval.gate_exit_code, GATE_IMMEDIATE,
                "since invalidator stamps no exit status"
            );
        }
    }

    #[test]
    fn a_source_declaration_requires_an_equals_between_name_and_kind() {
        // A `source` declaration is `source <name> = <kind> "<pattern>"`. After
        // the label name the parser demands an `=` token; anything else is
        // rejected with "expected '=' in source, got {tok}". Without the
        // guard, a stray word or `:` after the name would be misparsed as the
        // node kind rather than a structural error. Nobody pinned the
        // source-equals guard.
        use crate::dsl::parse::parse;
        let err = parse("source S file \"/**/s\"\n")
            .expect_err("a missing '=' in a source must be rejected");
        assert!(
            err.starts_with("expected '=' in source, got "),
            "the error names the offending token: {err}"
        );
        let err = parse("source S : file \"/**/s\"\n")
            .expect_err("a wrong token in a source must be rejected");
        assert!(
            err.starts_with("expected '=' in source, got "),
            "the error names the offending token: {err}"
        );

        // Positive control: a well-formed source declaration parses and
        // compiles.
        let pol = parse("source S = file \"/**/s\"\n").expect("a source parses");
        let _ = compile(&pol).expect("a valid source compiles");
    }

    #[test]
    fn file_sources_emit_their_update_target_matcher_bytes() {
        // A `file` source lowers its pattern through lower_path into the
        // update's CUpdate.m + CUpdate.target, and the kernel matches open
        // events against that byte pair to decide which events grant the
        // source label. #60 pinned a source update's add/del *direction*
        // (it located the source update by op + add + del) but never pinned
        // the m/target bytes, so a regression that dropped m or mis-truncated
        // the source target would go uncaught here.
        //
        // The decision pinned: the same glob shape lowers to M_CONTAINS when
        // repo-relative (no start anchor, substring scan) but M_PREFIX when
        // absolute (start-anchored, prefix scan) -- the lower_path dispatch
        // a source update relies on, exactly as a rule's own target does.
        fn tgt(p: &[u8; PAT]) -> String {
            let end = p.iter().position(|b| *b == 0).unwrap_or(PAT);
            String::from_utf8_lossy(&p[..end]).into_owned()
        }
        fn cfg(src: &str) -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        }

        // Absolute directory glob: start-anchored prefix scan on "/data/".
        let u = &cfg("source S = file \"/data/**\"\n").updates[0];
        assert_eq!(u.op, OP_OPEN, "a file source is an open event");
        assert_eq!(u.m, M_PREFIX, "absolute glob -> start-anchored prefix");
        assert_eq!(tgt(&u.target), "/data/");

        // Repo-relative directory glob: no start anchor, so substring scan.
        let u = &cfg("source S = file \"data/**\"\n").updates[0];
        assert_eq!(u.op, OP_OPEN);
        assert_eq!(u.m, M_CONTAINS, "repo-rel glob -> substring scan");
        assert_eq!(tgt(&u.target), "data/");

        // An absolute exact path has no wildcard and a start anchor, so it
        // lowers to M_EXACT on the full path.
        let u = &cfg("source S = file \"/etc/passwd\"\n").updates[0];
        assert_eq!(u.op, OP_OPEN);
        assert_eq!(u.m, M_EXACT, "absolute exact path -> exact match");
        assert_eq!(tgt(&u.target), "/etc/passwd");
    }

    #[test]
    fn a_double_star_middle_segment_lowers_to_a_contains_literal() {
        // A `**/X/**` pattern matches anything *inside* `X` at any depth, and
        // `**/X/*` matches files directly inside `X`. Both lower to the
        // `M_CONTAINS "/X/"` substring form (the engine matches the path
        // against the `/{inner}/` literal). The base test pins only the
        // `**/X` suffix form (`M_SUFFIX`), not the fully-globbed middle.
        assert_eq!(
            lower_path("**/secrets/**"),
            (M_CONTAINS, "/secrets/".into())
        );
        // `**/X/*` (files directly inside) lowers to the same literal.
        assert_eq!(lower_path("**/secrets/*"), (M_CONTAINS, "/secrets/".into()));
        // Control: a bare `**/X` (no trailing glob) is a suffix match, not a
        // contains literal.
        assert_eq!(lower_path("**/bin"), (M_SUFFIX, "/bin".into()));
    }

    #[test]
    fn connect_and_recv_targets_ignore_the_pattern() {
        // For net ops (connect / recv) the target string is irrelevant: the
        // kernel matches network edges on endpoint *labels*, not on a target
        // pattern, so lower_target always returns (M_ANY, "") for these ops
        // (lower.rs:768). Any pattern, including a bare wildcard or a concrete
        // dotted endpoint, collapses to the same match-anything byte. A
        // regression that started threading the target pattern through for net
        // ops would silently turn a label match into a (wrong) string match.
        assert_eq!(
            lower_target(OP_CONNECT, Kind::Endpoint, "10.0.0.0/8"),
            (M_ANY, String::new())
        );
        assert_eq!(
            lower_target(OP_RECV, Kind::Endpoint, "10.1.2.3/32"),
            (M_ANY, String::new())
        );
        assert_eq!(
            lower_target(OP_CONNECT, Kind::Endpoint, "*"),
            (M_ANY, String::new())
        );

        // Contrast: the non-net ops DO thread the target pattern through. Exec
        // delegates to lower_exec (comm match), and the default file ops
        // delegate to lower_path, so the target string is load-bearing there.
        assert_eq!(
            lower_target(OP_EXEC, Kind::Exec, "bash"),
            (M_EXACT, "bash".into())
        );
        assert_eq!(
            lower_target(OP_OPEN, Kind::File, "/tmp/x"),
            (M_EXACT, "/tmp/x".into())
        );
    }

    /// `unless target PAT` lowers into the `CRule` condition bytes that the
    /// kernel's `te_cond_satisfied` reads (taint_engine.bpf.h:2094-2102):
    /// `cond_kind`/`cond_neg` select the suppression, and either
    /// `cond_match`/`cond_pat` (path/exec targets) or `cond_ipv4`/`cond_ipv4_mask`
    /// (connect/recv targets) carry the pattern. `te_rule_effect` *skips* the
    /// rule when the condition is satisfied (taint_engine.bpf.h:2158), so a
    /// flipped `cond_neg`, a `cond_ipv4` leaked onto a path rule, or a swapped
    /// target/condition pattern silently turns "block except in /work" into
    /// "block in /work" (or the inverse) with no blob-size symptom. The
    /// existing e4/e5-style tests only assert these policies *compile*; they
    /// never read these bytes.
    #[test]
    fn unless_target_condition_bytes_stay_in_the_cond_region() {
        // Non-network: the condition pattern routes to cond_match/cond_pat,
        // never to cond_ipv4, and never into the rule's own target field.
        let pol = crate::dsl::parse::parse(
            r#"
            source AGENT = exec "**/codex"
            rule confine-writes:
              block write file "/**" if AGENT unless target "/work/**"
              because "agent may only modify /work"
            "#,
        )
        .expect("parse confine policy");
        let compiled = compile(&pol).expect("compile confine policy");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let cr = &cfg.rules[0];
        assert_eq!(cr.op, OP_WRITE);

        // The suppression is an un-negated target condition.
        assert_eq!(
            cr.cond_kind, C_TARGET,
            "`unless target` must set TCOND_TARGET"
        );
        assert_eq!(cr.cond_neg, 0, "a plain `unless target` is not negated");

        // The condition pattern goes to cond_pat, the rule target to `target`,
        // and the connect-only fields stay zero on a path rule.
        let (cm, clit) = lower_path("/work/**");
        let (tm, tlit) = lower_path("/**");
        assert_eq!(cr.cond_match, cm);
        assert_eq!(cr.m, tm);
        let mut want_cond = [0u8; PAT];
        set_pat(&mut want_cond, &clit);
        assert_eq!(
            cr.cond_pat, want_cond,
            "the condition pattern must land in cond_pat"
        );
        let mut want_tgt = [0u8; PAT];
        set_pat(&mut want_tgt, &tlit);
        assert_eq!(cr.target, want_tgt, "the rule target must stay in `target`");
        assert_eq!(cr.cond_ipv4, 0, "a path rule must not carry a cond IPv4");
        assert_eq!(
            cr.cond_ipv4_mask, 0,
            "a path rule must not carry a cond mask"
        );

        // The `when` mask region is orthogonal: the rule still requires the
        // AGENT source bit.
        assert_eq!(
            cr.req,
            compiled.labels.get("AGENT").copied().expect("AGENT bit")
        );

        // Control: a clause with no `unless` leaves the whole cond region in
        // its C_NONE / zeroed default state.
        let pol2 = crate::dsl::parse::parse(
            r#"
            source AGENT = exec "**/codex"
            rule all-writes:
              block write file "/**" if AGENT
              because "no writes anywhere"
            "#,
        )
        .expect("parse no-unless policy");
        let c2: CConfig = unsafe {
            std::ptr::read_unaligned(compile(&pol2).expect("ok").bytes.as_ptr() as *const CConfig)
        };
        let r2 = &c2.rules[0];
        assert_eq!(r2.cond_kind, C_NONE, "no `unless` must leave TCOND_NONE");
        assert_eq!(r2.cond_neg, 0);
        let empty = [0u8; PAT];
        assert_eq!(r2.cond_pat, empty);
        assert_eq!(r2.cond_ipv4, 0);
        assert_eq!(r2.cond_ipv4_mask, 0);
    }

    /// On connect/recv the condition pattern is a numeric endpoint and routes to
    /// `cond_ipv4`/`cond_ipv4_mask` (not `cond_pat`), with `cond_neg` carrying
    /// `not`. The kernel applies the negation at match time (`cond_neg ? !m : m`,
    /// taint_engine.bpf.h:2102), so a negated single-IP condition must keep the
    /// address set and flip only `cond_neg` -- zeroing the address would invert
    /// the match against a `0/0` instead of negating it.
    #[test]
    fn connect_unless_target_routes_pattern_into_cond_ipv4() {
        // The rule's own target endpoint and the condition endpoint differ, so a
        // swap between the rule's `ipv4` and `cond_ipv4` is observable.
        let pol = crate::dsl::parse::parse(
            r#"
            source NET = endpoint "127.0.0.1"
            rule egress:
              block connect endpoint "8.8.8.8" if NET unless target "10.0.0.0"
              because "no egress to 10/8"
            "#,
        )
        .expect("parse egress policy");
        let compiled = compile(&pol).expect("compile egress policy");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        let cr = &cfg.rules[0];
        assert_eq!(cr.op, OP_CONNECT);
        assert_eq!(cr.cond_kind, C_TARGET);
        assert_eq!(cr.cond_neg, 0);

        let (tgt_ip, tgt_mask) = lower_numeric_ipv4("8.8.8.8").expect("8.8.8.8 numeric");
        let (cond_ip, cond_mask) = lower_numeric_ipv4("10.0.0.0").expect("10.0.0.0 numeric");
        assert_eq!(cr.ipv4, tgt_ip, "the rule target keeps its own endpoint");
        assert_eq!(cr.ipv4_mask, tgt_mask);
        assert_eq!(
            cr.cond_ipv4, cond_ip,
            "the condition endpoint lands in cond_ipv4"
        );
        assert_eq!(cr.cond_ipv4_mask, cond_mask);
        assert_ne!(
            cr.ipv4, cr.cond_ipv4,
            "target and condition endpoints must differ"
        );
        // A connect condition carries no cond_pat; its matcher stays the default.
        assert_eq!(cr.cond_match, M_EXACT);
        let empty = [0u8; PAT];
        assert_eq!(cr.cond_pat, empty);

        // `not` flips only cond_neg; the address stays set (the kernel negates).
        let pol2 = crate::dsl::parse::parse(
            r#"
            source NET = endpoint "127.0.0.1"
            rule allow-hosts:
              block connect endpoint "*" if NET unless target not "127.0.0.1"
              because "everything except localhost"
            "#,
        )
        .expect("parse allow policy");
        let c2: CConfig = unsafe {
            std::ptr::read_unaligned(compile(&pol2).expect("ok").bytes.as_ptr() as *const CConfig)
        };
        let r2 = &c2.rules[0];
        let (lo_ip, lo_mask) = lower_numeric_ipv4("127.0.0.1").expect("localhost numeric");
        assert_eq!(r2.cond_neg, 1, "`not` must set cond_neg");
        assert_eq!(
            r2.cond_ipv4, lo_ip,
            "negation must keep the address, not zero it"
        );
        assert_eq!(r2.cond_ipv4_mask, lo_mask);
    }

    #[test]
    fn a_non_exec_target_with_a_wrong_kind_word_is_rejected() {
        // A non-exec target must name its node kind as one of `file`,
        // `endpoint`, or `exec`. A present-but-invalid kind word is
        // rejected with "expected kind in target, got '{w}'". This is the
        // distinct guard from the missing-kind rejection ("expected node
        // kind in target", #111) and from the source-path kind
        // vocabulary (#105). Without it, a misspelled kind (`proc`,
        // `blob`) would be silently ignored and the pattern misparsed.
        use crate::dsl::parse::parse;
        let err = parse("rule r:\n  block open proc \"/etc/passwd\"\n")
            .expect_err("a wrong target kind word must be rejected");
        assert_eq!(err, "expected kind in target, got 'proc'");

        let err = parse("rule r:\n  block connect proc \"8.8.8.8\"\n")
            .expect_err("a wrong target kind word must be rejected");
        assert_eq!(err, "expected kind in target, got 'proc'");

        let err = parse("rule r:\n  block open blob \"/etc/passwd\"\n")
            .expect_err("another wrong target kind word must be rejected");
        assert_eq!(err, "expected kind in target, got 'blob'");

        // Positive controls: the valid target kinds parse and compile.
        for pol in [
            "rule r:\n  block open file \"/etc/passwd\"\n",
            "rule r:\n  block connect endpoint \"8.8.8.8\"\n",
        ] {
            let p = parse(pol).expect("a valid target kind parses");
            let _ = compile(&p).expect("a valid target compiles");
        }
    }

    #[test]
    fn an_out_of_vocabulary_unless_cond_is_rejected() {
        // The `unless` clause accepts exactly three cond keywords: `target`,
        // `lineage-includes`, and `after`. Anything else hits the
        // catch-all `unknown unless cond '{w}'`. The unless cond is where
        // the gate / lineage / since machinery lives, so a stray cond token
        // (e.g. a misspelled `before`) is a common author mistake and must
        // fail at parse time, not lower to a wrong `Cond`. Nobody pinned the
        // closed cond-vocabulary guard.
        use crate::dsl::parse::parse;
        let err =
            parse("rule r:\n  block exec \"git\" unless before exec \"/in\"\n  because \"z\"\n")
                .expect_err("an unknown unless cond must be rejected");
        assert_eq!(err, "unknown unless cond 'before'");

        let err = parse("rule r:\n  block exec \"git\" unless when A\n  because \"z\"\n")
            .expect_err("another unknown unless cond must be rejected");
        assert_eq!(err, "unknown unless cond 'when'");

        // Positive controls: each valid cond keyword parses and compiles.
        for cond in [
            "target \"x\"",
            "lineage-includes exec \"/in\"",
            "after exec \"/in\"",
        ] {
            let pol = parse(&format!(
                "rule r:\n  block exec \"git\" unless {cond}\n  because \"z\"\n"
            ))
            .expect("a valid unless cond parses");
            let _ = compile(&pol).expect("a valid unless cond compiles");
        }
    }

    #[test]
    fn an_unquoted_pattern_is_rejected() {
        // DSL patterns are string literals. An unquoted pattern (a bare
        // `Word` where a `Str` is required) is a common authoring mistake
        // that must reject at parse time, not silently compile. This fires
        // only after a *valid* kind word precedes it, so it is distinct
        // from the kind-word guards (#112 wrong-kind, #105 unknown-kind).
        use crate::dsl::parse::parse;
        fn err(src: &str) -> String {
            parse(src)
                .map(|_| "OK".to_string())
                .unwrap_or_else(|e| format!("Err({e})"))
        }
        // An unquoted clause target pattern.
        assert_eq!(
            err("rule r:\n  block open file /x because \"z\"\n"),
            "Err(expected string, got Some(Word(\"/x\")))"
        );
        // An unquoted source pattern.
        assert_eq!(
            err("source S = file /x\nrule r:\n  block open file \"/x\" because \"z\"\n"),
            "Err(expected string, got Some(Word(\"/x\")))"
        );
        // Positive control: a quoted pattern compiles.
        parse("rule r:\n  block open file \"/x\" because \"z\"\n")
            .expect("a quoted pattern parses");
    }

    #[test]
    fn an_unterminated_string_is_rejected() {
        // A quoted string token is lexed by scanning to the closing `"`. If
        // the lexer reaches end-of-input first, the token is rejected with
        // "unterminated string". This is the most common author error in a
        // hand-edited policy, and a silent lexer recovery that swallowed the
        // rest of the buffer as one token would miscompile every following
        // declaration. Nobody pinned the guard.
        use crate::dsl::parse::parse;
        // The exec-pattern string is opened but never closed: the scanner
        // runs to end-of-input and the `z` token is absorbed into the string.
        let err = parse("rule r:\n  block exec \"git because \"z\"\n")
            .expect_err("an unterminated string must be rejected");
        assert_eq!(err, "unterminated string");

        // Positive control: a fully-terminated string parses and compiles.
        let pol = parse("rule r:\n  block exec \"git\" because \"z\"\n")
            .expect("a terminated string parses");
        let _ = compile(&pol).expect("a terminated-string policy compiles");
    }

    /// Two `file` sources on the same path lower to byte-identical `CUpdate`
    /// tuples (same `op`/matcher/target/`ipv4`/`gate_exit_code`), differing only
    /// in the label bit they add. `add_update` must therefore coalesce them into
    /// a *single* update whose `add` mask carries both bits -- not two updates.
    ///
    /// The kernel engine walks `CConfig.updates` once and applies the first
    /// matching update, so a missed coalesce silently loses the second source's
    /// label: the process would carry only one source's taint. No test exercised
    /// this OR-dedup. Label bits come from `collect_label_names` (a `BTreeSet`),
    /// so `A` is bit 0 and `B` is bit 1 -- the coalesced `add` is deterministically
    /// `0b11`.
    #[test]
    fn same_path_sources_coalesce_into_one_update() {
        let pol = crate::dsl::parse::parse(
            r#"
            source A = file "/etc/passwd"
            source B = file "/etc/passwd"
            "#,
        )
        .expect("parse two same-path sources");
        let compiled = compile(&pol).expect("compile same-path sources");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };
        assert_eq!(cfg.n_updates, 1, "identical update tuples must coalesce");
        let u = &cfg.updates[0];
        assert_eq!(u.op, OP_OPEN, "a `file` source lowers to an open update");
        assert_eq!(u.m, M_EXACT, "a plain path lowers to an exact matcher");
        assert_eq!(
            u.add, 0b11,
            "both source label bits must land in the single coalesced update"
        );
        assert_eq!(u.del, 0, "sources only add labels");
    }

    /// The kernel blob is a fixed-size rodata region holding at most
    /// MAX_UPDATES update slots. A policy that declares more distinct source
    /// updates than the blob can hold must be rejected at compile time, not
    /// silently truncated (which would drop taint updates the engine relies
    /// on). Each distinct file source lowers to exactly one update, and
    /// reusing one label across 321 distinct paths keeps the label count
    /// (capped at 64) far below its limit, so only the update cap is tripped.
    #[test]
    fn update_overflow_beyond_max_updates_is_rejected() {
        // MAX_UPDATES = 320. s0..=s320 gives 321 distinct file sources, so
        // the 321st add_update sees updates.len() == 320 and trips the guard.
        let mut src = String::from("source A = file \"/s0\"\n");
        for i in 1..=MAX_UPDATES {
            src.push_str(&format!("source A = file \"/s{i}\"\n"));
        }
        match crate::dsl::parse::parse(&src).and_then(|p| compile(&p)) {
            Ok(_) => panic!("compile must fail past MAX_UPDATES"),
            Err(err) => {
                assert!(err.contains("too many event updates"), "wrong error: {err}");
            }
        }
    }

    /// `endorse` and `declassify` are opposite directions of the same xform:
    /// `endorse` *grants* a label on a gate exec, `declassify` *strips* it.
    /// They lower to a single exec update with the label bit placed in exactly
    /// one of `add` / `del` (lower.rs: `add: if endorse { bit } else { 0 },
    /// del: if endorse { 0 } else { bit }`). The kernel applies that as
    /// `ns.labels = (ns.labels | c.add) & ~c.del` (taint_engine.bpf.h:1610),
    /// so a flipped or dual-set mask silently grants where it should strip
    /// (or vice versa), inverting every rule gated on that label -- with no
    /// compile-time or blob-size symptom. Pin the direction, relative to the
    /// actually-allocated label bit so the assert is not brittle to slot order.
    #[test]
    fn endorse_and_declassify_set_opposite_add_del_directions() {
        let pol = crate::dsl::parse::parse(
            "source S1 = file \"**/.env\"\n\
             source S2 = file \"**/secrets.json\"\n\
             endorse S1 by exec \"**/approve\"\n\
             declassify S2 by exec \"**/redact\"\n\
             rule guard:\n\
               block exec \"git\" if S1\n\
               because \"approve before commit\"\n",
        )
        .expect("parse xform policy");
        let compiled = compile(&pol).expect("compile xform policy");
        let cfg: CConfig =
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) };

        let s1 = compiled.labels.get("S1").copied().expect("S1 label bit");
        let s2 = compiled.labels.get("S2").copied().expect("S2 label bit");

        // Locate the two exec updates by their lowered comm target.
        let updates = &cfg.updates[..cfg.n_updates as usize];
        let approve = updates
            .iter()
            .find(|u| u.op == OP_EXEC && &u.target[..6] == "approv".as_bytes())
            .expect("endorse exec update present");
        let redact = updates
            .iter()
            .find(|u| u.op == OP_EXEC && &u.target[..6] == "redact".as_bytes())
            .expect("declassify exec update present");

        // Endorse grants: the S1 bit goes into `add`, `del` stays clear.
        assert_eq!(approve.add, s1, "endorse carries S1 in `add`");
        assert_eq!(approve.del, 0, "endorse must not strip anything");
        // Declassify strips: the S2 bit goes into `del`, `add` stays clear.
        assert_eq!(redact.add, 0, "declassify must not grant anything");
        assert_eq!(redact.del, s2, "declassify carries S2 in `del`");

        // Both directions are mutually exclusive per update: a xform update
        // never grants and strips the same bit in one event.
        for u in updates {
            assert_eq!(
                u.add & u.del,
                0,
                "an update must not set the same bit in both `add` and `del`"
            );
        }

        // A `file` source grants its own label via `add` only (the control that
        // proves the xform `del` direction is specific to declassify).
        let env_src = updates
            .iter()
            .find(|u| u.op == OP_OPEN && u.add == s1)
            .expect("S1 source update present");
        assert_eq!(env_src.del, 0, "a source never strips a label");
    }

    #[test]
    fn xform_updates_emit_their_exec_gate_matcher_bytes() {
        // A `by exec` gate lowers through `lower_exec` into the xform
        // update's `CUpdate.m` + `CUpdate.target` (with an empty `arg`),
        // and the kernel matches the gate event's `comm` against those
        // bytes to decide when the label move fires. #60 pinned the
        // xform update's `add`/`del` *direction* (it located the update by
        // `op == OP_EXEC` + target prefix) but never pinned the `m`/`target`
        // matcher bytes or the empty `arg`, so a regression that dropped
        // `m` or truncated the gate basename would go uncaught.
        //
        // The decision: the same gate shape lowers to `M_EXACT` on a bare
        // basename (no wildcard) but `M_PREFIX` when it ends in `*` -- the
        // `lower_exec` dispatch #71 pinned for the comm target, here wired
        // into the xform update rather than a rule target.
        fn tgt(p: &[u8; PAT]) -> String {
            let end = p.iter().position(|b| *b == 0).unwrap_or(PAT);
            String::from_utf8_lossy(&p[..end]).into_owned()
        }
        fn cfg(src: &str) -> CConfig {
            let pol = crate::dsl::parse::parse(src).expect("parse policy");
            let compiled = compile(&pol).expect("compile policy");
            unsafe { std::ptr::read_unaligned(compiled.bytes.as_ptr() as *const CConfig) }
        }

        let g = cfg("source S = file \"/**/.env\"\n\
             endorse S by exec \"**/approve\"\n\
             source T = file \"/**/secrets.json\"\n\
             declassify T by exec \"build*\"\n\
             rule r:\n\
               block exec \"git\" if S\n\
               because \"approve before commit\"\n");
        let updates = &g.updates[..g.n_updates as usize];

        // `endorse` gate: bare basename, no wildcard -> M_EXACT.
        let endorse = updates
            .iter()
            .find(|u| u.op == OP_EXEC && &u.target[..7] == "approve".as_bytes())
            .expect("the endorse exec update is present");
        assert_eq!(endorse.m, M_EXACT, "bare basename gate -> exact match");
        assert_eq!(
            tgt(&endorse.target),
            "approve",
            "target is the lowered comm"
        );
        assert!(
            endorse.arg.iter().all(|b| *b == 0),
            "a gate has no positional arg"
        );

        // `declassify` gate: trailing `*` -> M_PREFIX on the stripped base.
        let declass = updates
            .iter()
            .find(|u| u.op == OP_EXEC && &u.target[..5] == "build".as_bytes())
            .expect("the declassify exec update is present");
        assert_eq!(declass.m, M_PREFIX, "`build*` gate -> prefix match");
        assert_eq!(tgt(&declass.target), "build", "target is the stripped base");
        assert!(
            declass.arg.iter().all(|b| *b == 0),
            "a gate has no positional arg"
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
    gate_bits: HashMap<(u8, u8, String, Option<u8>), (u64, u32)>,
    next_gate: u32,
    inval_slots: HashMap<(u8, u8, String, String), u32>,
    next_inval: u32,
    endpoint_cache: HashMap<String, Vec<(u32, u32)>>,
    endpoint_resolutions: HashMap<String, Vec<String>>,
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
    /// Exact hostname endpoint patterns that were resolved at compile time.
    /// Non-empty values are the IPv4 A records expanded into kernel matchers;
    /// an empty value means resolution was attempted but yielded no IPv4.
    pub endpoint_resolutions: HashMap<String, Vec<String>>,
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
                    vec![(tm, tlit, 0, 0)]
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
        endpoint_resolutions: ctx.endpoint_resolutions,
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

#[cfg(test)]
mod shorten_tests {
    use super::*;

    #[test]
    fn contains_literal_shortening_keeps_the_trailing_segment() {
        // Anything already within the kernel suffix budget passes through.
        assert_eq!(shorten_contains_literal("/etc/secret"), "/etc/secret");

        // Over budget: leading separators are stripped first.
        assert_eq!(
            shorten_contains_literal(&format!("/{}", "a".repeat(MAX_CONTAINS_LITERAL))),
            "a".repeat(MAX_CONTAINS_LITERAL)
        );

        // Otherwise the first `/` whose suffix fits the budget wins.
        let long = format!("{}/keep", "x".repeat(30));
        assert_eq!(shorten_contains_literal(&long), "keep");
    }

    #[test]
    fn contains_literal_shortening_falls_back_to_a_hard_suffix() {
        // No `/` appears, so the result is the last MAX_CONTAINS_LITERAL bytes.
        let single = "z".repeat(40);
        assert_eq!(
            shorten_contains_literal(&single),
            single[single.len() - MAX_CONTAINS_LITERAL..]
        );

        // Every candidate suffix is still too long, so the hard tail remains.
        let long = format!("{}/keep/{}", "x".repeat(20), "y".repeat(20));
        let out = shorten_contains_literal(&long);
        assert_eq!(out, "y".repeat(MAX_CONTAINS_LITERAL));
        assert!(long.ends_with(&out));
    }

    #[test]
    fn repo_relative_exact_shortening_prefers_a_nested_tail() {
        // Short paths are untouched.
        assert_eq!(
            shorten_repo_relative_exact_literal("src/main.rs"),
            "src/main.rs"
        );

        // The first `/` that leaves a nested, short-enough tail wins.
        let nested = format!("{}/a/b", "d".repeat(20));
        assert_eq!(shorten_repo_relative_exact_literal(&nested), "a/b");

        // With no nested short tail it defers to the parent directory.
        let flat = format!("dir/{}", "f".repeat(40));
        assert_eq!(shorten_repo_relative_exact_literal(&flat), "dir/");
    }
}
