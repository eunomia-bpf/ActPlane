//! Startup-time enforcement diagnostics.
//!
//! At `run`/`watch`/MCP-attach startup, a requested `block` clause only pre-denies
//! an operation when the BPF-LSM pre-operation hooks are attached. Without those
//! hooks, `block` is unsupported and the rule does not fire in tracepoint mode.
//! These diagnostics make that effective behavior prominent before the target runs.
//!
//! The capability gate reuses the engine's authoritative [`ebpf_ifc_engine::bpf_lsm_active`]
//! so tracepoint-forced runs and non-BPF-LSM hosts are treated identically to the
//! kernel loader. `doctor` already emits the same two degradation codes at
//! compile time (`bpf_lsm_inactive_for_block`, `argv_block_exec_post_exec_only`);
//! this surfaces them again at the moment the target actually starts.

use crate::dsl::Compiled;
use crate::dsl::ast::Effect;

/// Pure, host-independent core: compute the block-degradation warnings for a
/// compiled policy given whether BPF-LSM is active on the host.
///
/// One warning per `block` clause that cannot pre-deny:
/// - an argv-token `block exec` never pre-denies (argv is only available after
///   exec), regardless of BPF-LSM; and
/// - any other `block` clause is unsupported and does not fire while BPF-LSM is
///   not active.
///
/// Deterministic and deduplicated by message so it is safe to unit-test without
/// touching the host.
pub fn block_degradation_messages(compiled: &Compiled, lsm_active: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for meta in &compiled.meta {
        if meta.effect != Effect::Block {
            continue;
        }
        let ops = if meta.ops.is_empty() {
            "the operation".to_string()
        } else {
            meta.ops.join("/")
        };
        let msg = if meta.kernel_op == "exec" && meta.target_arg.is_some() {
            // Most specific: degrades even with BPF-LSM active.
            format!(
                "ActPlane: rule `{}` requests `block exec` with an argv token, but argv is only \
                 available after exec, so this `block` clause cannot enforce that argv-sensitive \
                 operation. Use `kill exec` if terminating the process is acceptable, or `notify` \
                 for report-only handling.",
                meta.name
            )
        } else if !lsm_active {
            format!(
                "ActPlane: rule `{}` requests `block` on {} but BPF-LSM is not active on this \
                 host, so the pre-operation block hook is not attached and this rule will not fire \
                 in tracepoint mode. Enable BPF-LSM to pre-deny, or use `notify`/`kill` for \
                 tracepoint-backed post-operation handling.",
                meta.name, ops
            )
        } else {
            continue;
        };
        if !out.iter().any(|existing| existing == &msg) {
            out.push(msg);
        }
    }
    out
}

/// Compute the block-degradation warnings for a compiled policy using the host's
/// actual BPF-LSM state (honors `ACTPLANE_FORCE_TRACEPOINT`).
pub fn block_degradation_warnings(compiled: &Compiled) -> Vec<String> {
    block_degradation_messages(compiled, ebpf_ifc_engine::bpf_lsm_active())
}

/// Print each block-degradation warning to stderr. Non-blocking: the engine still
/// runs; this only names the effective behavior.
pub fn print_block_degradation_warnings(compiled: &Compiled) {
    for msg in block_degradation_warnings(compiled) {
        eprintln!("{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{RuleMeta, ast::Effect as AstEffect};

    fn meta(name: &str, effect: AstEffect, kernel_op: &str, target_arg: Option<&str>) -> RuleMeta {
        RuleMeta {
            name: name.to_string(),
            reason: "test".to_string(),
            effect,
            ops: vec![kernel_op.to_string()],
            clause_op: kernel_op.to_string(),
            kernel_op: kernel_op.to_string(),
            target_kind: crate::dsl::ast::Kind::File,
            target_pattern: "x".to_string(),
            target_arg: target_arg.map(str::to_string),
            clause_source_index: 0,
            source: None,
        }
    }

    fn compiled(rules: Vec<RuleMeta>) -> Compiled {
        Compiled {
            bytes: Vec::new(),
            reasons: rules.iter().map(|m| m.reason.clone()).collect(),
            meta: rules,
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn all_clear_when_lsm_active_and_no_argv_exec() {
        let c = compiled(vec![
            meta("r1", AstEffect::Block, "open", None),
            meta("r2", AstEffect::Notify, "open", None),
        ]);
        assert!(block_degradation_messages(&c, true).is_empty());
    }

    #[test]
    fn block_degrades_when_lsm_inactive() {
        let c = compiled(vec![meta("r1", AstEffect::Block, "open", None)]);
        let msgs = block_degradation_messages(&c, false);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("rule `r1`"), "{:?}", msgs);
        assert!(msgs[0].contains("BPF-LSM is not active"));
        assert!(msgs[0].contains("will not fire"));
    }

    #[test]
    fn argv_exec_block_degrades_even_when_lsm_active() {
        let c = compiled(vec![meta("r1", AstEffect::Block, "exec", Some("-rf"))]);
        let active = block_degradation_messages(&c, true);
        assert!(active[0].contains("argv"), "{:?}", active);
        assert!(active[0].contains("kill exec"), "{:?}", active);
    }

    #[test]
    fn argv_exec_block_uses_specific_message_not_lsm_message() {
        // Even without LSM, the argv-specific warning wins over the generic one.
        let c = compiled(vec![meta("r1", AstEffect::Block, "exec", Some("-rf"))]);
        let msgs = block_degradation_messages(&c, false);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("argv"));
        assert!(!msgs[0].contains("BPF-LSM is not active"));
    }

    #[test]
    fn kill_and_notify_never_warn() {
        let c = compiled(vec![
            meta("k", AstEffect::Kill, "open", None),
            meta("n", AstEffect::Notify, "open", None),
        ]);
        assert!(block_degradation_messages(&c, false).is_empty());
    }

    #[test]
    fn real_dsl_argv_exec_block_fires_even_with_lsm() {
        let c = crate::dsl::compile_str(
            r#"
            source AGENT = exec "**/codex"
            rule no-push:
              block exec "git" "push" if AGENT
              because "no pushes"
            "#,
        )
        .expect("compile real policy");
        let msgs = block_degradation_messages(&c, true);
        assert_eq!(msgs.len(), 1, "argv exec block must degrade: {msgs:?}");
        assert!(msgs[0].contains("no-push"), "{msgs:?}");
        assert!(msgs[0].contains("argv"), "{msgs:?}");
    }
}
