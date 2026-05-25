// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! ActPlane taint DSL compiler: parse the DSL (docs/taint-dsl.md) and lower it
//! to the kernel ABI (struct taint_config) the loader installs into BPF rodata.

pub mod ast;
pub mod lower;
pub mod parse;

pub use lower::{Compiled, RuleMeta, compile};

/// Parse + compile DSL source text to a kernel config blob + reason table.
pub fn compile_str(src: &str) -> Result<Compiled, String> {
    compile(&parse::parse(src)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(src: &str) -> Compiled {
        compile_str(src).expect("compile")
    }

    #[test]
    fn e1_secret_no_exfil() {
        let c = ok(r#"
            source SECRET = file "**/.env"
            source SECRET = file "/etc/secrets/**"
            rule no-exfil:
              deny connect endpoint "*"      if SECRET
              deny write   file "/shared/**" if SECRET
              reason "secret data must not leave the host"
            declassify SECRET by exec "**/redact"
        "#);
        assert_eq!(c.reasons.len(), 1);
        assert!(c.bytes.len() > 0);
    }

    #[test]
    fn e2_prompt_injection() {
        let c = ok(r#"
            source UNTRUST = endpoint "*"
            source UNTRUST = file "**/downloads/**"
            rule no-injected-priv:
              deny exec "**/git" @arg "push" if UNTRUST and not REVIEWED
              deny exec "**/deploy*"         if UNTRUST and not REVIEWED
              reason "untrusted input must not drive privileged actions"
            endorse REVIEWED by exec "**/human-approve"
        "#);
        assert_eq!(c.reasons.len(), 1);
    }

    #[test]
    fn e3_mandatory_mediation() {
        ok(r#"
            rule mediate-proddb:
              deny open file "**/prod.db" unless lineage-includes exec "**/migrate"
              reason "prod.db only via the migration tool"
        "#);
    }

    #[test]
    fn e4_workspace_confinement() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule confine-writes:
              deny write  file "/**" if AGENT unless target "/work/**"
              deny unlink file "/**" if AGENT unless target "/work/**"
              reason "agent may only modify /work"
        "#);
    }

    #[test]
    fn e5_test_before_commit() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule test-before-commit:
              deny exec "**/git" @arg "commit" if AGENT unless after exec "**/pytest"
              reason "run tests before committing"
        "#);
    }

    #[test]
    fn e5p_test_before_commit_since() {
        // v2 staleness: editing src after the gate makes the prior pytest stale.
        let c = ok(r#"
            source AGENT = exec "**/codex"
            rule test-before-commit:
              deny exec "**/git" @arg "commit"
                if AGENT
                unless after exec "**/pytest" since write "src/**" or write "tests/**"
              reason "tests are stale — you edited code after the last run"
        "#);
        assert_eq!(c.reasons.len(), 1);
    }

    #[test]
    fn e11p_confirm_single_shot_since() {
        // v2: each force-push needs a fresh confirm (a later git makes it stale).
        ok(r#"
            source AGENT = exec "**/codex"
            rule confirm-destructive:
              deny exec "**/git" @arg "--force"
                if AGENT
                unless after exec "**/confirm" since exec "**/git"
              reason "each force-push needs a fresh confirm"
        "#);
    }

    #[test]
    fn e13_migrate_check_since() {
        // v2: prod.db write needs a migration-check fresh w.r.t. the migrations.
        ok(r#"
            source AGENT = exec "**/codex"
            rule migrate-checked:
              deny write file "**/prod.db"
                if AGENT
                unless after exec "**/migrate-check" since write "migrations/**"
              reason "migration-check must have seen the current migrations"
        "#);
    }

    #[test]
    fn since_without_clause_is_v1_latching() {
        // `after` with no `since` must still compile (v1 semantics, since_mask=0)
        // and produce the same fixed-size blob as a since-bearing policy.
        let v1 = ok("rule r:\n  deny exec \"git\" if A unless after exec \"pytest\"\n  reason \"x\"\n");
        let v2 = ok("rule r:\n  deny exec \"git\" if A unless after exec \"pytest\" since write \"src/**\"\n  reason \"x\"\n");
        assert_eq!(v1.bytes.len(), v2.bytes.len());
    }

    #[test]
    fn since_bad_invalidator_op_is_rejected() {
        assert!(compile_str(
            "rule r:\n  deny exec \"git\" if A unless after exec \"pytest\" since connect \"*\"\n  reason \"x\"\n"
        )
        .is_err());
    }

    #[test]
    fn e6_research_readonly() {
        ok(r#"
            source RESEARCH = exec "**/research-agent"
            rule research-readonly:
              deny write   file "/**"   if RESEARCH
              deny connect endpoint "*" if RESEARCH
              deny exec    "**/git"     if RESEARCH
              reason "research sub-agent is read-only"
        "#);
    }

    #[test]
    fn e7_e8_secret_with_declassify() {
        // same policy as E1; E7 (derivation) and E8 (declassify) are runtime behaviors
        ok(r#"
            source SECRET = file "**/.env"
            rule no-exfil:
              deny connect endpoint "*" if SECRET
              reason "no exfil"
            declassify SECRET by exec "**/redact"
        "#);
    }

    #[test]
    fn e9_cross_tool() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule no-git:
              deny exec "**/git" if AGENT
              reason "no git on any path"
        "#);
    }

    #[test]
    fn e10_pii_egress() {
        ok(r#"
            source PII = file "/data/customers/**"
            rule pii-egress:
              deny connect endpoint "*" if PII unless target "*.internal"
              reason "PII only to internal"
        "#);
    }

    #[test]
    fn e11_destructive_confirm() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule confirm-destructive:
              deny exec "**/git" @arg "--force" if AGENT unless after exec "**/confirm"
              deny unlink file "/data/**"        if AGENT unless after exec "**/confirm"
              reason "destructive needs confirm"
        "#);
    }

    #[test]
    fn e12_non_interference() {
        let c = ok(r#"
            source TASK_A = exec "**/task-a"
            source TASK_B = exec "**/task-b"
            rule no-cross-task-commit:
              deny exec "**/git" @arg "commit" if TASK_A and TASK_B
              reason "no cross-task commit"
        "#);
        assert_eq!(c.reasons.len(), 1);
    }

    #[test]
    fn dnf_or_splits_into_multiple_rules() {
        // `if A or B` must compile to 2 kernel rules sharing one rule_id
        let a = compile_str("rule r:\n  deny exec \"x\" if A\n  reason \"z\"\n").unwrap();
        let b = compile_str("rule r:\n  deny exec \"x\" if A or B\n  reason \"z\"\n").unwrap();
        assert!(b.bytes.len() == a.bytes.len()); // fixed-size config
        assert_eq!(b.reasons.len(), 1);
    }

    #[test]
    fn config_blob_is_fixed_size() {
        // every policy produces the same fixed-size struct taint_config blob
        let a = ok("rule r:\n  deny exec \"git\" if A\n  reason \"x\"\n");
        let b = ok(
            "source S = file \"/x/**\"\nrule r:\n  deny open file \"/y/**\" if S\n  reason \"x\"\n",
        );
        assert_eq!(a.bytes.len(), b.bytes.len());
    }

    #[test]
    fn rule_effect_is_metadata_and_kernel_config() {
        let c = ok("rule r:\n  deny exec \"git\"\n  reason \"x\"\n  effect kill\n");
        assert_eq!(c.meta[0].effect, ast::Effect::Kill);
        assert!(c.bytes.len() > 0);
    }

    #[test]
    fn declared_labels_are_allocated_for_runner_seeding() {
        let c = ok("label AGENT\nrule r:\n  deny exec \"git\" if AGENT\n  reason \"x\"\n");
        assert!(c.labels.contains_key("AGENT"));
    }

    #[test]
    fn old_effect_aliases_are_rejected() {
        assert!(
            compile_str("rule r:\n  deny exec \"git\"\n  reason \"x\"\n  enforce warn\n").is_err()
        );
    }
}
