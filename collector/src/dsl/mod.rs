// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! ActPlane taint DSL compiler: parse the DSL (docs/rule-language.md) and lower it
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
    use crate::config::{FileConfig, LoadedPolicy, policy_source};
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    fn ok(src: &str) -> Compiled {
        compile_str(src).expect("compile")
    }

    fn corpus_policy_sources() -> Vec<(PathBuf, String)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test/policies");
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|ent| ent.expect("policy dir entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
            .collect();
        paths.sort();
        assert!(
            !paths.is_empty(),
            "no YAML policy corpus files in {}",
            dir.display()
        );
        paths
            .into_iter()
            .map(|path| {
                let src = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                let cfg: FileConfig = serde_yaml::from_str(&src)
                    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
                let loaded = LoadedPolicy {
                    config: cfg,
                    root: PathBuf::new(),
                    path: None,
                };
                let policy = policy_source(&loaded, None)
                    .unwrap_or_else(|e| panic!("resolve {}: {e}", path.display()));
                (path, policy)
            })
            .collect()
    }

    #[test]
    fn e1_secret_no_exfil() {
        let c = ok(r#"
            source SECRET = file "**/.env"
            source SECRET = file "/etc/secrets/**"
            rule no-exfil:
              block connect endpoint "*"      if SECRET
              block write   file "/shared/**" if SECRET
              because "secret data must not leave the host"
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
              block exec "git" "push" if UNTRUST and not REVIEWED
              block exec "**/deploy*"         if UNTRUST and not REVIEWED
              because "untrusted input must not drive privileged actions"
            endorse REVIEWED by exec "**/human-approve"
        "#);
        assert_eq!(c.reasons.len(), 1);
    }

    #[test]
    fn e3_mandatory_mediation() {
        ok(r#"
            rule mediate-proddb:
              block open file "**/prod.db" unless lineage-includes exec "**/migrate"
              because "prod.db only via the migration tool"
        "#);
    }

    #[test]
    fn e4_workspace_confinement() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule confine-writes:
              block write  file "/**" if AGENT unless target "/work/**"
              block unlink file "/**" if AGENT unless target "/work/**"
              because "agent may only modify /work"
        "#);
    }

    #[test]
    fn e5_test_before_commit() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule test-before-commit:
              block exec "git" "commit" if AGENT unless after exec "**/pytest"
              because "run tests before committing"
        "#);
    }

    #[test]
    fn e5p_test_before_commit_since() {
        // v2 staleness: editing src after the gate makes the prior pytest stale.
        let c = ok(r#"
            source AGENT = exec "**/codex"
            rule test-before-commit:
              block exec "git" "commit"
                if AGENT
                unless after exec "**/pytest" since write "src/**" or write "tests/**"
              because "tests are stale — you edited code after the last run"
        "#);
        assert_eq!(c.reasons.len(), 1);
    }

    #[test]
    fn e11p_confirm_single_shot_since() {
        // v2: each force-push needs a fresh confirm (a later git makes it stale).
        ok(r#"
            source AGENT = exec "**/codex"
            rule confirm-destructive:
              block exec "git" "--force"
                if AGENT
                unless after exec "**/confirm" since exec "git"
              because "each force-push needs a fresh confirm"
        "#);
    }

    #[test]
    fn e13_migrate_check_since() {
        // v2: prod.db write needs a migration-check fresh w.r.t. the migrations.
        ok(r#"
            source AGENT = exec "**/codex"
            rule migrate-checked:
              block write file "**/prod.db"
                if AGENT
                unless after exec "**/migrate-check" since write "migrations/**"
            because "migration-check must have seen the current migrations"
        "#);
    }

    #[test]
    fn e14_stdio_channels_are_ifc_files() {
        ok(r#"
            source PROMPT = file "stdio:stdin"
            rule no-prompt-to-stdout:
              notify write file "stdio:stdout" if PROMPT
              notify write file "stdio:stderr" if PROMPT
              because "prompt-derived data should not be printed without review"
        "#);
    }

    #[test]
    fn since_without_clause_is_v1_latching() {
        // `after` with no `since` must still compile (v1 semantics, since_mask=0)
        // and produce the same fixed-size blob as a since-bearing policy.
        let v1 = ok(
            "rule r:\n  block exec \"git\" if A unless after exec \"**/pytest\"\n  because \"x\"\n",
        );
        let v2 = ok(
            "rule r:\n  block exec \"git\" if A unless after exec \"**/pytest\" since write \"src/**\"\n  because \"x\"\n",
        );
        assert_eq!(v1.bytes.len(), v2.bytes.len());
    }

    #[test]
    fn since_bad_invalidator_op_is_rejected() {
        assert!(compile_str(
            "rule r:\n  block exec \"git\" if A unless after exec \"**/pytest\" since connect \"*\"\n  because \"x\"\n"
        )
        .is_err());
    }

    #[test]
    fn e6_research_readonly() {
        ok(r#"
            source RESEARCH = exec "**/research-agent"
            rule research-readonly:
              block write   file "/**"   if RESEARCH
              block connect endpoint "*" if RESEARCH
              block exec    "git"        if RESEARCH
              because "research sub-agent is read-only"
        "#);
    }

    #[test]
    fn e7_e8_secret_with_declassify() {
        // same policy as E1; E7 (derivation) and E8 (declassify) are runtime behaviors
        ok(r#"
            source SECRET = file "**/.env"
            rule no-exfil:
              block connect endpoint "*" if SECRET
              because "no exfil"
            declassify SECRET by exec "**/redact"
        "#);
    }

    #[test]
    fn e9_cross_tool() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule no-git:
              block exec "git" if AGENT
              because "no git on any path"
        "#);
    }

    #[test]
    fn e10_pii_egress() {
        ok(r#"
            source PII = file "/data/customers/**"
            rule pii-egress:
              block connect endpoint "*" if PII unless target "*.internal"
              because "PII only to internal"
        "#);
    }

    #[test]
    fn e11_destructive_confirm() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule confirm-destructive:
              block exec "git" "--force" if AGENT unless after exec "**/confirm"
              block unlink file "/data/**"    if AGENT unless after exec "**/confirm"
              because "destructive needs confirm"
        "#);
    }

    #[test]
    fn e12_non_interference() {
        let c = ok(r#"
            source TASK_A = exec "**/task-a"
            source TASK_B = exec "**/task-b"
            rule no-cross-task-commit:
              block exec "git" "commit" if TASK_A and TASK_B
              because "no cross-task commit"
        "#);
        assert_eq!(c.reasons.len(), 1);
    }

    #[test]
    fn dnf_or_splits_into_multiple_rules() {
        // `if A or B` must compile to 2 kernel rules sharing one rule_id
        let a = compile_str("rule r:\n  block exec \"x\" if A\n  because \"z\"\n").unwrap();
        let b = compile_str("rule r:\n  block exec \"x\" if A or B\n  because \"z\"\n").unwrap();
        assert!(b.bytes.len() == a.bytes.len()); // fixed-size config
        assert_eq!(b.reasons.len(), 1);
    }

    #[test]
    fn config_blob_is_fixed_size() {
        // every policy produces the same fixed-size struct taint_config blob
        let a = ok("rule r:\n  block exec \"git\" if A\n  because \"x\"\n");
        let b = ok(
            "source S = file \"/x/**\"\nrule r:\n  block open file \"/y/**\" if S\n  because \"x\"\n",
        );
        assert_eq!(a.bytes.len(), b.bytes.len());
    }

    #[test]
    fn policy_corpus_files_compile() {
        let policies = corpus_policy_sources();
        let mut blob_len = None;
        for (path, src) in &policies {
            let compiled =
                compile_str(src).unwrap_or_else(|e| panic!("compile {}: {e}", path.display()));
            assert!(
                !compiled.meta.is_empty(),
                "{} should contain at least one rule",
                path.display()
            );
            if let Some(n) = blob_len {
                assert_eq!(
                    compiled.bytes.len(),
                    n,
                    "{} blob size drift",
                    path.display()
                );
            } else {
                blob_len = Some(compiled.bytes.len());
            }
        }
    }

    #[test]
    #[ignore = "run collector/test/policy-corpus.sh for the release microbench"]
    fn policy_corpus_compile_perf() {
        let policies = corpus_policy_sources();
        let rounds = std::env::var("ACTPLANE_POLICY_BENCH_ROUNDS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(200);

        for (_, src) in &policies {
            compile_str(src).expect("warmup compile");
        }

        let start = Instant::now();
        let mut bytes = 0usize;
        for _ in 0..rounds {
            for (_, src) in &policies {
                bytes += compile_str(src).expect("bench compile").bytes.len();
            }
        }
        let elapsed = start.elapsed();
        let total = rounds * policies.len();
        let us_per_policy = elapsed.as_secs_f64() * 1_000_000.0 / total as f64;
        eprintln!(
            "ActPlane IFC compile perf: {total} policies in {:.3}s = {:.2} us/policy ({} bytes)",
            elapsed.as_secs_f64(),
            us_per_policy,
            bytes
        );
        assert!(bytes > 0);
    }

    #[test]
    fn rule_effect_is_metadata_and_kernel_config() {
        let c = ok("rule r:\n  kill exec \"git\"\n  because \"x\"\n");
        assert_eq!(c.meta[0].effect, ast::Effect::Kill);
        assert!(c.bytes.len() > 0);
    }

    #[test]
    fn source_labels_are_allocated_for_runner_seeding() {
        let c = ok(
            "source AGENT = exec \"**/claude\"\nrule r:\n  block exec \"git\" if AGENT\n  because \"x\"\n",
        );
        assert!(c.labels.contains_key("AGENT"));
    }

    #[test]
    fn old_label_keyword_is_rejected() {
        assert!(
            compile_str("label AGENT\nrule r:\n  block exec \"git\" if AGENT\n  because \"x\"\n")
                .is_err()
        );
    }

    #[test]
    fn old_deny_keyword_is_rejected() {
        assert!(compile_str("rule r:\n  deny exec \"git\"\n  because \"x\"\n").is_err());
    }

    #[test]
    fn implicit_basename_matching() {
        // `exec "git"` should be equivalent to `exec "**/git"` — both produce
        // the same compiled output.
        let a = ok("rule r:\n  block exec \"git\" if A\n  because \"x\"\n");
        let b = ok("rule r:\n  block exec \"**/git\" if A\n  because \"x\"\n");
        assert_eq!(a.bytes, b.bytes);
    }

    #[test]
    fn positional_args_work() {
        // positional args (no @arg keyword) should compile successfully
        let c = ok("rule r:\n  kill exec \"git\" \"commit\" if A\n  because \"x\"\n");
        assert_eq!(c.meta[0].effect, ast::Effect::Kill);
    }

    #[test]
    fn multi_verb_rule_strongest_effect() {
        // When clauses have different effects, the rule's meta should
        // report the strongest effect.
        let c = ok(r#"
            rule mixed:
              notify exec "git" if A
              kill exec "make" if A
              because "mixed effects"
        "#);
        assert_eq!(c.meta[0].effect, ast::Effect::Kill);
    }
}
