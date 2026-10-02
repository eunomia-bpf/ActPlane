// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! ActPlane taint DSL compiler: parse the DSL (docs/rule-language.md) and lower it
//! to the kernel ABI (struct taint_config) the loader installs into BPF rodata.

pub mod ast;
pub mod lower;
pub mod parse;

use std::collections::HashMap;

pub use lower::{Compiled, RuleMeta, RuleSourceMeta, compile};

/// Parse + compile DSL source text to a kernel config blob + reason table.
pub fn compile_str(src: &str) -> Result<Compiled, String> {
    let mut compiled = compile(&parse::parse(src)?)?;
    attach_source_meta(&mut compiled, src);
    Ok(compiled)
}

/// Parse + compile DSL while preserving an existing label-bit dictionary.
///
/// Runtime policy deltas use this so a later delta in the same runtime domain
/// can refer to labels created by an earlier delta without silently changing
/// their bit positions.
pub fn compile_str_with_labels(
    src: &str,
    existing_labels: &HashMap<String, u64>,
) -> Result<Compiled, String> {
    let mut compiled = lower::compile_with_labels(&parse::parse(src)?, existing_labels)?;
    attach_source_meta(&mut compiled, src);
    Ok(compiled)
}

fn attach_source_meta(compiled: &mut Compiled, src: &str) {
    let spans = rule_source_spans(src);
    for meta in &mut compiled.meta {
        if let Some(span) = spans.iter().find(|span| span.name == meta.name) {
            let clause = span.clauses.get(meta.clause_source_index);
            meta.source = Some(RuleSourceMeta {
                source_ref: span.source_ref.clone(),
                binding_mode: span.binding_mode.clone(),
                start_line: span.start_line,
                end_line: span.end_line,
                text: span.text.clone(),
                clause_start_line: clause.map(|c| c.start_line),
                clause_end_line: clause.map(|c| c.end_line),
                clause_text: clause.map(|c| c.text.clone()),
            });
        }
    }
}

struct RuleSourceSpan {
    name: String,
    source_ref: String,
    binding_mode: Option<String>,
    start_line: usize,
    end_line: usize,
    text: String,
    clauses: Vec<ClauseSourceSpan>,
}

#[derive(Clone)]
struct ClauseSourceSpan {
    start_line: usize,
    end_line: usize,
    text: String,
}

fn rule_source_spans(src: &str) -> Vec<RuleSourceSpan> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut pending_source: Option<(String, Option<String>, usize)> = None;
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if let Some(rest) = trimmed.strip_prefix("# actplane-rule-source ") {
            let (source_ref, binding_mode) = parse_rule_source_marker(rest);
            pending_source = Some((source_ref, binding_mode, i + 1));
            i += 1;
            continue;
        }
        let Some(name) = parse_rule_decl_name(trimmed) else {
            i += 1;
            continue;
        };
        let marker = pending_source.take();
        let start = marker
            .as_ref()
            .map(|(_, _, text_start)| *text_start)
            .unwrap_or(i);
        let mut end = i + 1;
        while end < lines.len() {
            let t = lines[end].trim();
            if t.starts_with("# actplane-rule-source ") || is_top_level_decl(t) {
                break;
            }
            end += 1;
        }
        out.push(RuleSourceSpan {
            source_ref: marker
                .as_ref()
                .map(|(source_ref, _, _)| source_ref.clone())
                .unwrap_or_else(|| format!("rule:{name}")),
            binding_mode: marker.and_then(|(_, mode, _)| mode),
            name,
            start_line: start + 1,
            end_line: end,
            text: lines[start..end].join("\n"),
            clauses: clause_source_spans(&lines, i, end),
        });
        i = end;
    }
    out
}

fn clause_source_spans(lines: &[&str], rule_decl: usize, rule_end: usize) -> Vec<ClauseSourceSpan> {
    let mut out = Vec::new();
    let mut current: Option<usize> = None;
    let mut line = rule_decl + 1;
    while line < rule_end {
        let trimmed = lines[line].trim();
        if is_clause_head(trimmed) {
            if let Some(start) = current.take() {
                out.push(make_clause_source_span(lines, start, line));
            }
            current = Some(line);
        } else if trimmed.starts_with("because ") {
            break;
        }
        line += 1;
    }
    if let Some(start) = current {
        out.push(make_clause_source_span(lines, start, line));
    }
    out
}

fn make_clause_source_span(lines: &[&str], start: usize, end: usize) -> ClauseSourceSpan {
    ClauseSourceSpan {
        start_line: start + 1,
        end_line: end,
        text: lines[start..end].join("\n"),
    }
}

fn is_clause_head(trimmed: &str) -> bool {
    let mut words = trimmed.split_whitespace();
    let Some(effect) = words.next() else {
        return false;
    };
    if !matches!(effect, "notify" | "block" | "kill") {
        return false;
    }
    matches!(
        words.next(),
        Some("exec" | "read" | "write" | "unlink" | "connect" | "recv" | "open")
    )
}

fn parse_rule_source_marker(text: &str) -> (String, Option<String>) {
    let mut source_ref = None;
    let mut binding_mode = None;
    for part in text.split_whitespace() {
        if let Some(value) = part.strip_prefix("ref=") {
            source_ref = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("mode=") {
            binding_mode = Some(value.to_string());
        }
    }
    (
        source_ref.unwrap_or_else(|| "inline".to_string()),
        binding_mode,
    )
}

fn parse_rule_decl_name(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("rule ")?;
    let name = rest.split(':').next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn is_top_level_decl(trimmed: &str) -> bool {
    matches!(
        trimmed.split_whitespace().next(),
        Some("source" | "declassify" | "endorse" | "rule" | "label")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    fn ok(src: &str) -> Compiled {
        compile_str(src).expect("compile")
    }

    fn corpus_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/policies")
    }

    fn corpus_policy_sources() -> Vec<(PathBuf, String)> {
        let dir = corpus_dir();
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
            .flat_map(|path| {
                let src = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                yaml_policy_sources(&path, &src)
                    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
            })
            .collect()
    }

    fn yaml_policy_sources(path: &Path, src: &str) -> Result<Vec<(PathBuf, String)>, String> {
        let value: serde_yaml::Value = serde_yaml::from_str(src).map_err(|e| e.to_string())?;
        if let Some(policy) = yaml_get(&value, "policy").and_then(serde_yaml::Value::as_str) {
            return Ok(vec![(path.to_path_buf(), policy.to_string())]);
        }
        let Some(rules) = yaml_get(&value, "rules").and_then(serde_yaml::Value::as_mapping) else {
            return Ok(Vec::new());
        };
        let mut source = String::new();
        for (name, entry) in rules {
            let Some(rule_name) = name.as_str() else {
                continue;
            };
            let Some(ifc) = yaml_get(entry, "ifc")
                .or_else(|| yaml_get(entry, "policy"))
                .and_then(serde_yaml::Value::as_str)
            else {
                continue;
            };
            source.push_str("\n# actplane-rule-source ref=rules.");
            source.push_str(rule_name);
            source.push_str(".ifc mode=test\n# rule ");
            source.push_str(rule_name);
            source.push('\n');
            source.push_str(ifc.trim());
            source.push('\n');
        }
        Ok(vec![(path.to_path_buf(), source)])
    }

    fn yaml_get<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a serde_yaml::Value> {
        value
            .as_mapping()?
            .get(&serde_yaml::Value::String(key.to_string()))
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
        assert_eq!(c.reasons.len(), 2);
        assert!(c.bytes.len() > 0);
    }

    #[test]
    fn compile_with_labels_preserves_runtime_delta_label_bits() {
        let mut existing = HashMap::new();
        existing.insert("SECRET".to_string(), 1u64 << 7);
        let c = compile_str_with_labels(
            r#"
            source SECRET = file "**/.env"
            rule no-secret:
              notify exec "git" if SECRET and not REVIEWED
              because "secret data needs review"
            "#,
            &existing,
        )
        .expect("compile with existing labels");

        assert_eq!(c.labels.get("SECRET"), Some(&(1u64 << 7)));
        assert_eq!(c.labels.get("REVIEWED"), Some(&1u64));
    }

    /// `compile_str_with_labels` guards the runtime delta ABI: a delta policy
    /// is handed the label-bit map allocated by an *earlier* delta, and must
    /// reference those labels without shifting their bit positions. Before
    /// allocating new labels, `validate_label_bindings` rejects (never
    /// panics) any binding that would corrupt that ABI -- a zero or multi-bit
    /// mask, a bit claimed by two names, or an empty label name. Each of
    /// these would otherwise silently alias or shift a label onto another
    /// label's kernel bit and corrupt every later delta's `req`/`forbid`.
    #[test]
    fn compile_with_labels_rejects_invalid_label_bindings() {
        // A minimal parseable delta that references one pre-existing label.
        let delta = "rule d:\n  notify exec \"git\" if SECRET\n  because \"secret in use\"\n";

        // A zero mask collapses the label into the "no labels" state.
        let mut zero = HashMap::new();
        zero.insert("SECRET".to_string(), 0u64);
        assert!(
            compile_str_with_labels(delta, &zero).is_err(),
            "zero mask must be rejected"
        );

        // A multi-bit mask would seed two labels at once and break first-free
        // allocation for every subsequent label.
        let mut multi = HashMap::new();
        multi.insert("SECRET".to_string(), 0b11);
        assert!(
            compile_str_with_labels(delta, &multi).is_err(),
            "non-power-of-two mask must be rejected"
        );

        // A bit claimed by two names aliases two labels onto one kernel bit.
        let mut dup = HashMap::new();
        dup.insert("SECRET".to_string(), 1u64 << 3);
        dup.insert("REVIEWED".to_string(), 1u64 << 3);
        assert!(
            compile_str_with_labels(delta, &dup).is_err(),
            "duplicate bit assignment must be rejected"
        );

        // An empty label name is indistinguishable from "no label" downstream.
        let mut empty = HashMap::new();
        empty.insert(String::new(), 1u64 << 3);
        assert!(
            compile_str_with_labels(delta, &empty).is_err(),
            "empty label name must be rejected"
        );

        // Control: a well-formed distinct single-bit map still compiles, so the
        // rejections above are the guard, not a broken happy path.
        let mut good = HashMap::new();
        good.insert("SECRET".to_string(), 1u64 << 5);
        let c = compile_str_with_labels(delta, &good).expect("valid bindings compile");
        assert_eq!(c.labels.get("SECRET"), Some(&(1u64 << 5)));
    }

    #[test]
    fn rule_source_metadata_records_marker_span_and_text() {
        let c = compile_str(
            r#"# actplane-rule-source ref=rules.secret.ifc mode=locked
# rule secret
source SECRET = file "**/.env"
rule secret:
  block exec "git" if SECRET
  because "secret needs review"
"#,
        )
        .expect("compile");

        let source = c.meta[0].source.as_ref().expect("source metadata");
        assert_eq!(source.source_ref, "rules.secret.ifc");
        assert_eq!(source.binding_mode.as_deref(), Some("locked"));
        assert_eq!(source.start_line, 2);
        assert_eq!(source.end_line, 6);
        assert!(source.text.contains("source SECRET"));
        assert!(source.text.contains("rule secret:"));
        assert_eq!(source.clause_start_line, Some(5));
        assert_eq!(source.clause_end_line, Some(5));
        assert_eq!(
            source.clause_text.as_deref(),
            Some("  block exec \"git\" if SECRET")
        );
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
        assert_eq!(c.reasons.len(), 2);
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
    fn e5_test_before_commit_requires_successful_exit() {
        ok(r#"
            source AGENT = exec "**/codex"
            rule test-before-commit:
              block exec "git" "commit" if AGENT unless after exec "**/pytest" exits 0
              because "run tests successfully before committing"
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
    fn exits_is_only_valid_for_exec_gates() {
        assert!(compile_str(
            "rule r:\n  block exec \"git\" if A unless after read \"src/**\" exits 0\n  because \"x\"\n"
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
        // `if A or B` must compile to 2 kernel rules with exact metadata for
        // each lowered clause.
        let a = compile_str("rule r:\n  block exec \"x\" if A\n  because \"z\"\n").unwrap();
        let b = compile_str("rule r:\n  block exec \"x\" if A or B\n  because \"z\"\n").unwrap();
        assert!(b.bytes.len() == a.bytes.len()); // fixed-size config
        assert_eq!(b.reasons.len(), 2);
        assert_eq!(b.meta.len(), 2);
        assert_eq!(b.meta[0].name, "r");
        assert_eq!(b.meta[1].name, "r");
        assert_eq!(b.meta[0].clause_op, "exec");
        assert_eq!(b.meta[1].kernel_op, "exec");
    }

    #[test]
    fn config_blob_is_fixed_size() {
        const TAINT_CONFIG_SIZE: usize = 74_760;
        // every policy produces the same fixed-size struct taint_config blob
        let a = ok("rule r:\n  block exec \"git\" if A\n  because \"x\"\n");
        let b = ok(
            "source S = file \"/x/**\"\nrule r:\n  block open file \"/y/**\" if S\n  because \"x\"\n",
        );
        assert_eq!(a.bytes.len(), TAINT_CONFIG_SIZE);
        assert_eq!(a.bytes.len(), b.bytes.len());
    }

    #[test]
    fn policy_corpus_files_compile() {
        const TAINT_CONFIG_SIZE: usize = 74_760;
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
        assert_eq!(blob_len, Some(TAINT_CONFIG_SIZE));
    }

    #[test]
    fn domain_policy_corpus_all_domains_compile() {
        let dir = corpus_dir();
        let mut checked = 0usize;
        for ent in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        {
            let path = ent.expect("policy dir entry").path();
            if !path.extension().is_some_and(|ext| ext == "yaml") {
                continue;
            }
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let value: serde_yaml::Value = serde_yaml::from_str(&src)
                .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            if yaml_get(&value, "domains").is_none() {
                continue;
            }
            for (_, policy) in yaml_policy_sources(&path, &src)
                .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
            {
                let compiled = compile_str(&policy)
                    .unwrap_or_else(|e| panic!("compile {} rule bodies: {e}", path.display()));
                assert!(
                    !compiled.meta.is_empty(),
                    "{} should contain at least one rule body",
                    path.display()
                );
                checked += 1;
            }
        }
        assert!(checked >= 1, "expected domain policies in corpus");
    }

    #[test]
    #[ignore = "run test/policy-corpus.sh for the release microbench"]
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
    fn duplicate_rule_names_are_rejected() {
        let err = match compile_str(
            r#"
            rule same:
              notify exec "git" if true
              because "one"
            rule same:
              notify exec "make" if true
              because "two"
        "#,
        ) {
            Ok(_) => panic!("duplicate rule name compiled successfully"),
            Err(err) => err,
        };
        assert!(err.contains("duplicate rule name `same`"));
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
    fn multi_verb_rule_preserves_clause_effects() {
        // When clauses have different effects, each lowered rule keeps the
        // clause-level effect that the kernel will enforce.
        let c = ok(r#"
            rule mixed:
              notify exec "git" if A
              kill exec "make" if A
              because "mixed effects"
        "#);
        assert_eq!(c.meta.len(), 2);
        assert_eq!(c.meta[0].effect, ast::Effect::Notify);
        assert_eq!(c.meta[0].target_pattern, "**/git");
        assert_eq!(c.meta[1].effect, ast::Effect::Kill);
        assert_eq!(c.meta[1].target_pattern, "**/make");
        assert_eq!(
            c.meta[0]
                .source
                .as_ref()
                .and_then(|source| source.clause_text.as_deref()),
            Some("              notify exec \"git\" if A")
        );
        assert_eq!(
            c.meta[1]
                .source
                .as_ref()
                .and_then(|source| source.clause_text.as_deref()),
            Some("              kill exec \"make\" if A")
        );
    }

    #[test]
    fn duplicate_clause_targets_keep_distinct_source_spans() {
        let c = ok(r#"
            rule repeated:
              notify exec "git" if A
              notify exec "git" if B
              because "same operation, different label"
        "#);
        assert_eq!(c.meta.len(), 2);
        assert_eq!(c.meta[0].clause_source_index, 0);
        assert_eq!(c.meta[1].clause_source_index, 1);
        assert_eq!(
            c.meta[0]
                .source
                .as_ref()
                .and_then(|source| source.clause_text.as_deref()),
            Some("              notify exec \"git\" if A")
        );
        assert_eq!(
            c.meta[1]
                .source
                .as_ref()
                .and_then(|source| source.clause_text.as_deref()),
            Some("              notify exec \"git\" if B")
        );
    }

    #[test]
    fn attach_source_meta_synthesizes_rule_ref_for_marker_less_source() {
        // Every other source-meta test uses a `# actplane-rule-source` marker;
        // this pins the marker-less path, where `attach_source_meta` derives a
        // `rule:<name>` source_ref, leaves binding_mode unset, and maps each
        // meta entry to its own clause span via clause_source_index.
        let c = compile_str(
            "source SECRET = file \"**/.env\"\nrule multi:\n  block exec \"git\" if SECRET\n  kill write file \"**/leak\" if SECRET\n  because \"two clauses\"\n",
        )
        .expect("compile");
        assert_eq!(c.meta.len(), 2);
        assert!(c.meta.iter().all(|m| m.name == "multi"));

        let first = c.meta[0].source.as_ref().expect("source metadata");
        assert_eq!(first.source_ref, "rule:multi");
        assert_eq!(first.binding_mode, None);
        assert_eq!(first.start_line, 2);
        assert_eq!(first.end_line, 5);
        assert!(first.text.contains("rule multi:"));
        assert!(first.text.contains("because \"two clauses\""));
        assert_eq!(first.clause_start_line, Some(3));
        assert_eq!(first.clause_end_line, Some(3));
        assert_eq!(
            first.clause_text.as_deref(),
            Some("  block exec \"git\" if SECRET")
        );

        let second = c.meta[1].source.as_ref().expect("source metadata");
        assert_eq!(second.clause_start_line, Some(4));
        assert_eq!(second.clause_end_line, Some(4));
        assert_eq!(
            second.clause_text.as_deref(),
            Some("  kill write file \"**/leak\" if SECRET")
        );
    }

    #[test]
    fn is_clause_head_classifies_effect_and_verb_pairs() {
        // `is_clause_head` recognizes a clause head only when the first token
        // is one of the effects and the second is one of the operation verbs.
        let effects = ["notify", "block", "kill"];
        let verbs = ["exec", "read", "write", "unlink", "connect", "recv", "open"];
        // Every supported (effect, verb) pair is a clause head.
        for e in effects {
            for v in verbs {
                let head = format!("{e} {v}");
                assert!(is_clause_head(&head), "expected a clause head: {head}");
            }
        }
        // A clause head requires both a known effect and a known verb: an
        // unknown verb, an unknown effect, a bare effect, or an empty token
        // all fail.
        assert!(
            !is_clause_head("notify foo"),
            "an unknown verb must not be a clause head"
        );
        assert!(
            !is_clause_head("warn exec"),
            "an unknown effect must not be a clause head"
        );
        assert!(
            !is_clause_head("notify"),
            "a bare effect without a verb is not a clause head"
        );
        assert!(!is_clause_head(""), "an empty token is not a clause head");
    }

    #[test]
    fn make_clause_source_span_builds_a_one_based_line_span() {
        // `make_clause_source_span` maps a 0-based line range `[start, end)`
        // onto a 1-based source span: the recorded `start_line` is `start +
        // 1`, the recorded `end_line` is `end`, and the text is the joined
        // lines in `[start, end)`. No base test pins this mapping directly.
        let lines: Vec<&str> = vec!["a", "b", "c", "d", "e"];
        let s = make_clause_source_span(&lines, 1, 3);
        assert_eq!(s.start_line, 2);
        assert_eq!(s.end_line, 3);
        assert_eq!(s.text, "b\nc");
        // A single-line span: `start` and `end` coincide on the 0-based
        // index, so `start_line` == `end_line`.
        let s2 = make_clause_source_span(&lines, 0, 1);
        assert_eq!(s2.start_line, 1);
        assert_eq!(s2.end_line, 1);
        assert_eq!(s2.text, "a");
        // The exclusive end: the line at index `end` is not included.
        let s3 = make_clause_source_span(&lines, 2, 4);
        assert_eq!(s3.start_line, 3);
        assert_eq!(s3.end_line, 4);
        assert_eq!(s3.text, "c\nd");
    }

    #[test]
    fn clause_source_spans_extracts_heads_and_stops_at_because() {
        // `clause_source_spans` walks the lines between a rule declaration
        // (0-based `rule_decl`) and the exclusive `rule_end`, starting a new
        // clause at every clause head, stopping at the first `because` line,
        // and emitting a 1-based span for each head. No base test pins the
        // direct span extraction (the base test only checks the
        // `Compiled.meta` summary fields).
        let lines: Vec<&str> = vec![
            "rule guard:",
            "  block exec \"git\" if A",
            "  kill read \"x\" if B",
            "  because \"needs review\"",
        ];
        let sp = clause_source_spans(&lines, 0, 4);
        assert_eq!(sp.len(), 2);
        assert_eq!(sp[0].start_line, 2);
        assert_eq!(sp[0].end_line, 2);
        assert_eq!(sp[0].text, "  block exec \"git\" if A");
        assert_eq!(sp[1].start_line, 3);
        assert_eq!(sp[1].end_line, 3);
        assert_eq!(sp[1].text, "  kill read \"x\" if B");

        // Without a `because` line, every head up to `rule_end` is a clause.
        let lines2: Vec<&str> = vec![
            "rule guard:",
            "  block exec \"git\" if A",
            "  kill read \"x\" if B",
        ];
        let sp2 = clause_source_spans(&lines2, 0, 3);
        assert_eq!(sp2.len(), 2);
        assert_eq!(sp2[0].text, "  block exec \"git\" if A");
        assert_eq!(sp2[1].text, "  kill read \"x\" if B");

        // No clause heads in the block: no spans are emitted.
        let lines3: Vec<&str> = vec!["rule guard:", "because \"no clauses\""];
        let sp3 = clause_source_spans(&lines3, 0, 2);
        assert!(sp3.is_empty());
    }
    #[test]
    fn too_many_compiled_rules_are_rejected() {
        let mut src = String::from("source A = exec \"**\"\n");
        for i in 0..130 {
            src.push_str(&format!(
                "rule r{i}:\n  notify exec \"g{i}\" if A\n  because \"x{i}\"\n"
            ));
        }
        let err = compile_str(&src).err().expect("130 rules exceed the cap");
        assert_eq!(err, "too many compiled rules (130 > 128)");
    }

    #[test]
    fn too_many_gates_are_rejected() {
        let mut src = String::from("source A = exec \"**\"\nrule r:\n");
        for i in 0..66 {
            src.push_str(&format!(
                "  notify exec \"g\" if A unless after exec \"p{i}\"\n"
            ));
        }
        src.push_str("  because \"x\"\n");
        let err = compile_str(&src).err().expect("66 gates exceed the cap");
        assert_eq!(err, "too many gates");
    }
    #[test]
    fn unknown_ops_and_unless_conditions_are_named() {
        let op = compile_str("rule r:\n  notify frob \"g\" if true\n  because \"x\"\n")
            .err()
            .expect("unknown op");
        assert_eq!(op, "unknown op 'frob'");

        let unless = compile_str(
            "source A = exec \"**\"\nrule r:\n  block exec \"git\" if A unless frob \"x\"\n  because \"x\"\n",
        )
        .err()
        .expect("unknown unless cond");
        assert_eq!(unless, "unknown unless cond 'frob'");
    }

    #[test]
    fn source_targets_require_words_and_strings() {
        let word = compile_str("source = exec \"**\"\n")
            .err()
            .expect("missing word");
        assert_eq!(word, "expected word, got Some(Eq)");

        let string = compile_str("source A = exec 5\n")
            .err()
            .expect("word target");
        assert_eq!(string, "expected string, got Some(Word(\"5\"))");

        let kind = compile_str("rule r:\n  notify exec 5 if true\n  because \"x\"\n")
            .err()
            .expect("non-word target kind");
        assert_eq!(kind, "expected kind in target, got '5'");
    }

    #[test]
    fn event_update_table_rejects_overflow() {
        let mut src = String::new();
        for i in 0..64 {
            for j in 0..6 {
                src.push_str(&format!("source S{i} = exec \"c{i:02}_{j}\"\n"));
            }
        }
        for i in 0..64 {
            src.push_str(&format!(
                "rule r{i}:\n  notify exec \"z{i:03}\" if S{i}\n  because \"b\"\n"
            ));
        }
        let err = compile_str(&src).err().expect("overflows update table");
        assert_eq!(err, "too many event updates (321 > 320)");

        let mut smaller = String::new();
        for i in 0..64 {
            for j in 0..5 {
                smaller.push_str(&format!("source S{i} = exec \"c{i:02}_{j}\"\n"));
            }
        }
        for i in 0..64 {
            smaller.push_str(&format!(
                "rule r{i}:\n  notify exec \"z{i:03}\" if S{i}\n  because \"b\"\n"
            ));
        }
        let compiled = ok(&smaller);
        assert_eq!(compiled.meta.len(), 64);
    }
    #[test]
    fn gate_exit_codes_outside_byte_range_are_rejected() {
        let over = compile_str(
            "source A = exec \"**\"\nrule r:\n  block exec \"git\" if A unless after exec \"make\" exits 300\n  because \"x\"\n",
        )
        .err()
        .expect("exit code 300 must be rejected");
        assert_eq!(over, "expected exit code 0..255, got '300'");

        let negative = compile_str(
            "source A = exec \"**\"\nrule r:\n  block exec \"git\" if A unless after exec \"make\" exits 256\n  because \"x\"\n",
        )
        .err()
        .expect("exit code 256 must be rejected");
        assert_eq!(negative, "expected exit code 0..255, got '256'");
    }

    #[test]
    fn exit_codes_are_rejected_on_non_exec_gates() {
        let err = compile_str(
            "source A = exec \"**\"\nrule r:\n  block exec \"git\" if A unless after write \"x\" exits 0\n  because \"x\"\n",
        )
        .err()
        .expect("exits on a write gate must be rejected");
        assert_eq!(err, "`exits` is only valid on `after exec` gates");
    }
    #[test]
    fn unknown_kinds_and_missing_target_kinds_are_named() {
        let kind = compile_str("source A = frob \"x\"\n")
            .err()
            .expect("unknown kind");
        assert_eq!(kind, "unknown kind 'frob'");

        let node = compile_str("rule r:\n  notify connect \"x\" if true\n  because \"y\"\n")
            .err()
            .expect("connect target needs an endpoint node");
        assert_eq!(node, "expected node kind in target");
    }

    #[test]
    fn top_level_tokens_must_be_declarations() {
        let colon = compile_str(":\n").err().expect("bare colon");
        assert_eq!(colon, "expected declaration, got Colon");

        let string = compile_str("\"hello\"\n").err().expect("bare string");
        assert_eq!(string, "expected declaration, got Str(\"hello\")");
    }
    #[test]
    fn too_many_labels_are_rejected() {
        let mut src = String::new();
        for i in 0..65 {
            src.push_str(&format!("source E{i} = exec \"g{i}\"\n"));
        }
        let err = compile_str(&src).err().expect("65 labels exceed the cap");
        assert_eq!(err, "too many labels (max 64)");
    }

    #[test]
    fn too_many_since_invalidators_are_rejected() {
        let mut src = String::from("source A = exec \"**\"\nrule r:\n");
        for i in 0..66 {
            src.push_str(&format!(
                "  notify exec \"g\" if A unless after exec \"same\" since read \"f{i}\"\n"
            ));
        }
        src.push_str("  because \"x\"\n");
        let err = compile_str(&src)
            .err()
            .expect("66 invalidators exceed the cap");
        assert_eq!(err, "too many `since` invalidators (max 64)");
    }

    #[test]
    fn unsupported_after_gate_ops_are_named() {
        let err = compile_str(
            "source A = exec \"**\"\nrule r:\n  block exec \"git\" if A unless after recv \"x\"\n  because \"x\"\n",
        )
        .err()
        .expect("recv is not a supported gate");
        assert_eq!(
            err,
            "`after recv` is not supported as a gate (use exec/read/write)"
        );
    }
    #[test]
    fn lineage_includes_requires_the_exec_keyword() {
        let err = compile_str(
            "source A = exec \"**\"\nrule r:\n  block exec \"git\" if A unless lineage-includes frob \"x\"\n  because \"x\"\n",
        )
        .err()
        .expect("lineage-includes must be followed by `exec`");
        assert_eq!(err, "expected 'exec', got Some(Word(\"frob\"))");

        assert!(
            compile_str(
                "source A = exec \"**\"\nrule r:\n  block exec \"git\" if A unless lineage-includes exec \"x\"\n  because \"x\"\n"
            )
            .is_ok()
        );
    }
    #[test]
    fn removed_label_keyword_reports_replacement_hint() {
        let err =
            compile_str("label AGENT\nrule r:\n  block exec \"git\" if AGENT\n  because \"x\"\n")
                .err()
                .expect("`label` must be rejected");
        assert_eq!(
            err,
            "the `label` keyword has been removed; use `source` instead (e.g. `source AGENT = exec \"**/your-agent\"`)"
        );
    }

    #[test]
    fn parse_errors_name_the_offending_token() {
        let unknown = compile_str("frob X = exec \"**\"\n")
            .err()
            .expect("unknown decl");
        assert_eq!(unknown, "unknown declaration 'frob'");

        let unterminated = compile_str("source A = exec \"**\n")
            .err()
            .expect("unterminated");
        assert_eq!(unterminated, "unterminated string");

        let missing_colon = compile_str("rule r\n  notify exec \"g\" if true\n  because \"x\"\n")
            .err()
            .expect("missing rule colon");
        assert_eq!(
            missing_colon,
            "expected ':' after rule name, got Some(Word(\"notify\"))"
        );

        let missing_equals = compile_str("source A exec \"**\"\n")
            .err()
            .expect("missing source equals");
        assert_eq!(
            missing_equals,
            "expected '=' in source, got Some(Word(\"exec\"))"
        );
    }

    #[test]
    fn rule_source_spans_cover_multiple_rules_and_inline_fallback() {
        let spans = rule_source_spans(
            "\
# actplane-rule-source ref=rules.a.ifc mode=locked
source A = file \"**/a\"
rule one:
  notify exec \"a\" if A
  because \"one\"
# actplane-rule-source ref=rules.b.ifc
rule two:
  block write \"b\" if A
  because \"two\"
",
        );
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].name, "one");
        assert_eq!(spans[0].source_ref, "rules.a.ifc");
        assert_eq!(spans[0].binding_mode.as_deref(), Some("locked"));
        assert_eq!(spans[0].start_line, 2);
        assert_eq!(spans[0].end_line, 5);
        assert_eq!(spans[0].text.lines().count(), 4);
        assert_eq!(spans[1].name, "two");
        assert_eq!(spans[1].source_ref, "rules.b.ifc");
        assert_eq!(spans[1].binding_mode, None);

        let inline = rule_source_spans("rule lone:\n  kill read \"**\" if X\n  because \"l\"\n");
        assert_eq!(inline.len(), 1);
        assert_eq!(inline[0].source_ref, "rule:lone");
        assert_eq!(inline[0].start_line, 1);
    }

    #[test]
    fn clause_source_spans_stop_at_because_and_multiline_targets() {
        let lines = [
            "rule multi:",
            "  notify exec \"lookup\" \\",
            "    if SECRET",
            "  block write \"log\" if SECRET",
            "  because \"multi\"",
            "  notify exec \"after\" if SECRET",
        ];
        let spans = clause_source_spans(&lines, 0, lines.len());
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start_line, 2);
        assert_eq!(spans[0].end_line, 3);
        assert_eq!(spans[0].text, "  notify exec \"lookup\" \\\n    if SECRET");
        assert_eq!(spans[1].start_line, 4);
        assert_eq!(spans[1].end_line, 4);

        assert!(clause_source_spans(&["rule r:", "  because \"r\""], 0, 2).is_empty());
    }

    #[test]
    fn source_span_classifiers_accept_only_canonical_shapes() {
        assert!(is_clause_head("notify    exec \"x\""));
        assert!(is_clause_head("kill connect \"1.2.3.4\""));
        assert!(!is_clause_head("notify scan \"x\""));
        assert!(!is_clause_head("allow exec \"x\""));
        assert!(!is_clause_head("notify"));
        assert!(!is_clause_head("   "));

        assert!(is_top_level_decl("source A = file \"**\""));
        assert!(is_top_level_decl("rule r:"));
        assert!(is_top_level_decl("declassify A: exec \"x\""));
        // Callers pass an already-trimmed line; leading whitespace is inert.
        assert!(is_top_level_decl("  source A = file \"**\""));
        assert!(!is_top_level_decl("because \"r\""));

        assert_eq!(parse_rule_decl_name("rule ok:").as_deref(), Some("ok"));
        assert_eq!(
            parse_rule_decl_name("rule spaced : name").as_deref(),
            Some("spaced")
        );
        assert_eq!(parse_rule_decl_name("  rule inner:  "), None);
        assert_eq!(
            parse_rule_decl_name("ruled out"),
            None,
            "prefix match must require the space"
        );

        let (source_ref, mode) = parse_rule_source_marker("ref=rules.x.ifc mode=locked extra=1");
        assert_eq!(source_ref, "rules.x.ifc");
        assert_eq!(mode.as_deref(), Some("locked"));
        let (fallback, none) = parse_rule_source_marker("");
        assert_eq!(fallback, "inline");
        assert_eq!(none, None);
    }

    #[test]
    fn rule_decl_name_parses_the_rule_prefix_and_first_colon_segment() {
        // `parse_rule_decl_name` requires the literal `"rule "` prefix, then
        // takes the first `:`-separated segment (trimmed). It returns the
        // declared rule name, or `None` when the prefix is missing, the
        // segment is empty, or there is nothing after the prefix.
        // Standard `rule name:` form.
        assert_eq!(
            parse_rule_decl_name("rule guard:"),
            Some("guard".to_string())
        );
        // The name segment is also returned when no `:` is present; the
        // whole trimmed remainder is the name.
        assert_eq!(
            parse_rule_decl_name("rule guard"),
            Some("guard".to_string())
        );
        // Internal whitespace in the name is collapsed by the final trim.
        assert_eq!(
            parse_rule_decl_name("rule   spaced-name:"),
            Some("spaced-name".to_string())
        );
        // Only the first `:`-separated segment is the name; later segments
        // are ignored.
        assert_eq!(parse_rule_decl_name("rule a:b:"), Some("a".to_string()));
        // An empty segment (nothing after the prefix) is rejected.
        assert_eq!(parse_rule_decl_name("rule "), None);
        // A missing `"rule "` prefix (a `:` glued to `rule`, or a different
        // declaration) is rejected.
        assert_eq!(parse_rule_decl_name("rule:foo"), None);
        assert_eq!(parse_rule_decl_name("source secret:"), None);
    }

    #[test]
    fn rule_source_marker_parses_ref_and_mode_tokens() {
        // `parse_rule_source_marker` pulls `ref=` and `mode=` tokens out of the
        // rule-source marker. When no `ref=` token is present the source ref
        // falls back to `"inline"`; when no `mode=` token is present the
        // binding mode stays `None`.
        assert_eq!(parse_rule_source_marker(""), ("inline".to_string(), None));
        assert_eq!(
            parse_rule_source_marker("ref=docs/guide.md"),
            ("docs/guide.md".to_string(), None)
        );
        assert_eq!(
            parse_rule_source_marker("mode=strict"),
            ("inline".to_string(), Some("strict".to_string()))
        );
        assert_eq!(
            parse_rule_source_marker("ref=a/x.md mode=strict"),
            ("a/x.md".to_string(), Some("strict".to_string()))
        );
        // Each key is independent and the last occurrence of that key wins:
        // a repeated `ref=`/`mode=` overwrites the earlier value of the same
        // key without affecting the other key.
        assert_eq!(
            parse_rule_source_marker("ref=early.md mode=early ref=late.md"),
            ("late.md".to_string(), Some("early".to_string()))
        );
        assert_eq!(
            parse_rule_source_marker("mode=early ref=x.md mode=late"),
            ("x.md".to_string(), Some("late".to_string()))
        );
    }

    #[test]
    fn rule_source_spans_defaults_source_ref_and_shifts_span_for_a_marker() {
        // `rule_source_spans` records one span per `rule` declaration. With
        // no `# actplane-rule-source` marker, `source_ref` defaults to
        // `"rule:{name}"`, no binding mode is captured, and `start_line` is
        // the rule declaration line (1-based). No base test pins these
        // extraction defaults directly (the base test goes through
        // `Compiled.meta`).
        let spans = rule_source_spans("rule guard:\n  block exec \"git\" if A\n");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].source_ref, "rule:guard");
        assert_eq!(spans[0].binding_mode, None);
        assert_eq!(spans[0].name, "guard");
        assert_eq!(spans[0].start_line, 1);
        assert_eq!(spans[0].end_line, 2);
        assert_eq!(spans[0].clauses.len(), 1);

        // A `# actplane-rule-source` marker pulls `source_ref` / `binding_mode`
        // from the marker and shifts `start_line` down to include the marker
        // line.
        let spans = rule_source_spans(
            "# actplane-rule-source ref=r.secret mode=locked\nrule guard:\n  block exec \"git\" if A\n",
        );
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].source_ref, "r.secret");
        assert_eq!(spans[0].binding_mode, Some("locked".to_string()));
        assert_eq!(spans[0].name, "guard");
        assert_eq!(spans[0].start_line, 2);
        assert_eq!(spans[0].end_line, 3);

        // A source with no rule declarations yields no spans.
        assert!(rule_source_spans("").is_empty());
        assert!(rule_source_spans("\n  \n").is_empty());

        // Consecutive rules each default to their own name with no crosstalk.
        let spans = rule_source_spans(
            "rule one:\n  block exec \"git\" if A\nrule two:\n  block read \"x\" if B\n",
        );
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].source_ref, "rule:one");
        assert_eq!(spans[0].start_line, 1);
        assert_eq!(spans[0].end_line, 2);
        assert_eq!(spans[1].source_ref, "rule:two");
        assert_eq!(spans[1].start_line, 3);
        assert_eq!(spans[1].end_line, 4);
    }

    #[test]
    fn is_top_level_decl_matches_only_the_declaration_keyword_heads() {
        // `is_top_level_decl` recognizes a top-level declaration when the
        // first whitespace-separated token is one of the five declaration
        // keyword heads; only the first token is checked, so a following
        // argument (e.g. the rule name after `rule`) does not matter.
        let heads = ["source", "declassify", "endorse", "rule", "label"];
        for h in heads {
            assert!(
                is_top_level_decl(h),
                "expected `{h}` to be a top-level declaration head"
            );
            // A trailing argument does not change the classification.
            let headed = format!("{h} guard:");
            assert!(
                is_top_level_decl(&headed),
                "expected `{headed}` to be a top-level declaration head"
            );
        }
        // A non-keyword first token, or an empty token, is not a
        // top-level declaration.
        for bad in ["", "notify", "if"] {
            assert!(
                !is_top_level_decl(bad),
                "expected `{bad}` to not be a top-level declaration head"
            );
        }
    }
}
