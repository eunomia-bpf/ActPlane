// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! ActPlane taint DSL compiler: parse the DSL (docs/rule-language.md) and lower it
//! to the kernel ABI (struct taint_config) the loader installs into BPF rodata.

pub mod ast;
pub mod lower;
pub mod parse;

use std::collections::HashMap;

pub use lower::{
    Compiled, PATTERN_EMPTY_LITERAL, PATTERN_MATCHER_LENGTH, PATTERN_TRUNCATED,
    PATTERN_WARNING_CODES, PatternWarning, RULE_CONDITION_CONTRADICTION,
    RULE_CONDITION_COVERS_TARGET, RULE_CONDITION_LABEL_WITHOUT_PRODUCER,
    RULE_CONDITION_WARNING_CODES, RUNTIME_SEEDED_LABELS, RuleMeta, RuleSourceMeta, compile,
    is_numeric_endpoint_pattern, repo_relative_condition_is_partial,
};

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
    fn since_argv_token_is_only_valid_for_exec() {
        // The kernel matches a `since` update's `arg` only on exec events
        // (taint_engine.bpf.h te_file_update_cb ignores it), so an ARG on a
        // path invalidator would lower into the blob and then never match.
        // Reject it so the miscompile is not silent.
        assert!(compile_str(
            "rule r:\n  block exec \"git\" if A unless after exec \"**/pytest\" since write \"src/**\" \"token\"\n  because \"x\"\n"
        )
        .is_err());
        // The exec form stays valid and carries the token.
        ok(
            "rule r:\n  block exec \"git\" if A unless after exec \"**/pytest\" since exec \"pnpm\" \"test\"\n  because \"x\"\n",
        );
    }

    #[test]
    fn exits_is_only_valid_for_exec_gates() {
        assert!(compile_str(
            "rule r:\n  block exec \"git\" if A unless after read \"src/**\" exits 0\n  because \"x\"\n"
        )
        .is_err());
    }

    #[test]
    fn target_kind_must_match_the_operation() {
        // The grammar pairs each op with one kind (`connect`/`recv` with
        // `endpoint`, file/exec ops with `file`/`exec`). The kind word drives
        // the endpoint_support warnings and the approval signature, so a wrong
        // word would lower to the same blob while skipping the diagnostics that
        // the correct spelling reports. Reject the mismatch instead.
        for bad in [
            "rule r:\n  notify connect file \"/work/**\"\n  because \"x\"\n",
            "rule r:\n  notify recv file \"**\"\n  because \"x\"\n",
            "rule r:\n  notify read endpoint \"*\"\n  because \"x\"\n",
            "rule r:\n  notify write endpoint \"*\"\n  because \"x\"\n",
            "rule r:\n  notify exec file \"git\"\n  because \"x\"\n",
        ] {
            assert!(compile_str(bad).is_err(), "should reject: {bad}");
        }
        // The grammar's pairings still compile, including the bare exec form.
        ok(
            "rule r:\n  notify connect endpoint \"**\"\n  because \"x\"\nrule s:\n  notify read file \"**\"\n  because \"y\"\nrule t:\n  notify exec \"git\"\n  because \"z\"\n",
        );
    }

    #[test]
    fn rule_without_clauses_is_rejected() {
        // The grammar is `clause+`, but the parser accepted a `rule` with only
        // a `because` (or nothing), which lowered to zero kernel matchers and
        // enforced nothing with no warning. Reject it so the silent no-op
        // becomes a compile error.
        assert!(compile_str("rule r:\n  because \"x\"\n").is_err());
        assert!(compile_str("rule r:\n").is_err());
        ok("rule r:\n  notify exec \"git\"\n  because \"x\"\n");
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

    /// Codes present in a compiled policy's pattern warnings.
    fn warning_codes(c: &Compiled) -> Vec<&'static str> {
        c.pattern_warnings.iter().map(|w| w.code).collect()
    }

    #[test]
    fn long_pattern_literal_is_reported_as_truncated() {
        // Kernel pattern fields hold 63 usable bytes, so a longer literal is
        // stored as a prefix. For an exact absolute path that means the rule can
        // never match the intended target, so the compiler must report it rather
        // than silently compiling a different rule.
        let long = "/var/lib/some/deeply/nested/directory/structure/that/is/very/long/target.txt";
        assert!(long.len() > 63);
        let compiled = ok(&format!(
            "source A = exec \"a\"\nrule r:\n  block write file \"{long}\" if A\n  because \"x\"\n"
        ));
        assert_eq!(
            warning_codes(&compiled),
            vec![lower::PATTERN_TRUNCATED],
            "one truncation expected: {:?}",
            compiled.pattern_warnings
        );
        assert!(
            compiled.pattern_warnings[0].message.contains(long),
            "message should name the literal: {}",
            compiled.pattern_warnings[0].message
        );

        // A literal that fits is stored whole and reported not at all.
        let short = ok(
            "source A = exec \"a\"\nrule r:\n  block write file \"/tmp/short.txt\" if A\n  because \"x\"\n",
        );
        assert!(
            short.pattern_warnings.is_empty(),
            "short literal must not be reported: {:?}",
            short.pattern_warnings
        );
    }

    #[test]
    fn over_bound_suffix_literal_is_reported() {
        // `taint_suffix` rejects any literal longer than TAINT_SUF_MAX (16), so a
        // `**/<long name>` pattern lowers to a literal the matcher can never
        // accept, i.e. a rule that never fires. That must be reported, and it is
        // a distinct failure from truncation.
        let compiled = ok(
            "source A = exec \"a\"\nrule r:\n  block write file \"**/*config.production.json\" if A\n  because \"x\"\n",
        );
        assert_eq!(
            warning_codes(&compiled),
            vec![lower::PATTERN_MATCHER_LENGTH],
            "one over-bound literal expected: {:?}",
            compiled.pattern_warnings
        );
        assert!(
            compiled.pattern_warnings[0]
                .message
                .contains("config.production.json"),
            "message should name the literal: {}",
            compiled.pattern_warnings[0].message
        );

        // A basename within the bound lowers to a usable suffix literal.
        let short = ok(
            "source A = exec \"a\"\nrule r:\n  notify write file \"**/.env\" if A\n  because \"x\"\n",
        );
        assert!(
            short.pattern_warnings.is_empty(),
            "in-bound suffix must not be reported: {:?}",
            short.pattern_warnings
        );
    }

    #[test]
    fn over_bound_suffix_literal_with_a_live_companion_is_not_reported_as_dead() {
        // A repo-relative `**/<name>` target also emits a bare `exact`
        // companion, and `exact` has no length bound, so an over-bound suffix
        // primary leaves the rule alive for the bare form. The message must say
        // which entry dies instead of claiming the pattern can never match.
        let long = "a".repeat(27);
        let compiled = ok(&format!(
            "source A = exec \"a\"\nrule r:\n  block write file \"**/{long}\" if A\n  because \"x\"\n"
        ));
        assert_eq!(
            warning_codes(&compiled),
            vec![lower::PATTERN_MATCHER_LENGTH],
            "one over-bound literal expected: {:?}",
            compiled.pattern_warnings
        );
        let message = &compiled.pattern_warnings[0].message;
        assert!(
            !message.contains("so the pattern can never match"),
            "a live exact companion keeps the pattern alive: {message}"
        );
        assert!(
            message.contains("this suffix entry can never match") && message.contains(&long),
            "message should scope the death to the entry and name the companion: {message}"
        );

        // A `**/*<name>` target lowers to a lone suffix entry with no companion,
        // so there the whole pattern really is dead.
        let compiled = ok(&format!(
            "source A = exec \"a\"\nrule r:\n  block write file \"**/*{long}\" if A\n  because \"x\"\n"
        ));
        assert!(
            compiled.pattern_warnings[0]
                .message
                .contains("so the pattern can never match"),
            "a companion-less form is dead: {}",
            compiled.pattern_warnings[0].message
        );
    }

    #[test]
    fn over_bound_suffix_literal_is_not_also_reported_as_truncated() {
        // A `suffix`/`contains` literal is compared against a fixed 16-byte
        // tail/window, so any literal long enough to be truncated (>63 bytes)
        // is necessarily still past that bound and never matches at all. The
        // truncation warning would then both duplicate and, worded as "matches
        // that prefix", contradict `pattern_matcher_length_exceeded` on the
        // same entry, so only the length bound is reported.
        let long = "x".repeat(70);
        let compiled = ok(&format!(
            "source A = exec \"a\"\nrule r:\n  block write file \"**/*{long}\" if A\n  because \"x\"\n"
        ));
        assert_eq!(
            warning_codes(&compiled),
            vec![lower::PATTERN_MATCHER_LENGTH],
            "a dead suffix entry is reported once: {:?}",
            compiled.pattern_warnings
        );

        // An absolute literal lowers to `PREFIX`/`EXACT`, where the stored
        // prefix really does keep matching, so the truncation consequence is
        // both true and distinct, and must still be reported.
        let compiled = ok(&format!(
            "source A = exec \"a\"\nrule r:\n  block write file \"/tmp/{long}\" if A\n  because \"x\"\n"
        ));
        assert_eq!(
            warning_codes(&compiled),
            vec![lower::PATTERN_TRUNCATED],
            "a prefix literal keeps its truncation warning: {:?}",
            compiled.pattern_warnings
        );
        assert!(
            compiled.pattern_warnings[0]
                .message
                .contains("matches that prefix"),
            "prefix wording expected: {}",
            compiled.pattern_warnings[0].message
        );
    }

    #[test]
    fn empty_literal_pattern_is_reported() {
        // Every non-ANY matcher rejects an empty pattern (`taint_streq`,
        // `taint_prefix` and `taint_contains` all guard on a zero pattern
        // length), so a pattern that lowers to an empty literal can never fire:
        // `exec "src/*"` and `exec "foo/"` both do. `*` is not affected, since
        // ANY always matches and is meant to carry an empty literal. The last
        // two policies keep concrete text *after* a leading wildcard, so the
        // wildcard-literal cleanup discards it while leaving an empty span: the
        // result is a strict subset of the glob, not a strict widening, so
        // `PATTERN_LITERAL_WIDENED` must NOT also fire and claim the matcher
        // "matches strictly more".
        for policy in [
            "source A = exec \"a\"\nrule r:\n  kill exec \"src/*\" if A\n  because \"x\"\n",
            "source A = exec \"a\"\nrule r:\n  kill exec \"foo/\" if A\n  because \"x\"\n",
            "rule r:\n  kill exec \"*g*t\"\n  because \"x\"\n",
            "rule r:\n  kill write file \"**/*b/*\"\n  because \"x\"\n",
        ] {
            let compiled = ok(policy);
            assert_eq!(
                warning_codes(&compiled),
                vec![lower::PATTERN_EMPTY_LITERAL],
                "{policy:?} should report one empty literal: {:?}",
                compiled.pattern_warnings
            );
        }
        let any = ok("source A = exec \"a\"\nrule r:\n  kill exec \"*\" if A\n  because \"x\"\n");
        assert!(
            any.pattern_warnings.is_empty(),
            "ANY is exempt: {:?}",
            any.pattern_warnings
        );
    }

    #[test]
    fn a_literal_warning_names_the_construct_it_came_from() {
        // The message is the corrective-feedback payload, so "event target"
        // tells the reader nothing when the literal actually came from a
        // source, gate, xform, or invalidator. Every update site names itself
        // the way the widened/capped warnings already did.
        let first = |policy: &str, code: &str| {
            let c = ok(policy);
            c.pattern_warnings
                .iter()
                .find(|w| w.code == code)
                .unwrap_or_else(|| panic!("{code} not emitted for {policy:?}"))
                .message
                .clone()
        };
        let cases = [
            (
                "source target",
                "source A = exec \"src/*\"\nrule r:\n  kill exec \"git\" if A\n  because \"x\"\n",
            ),
            (
                "gate target",
                "source A = exec \"a\"\nrule r:\n  kill exec \"git\" if A unless after exec \"src/*\"\n  because \"x\"\n",
            ),
            (
                "transform gate",
                "source A = exec \"a\"\nendorse X by exec \"src/*\"\nrule r:\n  kill exec \"git\" if A\n  because \"x\"\n",
            ),
            (
                "invalidator target",
                "source A = exec \"a\"\nrule r:\n  kill exec \"git\" if A unless after exec \"**/pytest\" since exec \"src/*\"\n  because \"x\"\n",
            ),
            (
                "rule target",
                "source A = exec \"a\"\nrule r:\n  kill exec \"src/*\" if A\n  because \"x\"\n",
            ),
        ];
        for (what, policy) in cases {
            let msg = first(policy, lower::PATTERN_EMPTY_LITERAL);
            assert!(
                msg.starts_with(&format!("{what} ")),
                "{policy:?} should name `{what}`, got: {msg}"
            );
            assert!(
                !msg.contains("event target"),
                "`{what}` must not fall back to the generic label: {msg}"
            );
        }
        // Truncation carries the same label, so pin one non-empty case too.
        let long = "/var/lib/some/deeply/nested/directory/structure/that/is/very/long/target.txt";
        let msg = first(
            &format!(
                "source A = file \"{long}\"\nrule r:\n  kill open file \"/x\" if A\n  because \"x\"\n"
            ),
            lower::PATTERN_TRUNCATED,
        );
        assert!(msg.starts_with("source target "), "got: {msg}");
        // The arg diagnostic follows the same rule: only a gate/invalidator
        // carries a non-empty arg, and the arg borrows the construct's name.
        let arg = "x".repeat(80);
        let msg = first(
            &format!(
                "source A = exec \"a\"\nrule r:\n  kill exec \"git\" if A unless after exec \"**/pnpm\" \"{arg}\"\n  because \"x\"\n"
            ),
            lower::PATTERN_TRUNCATED,
        );
        assert!(msg.starts_with("gate arg "), "got: {msg}");
        let msg = first(
            &format!(
                "source A = exec \"a\"\nrule r:\n  kill exec \"git\" if A unless after exec \"**/pytest\" since exec \"**/pnpm\" \"{arg}\"\n  because \"x\"\n"
            ),
            lower::PATTERN_TRUNCATED,
        );
        assert!(msg.starts_with("invalidator arg "), "got: {msg}");
    }

    #[test]
    fn capped_literal_emptied_by_wildcard_cleanup_is_not_also_reported_as_capped() {
        // The cap can shorten a literal to a span the wildcard cleanup then
        // empties: `**/a...a/*x` caps to `*x`, which cleans to `""`. An empty
        // literal makes every non-`ANY` matcher reject the entry, so
        // `pattern_contains_capped` ("matches strictly more than the glob") is
        // false there and contradicts `pattern_empty_literal` on the same
        // entry. Only the empty-literal consequence is reported.
        let policy =
            "rule r:\n  block write file \"**/aaaaaaaaaaaaaaaaaaaa/*x\"\n  because \"x\"\n";
        assert_eq!(
            warning_codes(&ok(policy)),
            vec![lower::PATTERN_EMPTY_LITERAL],
            "an emptied capped literal is reported once"
        );

        // A cap that leaves concrete text still widens the matcher, so the
        // capped warning must survive.
        let policy =
            "rule r:\n  block write file \"**/src/components/deep/nested/**\"\n  because \"x\"\n";
        assert_eq!(
            warning_codes(&ok(policy)),
            vec![lower::PATTERN_CONTAINS_CAPPED],
            "a capped literal with concrete text is still reported"
        );
    }

    #[test]
    fn dsl_rule_count_is_distinct_from_the_lowered_matcher_count() {
        // A repo-relative pattern that also emits a bare `exact` companion
        // lowers one DSL rule to two kernel matchers. Reporting `meta.len()` as
        // a rule count then overstates the policy, which is what `--explain`
        // already separates; `dsl_rule_count` is the count a reader gets by
        // counting the policy text.
        let c = ok("rule r:\n  block write file \"**/config.production.json\"\n  because \"x\"\n");
        assert_eq!(c.dsl_rule_count, 1);
        assert_eq!(c.meta.len(), 2, "primary plus a companion matcher");

        // Distinct DSL rules stay distinct: one clause per rule here.
        let c = ok(
            "rule a:\n  block exec \"git\" if true\n  because \"x\"\nrule b:\n  block exec \"make\" if true\n  because \"y\"\n",
        );
        assert_eq!(c.dsl_rule_count, 2);
        assert_eq!(c.meta.len(), 2);
    }

    #[test]
    fn every_pattern_warning_code_is_reachable() {
        // `PATTERN_WARNING_CODES` is what the CLI's doc-completeness guard
        // iterates, so a code listed there but never emitted would demand
        // documentation for a warning no policy can produce. Pin each code to a
        // policy that emits it, so the list stays exactly the emitted set.
        let triggered = [
            (
                lower::PATTERN_TRUNCATED,
                "rule r:\n  block write file \"/var/lib/some/deeply/nested/directory/structure/that/is/very/long/target.txt\" if A\n  because \"x\"\n",
            ),
            (
                lower::PATTERN_EMPTY_LITERAL,
                "rule r:\n  kill exec \"src/*\" if A\n  because \"x\"\n",
            ),
            (
                lower::PATTERN_MATCHER_LENGTH,
                "rule r:\n  block write file \"**/*config.production.json\" if A\n  because \"x\"\n",
            ),
            (
                lower::PATTERN_LITERAL_WIDENED,
                "rule r:\n  block exec \"g*t\" if A\n  because \"x\"\n",
            ),
            (
                lower::PATTERN_CONTAINS_CAPPED,
                "rule r:\n  block write file \"**/src/components/deep/nested/**\" if A\n  because \"x\"\n",
            ),
        ];
        assert_eq!(
            triggered.len(),
            PATTERN_WARNING_CODES.len(),
            "every code in PATTERN_WARNING_CODES needs a trigger policy here"
        );
        for (code, policy) in triggered {
            assert!(
                PATTERN_WARNING_CODES.contains(&code),
                "{code} is emitted but missing from PATTERN_WARNING_CODES"
            );
            let codes = warning_codes(&ok(policy));
            assert!(
                codes.contains(&code),
                "{policy:?} should emit {code}, got {codes:?}"
            );
        }
    }

    #[test]
    fn every_rule_condition_warning_code_is_reachable() {
        // `RULE_CONDITION_WARNING_CODES` is the second list the CLI's
        // doc-completeness guard iterates, so it carries the same obligation as
        // `PATTERN_WARNING_CODES`: a code listed there but never emitted would
        // demand documentation for a warning no policy can produce. Pin each
        // code to a policy that emits it.
        let triggered = [
            (
                lower::RULE_CONDITION_CONTRADICTION,
                "source A = exec \"a\"\nrule r:\n  kill open file \"**/s\" if A and not A\n  because \"x\"\n",
            ),
            (
                lower::RULE_CONDITION_COVERS_TARGET,
                "rule r:\n  kill exec \"git\" unless target \"g*\"\n  because \"x\"\n",
            ),
            (
                lower::RULE_CONDITION_LABEL_WITHOUT_PRODUCER,
                "source A = exec \"a\"\nrule r:\n  kill exec \"git\" if A and NOPE\n  because \"x\"\n",
            ),
        ];
        assert_eq!(
            triggered.len(),
            RULE_CONDITION_WARNING_CODES.len(),
            "every code in RULE_CONDITION_WARNING_CODES needs a trigger policy here"
        );
        for (code, policy) in triggered {
            assert!(
                RULE_CONDITION_WARNING_CODES.contains(&code),
                "{code} is emitted but missing from RULE_CONDITION_WARNING_CODES"
            );
            let codes = warning_codes(&ok(policy));
            assert!(
                codes.contains(&code),
                "{policy:?} should emit {code}, got {codes:?}"
            );
        }
    }

    #[test]
    fn parentheses_group_and_and_or_have_equal_precedence() {
        // The lexer used to glue `(A` and `B)` into single words, so `if (A)`
        // introduced a phantom label `(A` that no `source` can set: the clause
        // was silently dead. Grouping is now explicit. The blob is the enforced
        // artifact, so equality of blobs is the observable claim (`labels` alone
        // would not catch a wrong association order that happens to reuse names).
        let blob = |when: &str| {
            let src = format!(
                "source A = exec \"a\"\nsource B = exec \"b\"\nsource C = exec \"c\"\nrule r:\n  kill open file \"**/s\" if {when}\n  because \"x\"\n"
            );
            ok(&src).bytes
        };
        // Redundant grouping is a no-op, so `(A)` must lower exactly like `A`.
        assert_eq!(blob("A"), blob("(A)"));
        assert_eq!(blob("not A"), blob("(not A)"));
        // `and` and `or` are equal precedence and left-associative, so the
        // unparenthesized `A or B and C` is `(A or B) and C`. Pin that, and pin
        // that parenthesizing the other way is a different policy: a reader who
        // wants `A or (B and C)` gets it only with the parens.
        assert_eq!(blob("A or B and C"), blob("(A or B) and C"));
        assert_ne!(blob("A or B and C"), blob("A or (B and C)"));
        // An unbalanced paren is a loud error, not a phantom label.
        for bad in ["(A", "A)", "(A or B"] {
            let src = format!("rule r:\n  kill open file \"**/s\" if {bad}\n  because \"x\"\n");
            assert!(compile_str(&src).is_err(), "{bad:?} should fail to parse");
        }
        // `Expr::Not` carries a label name, not a sub-expression, so a negated
        // group is rejected with the De Morgan spelling rather than parsed as
        // `not ` plus a group.
        let err =
            match compile_str("rule r:\n  kill exec \"git\" if not (A or B)\n  because \"x\"\n") {
                Ok(_) => panic!("`not (...)` should be rejected"),
                Err(e) => e,
            };
        assert!(err.contains("not A and not B"), "unhelpful error: {err}");
    }

    #[test]
    fn contradiction_between_a_label_and_its_negation_is_reported() {
        // `taint_mask_ok` tests `(labels & req) == req && (labels & forbid) == 0`,
        // so a DNF term that requires and forbids the same bit is false in every
        // state. The warning names the label so the policy author can find it.
        let warn = |when: &str| {
            let src = format!(
                "source A = exec \"a\"\nsource B = exec \"b\"\nrule r:\n  kill open file \"**/s\" if {when}\n  because \"x\"\n"
            );
            let c = ok(&src);
            (
                warning_codes(&c),
                c.pattern_warnings
                    .iter()
                    .map(|w| w.message.clone())
                    .collect::<Vec<_>>(),
            )
        };
        let (codes, messages) = warn("A and not A");
        assert_eq!(codes, vec![lower::RULE_CONDITION_CONTRADICTION]);
        assert!(
            messages[0].contains("`A`"),
            "the warning must name the contradicted label: {messages:?}"
        );
        // Only one `or` branch is dead here: `B` can still fire. The message
        // must not claim the whole rule is unreachable, since the fix differs.
        let (codes, messages) = warn("(A or B) and not A");
        assert_eq!(codes, vec![lower::RULE_CONDITION_CONTRADICTION]);
        assert!(
            messages[0].contains("one branch"),
            "a surviving branch must not be reported as a dead rule: {messages:?}"
        );
        // Consistent conditions stay quiet, including `or`-with-negation, which
        // is satisfiable (`true or not A`), unlike an `and` between them.
        for quiet in ["A or not A", "A and not B", "A", "not A"] {
            assert!(warn(quiet).0.is_empty(), "{quiet:?} should not warn");
        }
    }

    #[test]
    fn non_ascii_bytes_are_tokenized_on_char_boundaries() {
        // The lexer used to advance and slice on raw bytes, so a word containing
        // a non-ASCII char whose trailing byte is ASCII whitespace (`∅`, U+2205,
        // ends in `0x85` = U+0085 NEL) sliced mid-char and panicked. `docs/`
        // embeds exactly that char, so any policy text carrying it crashed the
        // compiler instead of reporting a normal parse error.
        let bad = "source AGENT = exec \"**/codex\"\nrule r:\n  kill exec \"git\" if AGENT \u{2205}\n  because \"b\"\n";
        let err = match compile_str(bad) {
            Ok(_) => panic!("a bare non-ASCII word is not a label"),
            Err(e) => e,
        };
        assert!(
            err.contains('\u{2205}'),
            "the error must name the token: {err}"
        );
        // Inside a string literal the byte is ordinary payload, so the rule
        // compiles and the literal is stored whole.
        let quoted = "source AGENT = exec \"**/codex\"\nrule r:\n  kill exec \"git\u{2205}\" if AGENT\n  because \"b\"\n";
        assert!(compile_str(quoted).is_ok(), "quoted non-ASCII is payload");
        // A non-ASCII rule name is a word like any other, not a crash.
        let named = "source AGENT = exec \"**/codex\"\nrule r\u{2205}:\n  kill exec \"git\" if AGENT\n  because \"b\"\n";
        assert!(compile_str(named).is_ok(), "a non-ASCII rule name parses");
    }

    #[test]
    fn exception_covering_the_whole_target_is_reported() {
        // `te_cond_satisfied` suppresses a rule whose `target` condition holds,
        // so an exception that accepts every event the rule's own target accepts
        // makes the rule never fire. Reported per clause, once.
        let codes = |src: &str| warning_codes(&ok(src));
        let warned = [
            // Exact target and exact condition: the same single address.
            "rule r:\n  kill exec \"git\" unless target \"git\"\n  because \"x\"\n",
            // A prefix condition accepts the exact target.
            "rule r:\n  kill exec \"git\" unless target \"g*\"\n  because \"x\"\n",
            // `ANY` accepts everything.
            "rule r:\n  kill exec \"git\" unless target \"**\"\n  because \"x\"\n",
            // `contains` accepts its own literal, which is the whole target set.
            "rule r:\n  kill open file \"*.log\" unless target \"*.log\"\n  because \"x\"\n",
            // A `**/x` target also emits a companion exact-basename entry, so at
            // least one entry is dead even though the message is qualified.
            "rule r:\n  kill open file \"**/*.log\" unless target \"*.log\"\n  because \"x\"\n",
            // Exact target under a broad path prefix.
            "rule r:\n  kill open file \"/work/a\" unless target \"/work/**\"\n  because \"x\"\n",
        ];
        for src in warned {
            assert_eq!(
                codes(src),
                vec![RULE_CONDITION_COVERS_TARGET],
                "{src:?} should report a covering exception"
            );
        }
        // A branch of the condition that survives means the rule can still fire,
        // so the same inputs must stay quiet.
        let quiet = [
            // The condition is a strict sub-path: some targets are not covered.
            "rule r:\n  kill open file \"/work/**\" unless target \"/work\"\n  because \"x\"\n",
            "rule r:\n  kill open file \"/work/**\" unless target \"/work/\"\n  because \"x\"\n",
            // Target set is the subset, so the condition is not implied.
            "rule r:\n  kill exec \"g*\" unless target \"git\"\n  because \"x\"\n",
            "rule r:\n  kill exec \"git\" unless target \"*t\"\n  because \"x\"\n",
            "rule r:\n  kill open file \"/work/tmp/\" unless target \"/work/tmp/a\"\n  because \"x\"\n",
            // No condition, or a non-target condition.
            "rule r:\n  kill exec \"git\" if A\n  because \"x\"\n",
            "rule r:\n  kill exec \"git\" unless after exec \"**/pytest\"\n  because \"x\"\n",
        ];
        for src in quiet {
            // Other codes (`pattern_empty_literal` for `*t`) are orthogonal; this
            // test claims only that coverage is not reported.
            let got = codes(src);
            assert!(
                !got.contains(&RULE_CONDITION_COVERS_TARGET),
                "{src:?} should not report coverage: {got:?}"
            );
        }
    }

    #[test]
    fn negated_exception_is_reported_when_the_target_misses_the_condition() {
        // `unless target not PAT` fires only where the condition matcher is
        // false, so it dies when the target set is disjoint from the
        // condition's. The example is the allow-list shape: `not "/work/"`
        // accepts nothing under `/work/`, so a rule targeting `/work/a` never
        // fires.
        let src =
            "rule r:\n  kill open file \"/work/a\" unless target not \"/work/\"\n  because \"x\"\n";
        assert_eq!(warning_codes(&ok(src)), vec![RULE_CONDITION_COVERS_TARGET]);
        // Two prefixes that share no text are disjoint, so nothing the target
        // accepts can satisfy the negated condition.
        let disjoint = "rule r:\n  kill open file \"/work/**\" unless target not \"/other/\"\n  because \"x\"\n";
        assert_eq!(
            warning_codes(&ok(disjoint)),
            vec![RULE_CONDITION_COVERS_TARGET]
        );
        // A target strictly under the negated prefix still has texts outside it,
        // so the rule fires for those and stays quiet.
        let overlapping = "rule r:\n  kill open file \"/work/**\" unless target not \"/work/\"\n  because \"x\"\n";
        assert!(warning_codes(&ok(overlapping)).is_empty());
        // Endpoints: a numeric pattern reduces to net/mask, and the coverage
        // test is the masked-equality argument.
        let endpoint = "rule r:\n  kill recv endpoint \"1.2.3.4\" unless target \"1.2.3.4\"\n  because \"x\"\n";
        assert_eq!(
            warning_codes(&ok(endpoint)),
            vec![RULE_CONDITION_COVERS_TARGET]
        );
        // `*` is unconstrained, so the condition covers the whole target.
        let endpoint_quiet =
            "rule r:\n  kill connect endpoint \"*\" unless target \"127.\"\n  because \"x\"\n";
        assert!(warning_codes(&ok(endpoint_quiet)).is_empty());
    }

    #[test]
    fn condition_label_without_a_producer_is_reported() {
        // `label_bit` allocates a bit for a label the moment a condition names
        // it, but only an adding update sets it. With no producer the plain form
        // never fires and the negated form fires on every event the target
        // accepts, so both must be reported.
        let warn = |when: &str| {
            let src = format!(
                "source A = exec \"a\"\nrule r:\n  kill exec \"git\" if {when}\n  because \"x\"\n"
            );
            let c = ok(&src);
            (
                warning_codes(&c),
                c.pattern_warnings
                    .iter()
                    .map(|w| w.message.clone())
                    .collect::<Vec<_>>(),
            )
        };
        for when in ["NOPE", "not NOPE", "A and NOPE", "A or NOPE"] {
            let (codes, messages) = warn(when);
            assert_eq!(
                codes,
                vec![RULE_CONDITION_LABEL_WITHOUT_PRODUCER],
                "{when:?} references a producer-less label"
            );
            assert!(
                messages[0].contains("`NOPE`"),
                "the warning must name the label: {messages:?}"
            );
        }
        // Multiple missing labels are all named: naming only one would hide the
        // others behind a second compile round.
        let (_, messages) = warn("NOPE and ALSO_BAD");
        assert!(
            messages[0].contains("`NOPE`") && messages[0].contains("`ALSO_BAD`"),
            "every producer-less label must be named: {messages:?}"
        );
        // A declared label stays quiet whatever the shape of the condition
        // mentions it; `A and not A` is a contradiction, which is a different
        // code, so only the producer-less code is asserted absent.
        for quiet in ["A", "A and not A", "A or not A"] {
            assert!(
                !warn(quiet)
                    .0
                    .contains(&RULE_CONDITION_LABEL_WITHOUT_PRODUCER),
                "{quiet:?} names a declared label and must not warn"
            );
        }
    }

    #[test]
    fn rule_condition_warnings_identify_the_rule_by_name_not_reason() {
        // The rule name is the only identifier these diagnostics share with the
        // rest of the surface (`rule_missing_because` prints it, and `--explain`
        // labels each clause by it). Naming the rule by its `because` string
        // instead made a warning read `rule "keep secrets local"` for a rule
        // called `secret-guard`, and two rules sharing prose became
        // indistinguishable. A rule with no `because` could not be named at all
        // and printed the placeholder `(no `because`)`.
        let guard = "rule secret-guard:\n  kill exec \"git\" unless target \"git\"\n  because \"keep secrets local\"\n";
        let c = ok(guard);
        let msg = c
            .pattern_warnings
            .iter()
            .find(|w| w.code == RULE_CONDITION_COVERS_TARGET)
            .expect("a covering exception is reported")
            .message
            .clone();
        assert!(
            msg.contains("`secret-guard`"),
            "the warning must name the rule: {msg}"
        );
        assert!(
            !msg.contains("keep secrets local"),
            "the reason must not stand in for the name: {msg}"
        );
        // Without a `because` the name is still available, so the placeholder
        // is gone.
        let unnamed = ok("rule secret-guard:\n  kill exec \"git\" unless target \"git\"\n");
        let unnamed_msg = unnamed
            .pattern_warnings
            .iter()
            .find(|w| w.code == RULE_CONDITION_COVERS_TARGET)
            .expect("a covering exception is reported")
            .message
            .clone();
        assert!(
            unnamed_msg.contains("`secret-guard`") && !unnamed_msg.contains("(no `because`)"),
            "an unnamed rule is still identified by name: {unnamed_msg}"
        );
    }

    #[test]
    fn only_an_adding_xform_counts_as_a_producer() {
        // `endorse L` lowers to `add = bit` and sets the label, so it is a
        // producer. `declassify L` lowers to `del = bit` and *clears* it, so a
        // policy whose only mention of `L` is a `declassify` still has no
        // producer: `if L` never fires there, and `if not L` fires on every
        // event the target accepts. Counting every xform as a producer was the
        // bug; the two forms are opposite operations.
        let codes = |src: &str| warning_codes(&ok(src));
        let endorse = "endorse MCP by exec \"**/trust\"\nrule r:\n  kill exec \"git\" if MCP\n  because \"x\"\n";
        assert!(
            !codes(endorse).contains(&RULE_CONDITION_LABEL_WITHOUT_PRODUCER),
            "`endorse` sets the label, so it is a producer: {:?}",
            codes(endorse)
        );
        for when in ["MCP", "not MCP"] {
            let src = format!(
                "declassify MCP by exec \"**/trust\"\nrule r:\n  kill exec \"git\" if {when}\n  because \"x\"\n"
            );
            assert!(
                codes(&src).contains(&RULE_CONDITION_LABEL_WITHOUT_PRODUCER),
                "`declassify` clears the label, so `{when}` has no producer: {:?}",
                codes(&src)
            );
        }
        // A source alongside the `declassify` is a producer, so the pair is
        // quiet: the label can be present before the gate clears it.
        let both = "source MCP = exec \"a\"\ndeclassify MCP by exec \"**/trust\"\nrule r:\n  kill exec \"git\" if MCP\n  because \"x\"\n";
        assert!(
            !codes(both).contains(&RULE_CONDITION_LABEL_WITHOUT_PRODUCER),
            "a source still produces the label: {:?}",
            codes(both)
        );
    }

    #[test]
    fn runtime_seeded_labels_are_exempt_without_a_source() {
        // `actplane run`/`watch` seed the protected pid with COMMAND (AGENT as
        // the older spelling) before any exec update runs, and `runner_label`
        // accepts a policy that only references the label, so a reference
        // without a `source` is enforceable and must not warn.
        for label in ["COMMAND", "AGENT"] {
            let src = format!("rule r:\n  kill exec \"git\" if {label}\n  because \"x\"\n");
            let c = ok(&src);
            assert!(
                !warning_codes(&c).contains(&RULE_CONDITION_LABEL_WITHOUT_PRODUCER),
                "{label} is seeded by the runner and must not warn: {:?}",
                warning_codes(&c)
            );
            assert!(c.labels.contains_key(label), "{label} still gets a bit");
        }
    }

    #[test]
    fn label_from_an_earlier_delta_is_not_producer_less() {
        // A runtime delta compiles with the domain's existing label dictionary,
        // so a bit an earlier delta allocated is live even though no local
        // update writes it. Warning there would be a false positive.
        let src = "rule r:\n  kill exec \"git\" if SEEDED\n  because \"x\"\n";
        let mut existing = HashMap::new();
        existing.insert("SEEDED".to_string(), 1u64);
        let compiled = lower::compile_with_labels(&parse::parse(src).unwrap(), &existing).unwrap();
        assert!(
            !compiled
                .pattern_warnings
                .iter()
                .any(|w| w.code == RULE_CONDITION_LABEL_WITHOUT_PRODUCER),
            "a label carried in from an earlier delta must not warn: {:?}",
            compiled.pattern_warnings
        );
        // The same policy without the carried label does warn, so the exemption
        // is the existing label, not the policy text.
        assert_eq!(
            warning_codes(&ok(src)),
            vec![RULE_CONDITION_LABEL_WITHOUT_PRODUCER]
        );
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
    fn duplicate_because_is_rejected_rather_than_silently_overwritten() {
        // The grammar allows at most one `because` per rule, and the string is
        // the whole corrective-feedback payload forwarded to the agent on a
        // match. The parser used to assign unconditionally, so the second
        // string replaced the first and the reason for the clauses that
        // actually matched was lost with no diagnostic. Reject instead, the
        // way a duplicate rule name already is.
        let err = match compile_str(
            r#"
            rule r:
              notify exec "git" if true
              because "first"
              because "second"
        "#,
        ) {
            Ok(_) => panic!("a second `because` compiled successfully"),
            Err(err) => err,
        };
        assert!(
            err.contains("more than one `because`") && err.contains("first"),
            "the error must name the conflict, got: {err}"
        );
        // One `because` still compiles, and it is the reason that survives.
        let c = ok("rule r:\n  notify exec \"git\" if true\n  because \"only\"\n");
        assert_eq!(c.meta[0].reason, "only");
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
}
