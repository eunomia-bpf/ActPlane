use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::{Value, json};

use crate::config::{
    AppendDeltaApprovalConfig, DomainSummary, LoadedPolicy, ResolvedPolicy, domain_summaries,
    feedback_paths, load_policy, resolve_policy,
};
use crate::dsl::ast::{Clause, Cond, Effect, Expr, Kind, Op, Policy, Source};
use crate::runtime::{have_bpf_caps, passwordless_sudo_available};
use crate::setup::{codex_hook_has_actplane_command, project_mcp_auto_attach_ok};
use crate::{Result, dsl};
use actplane_runtime::PolicyInput;

pub(crate) fn check_policy(
    cli: &PolicyInput,
    json_output: bool,
    explain_output: bool,
    report_out: Option<&Path>,
    report_force: bool,
) -> Result<i32> {
    let where_ = policy_ref_for_cli(cli);
    let loaded = match load_policy(cli) {
        Ok(loaded) => loaded,
        Err(e) if json_output => {
            let report = render_check_error_json(&where_, None, &e.to_string())?;
            emit_check_report(&report, report_out, report_force, "compile report")?;
            return Ok(1);
        }
        Err(e) => return Err(e),
    };
    let resolved = match resolve_policy(&loaded, cli.domain.as_deref()) {
        Ok(resolved) => resolved,
        Err(e) if json_output => {
            let report = render_check_error_json(&where_, None, &e.to_string())?;
            emit_check_report(&report, report_out, report_force, "compile report")?;
            return Ok(1);
        }
        Err(e) => return Err(e),
    };
    let where_ = loaded
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "--rule".into());
    let parsed = match dsl::parse::parse(&resolved.source) {
        Ok(p) => p,
        Err(e) => {
            if json_output {
                let report = render_check_error_json(&where_, Some(&resolved), &e)?;
                emit_check_report(&report, report_out, report_force, "compile report")?;
            } else {
                eprintln!("✗ policy does not compile: {}", e);
            }
            return Ok(1);
        }
    };
    let compiled = match dsl::compile_str(&resolved.source) {
        Ok(c) => c,
        Err(e) => {
            if json_output {
                let report = render_check_error_json(&where_, Some(&resolved), &e)?;
                emit_check_report(&report, report_out, report_force, "compile report")?;
            } else {
                eprintln!("✗ policy does not compile: {}", e);
            }
            return Ok(1);
        }
    };
    let active_lsms = active_lsms().unwrap_or_default();
    let force_tracepoint = std::env::var_os("ACTPLANE_FORCE_TRACEPOINT").is_some();
    let lsm_bpf = lsm_list_has_bpf(&active_lsms) && !force_tracepoint;
    if json_output {
        let report = render_check_json(
            &where_,
            &resolved,
            &parsed,
            &compiled,
            &active_lsms,
            lsm_bpf,
            force_tracepoint,
        )?;
        emit_check_report(&report, report_out, report_force, "compile report")?;
        return Ok(0);
    }
    if explain_output {
        let artifact = render_check_explain(
            &where_,
            &loaded,
            &resolved,
            &parsed,
            &compiled,
            &active_lsms,
            lsm_bpf,
            force_tracepoint,
        );
        emit_check_report(&artifact, report_out, report_force, "policy review")?;
        return Ok(0);
    }

    println!("✓ {}: {} rule(s) compile.\n", where_, compiled.meta.len());
    if let Some(domain) = &resolved.domain {
        println!("domain: {}", domain.name);
        if let Some(parent) = &domain.parent {
            println!("parent: {}", parent);
        }
        println!("policy: {}\n", format_domain_policy_rules(domain));
    }
    for (i, m) in compiled.meta.iter().enumerate() {
        let eff = format!("{:?}", m.effect).to_lowercase();
        let ops = if m.ops.is_empty() {
            "—".into()
        } else {
            m.ops.join("/")
        };
        println!("  {}. {} — {} {} ({})", i + 1, m.name, eff, ops, m.reason);
    }
    println!("\nbackend support:");
    for line in backend_support_lines(&parsed, &compiled, lsm_bpf) {
        println!("  - {}", line);
    }
    let warns = backend_support_warnings(&parsed, &compiled, lsm_bpf);
    if warns.is_empty() {
        println!("\n✓ no warnings.");
    } else {
        println!("\n⚠ {} warning(s):", warns.len());
        for w in &warns {
            println!("  - {}", w.message);
        }
    }
    if unsafe { libc::geteuid() } != 0 {
        println!(
            "\n(note: `compile` needs no privileges; applying policies needs `sudo -E actplane run/watch`.)"
        );
    }
    Ok(0)
}

#[allow(dead_code)]
pub(crate) fn render_policy_review_for_loaded(
    loaded: &LoadedPolicy,
    domain: Option<&str>,
) -> Result<String> {
    let resolved = resolve_policy(loaded, domain)?;
    let where_ = loaded
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "--rule".into());
    let parsed =
        dsl::parse::parse(&resolved.source).map_err(|e| format!("policy does not compile: {e}"))?;
    let compiled =
        dsl::compile_str(&resolved.source).map_err(|e| format!("policy does not compile: {e}"))?;
    let active_lsms = active_lsms().unwrap_or_default();
    let force_tracepoint = std::env::var_os("ACTPLANE_FORCE_TRACEPOINT").is_some();
    let lsm_bpf = lsm_list_has_bpf(&active_lsms) && !force_tracepoint;
    Ok(render_check_explain(
        &where_,
        loaded,
        &resolved,
        &parsed,
        &compiled,
        &active_lsms,
        lsm_bpf,
        force_tracepoint,
    ))
}

#[allow(dead_code)]
pub(crate) struct RolloutArtifacts {
    pub(crate) plan: String,
    pub(crate) observe_policy_yaml: String,
}

#[allow(dead_code)]
pub(crate) fn render_rollout_artifacts(
    cli: &PolicyInput,
    event_paths: &[PathBuf],
    annotation_paths: &[PathBuf],
) -> Result<RolloutArtifacts> {
    let loaded = load_policy(cli)?;
    let resolved = resolve_policy(&loaded, cli.domain.as_deref())?;
    let where_ = loaded
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "--rule".into());
    let parsed =
        dsl::parse::parse(&resolved.source).map_err(|e| format!("policy does not compile: {e}"))?;
    let compiled =
        dsl::compile_str(&resolved.source).map_err(|e| format!("policy does not compile: {e}"))?;
    let active_lsms = active_lsms().unwrap_or_default();
    let force_tracepoint = std::env::var_os("ACTPLANE_FORCE_TRACEPOINT").is_some();
    let lsm_bpf = lsm_list_has_bpf(&active_lsms) && !force_tracepoint;
    let evidence = load_rollout_evidence(event_paths, annotation_paths, &parsed)?;
    Ok(RolloutArtifacts {
        plan: render_rollout_plan(
            &where_,
            &resolved,
            &parsed,
            &compiled,
            &active_lsms,
            lsm_bpf,
            force_tracepoint,
            &evidence,
        ),
        observe_policy_yaml: render_observe_policy_yaml(&where_, &resolved, &parsed),
    })
}

#[derive(Default)]
#[allow(dead_code)]
struct RolloutEvidence {
    event_paths: Vec<PathBuf>,
    annotation_paths: Vec<PathBuf>,
    total_events: usize,
    total_annotations: usize,
    ignored_lines: usize,
    ignored_annotations: usize,
    warnings: Vec<String>,
    clauses: BTreeMap<(String, usize), ClauseObservation>,
}

#[derive(Default)]
#[allow(dead_code)]
struct ClauseObservation {
    count: usize,
    actions: BTreeMap<String, usize>,
    targets: Vec<String>,
    domains: BTreeMap<String, usize>,
    annotations: BTreeMap<String, usize>,
    annotation_notes: Vec<String>,
}

#[allow(dead_code)]
struct ClauseEventSignature {
    clause_op: &'static str,
    target_kind: &'static str,
    target_pattern: String,
    target_arg: Option<String>,
    clause_text: String,
    clause_hash: String,
}

#[allow(dead_code)]
fn render_rollout_plan(
    policy_ref: &str,
    resolved: &ResolvedPolicy,
    parsed: &Policy,
    compiled: &dsl::Compiled,
    active_lsms: &str,
    lsm_bpf: bool,
    force_tracepoint: bool,
    evidence: &RolloutEvidence,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "ActPlane rollout plan").unwrap();
    writeln!(&mut out, "policy: {}", policy_ref).unwrap();
    match &resolved.domain {
        Some(domain) => {
            writeln!(&mut out, "domain: {}", domain.name).unwrap();
            if let Some(parent) = &domain.parent {
                writeln!(&mut out, "parent: {}", parent).unwrap();
            }
            writeln!(
                &mut out,
                "policy rules: {}",
                format_domain_policy_rules(domain)
            )
            .unwrap();
        }
        None => writeln!(&mut out, "domain: none (flat policy)").unwrap(),
    }
    writeln!(
        &mut out,
        "rules: {} DSL rule(s), {} lowered kernel matcher(s)",
        parsed.rules.len(),
        compiled.meta.len()
    )
    .unwrap();
    writeln!(&mut out, "\nhost/backend:").unwrap();
    writeln!(
        &mut out,
        "  - active LSMs: {}",
        if active_lsms.trim().is_empty() {
            "unknown"
        } else {
            active_lsms
        }
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - BPF-LSM pre-op block: {}",
        if lsm_bpf { "available" } else { "unavailable" }
    )
    .unwrap();
    if force_tracepoint {
        writeln!(
            &mut out,
            "  - ACTPLANE_FORCE_TRACEPOINT: set, so BPF-LSM is treated as unavailable"
        )
        .unwrap();
    }
    append_rollout_evidence_summary(&mut out, evidence);

    writeln!(&mut out, "\nrecommended rollout sequence:").unwrap();
    writeln!(
        &mut out,
        "  1. Static review: run `actplane compile --explain --report-out <review.txt>` and inspect warnings."
    )
    .unwrap();
    writeln!(
        &mut out,
        "  2. Observe first: run the generated observe-first policy; every clause is downgraded to notify."
    )
    .unwrap();
    writeln!(
        &mut out,
        "  3. Promote narrowly: restore block/kill only for clauses with stable event volume, clear ownership, and backend support."
    )
    .unwrap();
    writeln!(
        &mut out,
        "  4. Fail closed only after proving the policy and hook profile on the deployment host."
    )
    .unwrap();

    writeln!(&mut out, "\nrule rollout recommendations:").unwrap();
    if parsed.rules.is_empty() {
        writeln!(&mut out, "  - none").unwrap();
    }
    for (rule_idx, rule) in parsed.rules.iter().enumerate() {
        writeln!(&mut out, "  {}. rule {}", rule_idx + 1, rule.name).unwrap();
        writeln!(&mut out, "     reason: {}", rule.reason).unwrap();
        for clause in &rule.clauses {
            let current = clause_support_detail(
                compiled,
                clause.effect,
                clause.op,
                clause.target.kind,
                &clause.target.pattern,
                clause.target.arg.as_deref(),
                lsm_bpf,
            );
            let block = clause_support_detail(
                compiled,
                Effect::Block,
                clause.op,
                clause.target.kind,
                &clause.target.pattern,
                clause.target.arg.as_deref(),
                lsm_bpf,
            );
            writeln!(
                &mut out,
                "     clause {}: {}",
                clause.source_index + 1,
                clause_summary(clause)
            )
            .unwrap();
            writeln!(
                &mut out,
                "       current: {}; {}; timing={}",
                effect_name(clause.effect),
                current.status,
                enforcement_timing(clause.effect, &current)
            )
            .unwrap();
            for warning in clause_condition_warnings(clause, compiled) {
                writeln!(&mut out, "       condition warning: {}", warning.message).unwrap();
            }
            let observation = evidence
                .clauses
                .get(&(rule.name.clone(), clause.source_index));
            append_clause_observation(&mut out, evidence, observation);
            let (stage, promote, risk) = rollout_recommendation(clause, &current, &block);
            writeln!(&mut out, "       observe stage: {}", stage).unwrap();
            writeln!(&mut out, "       promotion: {}", promote).unwrap();
            if let Some(note) =
                event_backed_promotion_note(evidence, observation, clause.effect, block.supported)
            {
                writeln!(&mut out, "       event-backed promotion: {}", note).unwrap();
            }
            writeln!(&mut out, "       residual risk: {}", risk).unwrap();
        }
    }

    let warns = backend_support_warnings(parsed, compiled, lsm_bpf);
    if !warns.is_empty() {
        writeln!(&mut out, "\nstatic warnings to resolve before promotion:").unwrap();
        for warning in warns {
            writeln!(&mut out, "  - {}: {}", warning.code, warning.message).unwrap();
        }
    }
    out
}

#[allow(dead_code)]
fn load_rollout_evidence(
    event_paths: &[PathBuf],
    annotation_paths: &[PathBuf],
    parsed: &Policy,
) -> Result<RolloutEvidence> {
    let mut evidence = RolloutEvidence {
        event_paths: event_paths.to_vec(),
        annotation_paths: annotation_paths.to_vec(),
        ..RolloutEvidence::default()
    };
    let signatures = rollout_clause_signatures(parsed);
    for path in event_paths {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading rollout event log {}: {}", path.display(), e))?;
        for (line_idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_str(trimmed) {
                Ok(value) => value,
                Err(e) => {
                    evidence.ignored_lines += 1;
                    push_evidence_warning(
                        &mut evidence,
                        format!("{}:{} is not JSON: {}", path.display(), line_idx + 1, e),
                    );
                    continue;
                }
            };
            if value.get("schema").and_then(Value::as_str) != Some("actplane.violation.v1")
                || value.get("event").and_then(Value::as_str) != Some("taint_violation")
            {
                evidence.ignored_lines += 1;
                continue;
            }
            let action = value
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let effect = value
                .get("effect")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if action != "report" || effect != "notify" {
                evidence.ignored_lines += 1;
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} ignored non-observe event action={} effect={}",
                        path.display(),
                        line_idx + 1,
                        action,
                        effect
                    ),
                );
                continue;
            }
            let Some(rule) = value
                .get("rule")
                .and_then(|rule| rule.get("name"))
                .and_then(Value::as_str)
            else {
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} violation event has no rule.name; it cannot be matched to a clause",
                        path.display(),
                        line_idx + 1
                    ),
                );
                continue;
            };
            let Some(clause_index) = value
                .get("rule")
                .and_then(|rule| rule.get("clause_source_index"))
                .and_then(Value::as_u64)
                .and_then(|idx| usize::try_from(idx).ok())
            else {
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} violation event for rule `{}` has no clause_source_index",
                        path.display(),
                        line_idx + 1,
                        rule
                    ),
                );
                continue;
            };
            let Some(signature) = signatures.get(&(rule.to_string(), clause_index)) else {
                evidence.ignored_lines += 1;
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} ignored event for rule `{}` clause {}; no matching clause exists in the selected policy",
                        path.display(),
                        line_idx + 1,
                        rule,
                        clause_index + 1
                    ),
                );
                continue;
            };
            if !event_rule_matches_signature(&value, signature) {
                evidence.ignored_lines += 1;
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} ignored stale event for rule `{}` clause {}; rule metadata does not match the selected policy",
                        path.display(),
                        line_idx + 1,
                        rule,
                        clause_index + 1
                    ),
                );
                continue;
            }
            evidence.total_events += 1;
            let observation = evidence
                .clauses
                .entry((rule.to_string(), clause_index))
                .or_default();
            observation.count += 1;
            *observation.actions.entry(action.to_string()).or_default() += 1;
            if let Some(target) = value.get("target").and_then(Value::as_str)
                && !target.is_empty()
                && observation.targets.len() < 5
                && !observation
                    .targets
                    .iter()
                    .any(|existing| existing == target)
            {
                observation.targets.push(target.to_string());
            }
            if let Some(domain_id) = value.get("domain_id").and_then(Value::as_u64) {
                *observation
                    .domains
                    .entry(domain_id.to_string())
                    .or_default() += 1;
            }
        }
    }
    for path in annotation_paths {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading rollout annotation log {}: {}", path.display(), e))?;
        for (line_idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_str(trimmed) {
                Ok(value) => value,
                Err(e) => {
                    evidence.ignored_annotations += 1;
                    push_evidence_warning(
                        &mut evidence,
                        format!(
                            "{}:{} annotation is not JSON: {}",
                            path.display(),
                            line_idx + 1,
                            e
                        ),
                    );
                    continue;
                }
            };
            if value.get("schema").and_then(Value::as_str) != Some("actplane.rollout.annotation.v1")
            {
                evidence.ignored_annotations += 1;
                continue;
            }
            let classification = value
                .get("classification")
                .or_else(|| value.get("class"))
                .and_then(Value::as_str)
                .map(normalize_rollout_classification);
            let Some(classification) = classification else {
                evidence.ignored_annotations += 1;
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} annotation has no classification",
                        path.display(),
                        line_idx + 1
                    ),
                );
                continue;
            };
            let Some(rule) = value
                .get("rule")
                .and_then(|rule| rule.get("name"))
                .and_then(Value::as_str)
            else {
                evidence.ignored_annotations += 1;
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} annotation has no rule.name; it cannot be matched to a clause",
                        path.display(),
                        line_idx + 1
                    ),
                );
                continue;
            };
            let Some(clause_index) = value
                .get("rule")
                .and_then(|rule| rule.get("clause_source_index"))
                .and_then(Value::as_u64)
                .and_then(|idx| usize::try_from(idx).ok())
            else {
                evidence.ignored_annotations += 1;
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} annotation for rule `{}` has no clause_source_index",
                        path.display(),
                        line_idx + 1,
                        rule
                    ),
                );
                continue;
            };
            let Some(signature) = signatures.get(&(rule.to_string(), clause_index)) else {
                evidence.ignored_annotations += 1;
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} ignored annotation for rule `{}` clause {}; no matching clause exists in the selected policy",
                        path.display(),
                        line_idx + 1,
                        rule,
                        clause_index + 1
                    ),
                );
                continue;
            };
            if !annotation_rule_matches_signature(&value, signature) {
                evidence.ignored_annotations += 1;
                push_evidence_warning(
                    &mut evidence,
                    format!(
                        "{}:{} ignored stale annotation for rule `{}` clause {}; rule metadata does not match the selected policy",
                        path.display(),
                        line_idx + 1,
                        rule,
                        clause_index + 1
                    ),
                );
                continue;
            }
            evidence.total_annotations += 1;
            let observation = evidence
                .clauses
                .entry((rule.to_string(), clause_index))
                .or_default();
            *observation
                .annotations
                .entry(classification.to_string())
                .or_default() += 1;
            if let Some(note) = value.get("note").and_then(Value::as_str)
                && !note.is_empty()
                && observation.annotation_notes.len() < 3
                && !observation
                    .annotation_notes
                    .iter()
                    .any(|existing| existing == note)
            {
                observation.annotation_notes.push(note.to_string());
            }
        }
    }
    Ok(evidence)
}

#[allow(dead_code)]
fn rollout_clause_signatures(policy: &Policy) -> BTreeMap<(String, usize), ClauseEventSignature> {
    let mut out = BTreeMap::new();
    for rule in &policy.rules {
        for clause in &rule.clauses {
            out.insert(
                (rule.name.clone(), clause.source_index),
                ClauseEventSignature {
                    clause_op: op_name(clause.op),
                    target_kind: kind_name(clause.target.kind),
                    target_pattern: clause.target.pattern.clone(),
                    target_arg: clause.target.arg.clone(),
                    clause_text: format!("  {}", render_observe_clause(clause)),
                    clause_hash: crate::audit::policy_hash(&format!(
                        "  {}",
                        render_observe_clause(clause)
                    )),
                },
            );
        }
    }
    out
}

#[allow(dead_code)]
fn event_rule_matches_signature(value: &Value, signature: &ClauseEventSignature) -> bool {
    let Some(rule) = value.get("rule") else {
        return false;
    };
    if rule.get("effect").and_then(Value::as_str) != Some("notify") {
        return false;
    }
    if rule.get("clause_op").and_then(Value::as_str) != Some(signature.clause_op) {
        return false;
    }
    if rule.get("target_kind").and_then(Value::as_str) != Some(signature.target_kind) {
        return false;
    }
    if rule.get("target_pattern").and_then(Value::as_str) != Some(signature.target_pattern.as_str())
    {
        return false;
    }
    rule.get("target_arg").and_then(Value::as_str) == signature.target_arg.as_deref()
        && event_clause_identity_matches(rule, signature)
}

#[allow(dead_code)]
fn annotation_rule_matches_signature(value: &Value, signature: &ClauseEventSignature) -> bool {
    let Some(rule) = value.get("rule") else {
        return false;
    };
    if let Some(effect) = rule.get("effect").and_then(Value::as_str)
        && effect != "notify"
    {
        return false;
    }
    if rule.get("clause_op").and_then(Value::as_str) != Some(signature.clause_op) {
        return false;
    }
    if rule.get("target_kind").and_then(Value::as_str) != Some(signature.target_kind) {
        return false;
    }
    if rule.get("target_pattern").and_then(Value::as_str) != Some(signature.target_pattern.as_str())
    {
        return false;
    }
    rule.get("target_arg").and_then(Value::as_str) == signature.target_arg.as_deref()
        && event_clause_identity_matches(rule, signature)
}

#[allow(dead_code)]
fn event_clause_identity_matches(rule: &Value, signature: &ClauseEventSignature) -> bool {
    if let Some(hash) = rule.get("clause_hash").and_then(Value::as_str) {
        return hash == signature.clause_hash;
    }
    if let Some(text) = rule.get("clause_text").and_then(Value::as_str) {
        return text == signature.clause_text;
    }
    false
}

#[allow(dead_code)]
fn normalize_rollout_classification(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tp" | "true-positive" | "true_positive" | "wanted_block" | "wanted_kill" | "unwanted" => {
            "true_positive"
        }
        "fp" | "false-positive" | "false_positive" => "false_positive",
        "allowed" | "expected" | "benign" => "allowed",
        "noise" | "irrelevant" => "noise",
        "unknown" | "needs-review" | "needs_review" | "review" => "needs_review",
        _ => "needs_review",
    }
}

#[allow(dead_code)]
fn push_evidence_warning(evidence: &mut RolloutEvidence, warning: String) {
    if evidence.warnings.len() < 8 {
        evidence.warnings.push(warning);
    } else if evidence.warnings.len() == 8 {
        evidence
            .warnings
            .push("additional rollout event-log warnings omitted".into());
    }
}

#[allow(dead_code)]
fn append_rollout_evidence_summary(out: &mut String, evidence: &RolloutEvidence) {
    writeln!(out, "\nobserve evidence:").unwrap();
    if evidence.event_paths.is_empty() && evidence.annotation_paths.is_empty() {
        writeln!(
            out,
            "  - no event or annotation log supplied; pass --events .actplane/events.jsonl after an observe run and --annotations <annotations.jsonl> after classification"
        )
        .unwrap();
        return;
    }
    for path in &evidence.event_paths {
        writeln!(out, "  - event log: {}", path.display()).unwrap();
    }
    for path in &evidence.annotation_paths {
        writeln!(out, "  - annotation log: {}", path.display()).unwrap();
    }
    writeln!(
        out,
        "  - parsed violation events: {}",
        evidence.total_events
    )
    .unwrap();
    writeln!(
        out,
        "  - parsed rollout annotations: {}",
        evidence.total_annotations
    )
    .unwrap();
    if evidence.ignored_lines > 0 {
        writeln!(
            out,
            "  - ignored non-violation or malformed lines: {}",
            evidence.ignored_lines
        )
        .unwrap();
    }
    if evidence.ignored_annotations > 0 {
        writeln!(
            out,
            "  - ignored malformed or stale annotations: {}",
            evidence.ignored_annotations
        )
        .unwrap();
    }
    for warning in &evidence.warnings {
        writeln!(out, "  - warning: {}", warning).unwrap();
    }
}

#[allow(dead_code)]
fn append_clause_observation(
    out: &mut String,
    evidence: &RolloutEvidence,
    observation: Option<&ClauseObservation>,
) {
    if evidence.event_paths.is_empty() && evidence.annotation_paths.is_empty() {
        return;
    }
    match observation {
        Some(observation) => {
            if !evidence.event_paths.is_empty() {
                writeln!(
                    out,
                    "       observed events: {}; actions={}; domains={}; targets={}",
                    observation.count,
                    format_count_map(&observation.actions),
                    format_count_map(&observation.domains),
                    format_sample_list(&observation.targets)
                )
                .unwrap();
            }
            if !evidence.annotation_paths.is_empty() {
                writeln!(
                    out,
                    "       annotations: {}; notes={}",
                    format_count_map(&observation.annotations),
                    format_sample_list(&observation.annotation_notes)
                )
                .unwrap();
            }
        }
        None => {
            if !evidence.event_paths.is_empty() {
                writeln!(out, "       observed events: 0 in supplied logs").unwrap();
            }
            if !evidence.annotation_paths.is_empty() {
                writeln!(out, "       annotations: none for this clause").unwrap();
            }
        }
    }
}

#[allow(dead_code)]
fn event_backed_promotion_note(
    evidence: &RolloutEvidence,
    observation: Option<&ClauseObservation>,
    effect: Effect,
    block_supported: bool,
) -> Option<String> {
    if evidence.event_paths.is_empty() && evidence.annotation_paths.is_empty() {
        return None;
    }
    if let Some(note) = annotation_backed_promotion_note(evidence, observation, effect) {
        return Some(note);
    }
    if effect == Effect::Kill {
        return match observation {
            Some(observation) if observation.count > 0 => Some(format!(
                "observed {} matching event(s); keep notify until examples are classified, and promote to kill only if every observed class should terminate the task",
                observation.count
            )),
            _ => Some(
                "0 matching events in supplied logs; candidate for limited kill promotion only after workload coverage and severity review"
                    .into(),
            ),
        };
    }
    if !block_supported {
        return Some(
            "do not promote to block from these logs alone; backend support is insufficient".into(),
        );
    }
    match observation {
        Some(observation) if observation.count > 0 => Some(format!(
            "observed {} matching event(s); keep notify until examples are classified, and promote only if every observed class is unwanted",
            observation.count
        )),
        _ => Some(
            "0 matching events in supplied logs; candidate for limited promotion only after workload coverage review"
                .into(),
        ),
    }
}

#[allow(dead_code)]
fn annotation_backed_promotion_note(
    evidence: &RolloutEvidence,
    observation: Option<&ClauseObservation>,
    effect: Effect,
) -> Option<String> {
    if evidence.annotation_paths.is_empty() {
        return None;
    }
    let Some(observation) = observation else {
        return Some(
            "no annotations for this clause; keep observe mode until examples are classified"
                .into(),
        );
    };
    if observation.annotations.is_empty() {
        return Some(
            "no annotations for this clause; keep observe mode until examples are classified"
                .into(),
        );
    }
    let false_positive = annotation_count(observation, "false_positive");
    let allowed = annotation_count(observation, "allowed");
    let noise = annotation_count(observation, "noise");
    if false_positive + allowed + noise > 0 {
        return Some(format!(
            "do not promote yet; annotations include false_positive={}, allowed={}, noise={}",
            false_positive, allowed, noise
        ));
    }
    let needs_review = annotation_count(observation, "needs_review");
    if needs_review > 0 {
        return Some(format!(
            "keep notify; {} annotated example(s) still need review",
            needs_review
        ));
    }
    let true_positive = annotation_count(observation, "true_positive");
    if true_positive > 0 {
        return Some(match effect {
            Effect::Kill => format!(
                "{} annotated true_positive example(s); candidate for limited kill promotion after workload coverage review",
                true_positive
            ),
            _ => format!(
                "{} annotated true_positive example(s); candidate for limited promotion after backend and workload coverage review",
                true_positive
            ),
        });
    }
    Some("annotations use no recognized promotion class; keep observe mode".into())
}

#[allow(dead_code)]
fn annotation_count(observation: &ClauseObservation, key: &str) -> usize {
    observation
        .annotations
        .get(key)
        .copied()
        .unwrap_or_default()
}

#[allow(dead_code)]
fn format_count_map(map: &BTreeMap<String, usize>) -> String {
    if map.is_empty() {
        return "none".into();
    }
    map.iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[allow(dead_code)]
fn format_sample_list(values: &[String]) -> String {
    if values.is_empty() {
        return "none".into();
    }
    values.join(",")
}

#[allow(dead_code)]
fn rollout_recommendation(
    clause: &Clause,
    current: &SupportDetail,
    block: &SupportDetail,
) -> (String, String, String) {
    let observe = "use notify-only observe policy for this clause before enforcement".to_string();
    match clause.effect {
        Effect::Notify => {
            if block.supported {
                (
                    "already notify; collect baseline event volume".into(),
                    "eligible for later block if the observed events are all unwanted".into(),
                    "promotion changes timing from post-event report to pre-operation denial"
                        .into(),
                )
            } else {
                (
                    "already notify; keep as observe/report-only".into(),
                    format!("do not promote to block yet: {}", block.reason),
                    "promotion would overclaim backend support".into(),
                )
            }
        }
        Effect::Block => {
            if current.supported {
                (
                    observe,
                    "eligible for block after observe period and false-positive review".into(),
                    "block denies before syscall commit only on hosts with matching BPF-LSM and hook profile".into(),
                )
            } else {
                (
                    observe,
                    format!("do not deploy as block yet: {}", current.reason),
                    "the declared block effect is not enforceable by the current backend selection"
                        .into(),
                )
            }
        }
        Effect::Kill => (
            observe,
            "promote to kill only after manual review; kill is post-event termination".into(),
            "the triggering syscall may already have completed before termination".into(),
        ),
    }
}

#[allow(dead_code)]
fn render_observe_policy_yaml(
    policy_ref: &str,
    resolved: &ResolvedPolicy,
    parsed: &Policy,
) -> String {
    let mut out = String::new();
    writeln!(
        &mut out,
        "# ActPlane observe-first policy generated from {}.",
        policy_ref
    )
    .unwrap();
    writeln!(
        &mut out,
        "# Every rule clause is downgraded to notify for rollout observation."
    )
    .unwrap();
    if let Some(domain) = &resolved.domain {
        writeln!(
            &mut out,
            "# Source domain: {} (flattened selected policy).",
            domain.name
        )
        .unwrap();
    }
    writeln!(&mut out, "version: 1").unwrap();
    writeln!(&mut out, "policy: |").unwrap();
    for line in render_observe_dsl(parsed).trim_end().lines() {
        if !line.is_empty() {
            out.push_str("  ");
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

#[allow(dead_code)]
fn render_observe_dsl(parsed: &Policy) -> String {
    let mut out = String::new();
    for source in &parsed.sources {
        writeln!(
            &mut out,
            "source {} = {} \"{}\"",
            source.label,
            kind_name(source.kind),
            dsl_literal(&source.pattern)
        )
        .unwrap();
    }
    if !parsed.sources.is_empty() {
        out.push('\n');
    }
    for xform in &parsed.xforms {
        writeln!(
            &mut out,
            "{} {} by exec \"{}\"",
            if xform.endorse {
                "endorse"
            } else {
                "declassify"
            },
            xform.label,
            dsl_literal(&xform.gate)
        )
        .unwrap();
    }
    if !parsed.xforms.is_empty() {
        out.push('\n');
    }
    for rule in &parsed.rules {
        writeln!(&mut out, "rule {}:", rule.name).unwrap();
        for clause in &rule.clauses {
            writeln!(&mut out, "  {}", render_observe_clause(clause)).unwrap();
        }
        let reason = if rule.reason.trim().is_empty() {
            "Observe-first rollout for original policy.".to_string()
        } else {
            format!("Observe-first rollout for original policy: {}", rule.reason)
        };
        writeln!(&mut out, "  because \"{}\"", dsl_literal(&reason)).unwrap();
        out.push('\n');
    }
    out
}

#[allow(dead_code)]
fn render_observe_clause(clause: &Clause) -> String {
    let mut out = format!("notify {}", op_name(clause.op));
    match clause.target.kind {
        Kind::Exec => {
            out.push_str(&format!(" \"{}\"", dsl_literal(&clause.target.pattern)));
            if let Some(arg) = &clause.target.arg {
                out.push_str(&format!(" \"{}\"", dsl_literal(arg)));
            }
        }
        Kind::File | Kind::Endpoint => {
            out.push_str(&format!(
                " {} \"{}\"",
                kind_name(clause.target.kind),
                dsl_literal(&clause.target.pattern)
            ));
        }
    }
    if !matches!(clause.when, Expr::True) {
        out.push_str(" if ");
        out.push_str(&render_dsl_expr(&clause.when));
    }
    if let Some(cond) = &clause.unless {
        out.push_str(" unless ");
        out.push_str(&render_dsl_cond(cond));
    }
    out
}

#[allow(dead_code)]
fn render_dsl_expr(expr: &Expr) -> String {
    match expr {
        Expr::True => "true".into(),
        Expr::Label(label) => label.clone(),
        Expr::Not(label) => format!("not {}", label),
        Expr::And(left, right) => {
            format!("{} and {}", render_dsl_expr(left), render_dsl_expr(right))
        }
        Expr::Or(left, right) => format!("{} or {}", render_dsl_expr(left), render_dsl_expr(right)),
    }
}

#[allow(dead_code)]
fn render_dsl_cond(cond: &Cond) -> String {
    match cond {
        Cond::Target { negate, pattern } => {
            if *negate {
                format!("target not \"{}\"", dsl_literal(pattern))
            } else {
                format!("target \"{}\"", dsl_literal(pattern))
            }
        }
        Cond::LineageIncludes { exec } => {
            format!("lineage-includes exec \"{}\"", dsl_literal(exec))
        }
        Cond::After {
            gate_op,
            gate_pattern,
            gate_exit,
            since,
        } => {
            let mut out = format!(
                "after {} \"{}\"",
                op_name(*gate_op),
                dsl_literal(gate_pattern)
            );
            if let Some(exit) = gate_exit {
                out.push_str(&format!(" exits {}", exit));
            }
            if !since.is_empty() {
                out.push_str(" since ");
                out.push_str(
                    &since
                        .iter()
                        .map(|(op, pattern, arg)| render_dsl_event(*op, pattern, arg.as_deref()))
                        .collect::<Vec<_>>()
                        .join(" or "),
                );
            }
            out
        }
    }
}

#[allow(dead_code)]
fn render_dsl_event(op: Op, pattern: &str, arg: Option<&str>) -> String {
    let mut out = format!("{} \"{}\"", op_name(op), dsl_literal(pattern));
    if let Some(arg) = arg {
        out.push_str(&format!(" \"{}\"", dsl_literal(arg)));
    }
    out
}

#[allow(dead_code)]
fn dsl_literal(value: &str) -> String {
    value.replace(['\n', '\r'], " ").replace('"', "'")
}

fn policy_ref_for_cli(cli: &PolicyInput) -> String {
    cli.policy
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| {
            if cli.rule.is_some() {
                "--rule".to_string()
            } else {
                "auto-discovered policy".to_string()
            }
        })
}

fn emit_check_report(contents: &str, out: Option<&Path>, force: bool, label: &str) -> Result<()> {
    if let Some(path) = out {
        if path.exists() && !force {
            return Err(format!(
                "{} already exists (use --force to overwrite)",
                path.display()
            )
            .into());
        }
        std::fs::write(path, contents)?;
        eprintln!("actplane: wrote {label} {}", path.display());
    } else {
        print!("{contents}");
    }
    Ok(())
}

fn render_check_error_json(
    policy_ref: &str,
    resolved: Option<&ResolvedPolicy>,
    error: &str,
) -> Result<String> {
    let record = json!({
        "schema": "actplane.compile.v1",
        "ok": false,
        "policy_ref": policy_ref,
        "domain": resolved.map(domain_json).unwrap_or(Value::Null),
        "error": error,
    });
    Ok(serde_json::to_string_pretty(&record)? + "\n")
}

fn render_check_json(
    policy_ref: &str,
    resolved: &ResolvedPolicy,
    parsed: &Policy,
    compiled: &dsl::Compiled,
    active_lsms: &str,
    lsm_bpf: bool,
    force_tracepoint: bool,
) -> Result<String> {
    let warnings = backend_support_warnings(parsed, compiled, lsm_bpf)
        .into_iter()
        .map(|w| {
            json!({
                "code": w.code,
                "message": w.message,
            })
        })
        .collect::<Vec<_>>();
    let record = json!({
        "schema": "actplane.compile.v1",
        "ok": true,
        "policy_ref": policy_ref,
        "domain": domain_json(resolved),
        "host": {
            "active_lsms": active_lsms,
            "bpf_lsm_active": lsm_bpf,
            "force_tracepoint": force_tracepoint,
        },
        "matrix_scope": "static_policy_host_support",
        "matrix_note": "This reports static host/backend support for the selected policy. Runtime delta admission can reject later deltas that require hook classes or path matcher classes not enabled when the engine was loaded.",
        "environment": {
            "ACTPLANE_FORCE_TRACEPOINT": std::env::var("ACTPLANE_FORCE_TRACEPOINT").ok(),
            "ACTPLANE_HOOK_PROFILE": std::env::var("ACTPLANE_HOOK_PROFILE").ok(),
            "ACTPLANE_ENABLE_ADVANCED_HOOKS": std::env::var("ACTPLANE_ENABLE_ADVANCED_HOOKS").ok(),
            "ACTPLANE_RESERVE_FILE_FLOW": std::env::var("ACTPLANE_RESERVE_FILE_FLOW").ok(),
        },
        "rule_count": compiled.meta.len(),
        "rules": rule_meta_json(compiled),
        "backend_support": {
            "sources": source_support_json(parsed, compiled),
            "clauses": clause_support_json(parsed, compiled, lsm_bpf),
        },
        "warnings": warnings,
    });
    Ok(serde_json::to_string_pretty(&record)? + "\n")
}

fn render_check_explain(
    policy_ref: &str,
    loaded: &LoadedPolicy,
    resolved: &ResolvedPolicy,
    parsed: &Policy,
    compiled: &dsl::Compiled,
    active_lsms: &str,
    lsm_bpf: bool,
    force_tracepoint: bool,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "ActPlane policy review").unwrap();
    writeln!(&mut out, "policy: {}", policy_ref).unwrap();
    match &resolved.domain {
        Some(domain) => {
            writeln!(&mut out, "domain: {}", domain.name).unwrap();
            if let Some(parent) = &domain.parent {
                writeln!(&mut out, "parent: {}", parent).unwrap();
            }
            writeln!(
                &mut out,
                "policy rules: {}",
                format_domain_policy_rules(domain)
            )
            .unwrap();
        }
        None => writeln!(&mut out, "domain: none (flat policy)").unwrap(),
    }
    writeln!(
        &mut out,
        "rules: {} DSL rule(s), {} lowered kernel matcher(s)",
        parsed.rules.len(),
        compiled.meta.len()
    )
    .unwrap();

    writeln!(&mut out, "\nhost/backend:").unwrap();
    writeln!(
        &mut out,
        "  - active LSMs: {}",
        if active_lsms.trim().is_empty() {
            "unknown"
        } else {
            active_lsms
        }
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - BPF-LSM pre-op block: {}",
        if lsm_bpf { "available" } else { "unavailable" }
    )
    .unwrap();
    if force_tracepoint {
        writeln!(
            &mut out,
            "  - ACTPLANE_FORCE_TRACEPOINT: set, so BPF-LSM is treated as unavailable"
        )
        .unwrap();
    }
    writeln!(
        &mut out,
        "  - engine profile: policy-selected attach set; runtime deltas cannot add hook classes or path contains/suffix matcher classes after load"
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - review scope: selected policy and current host support, not a live loaded-engine guarantee"
    )
    .unwrap();

    writeln!(&mut out, "\nruntime delta admission:").unwrap();
    append_append_delta_approval(&mut out, &loaded.config.runtime.approval.append_delta);

    writeln!(&mut out, "\nlabels:").unwrap();
    append_label_bits(&mut out, compiled);

    writeln!(&mut out, "\nsources and flows:").unwrap();
    if parsed.sources.is_empty() {
        writeln!(&mut out, "  - none").unwrap();
    } else {
        for source in &parsed.sources {
            let (supported, reason, limitations) =
                source_support_detail(compiled, source.kind, &source.pattern);
            writeln!(&mut out, "  - {}", source_summary(source)).unwrap();
            writeln!(&mut out, "    flow: {}", source_flow_summary(source.kind)).unwrap();
            writeln!(
                &mut out,
                "    support: {}; {}",
                if supported {
                    "supported"
                } else {
                    "unsupported"
                },
                reason
            )
            .unwrap();
            if !limitations.is_empty() {
                writeln!(&mut out, "    limitations: {}", limitations.join("; ")).unwrap();
            }
        }
    }
    writeln!(
        &mut out,
        "  - coverage note: ordinary flows use the loaded hook profile; advanced mmap/mprotect, SCM_RIGHTS, Unix-socket IPC, pipe/socketpair, sendfile, copy_file_range, and splice coverage requires advanced hooks or the full hook profile"
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - coverage note: shared memory, IPv6, hostname endpoint globs, batch UDP syscalls, and unbounded fd/provenance chains remain limited or unsupported"
    )
    .unwrap();

    writeln!(&mut out, "\ntransforms:").unwrap();
    if parsed.xforms.is_empty() {
        writeln!(&mut out, "  - none").unwrap();
    } else {
        for xform in &parsed.xforms {
            let verb = if xform.endorse {
                "endorse"
            } else {
                "declassify"
            };
            let effect = if xform.endorse {
                "adds the label when the gate exec matches"
            } else {
                "removes the label when the gate exec matches"
            };
            writeln!(
                &mut out,
                "  - {} {} by exec \"{}\" -> {}",
                verb, xform.label, xform.gate, effect
            )
            .unwrap();
        }
        writeln!(
            &mut out,
            "  - runtime appended declassification still requires AUTH_DECLASSIFY and authority over the cleared local label bits"
        )
        .unwrap();
    }

    writeln!(&mut out, "\nrules:").unwrap();
    for (rule_idx, rule) in parsed.rules.iter().enumerate() {
        writeln!(&mut out, "  {}. rule {}", rule_idx + 1, rule.name).unwrap();
        writeln!(&mut out, "     reason: {}", rule.reason).unwrap();
        for clause in &rule.clauses {
            let support = clause_support_detail(
                compiled,
                clause.effect,
                clause.op,
                clause.target.kind,
                &clause.target.pattern,
                clause.target.arg.as_deref(),
                lsm_bpf,
            );
            let lowered = lowered_clause_summary(compiled, &rule.name, clause.source_index);
            writeln!(
                &mut out,
                "     clause {}: {}",
                clause.source_index + 1,
                clause_summary(clause)
            )
            .unwrap();
            writeln!(
                &mut out,
                "       enforcement: {}; {}",
                support.status, support.reason
            )
            .unwrap();
            writeln!(
                &mut out,
                "       timing: {}",
                enforcement_timing(clause.effect, &support)
            )
            .unwrap();
            writeln!(
                &mut out,
                "       backend: {}; pre_op={}",
                support.mode, support.pre_op
            )
            .unwrap();
            if !support.limitations.is_empty() {
                writeln!(
                    &mut out,
                    "       limitations: {}",
                    support.limitations.join("; ")
                )
                .unwrap();
            }
            for warning in clause_condition_warnings(clause, compiled) {
                writeln!(&mut out, "       condition warning: {}", warning.message).unwrap();
            }
            writeln!(&mut out, "       lowered: {}", lowered).unwrap();
        }
    }

    writeln!(&mut out, "\nviolation event/audit semantics:").unwrap();
    writeln!(
        &mut out,
        "  - reports exact lowered clause effect, declared op, kernel op, target kind, target pattern, and optional argv token"
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - matched_label_details enumerates positive required label bits for the selected lowered matcher, not labels that appear only in `not` terms"
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - causal_chain is a reported single-hop origin when available, not a complete provenance graph"
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - append policy delta is the authority-checked runtime mutation path"
    )
    .unwrap();

    let warns = backend_support_warnings(parsed, compiled, lsm_bpf);
    if warns.is_empty() {
        writeln!(&mut out, "\nwarnings: none").unwrap();
    } else {
        writeln!(&mut out, "\nwarnings:").unwrap();
        for w in warns {
            writeln!(&mut out, "  - {}: {}", w.code, w.message).unwrap();
        }
    }
    out
}

fn domain_json(resolved: &ResolvedPolicy) -> Value {
    match &resolved.domain {
        Some(domain) => json!({
            "name": domain.name,
            "parent": domain.parent,
            "locked": domain.locked,
            "default": domain.defaults,
            "disabled": domain.disabled,
        }),
        None => Value::Null,
    }
}

fn rule_meta_json(compiled: &dsl::Compiled) -> Vec<Value> {
    compiled
        .meta
        .iter()
        .enumerate()
        .map(|(idx, rule)| {
            let mut value = json!({
                "rule_id": idx,
                "name": rule.name,
                "effect": effect_name(rule.effect),
                "ops": rule.ops,
                "clause_op": rule.clause_op,
                "clause_source_index": rule.clause_source_index,
                "kernel_op": rule.kernel_op,
                "target_kind": kind_name(rule.target_kind),
                "target_pattern": rule.target_pattern,
                "target_arg": rule.target_arg,
                "reason": rule.reason,
            });
            if let Some(source) = &rule.source {
                value["source_ref"] = json!(source.source_ref);
                value["source_start_line"] = json!(source.start_line);
                value["source_end_line"] = json!(source.end_line);
                value["source_hash"] = json!(crate::audit::policy_hash(&source.text));
                value["source_text"] = json!(source.text);
                if let Some(line) = source.clause_start_line {
                    value["clause_start_line"] = json!(line);
                }
                if let Some(line) = source.clause_end_line {
                    value["clause_end_line"] = json!(line);
                }
                if let Some(text) = &source.clause_text {
                    value["clause_hash"] = json!(crate::audit::policy_hash(text));
                    value["clause_text"] = json!(text);
                }
                if let Some(mode) = &source.binding_mode {
                    value["binding_mode"] = json!(mode);
                }
                value["immutable"] = json!(source.binding_mode.as_deref() == Some("locked"));
            }
            value
        })
        .collect()
}

fn source_support_json(policy: &Policy, compiled: &dsl::Compiled) -> Vec<Value> {
    policy
        .sources
        .iter()
        .map(|source| {
            let (supported, reason, limitations) =
                source_support_detail(compiled, source.kind, &source.pattern);
            json!({
                "label": source.label,
                "kind": kind_name(source.kind),
                "pattern": source.pattern,
                "supported": supported,
                "reason": reason,
                "limitations": limitations,
            })
        })
        .collect()
}

fn clause_support_json(policy: &Policy, compiled: &dsl::Compiled, lsm_bpf: bool) -> Vec<Value> {
    let mut out = Vec::new();
    for rule in &policy.rules {
        for (clause_index, clause) in rule.clauses.iter().enumerate() {
            let support = clause_support_detail(
                compiled,
                clause.effect,
                clause.op,
                clause.target.kind,
                &clause.target.pattern,
                clause.target.arg.as_deref(),
                lsm_bpf,
            );
            let condition_warnings = clause_condition_warnings(clause, compiled)
                .into_iter()
                .map(|w| {
                    json!({
                        "code": w.code,
                        "message": w.message,
                    })
                })
                .collect::<Vec<_>>();
            out.push(json!({
                "rule": rule.name,
                "clause_index": clause_index,
                "effect": effect_name(clause.effect),
                "op": op_name(clause.op),
                "target_kind": kind_name(clause.target.kind),
                "target_pattern": clause.target.pattern,
                "target_arg": clause.target.arg,
                "supported": support.supported,
                "status": support.status,
                "mode": support.mode,
                "pre_op": support.pre_op,
                "reason": support.reason,
                "limitations": support.limitations,
                "condition_warnings": condition_warnings,
            }));
        }
    }
    out
}

fn source_support_detail(
    compiled: &dsl::Compiled,
    kind: Kind,
    pattern: &str,
) -> (bool, String, Vec<&'static str>) {
    match kind {
        Kind::Exec => (
            true,
            "exec source labels are applied on process exec".into(),
            vec![],
        ),
        Kind::File => (
            true,
            "file source labels are applied through file open/read flow".into(),
            vec!["open-time file source handling is conservative"],
        ),
        Kind::Endpoint => endpoint_support_detail(compiled, pattern, "source"),
    }
}

struct SupportDetail {
    supported: bool,
    status: &'static str,
    mode: &'static str,
    pre_op: bool,
    reason: String,
    limitations: Vec<&'static str>,
}

#[derive(Clone)]
struct BackendWarning {
    code: &'static str,
    message: String,
}

#[derive(Clone)]
struct ClauseConditionWarning {
    code: &'static str,
    message: String,
}

fn clause_support_detail(
    compiled: &dsl::Compiled,
    effect: Effect,
    op: Op,
    kind: Kind,
    pattern: &str,
    arg: Option<&str>,
    lsm_bpf: bool,
) -> SupportDetail {
    if matches!(op, Op::Connect | Op::Recv)
        && kind == Kind::Endpoint
        && !endpoint_pattern_supported(compiled, pattern)
    {
        let (_, reason, limitations) = endpoint_support_detail(compiled, pattern, "target");
        return SupportDetail {
            supported: false,
            status: "unsupported",
            mode: "none",
            pre_op: false,
            reason,
            limitations,
        };
    }

    match effect {
        Effect::Block => {
            if op == Op::Exec && arg.is_some() {
                SupportDetail {
                    supported: false,
                    status: "unsupported",
                    mode: "none",
                    pre_op: false,
                    reason: "argv is only available after exec, so this cannot block pre-exec"
                        .into(),
                    limitations: vec!["use kill exec for post-exec termination"],
                }
            } else if !lsm_bpf {
                SupportDetail {
                    supported: false,
                    status: "unsupported",
                    mode: "none",
                    pre_op: false,
                    reason: "BPF-LSM is not active on this host".into(),
                    limitations: vec!["notify and kill still use tracepoint paths where available"],
                }
            } else {
                let (reason, limitations) = match op {
                    Op::Exec => ("pre-op block via BPF-LSM bprm_check_security", vec![]),
                    Op::Read | Op::Open | Op::Write | Op::Unlink => {
                        ("pre-op block via BPF-LSM file/path hooks", vec![])
                    }
                    Op::Connect => (
                        "pre-op block via BPF-LSM socket_connect",
                        endpoint_limitations(compiled, pattern),
                    ),
                    Op::Recv => (
                        "pre-op block via BPF-LSM socket_recvmsg",
                        endpoint_limitations(compiled, pattern),
                    ),
                };
                SupportDetail {
                    supported: true,
                    status: "supported",
                    mode: "bpf-lsm",
                    pre_op: true,
                    reason: reason.into(),
                    limitations,
                }
            }
        }
        Effect::Notify => {
            let (reason, limitations) = match op {
                Op::Recv => (
                    "tracepoint report after recv",
                    endpoint_limitations_with(compiled, pattern, "post-receive in tracepoint mode"),
                ),
                Op::Exec => ("post-exec tracepoint report", vec![]),
                Op::Read | Op::Open | Op::Write | Op::Unlink => ("tracepoint report", vec![]),
                Op::Connect => (
                    "connect tracepoint report",
                    endpoint_limitations(compiled, pattern),
                ),
            };
            SupportDetail {
                supported: true,
                status: "supported",
                mode: "tracepoint",
                pre_op: false,
                reason: reason.into(),
                limitations,
            }
        }
        Effect::Kill => {
            let (reason, limitations) = match op {
                Op::Recv => (
                    "tracepoint kill after recv",
                    endpoint_limitations_with(compiled, pattern, "post-receive in tracepoint mode"),
                ),
                Op::Exec => ("post-exec tracepoint kill", vec![]),
                Op::Read | Op::Open | Op::Write | Op::Unlink => ("tracepoint kill", vec![]),
                Op::Connect => (
                    "connect tracepoint kill",
                    endpoint_limitations(compiled, pattern),
                ),
            };
            SupportDetail {
                supported: true,
                status: "supported",
                mode: "tracepoint",
                pre_op: false,
                reason: reason.into(),
                limitations,
            }
        }
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::File => "file",
        Kind::Endpoint => "endpoint",
        Kind::Exec => "exec",
    }
}

fn endpoint_pattern_supported(compiled: &dsl::Compiled, pattern: &str) -> bool {
    endpoint_pattern_is_numeric_ipv4(pattern)
        || compiled
            .endpoint_resolutions
            .get(pattern)
            .is_some_and(|addrs| !addrs.is_empty())
}

fn endpoint_support_detail(
    compiled: &dsl::Compiled,
    pattern: &str,
    role: &str,
) -> (bool, String, Vec<&'static str>) {
    if endpoint_pattern_is_numeric_ipv4(pattern) {
        return (
            true,
            format!("endpoint {role} matches numeric IPv4 connect and recv paths"),
            vec!["IPv6 is not enforced in-kernel"],
        );
    }
    match compiled.endpoint_resolutions.get(pattern) {
        Some(addrs) if !addrs.is_empty() => (
            true,
            format!(
                "endpoint {role} hostname resolved to IPv4 address(es): {}",
                addrs.join(", ")
            ),
            vec![
                "hostname is resolved at policy compile/load time",
                "DNS changes require policy reload",
                "IPv6 addresses are ignored",
            ],
        ),
        Some(_) => (
            false,
            format!("endpoint {role} hostname did not resolve to an IPv4 address"),
            vec![
                "hostname is resolved at policy compile/load time",
                "DNS changes require policy reload",
                "IPv6 addresses are ignored",
            ],
        ),
        None => (
            false,
            format!("endpoint {role} pattern is not numeric IPv4 or an exact resolvable hostname"),
            vec!["wildcard hostnames and IPv6 are not enforced in-kernel"],
        ),
    }
}

fn endpoint_limitations(compiled: &dsl::Compiled, pattern: &str) -> Vec<&'static str> {
    if endpoint_pattern_is_numeric_ipv4(pattern) {
        vec!["IPv4 only"]
    } else if compiled
        .endpoint_resolutions
        .get(pattern)
        .is_some_and(|addrs| !addrs.is_empty())
    {
        vec![
            "hostname resolved at policy compile/load time",
            "DNS changes require policy reload",
            "IPv4 only",
        ]
    } else {
        vec!["IPv4 only"]
    }
}

fn endpoint_limitations_with(
    compiled: &dsl::Compiled,
    pattern: &str,
    extra: &'static str,
) -> Vec<&'static str> {
    let mut limitations = endpoint_limitations(compiled, pattern);
    limitations.push(extra);
    limitations
}

fn backend_support_lines(policy: &Policy, compiled: &dsl::Compiled, lsm_bpf: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for rule in &policy.rules {
        for clause in &rule.clauses {
            lines.push(format!(
                "{}: {} {} -> {}",
                rule.name,
                effect_name(clause.effect),
                op_name(clause.op),
                clause_support(
                    clause.effect,
                    clause.op,
                    clause.target.kind,
                    &clause.target.pattern,
                    clause.target.arg.as_deref(),
                    compiled,
                    lsm_bpf
                )
            ));
        }
    }
    lines
}

fn clause_condition_warnings(
    clause: &Clause,
    compiled: &dsl::Compiled,
) -> Vec<ClauseConditionWarning> {
    let mut warnings = Vec::new();
    if matches!(clause.op, Op::Connect | Op::Recv)
        && clause.target.kind == Kind::Endpoint
        && let Some(Cond::Target { negate, pattern }) = &clause.unless
    {
        if endpoint_pattern_is_numeric_ipv4(pattern) {
            return warnings;
        }
        match compiled.endpoint_resolutions.get(pattern) {
            Some(addrs) if addrs.len() == 1 => {}
            Some(addrs) if addrs.len() > 1 => warnings.push(ClauseConditionWarning {
                code: "endpoint_target_condition_multi_ipv4_hostname",
                message: format!(
                    "unless target{} \"{}\" resolves to multiple IPv4 addresses, but endpoint target conditions can store one address in the current ABI; the condition fails closed.",
                    if *negate { " not" } else { "" },
                    pattern
                ),
            }),
            Some(_) => warnings.push(ClauseConditionWarning {
                code: "endpoint_target_condition_unresolved_hostname",
                message: format!(
                    "unless target{} \"{}\" did not resolve to an IPv4 address at compile/load time; the condition fails closed.",
                    if *negate { " not" } else { "" },
                    pattern
                ),
            }),
            None => warnings.push(ClauseConditionWarning {
                code: "endpoint_target_condition_unsupported_pattern",
                message: format!(
                    "unless target{} \"{}\" uses a wildcard hostname or IPv6 pattern; endpoint target conditions support numeric IPv4 or a single resolved IPv4 hostname.",
                    if *negate { " not" } else { "" },
                    pattern
                ),
            }),
        }
    }
    warnings
}

fn backend_support_warnings(
    policy: &Policy,
    compiled: &dsl::Compiled,
    lsm_bpf: bool,
) -> Vec<BackendWarning> {
    let mut warnings = Vec::new();
    for source in &policy.sources {
        if source.kind == Kind::Endpoint && !endpoint_pattern_supported(compiled, &source.pattern) {
            let (_, reason, _) = endpoint_support_detail(compiled, &source.pattern, "source");
            warnings.push(BackendWarning {
                code: "endpoint_source_unsupported",
                message: format!(
                    "source {} = endpoint \"{}\" is unsupported: {}.",
                    source.label, source.pattern, reason
                ),
            });
        }
    }
    for rule in &policy.rules {
        for clause in &rule.clauses {
            if matches!(clause.op, Op::Connect | Op::Recv)
                && clause.target.kind == Kind::Endpoint
                && !endpoint_pattern_supported(compiled, &clause.target.pattern)
            {
                let (_, reason, _) =
                    endpoint_support_detail(compiled, &clause.target.pattern, "target");
                warnings.push(BackendWarning {
                    code: "endpoint_target_unsupported",
                    message: format!(
                        "{} {} endpoint \"{}\" is unsupported: {}; this rule will not fire for that endpoint.",
                        effect_name(clause.effect),
                        op_name(clause.op),
                        clause.target.pattern,
                        reason
                    ),
                });
            }
            warnings.extend(clause_condition_warnings(clause, compiled).into_iter().map(
                |warning| BackendWarning {
                    code: warning.code,
                    message: format!("{}: {}", rule.name, warning.message),
                },
            ));
            if clause.effect == Effect::Block
                && clause.op == Op::Exec
                && clause.target.arg.is_some()
            {
                warnings.push(BackendWarning {
                    code: "argv_block_exec_post_exec_only",
                    message: format!(
                        "{}: `block exec` with an argv token cannot block pre-exec because argv is only available after exec; use `kill exec` if termination after exec is acceptable.",
                        rule.name
                    ),
                });
            }
            if clause.effect == Effect::Block && !lsm_bpf {
                warnings.push(BackendWarning {
                    code: "bpf_lsm_inactive_for_block",
                    message: format!(
                        "{}: `block {}` is unsupported on this host until BPF-LSM is active.",
                        rule.name,
                        op_name(clause.op)
                    ),
                });
            }
        }
    }
    warnings
}

fn clause_support(
    effect: Effect,
    op: Op,
    kind: Kind,
    pattern: &str,
    arg: Option<&str>,
    compiled: &dsl::Compiled,
    lsm_bpf: bool,
) -> String {
    let detail = clause_support_detail(compiled, effect, op, kind, pattern, arg, lsm_bpf);
    if detail.limitations.is_empty() {
        detail.reason
    } else {
        format!("{}, {}", detail.reason, detail.limitations.join(", "))
    }
}

fn append_append_delta_approval(out: &mut String, approval: &AppendDeltaApprovalConfig) {
    if !approval.required {
        writeln!(out, "  - append policy delta approval: not required").unwrap();
        writeln!(out, "  - admission model: metadata_only").unwrap();
        return;
    }

    let mut fields = vec!["approved_by"];
    if approval.require_approval_ref {
        fields.push("approval_ref");
    }
    if approval.require_generated_by {
        fields.push("generated_by");
    }
    writeln!(out, "  - append policy delta approval: required").unwrap();
    writeln!(out, "  - required metadata: {}", fields.join(", ")).unwrap();
    if approval.allowed_approvers.is_empty() {
        writeln!(out, "  - allowed approvers: any non-empty approved_by").unwrap();
    } else {
        writeln!(
            out,
            "  - allowed approvers: {}",
            approval.allowed_approvers.join(", ")
        )
        .unwrap();
    }
    writeln!(out, "  - admission model: static_metadata_allowlist").unwrap();
    writeln!(out, "  - external_verified=false, signature=null").unwrap();
}

fn append_label_bits(out: &mut String, compiled: &dsl::Compiled) {
    if compiled.labels.is_empty() {
        writeln!(out, "  - none").unwrap();
        return;
    }
    let mut labels = compiled.labels.iter().collect::<Vec<_>>();
    labels.sort_by_key(|(_, mask)| **mask);
    for (name, mask) in labels {
        writeln!(out, "  - {} = {:#x}", name, mask).unwrap();
    }
}

fn source_summary(source: &Source) -> String {
    format!(
        "source {} = {} \"{}\"",
        source.label,
        kind_name(source.kind),
        source.pattern
    )
}

fn source_flow_summary(kind: Kind) -> &'static str {
    match kind {
        Kind::Exec => "matching exec adds the label to the process and fork descendants",
        Kind::File => {
            "matching file carries the label; reads copy it into the process, writes copy process labels into the file"
        }
        Kind::Endpoint => {
            "matching IPv4 endpoint carries the label; recv copies it into the process, connect records egress labels"
        }
    }
}

fn clause_summary(clause: &Clause) -> String {
    let mut out = format!("{} {}", effect_name(clause.effect), op_name(clause.op));
    match clause.target.kind {
        Kind::Exec => {
            out.push_str(&format!(" \"{}\"", clause.target.pattern));
            if let Some(arg) = &clause.target.arg {
                out.push_str(&format!(" \"{}\"", arg));
            }
        }
        Kind::File | Kind::Endpoint => {
            out.push_str(&format!(
                " {} \"{}\"",
                kind_name(clause.target.kind),
                clause.target.pattern
            ));
        }
    }
    out.push_str(" if ");
    out.push_str(&expr_summary(&clause.when));
    if let Some(cond) = &clause.unless {
        out.push_str(" unless ");
        out.push_str(&cond_summary(cond));
    }
    out
}

fn expr_summary(expr: &Expr) -> String {
    match expr {
        Expr::True => "true".into(),
        Expr::Label(label) => label.clone(),
        Expr::Not(label) => format!("not {}", label),
        Expr::And(left, right) => {
            format!("({} and {})", expr_summary(left), expr_summary(right))
        }
        Expr::Or(left, right) => format!("({} or {})", expr_summary(left), expr_summary(right)),
    }
}

fn cond_summary(cond: &Cond) -> String {
    match cond {
        Cond::Target { negate, pattern } => {
            if *negate {
                format!("target not \"{}\"", pattern)
            } else {
                format!("target \"{}\"", pattern)
            }
        }
        Cond::LineageIncludes { exec } => format!("lineage-includes exec \"{}\"", exec),
        Cond::After {
            gate_op,
            gate_pattern,
            gate_exit,
            since,
        } => {
            let mut out = format!("after {} \"{}\"", op_name(*gate_op), gate_pattern);
            if let Some(exit) = gate_exit {
                out.push_str(&format!(" exits {}", exit));
            }
            if !since.is_empty() {
                let events = since
                    .iter()
                    .map(|(op, pattern, arg)| event_summary(*op, pattern, arg.as_deref()))
                    .collect::<Vec<_>>();
                out.push_str(" since ");
                out.push_str(&events.join(" or "));
            }
            out
        }
    }
}

fn event_summary(op: Op, pattern: &str, arg: Option<&str>) -> String {
    let mut out = format!("{} \"{}\"", op_name(op), pattern);
    if let Some(arg) = arg {
        out.push_str(&format!(" \"{}\"", arg));
    }
    out
}

fn enforcement_timing(effect: Effect, support: &SupportDetail) -> &'static str {
    if !support.supported {
        return "not enforceable by the current backend selection";
    }
    match effect {
        Effect::Block if support.pre_op => "pre-operation denial before syscall commit",
        Effect::Block => "block requested, but no pre-operation backend is available",
        Effect::Notify => "post-event report; operation proceeds",
        Effect::Kill => "post-event termination; the triggering syscall may already have completed",
    }
}

fn lowered_clause_summary(
    compiled: &dsl::Compiled,
    rule_name: &str,
    clause_source_index: usize,
) -> String {
    let mut rule_ids = Vec::new();
    let mut kernel_ops = std::collections::BTreeSet::new();
    for (idx, meta) in compiled.meta.iter().enumerate() {
        if meta.name == rule_name && meta.clause_source_index == clause_source_index {
            rule_ids.push(idx);
            kernel_ops.insert(meta.kernel_op.clone());
        }
    }
    if rule_ids.is_empty() {
        return "0 kernel matcher(s)".into();
    }
    let ids = rule_ids
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let ops = kernel_ops.into_iter().collect::<Vec<_>>().join(", ");
    format!(
        "{} kernel matcher(s), rule_id(s) [{}], kernel_op(s) [{}]",
        rule_ids.len(),
        ids,
        ops
    )
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Notify => "notify",
        Effect::Block => "block",
        Effect::Kill => "kill",
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

fn endpoint_pattern_is_numeric_ipv4(pat: &str) -> bool {
    if pat == "*" {
        return true;
    }
    let body = pat.trim_end_matches('.');
    let mut count = 0usize;
    for octet in body.split('.') {
        if octet.is_empty() || octet.parse::<u8>().is_err() {
            return false;
        }
        count += 1;
    }
    (1..=4).contains(&count)
}

pub(crate) fn doctor(cli: &PolicyInput) -> Result<i32> {
    println!("ActPlane doctor\n");
    let mut problems = 0;

    doctor_path_actplane(&mut problems);

    match load_policy(cli) {
        Ok(loaded) => {
            let where_ = loaded
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "--rule".into());
            let resolved = resolve_policy(&loaded, cli.domain.as_deref())?;
            match dsl::compile_str(&resolved.source) {
                Ok(compiled) => {
                    if let Some(domain) = &resolved.domain {
                        println!(
                            "✓ policy: {} domain `{}` ({} rule(s))",
                            where_,
                            domain.name,
                            compiled.meta.len()
                        );
                    } else {
                        println!("✓ policy: {} ({} rule(s))", where_, compiled.meta.len());
                    }
                    let feedback = feedback_paths(&loaded);
                    println!("✓ feedback file: {}", feedback.feedback.display());
                    println!("✓ audit log: {}", feedback.audit.display());
                    println!("✓ event log: {}", feedback.events.display());
                }
                Err(e) => {
                    problems += 1;
                    println!("✗ policy: {} does not compile: {}", where_, e);
                }
            }
            doctor_agent_files(&loaded.root, &mut problems);
        }
        Err(e) => {
            problems += 1;
            println!("✗ policy: {}", e);
            let cwd = std::env::current_dir()?;
            doctor_agent_files(&cwd, &mut problems);
        }
    }

    if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        println!("✓ kernel BTF: /sys/kernel/btf/vmlinux");
    } else {
        problems += 1;
        println!("✗ kernel BTF: missing /sys/kernel/btf/vmlinux");
    }

    if have_bpf_caps() {
        println!("✓ eBPF privilege: current process has root/CAP_BPF+CAP_SYS_ADMIN");
    } else if passwordless_sudo_available() {
        println!("✓ eBPF privilege: passwordless sudo is available");
    } else {
        problems += 1;
        println!("✗ eBPF privilege: run/watch needs sudo or CAP_BPF+CAP_SYS_ADMIN");
    }

    let lsm = active_lsms().unwrap_or_default();
    if lsm_list_has_bpf(&lsm) {
        println!("✓ BPF-LSM: active ({})", lsm.trim());
    } else if let Some(source) = bpf_lsm_configured_for_next_boot() {
        println!(
            "⚠ BPF-LSM: configured for next boot in {}; reboot pending ({})",
            source.display(),
            lsm.trim()
        );
    } else {
        println!(
            "⚠ BPF-LSM: not active; `block` rules will not fire ({})",
            lsm.trim()
        );
    }

    println!("\nNext commands:");
    println!("  actplane compile");
    println!("  codex");
    println!("  sudo -E actplane run -- <agent-or-command>");

    if problems == 0 {
        println!("\n✓ setup looks usable.");
        Ok(0)
    } else {
        println!("\n✗ setup has {} problem(s).", problems);
        Ok(1)
    }
}

pub(crate) fn list_domains(cli: &PolicyInput) -> Result<i32> {
    let loaded = load_policy(cli)?;
    let where_ = loaded
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "--rule".into());
    if loaded.config.policy.is_some() {
        println!(
            "{} uses legacy `policy: |`; no domains are defined.",
            where_
        );
        return Ok(0);
    }

    let selected = resolve_policy(&loaded, cli.domain.as_deref())?
        .domain
        .map(|d| d.name);
    println!("Domains in {}", where_);
    for domain in domain_summaries(&loaded.config)? {
        let mark = if Some(domain.name.as_str()) == selected.as_deref() {
            "*"
        } else {
            " "
        };
        println!("{} {}", mark, domain.name);
        if let Some(parent) = &domain.parent {
            println!("    parent: {}", parent);
        }
        println!("    policy: {}", format_domain_policy_rules(&domain));
    }
    Ok(0)
}

fn format_rule_list(rules: &[String]) -> String {
    if rules.is_empty() {
        "none".into()
    } else {
        rules.join(", ")
    }
}

fn format_domain_policy_rules(domain: &DomainSummary) -> String {
    let mut rules = domain.locked.clone();
    rules.extend(domain.defaults.clone());
    format_rule_list(&rules)
}

fn doctor_path_actplane(problems: &mut usize) {
    match find_executable_on_path("actplane") {
        Some(path) => {
            let version = command_version(&path).unwrap_or_else(|| "version unknown".into());
            println!("✓ PATH actplane: {} ({})", path.display(), version);
        }
        None => {
            *problems += 1;
            println!("✗ PATH actplane: not found; install or add the release binary to PATH");
        }
    }
}

fn doctor_agent_files(root: &Path, problems: &mut usize) {
    let codex_hooks = root.join(".codex/hooks.json");
    if codex_hooks.is_file() {
        let hooks = std::fs::read_to_string(&codex_hooks).unwrap_or_default();
        if codex_hook_has_actplane_command(&hooks) {
            println!("✓ Codex hook: {}", codex_hooks.display());
        } else {
            *problems += 1;
            println!(
                "✗ Codex hook: {} exists but is not wired to `actplane feedback-hook`; run `actplane init --with-codex --force`",
                codex_hooks.display()
            );
        }
    } else {
        *problems += 1;
        println!(
            "✗ Codex hook: missing {}; add `actplane feedback-hook` as PostToolUse",
            codex_hooks.display()
        );
    }

    let agents = root.join("AGENTS.md");
    if agents.is_symlink() {
        println!(
            "✓ Codex instructions: {} -> {:?}",
            agents.display(),
            std::fs::read_link(&agents).ok()
        );
    } else if agents.is_file() {
        println!("✓ Codex instructions: {}", agents.display());
    } else {
        println!("⚠ Codex instructions: AGENTS.md missing");
    }

    let mcp = root.join(".mcp.json");
    let mut project_mcp_ok = false;
    if mcp.is_file() {
        let text = std::fs::read_to_string(&mcp).unwrap_or_default();
        if project_mcp_auto_attach_ok(&text) {
            project_mcp_ok = true;
            println!("✓ project MCP config: {}", mcp.display());
        } else {
            *problems += 1;
            println!(
                "✗ project MCP config: {} does not auto-attach with PATH `actplane`; run `actplane init --with-mcp`",
                mcp.display()
            );
        }
    } else {
        println!("⚠ project MCP config: .mcp.json missing");
    }
    if project_mcp_ok && let Some(global) = codex_global_mcp_actplane_config() {
        println!(
            "⚠ Codex global MCP also defines actplane ({}); keep either global or project config, not both",
            global.display()
        );
    }
}

fn codex_global_mcp_actplane_config() -> Option<PathBuf> {
    let path = std::env::var_os("HOME")
        .map(PathBuf::from)?
        .join(".codex/config.toml");
    let text = std::fs::read_to_string(&path).ok()?;
    text.lines()
        .any(|line| line.trim() == "[mcp_servers.actplane]")
        .then_some(path)
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn command_version(path: &Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!version.is_empty()).then_some(version)
}

fn active_lsms() -> Option<String> {
    std::fs::read_to_string("/sys/kernel/security/lsm").ok()
}

fn lsm_list_has_bpf(lsms: &str) -> bool {
    lsms.split(',').any(|name| name.trim() == "bpf")
}

fn bpf_lsm_configured_for_next_boot() -> Option<PathBuf> {
    [
        "/proc/cmdline",
        "/etc/default/grub.d/99-actplane-bpf-lsm.cfg",
        "/boot/grub/grub.cfg",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| {
        std::fs::read_to_string(path)
            .map(|text| text_has_bpf_lsm_arg(&text))
            .unwrap_or(false)
    })
}

fn text_has_bpf_lsm_arg(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .filter_map(|token| token.strip_prefix("lsm="))
        .any(lsm_list_has_bpf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsm_parser_requires_exact_bpf_token() {
        assert!(lsm_list_has_bpf("lockdown,capability,bpf"));
        assert!(text_has_bpf_lsm_arg(
            r#"GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} lsm=landlock,lockdown,yama,bpf""#
        ));
        assert!(!lsm_list_has_bpf("lockdown,capability,bpfish"));
        assert!(!text_has_bpf_lsm_arg(
            "BOOT_IMAGE=/vmlinuz lsm=landlock,lockdown,yama,bpfish"
        ));
    }

    #[test]
    fn boot_lsm_probe_mirrors_the_live_cmdline_and_reports_active_lsms() {
        // `/proc/cmdline` is the probe's first source, so whenever this boot's
        // command line names bpf in `lsm=...`, the probe must resolve to it.
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if text_has_bpf_lsm_arg(&cmdline) {
            assert_eq!(
                bpf_lsm_configured_for_next_boot(),
                Some(PathBuf::from("/proc/cmdline"))
            );
        }

        // The active-LSM reader reports a token list exactly when the kernel
        // exposes the securityfs file, and `None` means it was unreadable.
        match active_lsms() {
            Some(lsms) => {
                assert!(!lsms.trim().is_empty());
                assert_eq!(
                    lsm_list_has_bpf(&lsms),
                    lsms.split(',').any(|name| name.trim() == "bpf")
                );
            }
            None => assert!(std::fs::read_to_string("/sys/kernel/security/lsm").is_err()),
        }
    }

    #[test]
    fn doctor_agent_files_reports_wired_and_missing_integrations() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".codex")).expect("codex dir");
        std::fs::write(
            tmp.path().join(".codex/hooks.json"),
            r#"{"hooks":{"PostToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"actplane feedback-hook"}]}]}}"#,
        )
        .expect("hooks");
        std::fs::write(tmp.path().join("AGENTS.md"), "# AGENTS\n").expect("agents");
        std::fs::write(
            tmp.path().join(".mcp.json"),
            r#"{"mcpServers":{"actplane":{"type":"stdio","command":"actplane","args":["mcp","--auto-attach-parent"]}}}"#,
        )
        .expect("mcp");

        let mut problems = 0;
        doctor_agent_files(tmp.path(), &mut problems);
        assert_eq!(problems, 0);

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".codex")).expect("codex dir");
        std::fs::write(tmp.path().join(".codex/hooks.json"), r#"{"hooks":{}}"#).expect("hooks");
        std::fs::write(tmp.path().join("AGENTS.md"), "# A\n").expect("agents");
        std::fs::write(
            tmp.path().join(".mcp.json"),
            r#"{"mcpServers":{"actplane":{"command":"other","args":[]}}}"#,
        )
        .expect("mcp");

        let mut problems = 0;
        doctor_agent_files(tmp.path(), &mut problems);
        assert_eq!(problems, 2);

        let tmp = tempfile::tempdir().expect("tempdir");
        let mut problems = 0;
        doctor_agent_files(tmp.path(), &mut problems);
        // A missing Codex hook is the only hard failure; AGENTS.md and the
        // project MCP config are advisories.
        assert_eq!(problems, 1);
    }
    #[test]
    fn annotation_backed_promotion_note_selects_the_promotion_branch() {
        // `annotation_backed_promotion_note` derives a promotion note from the
        // per-clause annotation counts: it requires a supplied annotation log,
        // a present observation with non-empty annotations, then inspects the
        // false_positive / allowed / noise, needs_review, and true_positive
        // classes in that order. No base or branch test pins this note
        // directly.
        let evidence = |with_annotation_log: bool| RolloutEvidence {
            event_paths: Vec::new(),
            annotation_paths: if with_annotation_log {
                vec![PathBuf::from("an.jsonl")]
            } else {
                Vec::new()
            },
            total_events: 0,
            total_annotations: 0,
            ignored_lines: 0,
            ignored_annotations: 0,
            warnings: Vec::new(),
            clauses: BTreeMap::new(),
        };
        let observation = |annotations: &[(&str, usize)]| ClauseObservation {
            count: 0,
            actions: BTreeMap::new(),
            targets: Vec::new(),
            domains: BTreeMap::new(),
            annotations: BTreeMap::from_iter(annotations.iter().map(|(k, v)| (k.to_string(), *v))),
            annotation_notes: Vec::new(),
        };

        // No annotation log supplied: no note.
        assert!(
            annotation_backed_promotion_note(
                &evidence(false),
                Some(&observation(&[("true_positive", 5)])),
                Effect::Notify
            )
            .is_none()
        );

        // No observation at all (but a log is supplied): keep observe mode.
        assert_eq!(
            annotation_backed_promotion_note(&evidence(true), None, Effect::Notify),
            Some(
                "no annotations for this clause; keep observe mode until examples are classified"
                    .into()
            )
        );

        // An observation with empty annotations also keeps observe mode.
        assert_eq!(
            annotation_backed_promotion_note(
                &evidence(true),
                Some(&observation(&[])),
                Effect::Notify
            ),
            Some(
                "no annotations for this clause; keep observe mode until examples are classified"
                    .into()
            )
        );

        // A mix of do-not-promote classes names all three counts.
        assert_eq!(
            annotation_backed_promotion_note(
                &evidence(true),
                Some(&observation(&[
                    ("false_positive", 2),
                    ("allowed", 1),
                    ("noise", 3)
                ])),
                Effect::Notify
            ),
            Some(
                "do not promote yet; annotations include false_positive=2, allowed=1, noise=3"
                    .into()
            )
        );

        // A needs_review count holds back promotion.
        assert_eq!(
            annotation_backed_promotion_note(
                &evidence(true),
                Some(&observation(&[("needs_review", 4)])),
                Effect::Notify
            ),
            Some("keep notify; 4 annotated example(s) still need review".into())
        );

        // A true_positive count with a Kill effect names the kill promotion.
        assert_eq!(
            annotation_backed_promotion_note(
                &evidence(true),
                Some(&observation(&[("true_positive", 6)])),
                Effect::Kill
            ),
            Some(
                "6 annotated true_positive example(s); candidate for limited kill promotion \
                 after workload coverage review"
                    .into()
            )
        );

        // A true_positive count with a non-Kill effect names the generic
        // promotion.
        assert_eq!(
            annotation_backed_promotion_note(
                &evidence(true),
                Some(&observation(&[("true_positive", 6)])),
                Effect::Notify
            ),
            Some(
                "6 annotated true_positive example(s); candidate for limited promotion after \
                 backend and workload coverage review"
                    .into()
            )
        );

        // Annotations present but none in a recognized class keep observe mode.
        assert_eq!(
            annotation_backed_promotion_note(
                &evidence(true),
                Some(&observation(&[("unrecognized", 2)])),
                Effect::Notify
            ),
            Some("annotations use no recognized promotion class; keep observe mode".into())
        );
    }
    #[test]
    fn annotation_count_reads_annotation_counts_defaulting_to_zero() {
        // `annotation_count` looks up a single key in a `ClauseObservation`'s
        // annotation counter map, returning the stored count for a present key
        // and `0` for an absent one. No base or branch test pins this accessor
        // directly.
        let observation = ClauseObservation {
            count: 6,
            actions: BTreeMap::new(),
            targets: Vec::new(),
            domains: BTreeMap::new(),
            annotations: BTreeMap::from([
                ("true_positive".to_string(), 3),
                ("false_positive".to_string(), 2),
                ("noise".to_string(), 1),
            ]),
            annotation_notes: Vec::new(),
        };

        // A present key returns its stored count.
        assert_eq!(annotation_count(&observation, "true_positive"), 3);
        assert_eq!(annotation_count(&observation, "false_positive"), 2);
        assert_eq!(annotation_count(&observation, "noise"), 1);

        // An absent key defaults to zero.
        assert_eq!(annotation_count(&observation, "needs_review"), 0);
        assert_eq!(annotation_count(&observation, "not-a-key"), 0);

        // An observation with no annotations at all returns zero for every key.
        let empty = ClauseObservation {
            count: 0,
            actions: BTreeMap::new(),
            targets: Vec::new(),
            domains: BTreeMap::new(),
            annotations: BTreeMap::new(),
            annotation_notes: Vec::new(),
        };
        assert_eq!(annotation_count(&empty, "true_positive"), 0);
    }
    #[test]
    fn annotation_rule_matches_signature_allows_an_absent_effect() {
        // `annotation_rule_matches_signature` is the annotation-log sibling of
        // `event_rule_matches_signature`. Its `effect` field is optional: an
        // absent effect passes, while a present but non-notify effect (e.g.
        // `"block"`) rejects the match. A positive also requires the clause
        // identity (hash or text). No base or branch test pins this predicate
        // directly.
        let signature = ClauseEventSignature {
            clause_op: "open",
            target_kind: "file",
            target_pattern: "out.txt".to_string(),
            target_arg: None,
            clause_text: "notify open file \"out.txt\"".to_string(),
            clause_hash: "hash-1".to_string(),
        };

        // An explicit `notify` effect plus matching fields and identity.
        assert!(annotation_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "notify",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "out.txt",
                    "clause_hash": "hash-1"
                }
            }),
            &signature
        ));

        // An absent effect still matches when the remaining fields agree.
        assert!(annotation_rule_matches_signature(
            &json!({
                "rule": {
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "out.txt",
                    "clause_hash": "hash-1"
                }
            }),
            &signature
        ));

        // No `rule` object at all.
        assert!(!annotation_rule_matches_signature(
            &json!({ "event": "x" }),
            &signature
        ));

        // A present non-notify effect rejects the match.
        assert!(!annotation_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "block",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "out.txt",
                    "clause_hash": "hash-1"
                }
            }),
            &signature
        ));

        // A mismatched target pattern fails.
        assert!(!annotation_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "notify",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "other.txt",
                    "clause_hash": "hash-1"
                }
            }),
            &signature
        ));

        // All rule fields match but the clause identity is missing.
        assert!(!annotation_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "notify",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "out.txt"
                }
            }),
            &signature
        ));
    }

    fn compiled_with_endpoints(entries: &[(&str, Vec<&str>)]) -> dsl::Compiled {
        let mut resolutions = std::collections::HashMap::new();
        for (pattern, addrs) in entries {
            resolutions.insert(
                (*pattern).to_string(),
                addrs.iter().map(|a| (*a).to_string()).collect(),
            );
        }
        dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: resolutions,
        }
    }

    fn target(kind: Kind, pattern: &str, arg: Option<&str>) -> crate::dsl::ast::Target {
        crate::dsl::ast::Target {
            kind,
            pattern: pattern.to_string(),
            arg: arg.map(str::to_string),
        }
    }

    #[test]
    fn append_label_bits_lists_none_or_sorted_masks() {
        let mut compiled = compiled_with_endpoints(&[]);
        let mut out = String::new();
        append_label_bits(&mut out, &compiled);
        assert_eq!(out, "  - none\n");
        compiled.labels.insert("high".into(), 0x10);
        compiled.labels.insert("low".into(), 0x1);
        let mut out = String::new();
        append_label_bits(&mut out, &compiled);
        assert_eq!(out, "  - low = 0x1\n  - high = 0x10\n");
    }

    #[test]
    fn append_append_delta_approval_renders_required_and_optional_fields() {
        let mut out = String::new();
        append_append_delta_approval(&mut out, &AppendDeltaApprovalConfig::default());
        assert!(out.contains("append policy delta approval: not required"));
        assert!(out.contains("admission model: metadata_only"));

        let required = AppendDeltaApprovalConfig {
            required: true,
            require_approval_ref: true,
            require_generated_by: false,
            allowed_approvers: vec!["alice".into(), "bob".into()],
        };
        let mut out = String::new();
        append_append_delta_approval(&mut out, &required);
        assert!(out.contains("required metadata: approved_by, approval_ref"));
        assert!(out.contains("allowed approvers: alice, bob"));
        assert!(out.contains("external_verified=false, signature=null"));

        let any = AppendDeltaApprovalConfig {
            required: true,
            ..AppendDeltaApprovalConfig::default()
        };
        let mut out = String::new();
        append_append_delta_approval(&mut out, &any);
        assert!(out.contains("allowed approvers: any non-empty approved_by"));
    }

    #[test]
    fn backend_support_warnings_flags_endpoint_and_argv_and_lsm() {
        let compiled = compiled_with_endpoints(&[]);
        let policy = Policy {
            labels: Vec::new(),
            sources: vec![Source {
                label: "E".into(),
                kind: Kind::Endpoint,
                pattern: "*.example".into(),
            }],
            rules: vec![crate::dsl::ast::Rule {
                name: "r".into(),
                reason: String::new(),
                clauses: vec![
                    Clause {
                        op: Op::Connect,
                        target: target(Kind::Endpoint, "*.example", None),
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Notify,
                        source_index: 0,
                    },
                    Clause {
                        op: Op::Exec,
                        target: target(Kind::Exec, "git", Some("push")),
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Block,
                        source_index: 0,
                    },
                ],
            }],
            xforms: Vec::new(),
        };
        let codes: Vec<&str> = backend_support_warnings(&policy, &compiled, false)
            .iter()
            .map(|warning| warning.code)
            .collect();
        assert!(codes.contains(&"endpoint_source_unsupported"));
        assert!(codes.contains(&"endpoint_target_unsupported"));
        assert!(codes.contains(&"argv_block_exec_post_exec_only"));
        assert!(codes.contains(&"bpf_lsm_inactive_for_block"));
    }

    #[test]
    fn backend_support_warnings_empty_when_all_supported() {
        let compiled = compiled_with_endpoints(&[]);
        let policy = Policy {
            labels: Vec::new(),
            sources: Vec::new(),
            rules: vec![crate::dsl::ast::Rule {
                name: "r".into(),
                reason: String::new(),
                clauses: vec![Clause {
                    op: Op::Read,
                    target: target(Kind::File, "**/.env", None),
                    when: Expr::True,
                    unless: None,
                    effect: Effect::Block,
                    source_index: 0,
                }],
            }],
            xforms: Vec::new(),
        };
        assert!(backend_support_warnings(&policy, &compiled, true).is_empty());
    }
    #[test]
    fn append_clause_observation_renders_only_the_supplied_paths() {
        // `append_clause_observation` appends per-clause observation lines, but
        // only for the log kinds actually supplied: an event line only when
        // `event_paths` is non-empty, an annotation line only when
        // `annotation_paths` is non-empty. With no logs at all it is a no-op.
        // A `None` observation prints a "0 / none" placeholder; a `Some` one
        // renders the (BTree-sorted) counts and sample lists. No base or
        // branch test pins this appender directly.
        let evidence = |event: bool, annotation: bool| {
            let mut ev = RolloutEvidence {
                event_paths: Vec::new(),
                annotation_paths: Vec::new(),
                total_events: 0,
                total_annotations: 0,
                ignored_lines: 0,
                ignored_annotations: 0,
                warnings: Vec::new(),
                clauses: BTreeMap::new(),
            };
            if event {
                ev.event_paths.push(PathBuf::from("ev.jsonl"));
            }
            if annotation {
                ev.annotation_paths.push(PathBuf::from("an.jsonl"));
            }
            ev
        };

        // No logs: nothing is appended.
        let mut out = String::new();
        append_clause_observation(&mut out, &evidence(false, false), None);
        assert_eq!(out, "");

        // A `None` observation with both kinds of log prints both placeholders.
        let mut out = String::new();
        append_clause_observation(&mut out, &evidence(true, true), None);
        assert_eq!(
            out,
            "       observed events: 0 in supplied logs\n       annotations: none for \
             this clause\n"
        );

        // A `Some` observation with only an event log renders the event line,
        // with BTree-sorted `actions` / `domains` and a sample `targets` list.
        let observation = ClauseObservation {
            count: 3,
            actions: BTreeMap::from([("open".to_string(), 2), ("connect".to_string(), 1)]),
            targets: vec!["out.txt".to_string(), "in.txt".to_string()],
            domains: BTreeMap::from([("repo".to_string(), 3)]),
            annotations: BTreeMap::new(),
            annotation_notes: Vec::new(),
        };
        let mut out = String::new();
        append_clause_observation(&mut out, &evidence(true, false), Some(&observation));
        assert_eq!(
            out,
            "       observed events: 3; actions=connect=1,open=2; domains=repo=3; \
             targets=out.txt,in.txt\n"
        );

        // A `Some` observation with only an annotation log renders the
        // annotation line, with BTree-sorted `annotations` and sample `notes`.
        let mut out = String::new();
        append_clause_observation(&mut out, &evidence(false, true), Some(&observation));
        assert_eq!(out, "       annotations: none; notes=none\n");
    }
    #[test]
    fn append_append_delta_approval_renders_the_approval_block() {
        // `append_append_delta_approval` appends the append-policy-delta
        // approval section. A `not required` config short-circuits to the
        // metadata-only admission model; a `required` config lists the
        // metadata fields (`approved_by` plus optional `approval_ref` /
        // `generated_by`), the allowed-approvers line, and the static-allowlist
        // admission model. No base or branch test pins this appender directly.
        let mut out = String::new();
        append_append_delta_approval(
            &mut out,
            &AppendDeltaApprovalConfig {
                required: false,
                require_approval_ref: false,
                require_generated_by: false,
                allowed_approvers: Vec::new(),
            },
        );
        assert_eq!(
            out,
            "  - append policy delta approval: not required\n  - admission model: \
             metadata_only\n"
        );

        let mut out = String::new();
        append_append_delta_approval(
            &mut out,
            &AppendDeltaApprovalConfig {
                required: true,
                require_approval_ref: false,
                require_generated_by: false,
                allowed_approvers: Vec::new(),
            },
        );
        assert_eq!(
            out,
            "  - append policy delta approval: required\n  - required metadata: \
             approved_by\n  - allowed approvers: any non-empty approved_by\n  - \
             admission model: static_metadata_allowlist\n  - external_verified=\
             false, signature=null\n"
        );

        let mut out = String::new();
        append_append_delta_approval(
            &mut out,
            &AppendDeltaApprovalConfig {
                required: true,
                require_approval_ref: true,
                require_generated_by: true,
                allowed_approvers: vec!["alice".to_string(), "bob".to_string()],
            },
        );
        assert_eq!(
            out,
            "  - append policy delta approval: required\n  - required metadata: \
             approved_by, approval_ref, generated_by\n  - allowed approvers: \
             alice, bob\n  - admission model: static_metadata_allowlist\n  - \
             external_verified=false, signature=null\n"
        );
    }
    #[test]
    fn append_label_bits_sorts_labels_by_mask() {
        // `append_label_bits` renders each compiled label as `  - {name} =
        // {mask:#x}`, sorted ascending by the numeric mask. An empty label set
        // renders a single "  - none" line. No base or branch test pins this
        // appender directly.
        use std::collections::HashMap;

        let compiled = |labels: HashMap<String, u64>| dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels,
            endpoint_resolutions: HashMap::new(),
        };

        // Empty label set: a single "none" line.
        let mut out = String::new();
        append_label_bits(&mut out, &compiled(HashMap::new()));
        assert_eq!(out, "  - none\n");

        // Populated: sorted ascending by mask, each rendered as `name = 0x…`.
        // The input map is unordered; the output order is by mask value.
        let labels = HashMap::from([
            ("repo".to_string(), 4u64),
            ("tmp".to_string(), 1u64),
            ("net".to_string(), 2u64),
        ]);
        let mut out = String::new();
        append_label_bits(&mut out, &compiled(labels));
        assert_eq!(out, "  - tmp = 0x1\n  - net = 0x2\n  - repo = 0x4\n");
    }
    #[test]
    fn append_rollout_evidence_summary_renders_the_evidence_block() {
        // `append_rollout_evidence_summary` appends a deterministic
        // "observe evidence:" block. An empty evidence set short-circuits to a
        // single "no log supplied" line; a populated set lists the event /
        // annotation paths, the parsed counts, any ignored lines, and any
        // warnings (ignored lines and warnings are omitted when zero / empty).
        // No base or branch test pins this appender directly.
        let empty = RolloutEvidence {
            event_paths: Vec::new(),
            annotation_paths: Vec::new(),
            total_events: 0,
            total_annotations: 0,
            ignored_lines: 0,
            ignored_annotations: 0,
            warnings: Vec::new(),
            clauses: BTreeMap::new(),
        };
        let mut out = String::new();
        append_rollout_evidence_summary(&mut out, &empty);
        assert_eq!(
            out,
            "\nobserve evidence:\n  - no event or annotation log supplied; \
             pass --events .actplane/events.jsonl after an observe run and \
             --annotations <annotations.jsonl> after classification\n"
        );

        let populated = RolloutEvidence {
            event_paths: vec![PathBuf::from("ev1.jsonl")],
            annotation_paths: vec![PathBuf::from("an1.jsonl")],
            total_events: 10,
            total_annotations: 5,
            ignored_lines: 2,
            ignored_annotations: 1,
            warnings: vec!["warn-a".to_string()],
            clauses: BTreeMap::new(),
        };
        let mut out = String::new();
        append_rollout_evidence_summary(&mut out, &populated);
        assert_eq!(
            out,
            "\nobserve evidence:\n  - event log: ev1.jsonl\n  - annotation log: \
             an1.jsonl\n  - parsed violation events: 10\n  - parsed rollout \
             annotations: 5\n  - ignored non-violation or malformed lines: 2\n  - \
             ignored malformed or stale annotations: 1\n  - warning: warn-a\n"
        );

        // A populated set with zero ignored lines and no warnings omits those
        // optional lines.
        let no_ignored = RolloutEvidence {
            event_paths: vec![PathBuf::from("ev1.jsonl")],
            annotation_paths: Vec::new(),
            total_events: 3,
            total_annotations: 0,
            ignored_lines: 0,
            ignored_annotations: 0,
            warnings: Vec::new(),
            clauses: BTreeMap::new(),
        };
        let mut out = String::new();
        append_rollout_evidence_summary(&mut out, &no_ignored);
        assert_eq!(
            out,
            "\nobserve evidence:\n  - event log: ev1.jsonl\n  - parsed violation \
             events: 3\n  - parsed rollout annotations: 0\n"
        );
    }
    #[test]
    fn backend_support_lines_renders_one_line_per_clause() {
        // `backend_support_lines` renders one line per clause in a policy as
        // `"{rule}: {effect} {op} -> {clause_support}"`. No base or branch
        // test pins this formatter directly.
        use crate::dsl::ast::{Rule, Target};
        use std::collections::HashMap;

        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        let policy = Policy {
            labels: Vec::new(),
            sources: Vec::new(),
            rules: vec![
                Rule {
                    name: "guard".to_string(),
                    clauses: vec![
                        Clause {
                            op: Op::Exec,
                            target: Target {
                                kind: Kind::Exec,
                                pattern: "python3".to_string(),
                                arg: None,
                            },
                            when: Expr::True,
                            unless: None,
                            effect: Effect::Notify,
                            source_index: 0,
                        },
                        Clause {
                            op: Op::Exec,
                            target: Target {
                                kind: Kind::Exec,
                                pattern: "python3".to_string(),
                                arg: None,
                            },
                            when: Expr::True,
                            unless: None,
                            effect: Effect::Block,
                            source_index: 0,
                        },
                    ],
                    reason: "guard exec".to_string(),
                },
                Rule {
                    name: "egress".to_string(),
                    clauses: vec![Clause {
                        op: Op::Connect,
                        target: Target {
                            kind: Kind::Endpoint,
                            pattern: "10.0.0.7".to_string(),
                            arg: None,
                        },
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Block,
                        source_index: 0,
                    }],
                    reason: "guard egress".to_string(),
                },
            ],
            xforms: Vec::new(),
        };

        // Under BPF-LSM: the exec block and connect block resolve to pre-op
        // denials (the connect carries the IPv4-only limitation).
        assert_eq!(
            backend_support_lines(&policy, &compiled, true),
            vec![
                "guard: notify exec -> post-exec tracepoint report",
                "guard: block exec -> pre-op block via BPF-LSM bprm_check_security",
                "egress: block connect -> pre-op block via BPF-LSM socket_connect, \
                 IPv4 only",
            ]
        );

        // Without BPF-LSM: the block clauses fall back to the tracepoint path.
        assert_eq!(
            backend_support_lines(&policy, &compiled, false),
            vec![
                "guard: notify exec -> post-exec tracepoint report",
                "guard: block exec -> BPF-LSM is not active on this host, notify \
                 and kill still use tracepoint paths where available",
                "egress: block connect -> BPF-LSM is not active on this host, \
                 notify and kill still use tracepoint paths where available",
            ]
        );
    }
    #[test]
    fn backend_support_warnings_collects_source_target_and_block_warnings() {
        // `backend_support_warnings` gathers the per-policy backend support
        // warnings: unsupported endpoint sources, unsupported endpoint targets,
        // unusable endpoint `unless target` conditions, argv-only exec blocks,
        // and blocks issued while BPF-LSM is inactive. No base or branch test
        // pins this collector directly.
        use crate::dsl::ast::{Rule, Target};
        use std::collections::HashMap;

        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        let policy = Policy {
            labels: Vec::new(),
            sources: vec![Source {
                label: "eg".to_string(),
                kind: Kind::Endpoint,
                pattern: "*.evil".to_string(),
            }],
            rules: vec![Rule {
                name: "guard".to_string(),
                clauses: vec![
                    Clause {
                        op: Op::Connect,
                        target: Target {
                            kind: Kind::Endpoint,
                            pattern: "api.evil".to_string(),
                            arg: None,
                        },
                        when: Expr::True,
                        unless: Some(Cond::Target {
                            negate: false,
                            pattern: "api.evil".to_string(),
                        }),
                        effect: Effect::Block,
                        source_index: 0,
                    },
                    Clause {
                        op: Op::Exec,
                        target: Target {
                            kind: Kind::Exec,
                            pattern: "python3".to_string(),
                            arg: Some("run".to_string()),
                        },
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Block,
                        source_index: 0,
                    },
                ],
                reason: "guard".to_string(),
            }],
            xforms: Vec::new(),
        };

        // BPF-LSM inactive: every block clause also yields the LSM-inactive
        // warning, on top of the endpoint / condition / argv warnings.
        let warnings = backend_support_warnings(&policy, &compiled, false);
        let pairs: Vec<(String, String)> = warnings
            .iter()
            .map(|w| (w.code.to_string(), w.message.clone()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (
                    "endpoint_source_unsupported".to_string(),
                    "source eg = endpoint \"*.evil\" is unsupported: endpoint source \
                     pattern is not numeric IPv4 or an exact resolvable hostname."
                        .to_string()
                ),
                (
                    "endpoint_target_unsupported".to_string(),
                    "block connect endpoint \"api.evil\" is unsupported: endpoint \
                     target pattern is not numeric IPv4 or an exact resolvable \
                     hostname; this rule will not fire for that endpoint."
                        .to_string()
                ),
                (
                    "endpoint_target_condition_unsupported_pattern".to_string(),
                    "guard: unless target \"api.evil\" uses a wildcard hostname or \
                     IPv6 pattern; endpoint target conditions support numeric IPv4 \
                     or a single resolved IPv4 hostname."
                        .to_string()
                ),
                (
                    "bpf_lsm_inactive_for_block".to_string(),
                    "guard: `block connect` is unsupported on this host until \
                     BPF-LSM is active."
                        .to_string()
                ),
                (
                    "argv_block_exec_post_exec_only".to_string(),
                    "guard: `block exec` with an argv token cannot block pre-exec \
                     because argv is only available after exec; use `kill exec` \
                     if termination after exec is acceptable."
                        .to_string()
                ),
                (
                    "bpf_lsm_inactive_for_block".to_string(),
                    "guard: `block exec` is unsupported on this host until \
                     BPF-LSM is active."
                        .to_string()
                ),
            ]
        );
    }
    #[test]
    fn render_check_error_json_reports_the_failure_record() {
        // `render_check_error_json` renders the failed compile record: the
        // actplane.compile.v1 schema, ok=false, the policy ref, the (optional)
        // domain, and the error message, as pretty JSON with a trailing
        // newline. No base or branch test pins this renderer directly.
        let no_domain = ResolvedPolicy {
            source: "policy.dsl".to_string(),
            domain: None,
        };
        let got =
            render_check_error_json("policy.dsl", Some(&no_domain), "unknown label: e1").unwrap();
        assert!(got.ends_with('\n'));
        let parsed: serde_json::Value =
            serde_json::from_str(&got).expect("error json is valid JSON");
        assert_eq!(
            parsed,
            json!({
                "schema": "actplane.compile.v1",
                "ok": false,
                "policy_ref": "policy.dsl",
                "domain": null,
                "error": "unknown label: e1",
            })
        );

        // A resolved domain is embedded as the same object `domain_json` renders.
        let with_domain = ResolvedPolicy {
            source: "web.dsl".to_string(),
            domain: Some(DomainSummary {
                name: "web".to_string(),
                parent: Some("app".to_string()),
                disabled: vec!["legacy".to_string()],
                locked: vec!["egress".to_string()],
                defaults: vec!["audit".to_string()],
            }),
        };
        let got = render_check_error_json("web.dsl", Some(&with_domain), "no egress").unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&got).expect("error json is valid JSON");
        assert_eq!(
            parsed,
            json!({
                "schema": "actplane.compile.v1",
                "ok": false,
                "policy_ref": "web.dsl",
                "domain": {
                    "name": "web",
                    "parent": "app",
                    "locked": ["egress"],
                    "default": ["audit"],
                    "disabled": ["legacy"],
                },
                "error": "no egress",
            })
        );
    }

    #[test]
    fn render_check_json_reports_static_matrix() {
        let src = concat!(
            "source COMMAND = exec \"**\"\n",
            "rule guard:\n",
            "  block open file \"/etc/secret\" if COMMAND\n",
            "  because \"deny secret reads\"\n",
        );
        let parsed = dsl::parse::parse(src).expect("parse");
        let compiled = dsl::compile_str(src).expect("compile");
        let resolved = ResolvedPolicy {
            source: src.to_string(),
            domain: None,
        };

        let rendered = render_check_json(
            "--rule",
            &resolved,
            &parsed,
            &compiled,
            "capability",
            false,
            false,
        )
        .expect("render");
        let value: Value = serde_json::from_str(&rendered).expect("json");
        assert_eq!(value["schema"], "actplane.compile.v1");
        assert_eq!(value["ok"], true);
        assert_eq!(value["policy_ref"], "--rule");
        assert_eq!(value["domain"], Value::Null);
        assert_eq!(value["host"]["active_lsms"], "capability");
        assert_eq!(value["host"]["bpf_lsm_active"], false);
        assert_eq!(value["host"]["force_tracepoint"], false);
        assert_eq!(value["matrix_scope"], "static_policy_host_support");
        assert_eq!(value["rule_count"], 1);
        assert_eq!(value["rules"][0]["name"], "guard");
        assert_eq!(value["backend_support"]["clauses"][0]["op"], "open");
        assert_eq!(value["backend_support"]["clauses"][0]["effect"], "block");
        assert!(
            value["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .any(|w| w["code"] == "bpf_lsm_inactive_for_block"),
            "{rendered}"
        );
    }

    #[test]
    fn check_policy_succeeds_and_reports_compile_failures() {
        let good = PolicyInput {
            rule: Some(
                "source COMMAND = exec \"**\"\nrule guard:\n  notify exec \"/bin/true\" if COMMAND\n  because \"b\"\n"
                    .to_string(),
            ),
            ..PolicyInput::default()
        };
        assert_eq!(
            check_policy(&good, false, false, None, false).expect("ok"),
            0
        );

        let report_dir = tempfile::tempdir().expect("tempdir");
        let report = report_dir.path().join("report.json");
        let bad = PolicyInput {
            rule: Some("rule guard notify exec".to_string()),
            ..PolicyInput::default()
        };
        assert_eq!(
            check_policy(&bad, true, false, Some(&report), false).expect("reported"),
            1
        );
        let value: Value =
            serde_json::from_str(&std::fs::read_to_string(&report).expect("read")).expect("json");
        assert_eq!(value["schema"], "actplane.compile.v1");
        assert_eq!(value["ok"], false);
        assert_eq!(value["policy_ref"], "--rule");
        assert_eq!(value["domain"], Value::Null);
        assert!(
            value["error"].as_str().expect("error").contains("expected"),
            "{value}"
        );

        assert!(
            check_policy(&bad, true, false, Some(&report), false).is_err(),
            "existing report without force must error"
        );
    }

    #[test]
    fn policy_ref_for_cli_names_the_input() {
        let auto = PolicyInput::default();
        assert_eq!(policy_ref_for_cli(&auto), "auto-discovered policy");

        let inline = PolicyInput {
            rule: Some("rule r".into()),
            ..PolicyInput::default()
        };
        assert_eq!(policy_ref_for_cli(&inline), "--rule");

        let path = PolicyInput {
            policy: Some(PathBuf::from("/tmp/policy.yaml")),
            ..PolicyInput::default()
        };
        assert_eq!(policy_ref_for_cli(&path), "/tmp/policy.yaml");
    }

    #[test]
    fn check_policy_reports_status_and_writes_error_reports() {
        let good = r#"
            source SECRET = file "**/.env"
            rule no-exfil:
              block connect endpoint "*" if SECRET
              because "secret data must not leave the host"
        "#;
        let compiling = PolicyInput {
            policy: None,
            rule: Some(good.to_string()),
            domain: None,
            run_as_root: false,
            internal_elevated: false,
        };
        assert_eq!(
            check_policy(&compiling, false, false, None, false).unwrap(),
            0
        );

        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        let unparseable = PolicyInput {
            policy: None,
            rule: Some("rule :".to_string()),
            domain: None,
            run_as_root: false,
            internal_elevated: false,
        };
        assert_eq!(
            check_policy(&unparseable, true, false, Some(&report), false).unwrap(),
            1
        );
        let value: Value =
            serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["policy_ref"], "--rule");

        let policy_file = dir.path().join("actplane.yaml");
        std::fs::write(
            &policy_file,
            "policy: |\n  rule r:\n    notify exec \"git\"\n    because \"x\"\n",
        )
        .unwrap();
        let domain_cli = PolicyInput {
            policy: Some(policy_file.clone()),
            rule: None,
            domain: Some("work".to_string()),
            run_as_root: false,
            internal_elevated: false,
        };
        let report2 = dir.path().join("report2.json");
        assert_eq!(
            check_policy(&domain_cli, true, false, Some(&report2), false).unwrap(),
            1
        );
        let value: Value =
            serde_json::from_str(&std::fs::read_to_string(&report2).unwrap()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["policy_ref"], policy_file.display().to_string());
    }

    #[test]
    fn emit_check_report_writes_file_and_honors_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        emit_check_report("{}", Some(&path), false, "compile report").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}");
        let err = emit_check_report("[]", Some(&path), false, "compile report").unwrap_err();
        assert!(
            err.to_string()
                .contains("already exists (use --force to overwrite)")
        );
        emit_check_report("[]", Some(&path), true, "compile report").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[]");
    }

    #[test]
    fn render_observe_policy_yaml_annotates_and_indents_dsl() {
        let resolved = ResolvedPolicy {
            source: "cli".into(),
            domain: Some(DomainSummary {
                name: "work".into(),
                parent: None,
                disabled: Vec::new(),
                locked: Vec::new(),
                defaults: Vec::new(),
            }),
        };
        let parsed = dsl::ast::Policy {
            labels: Vec::new(),
            sources: vec![Source {
                label: "T".into(),
                kind: Kind::File,
                pattern: "**/.env".into(),
            }],
            rules: Vec::new(),
            xforms: Vec::new(),
        };
        let yaml = render_observe_policy_yaml("policy.dsl", &resolved, &parsed);
        assert!(yaml.contains("# ActPlane observe-first policy generated from policy.dsl."));
        assert!(yaml.contains("# Source domain: work (flattened selected policy)."));
        assert!(yaml.contains("version: 1"));
        assert!(yaml.contains("policy: |"));
        assert!(yaml.contains("  source T = file \"**/.env\""));

        let no_domain = ResolvedPolicy {
            source: "cli".into(),
            domain: None,
        };
        let yaml = render_observe_policy_yaml("--rule", &no_domain, &parsed);
        assert!(!yaml.contains("# Source domain:"));
    }
    #[test]
    fn clause_condition_warnings_flags_unusable_endpoint_target_conditions() {
        // `clause_condition_warnings` flags endpoint `unless target` conditions
        // that cannot be enforced: a hostname resolving to multiple IPv4
        // addresses, an empty resolution, or an unresolvable pattern. Numeric
        // IPv4 and a single resolved hostname produce no warning. No base or
        // branch test pins this directly.
        use crate::dsl::ast::Target;
        use std::collections::HashMap;

        let with_resolutions = |resolutions: HashMap<String, Vec<String>>| dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: resolutions,
        };

        let target_clause = |pattern: &str, negate: bool| Clause {
            op: Op::Connect,
            target: Target {
                kind: Kind::Endpoint,
                pattern: pattern.to_string(),
                arg: None,
            },
            when: Expr::True,
            unless: Some(Cond::Target {
                negate,
                pattern: pattern.to_string(),
            }),
            effect: Effect::Notify,
            source_index: 0,
        };

        // Numeric IPv4: no warning.
        let compiled = with_resolutions(HashMap::new());
        assert!(clause_condition_warnings(&target_clause("10.0.0.7", false), &compiled).is_empty());

        // Exactly one resolved address: no warning.
        let compiled = with_resolutions(HashMap::from([(
            "one.com".to_string(),
            vec!["1.2.3.4".to_string()],
        )]));
        assert!(clause_condition_warnings(&target_clause("one.com", false), &compiled).is_empty());

        // Multiple resolved addresses: one multi-hostname warning.
        let compiled = with_resolutions(HashMap::from([(
            "many.com".to_string(),
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
        )]));
        let warnings = clause_condition_warnings(&target_clause("many.com", false), &compiled);
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].code,
            "endpoint_target_condition_multi_ipv4_hostname"
        );
        assert_eq!(
            warnings[0].message,
            "unless target \"many.com\" resolves to multiple IPv4 addresses, but \
             endpoint target conditions can store one address in the current ABI; \
             the condition fails closed."
        );

        // Empty resolution: one unresolved-hostname warning.
        let compiled = with_resolutions(HashMap::from([("none.com".to_string(), Vec::new())]));
        let warnings = clause_condition_warnings(&target_clause("none.com", false), &compiled);
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].code,
            "endpoint_target_condition_unresolved_hostname"
        );
        assert_eq!(
            warnings[0].message,
            "unless target \"none.com\" did not resolve to an IPv4 address at \
             compile/load time; the condition fails closed."
        );

        // Unresolvable pattern: one unsupported-pattern warning.
        let warnings = clause_condition_warnings(
            &target_clause("bad.*", false),
            &with_resolutions(HashMap::new()),
        );
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].code,
            "endpoint_target_condition_unsupported_pattern"
        );
        assert_eq!(
            warnings[0].message,
            "unless target \"bad.*\" uses a wildcard hostname or IPv6 pattern; \
             endpoint target conditions support numeric IPv4 or a single resolved \
             IPv4 hostname."
        );

        // A negated target condition inserts " not" after "target".
        let compiled = with_resolutions(HashMap::from([(
            "many.com".to_string(),
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
        )]));
        let warnings = clause_condition_warnings(&target_clause("many.com", true), &compiled);
        assert_eq!(
            warnings[0].message,
            "unless target not \"many.com\" resolves to multiple IPv4 addresses, \
             but endpoint target conditions can store one address in the current \
             ABI; the condition fails closed."
        );
    }
    #[test]
    fn clause_summary_renders_effect_op_target_when_and_unless() {
        // `clause_summary` renders a `Clause` as
        // `<effect> <op> <target> if <expr> [unless <cond>]`, where the
        // target renders as `"pattern" [arg]` for Exec and `<kind> "pattern"`
        // for File / Endpoint. No base or branch test pins this formatter
        // directly.
        use crate::dsl::ast::Target;

        // Exec target with no arg, label expr, no unless.
        assert_eq!(
            clause_summary(&Clause {
                op: Op::Exec,
                target: Target {
                    kind: Kind::Exec,
                    pattern: "agent".into(),
                    arg: None,
                },
                when: Expr::Label("repo".into()),
                unless: None,
                effect: Effect::Notify,
                source_index: 0,
            }),
            "notify exec \"agent\" if repo"
        );

        // Exec target with an arg.
        assert_eq!(
            clause_summary(&Clause {
                op: Op::Exec,
                target: Target {
                    kind: Kind::Exec,
                    pattern: "agent".into(),
                    arg: Some("run".into()),
                },
                when: Expr::True,
                unless: None,
                effect: Effect::Notify,
                source_index: 0,
            }),
            "notify exec \"agent\" \"run\" if true"
        );

        // File target, composite expr, and an `unless` condition.
        assert_eq!(
            clause_summary(&Clause {
                op: Op::Open,
                target: Target {
                    kind: Kind::File,
                    pattern: "policy.dsl".into(),
                    arg: None,
                },
                when: Expr::And(
                    Box::new(Expr::Label("repo".into())),
                    Box::new(Expr::Label("agent".into()))
                ),
                unless: Some(Cond::LineageIncludes {
                    exec: "agent".into()
                }),
                effect: Effect::Block,
                source_index: 1,
            }),
            "block open file \"policy.dsl\" if (repo and agent) \
             unless lineage-includes exec \"agent\""
        );

        // Endpoint target, `true` expr, `kill` effect.
        assert_eq!(
            clause_summary(&Clause {
                op: Op::Connect,
                target: Target {
                    kind: Kind::Endpoint,
                    pattern: "10.0.0.0/8".into(),
                    arg: None,
                },
                when: Expr::True,
                unless: None,
                effect: Effect::Kill,
                source_index: 0,
            }),
            "kill connect endpoint \"10.0.0.0/8\" if true"
        );
    }
    #[test]
    fn clause_support_joins_the_reason_with_limitations() {
        // `clause_support` collapses a clause's support detail into a single
        // string: the reason when there are no limitations, or the reason
        // joined to the comma-separated limitations otherwise. It delegates to
        // `clause_support_detail`. No base or branch test pins this formatter
        // directly.
        use std::collections::HashMap;

        let empty = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        // No limitations: the bare tracepoint report reason.
        assert_eq!(
            clause_support(
                Effect::Notify,
                Op::Exec,
                Kind::Exec,
                "python3",
                None,
                &empty,
                true
            ),
            "post-exec tracepoint report"
        );

        // Block of an exec with an argv: pre-exec is impossible, with the
        // kill-exec limitation appended.
        assert_eq!(
            clause_support(
                Effect::Block,
                Op::Exec,
                Kind::Exec,
                "python3",
                Some("run"),
                &empty,
                true
            ),
            "argv is only available after exec, so this cannot block pre-exec, \
             use kill exec for post-exec termination"
        );

        // Block of a plain exec under BPF-LSM: pre-op denial, no limitations.
        assert_eq!(
            clause_support(
                Effect::Block,
                Op::Exec,
                Kind::Exec,
                "python3",
                None,
                &empty,
                true
            ),
            "pre-op block via BPF-LSM bprm_check_security"
        );

        // Block of a numeric-IPv4 connect under BPF-LSM: pre-op denial with
        // the IPv4-only limitation.
        assert_eq!(
            clause_support(
                Effect::Block,
                Op::Connect,
                Kind::Endpoint,
                "10.0.0.7",
                None,
                &empty,
                true
            ),
            "pre-op block via BPF-LSM socket_connect, IPv4 only"
        );

        // Block requested without BPF-LSM active: unsupported, with the
        // tracepoint-fallback limitation.
        assert_eq!(
            clause_support(
                Effect::Block,
                Op::Exec,
                Kind::Exec,
                "python3",
                None,
                &empty,
                false
            ),
            "BPF-LSM is not active on this host, notify and kill still use \
             tracepoint paths where available"
        );
    }
    #[test]
    fn clause_support_detail_reports_mode_and_limitations_per_effect() {
        // `clause_support_detail` decides, per (effect, op, kind), whether a
        // clause can run at that effect, in which kernel mode, and with which
        // limitations. No base or branch test pins these branches directly.
        use crate::dsl::Compiled;
        use std::collections::HashMap;

        let compiled = Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        // Endpoint target that is neither numeric IPv4 nor a resolved hostname
        // short-circuits connect/recv to "unsupported" before the effect match.
        let d = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Connect,
            Kind::Endpoint,
            "example.internal",
            None,
            true,
        );
        assert!(!d.supported);
        assert_eq!(d.status, "unsupported");
        assert_eq!(d.mode, "none");
        assert!(!d.pre_op);
        assert_eq!(
            d.reason,
            "endpoint target pattern is not numeric IPv4 or an exact resolvable hostname"
        );
        assert_eq!(
            d.limitations,
            vec!["wildcard hostnames and IPv6 are not enforced in-kernel"]
        );

        // Block + exec with an argv target: argv is only known after exec, so it
        // cannot block pre-exec; steer the caller to kill for post-exec.
        let d = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Exec,
            Kind::Exec,
            "python3",
            Some("script.py"),
            true,
        );
        assert!(!d.supported);
        assert_eq!(d.status, "unsupported");
        assert_eq!(
            d.reason,
            "argv is only available after exec, so this cannot block pre-exec"
        );
        assert_eq!(
            d.limitations,
            vec!["use kill exec for post-exec termination"]
        );

        // Block with BPF-LSM inactive falls back to unsupported for every op.
        let d = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Read,
            Kind::File,
            "/etc/passwd",
            None,
            false,
        );
        assert!(!d.supported);
        assert_eq!(d.status, "unsupported");
        assert_eq!(d.reason, "BPF-LSM is not active on this host");
        assert_eq!(
            d.limitations,
            vec!["notify and kill still use tracepoint paths where available"]
        );

        // Block with BPF-LSM active runs pre-op in bpf-lsm mode.
        let d = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Exec,
            Kind::Exec,
            "python3",
            None,
            true,
        );
        assert!(d.supported);
        assert_eq!(d.status, "supported");
        assert_eq!(d.mode, "bpf-lsm");
        assert!(d.pre_op);
        assert_eq!(d.reason, "pre-op block via BPF-LSM bprm_check_security");
        assert!(d.limitations.is_empty());

        // A bpf-lsm connect block keeps the endpoint limitation.
        let d = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Connect,
            Kind::Endpoint,
            "10.0.0.7",
            None,
            true,
        );
        assert!(d.supported);
        assert_eq!(d.mode, "bpf-lsm");
        assert_eq!(d.reason, "pre-op block via BPF-LSM socket_connect");
        assert_eq!(d.limitations, vec!["IPv4 only"]);

        // Notify and kill both fall back to the tracepoint path, after the op.
        let d = clause_support_detail(
            &compiled,
            Effect::Notify,
            Op::Exec,
            Kind::Exec,
            "python3",
            None,
            false,
        );
        assert!(d.supported);
        assert_eq!(d.mode, "tracepoint");
        assert!(!d.pre_op);
        assert_eq!(d.reason, "post-exec tracepoint report");
        assert!(d.limitations.is_empty());

        let d = clause_support_detail(
            &compiled,
            Effect::Kill,
            Op::Recv,
            Kind::Endpoint,
            "10.0.0.7",
            None,
            false,
        );
        assert!(d.supported);
        assert_eq!(d.mode, "tracepoint");
        assert!(!d.pre_op);
        assert_eq!(d.reason, "tracepoint kill after recv");
        assert_eq!(
            d.limitations,
            vec!["IPv4 only", "post-receive in tracepoint mode"]
        );
    }
    #[test]
    fn clause_support_json_renders_one_object_per_clause() {
        // `clause_support_json` renders one JSON object per clause, projecting
        // `clause_support_detail` into the support fields plus the clause's
        // condition warnings. No base or branch test pins this serializer
        // directly.
        use crate::dsl::ast::{Rule, Target};
        use std::collections::HashMap;

        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        let policy = Policy {
            labels: Vec::new(),
            sources: Vec::new(),
            rules: vec![
                Rule {
                    name: "guard".to_string(),
                    clauses: vec![Clause {
                        op: Op::Exec,
                        target: Target {
                            kind: Kind::Exec,
                            pattern: "python3".to_string(),
                            arg: None,
                        },
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Notify,
                        source_index: 0,
                    }],
                    reason: "guard exec".to_string(),
                },
                Rule {
                    name: "egress".to_string(),
                    clauses: vec![
                        Clause {
                            op: Op::Connect,
                            target: Target {
                                kind: Kind::Endpoint,
                                pattern: "10.0.0.7".to_string(),
                                arg: None,
                            },
                            when: Expr::True,
                            unless: None,
                            effect: Effect::Block,
                            source_index: 0,
                        },
                        Clause {
                            op: Op::Connect,
                            target: Target {
                                kind: Kind::Endpoint,
                                pattern: "api.evil".to_string(),
                                arg: None,
                            },
                            when: Expr::True,
                            unless: None,
                            effect: Effect::Block,
                            source_index: 0,
                        },
                    ],
                    reason: "guard egress".to_string(),
                },
            ],
            xforms: Vec::new(),
        };

        let got = clause_support_json(&policy, &compiled, true);
        let expected = vec![
            json!({
                "rule": "guard",
                "clause_index": 0,
                "effect": "notify",
                "op": "exec",
                "target_kind": "exec",
                "target_pattern": "python3",
                "target_arg": null,
                "supported": true,
                "status": "supported",
                "mode": "tracepoint",
                "pre_op": false,
                "reason": "post-exec tracepoint report",
                "limitations": [],
                "condition_warnings": [],
            }),
            json!({
                "rule": "egress",
                "clause_index": 0,
                "effect": "block",
                "op": "connect",
                "target_kind": "endpoint",
                "target_pattern": "10.0.0.7",
                "target_arg": null,
                "supported": true,
                "status": "supported",
                "mode": "bpf-lsm",
                "pre_op": true,
                "reason": "pre-op block via BPF-LSM socket_connect",
                "limitations": ["IPv4 only"],
                "condition_warnings": [],
            }),
            json!({
                "rule": "egress",
                "clause_index": 1,
                "effect": "block",
                "op": "connect",
                "target_kind": "endpoint",
                "target_pattern": "api.evil",
                "target_arg": null,
                "supported": false,
                "status": "unsupported",
                "mode": "none",
                "pre_op": false,
                "reason": "endpoint target pattern is not numeric IPv4 or an exact \
                          resolvable hostname",
                "limitations": ["wildcard hostnames and IPv6 are not enforced in-kernel"],
                "condition_warnings": [],
            }),
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn codex_global_mcp_config_only_matches_exact_section() {
        if std::env::var_os("HOME").is_none() {
            return;
        }
        let mut problems = 0usize;
        assert!(codex_global_mcp_actplane_config().is_none());

        let home = tempfile::tempdir().expect("tempdir");
        let previous = std::env::var_os("HOME");
        // SAFETY: `doctor` filter runs this test alone; HOME is restored below.
        unsafe { std::env::set_var("HOME", home.path()) };
        assert!(codex_global_mcp_actplane_config().is_none());

        let codex = home.path().join(".codex");
        std::fs::create_dir_all(&codex).expect("codex dir");
        let config = codex.join("config.toml");
        std::fs::write(&config, "[mcp_servers.actplane_extra]\n").expect("config");
        assert!(codex_global_mcp_actplane_config().is_none());

        std::fs::write(&config, "  [mcp_servers.actplane]  \n").expect("config");
        assert_eq!(
            codex_global_mcp_actplane_config().as_deref(),
            Some(config.as_path())
        );

        match previous {
            Some(value) => unsafe { std::env::set_var("HOME", value) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        doctor_agent_files(home.path(), &mut problems);
        assert_eq!(problems, 1);
    }

    #[test]
    #[cfg(unix)]
    fn command_version_reports_successful_probes_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("good-tool");
        std::fs::write(&good, "#!/bin/sh\necho v9.9\n").expect("write");
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(command_version(&good), Some("v9.9".to_string()));

        let failing = dir.path().join("failing-tool");
        std::fs::write(&failing, "#!/bin/sh\nexit 3\n").expect("write");
        std::fs::set_permissions(&failing, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(command_version(&failing), None);

        let silent = dir.path().join("silent-tool");
        std::fs::write(&silent, "#!/bin/sh\ntrue\n").expect("write");
        std::fs::set_permissions(&silent, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(command_version(&silent), None);

        assert_eq!(command_version(&dir.path().join("missing-tool")), None);
    }
    #[test]
    fn cond_summary_renders_every_cond_variant() {
        // `cond_summary` renders a `Cond` to a human-readable string,
        // recursing for the `After` `since` events. No base or branch test
        // pins this formatter directly.
        assert_eq!(
            cond_summary(&Cond::Target {
                negate: false,
                pattern: "out.txt".into()
            }),
            "target \"out.txt\""
        );
        assert_eq!(
            cond_summary(&Cond::Target {
                negate: true,
                pattern: "out.txt".into()
            }),
            "target not \"out.txt\""
        );
        assert_eq!(
            cond_summary(&Cond::LineageIncludes {
                exec: "agent".into()
            }),
            "lineage-includes exec \"agent\""
        );

        // `After` with an exit stamp and a single `since` event.
        assert_eq!(
            cond_summary(&Cond::After {
                gate_op: Op::Exec,
                gate_pattern: "agent".into(),
                gate_exit: Some(0),
                since: vec![(Op::Open, "policy.dsl".into(), None)]
            }),
            "after exec \"agent\" exits 0 since open \"policy.dsl\""
        );

        // `After` with no exit and two `since` events joined by " or ".
        assert_eq!(
            cond_summary(&Cond::After {
                gate_op: Op::Open,
                gate_pattern: "policy.dsl".into(),
                gate_exit: None,
                since: vec![
                    (Op::Exec, "agent".into(), None),
                    (Op::Connect, "10.0.0.0/8".into(), Some("r".into())),
                ]
            }),
            "after open \"policy.dsl\" since exec \"agent\" or connect \"10.0.0.0/8\" \"r\""
        );
    }
    #[test]
    fn domain_json_renders_the_domain_summary_or_null() {
        // `domain_json` serializes a resolved policy's domain summary. A
        // `None` domain renders as JSON `null`; a `Some` domain renders the
        // name, optional parent, locked, default, and disabled fields. No base
        // or branch test pins this serializer directly.
        let no_domain = ResolvedPolicy {
            source: "inline".to_string(),
            domain: None,
        };
        assert_eq!(domain_json(&no_domain), Value::Null);

        // A domain summary with every field populated, including `parent`.
        let some_domain = ResolvedPolicy {
            source: "inline".to_string(),
            domain: Some(DomainSummary {
                name: "repo".to_string(),
                parent: Some("org".to_string()),
                locked: vec!["git".to_string()],
                defaults: vec!["notify".to_string()],
                disabled: vec!["rm".to_string()],
            }),
        };
        assert_eq!(
            domain_json(&some_domain),
            json!({
                "name": "repo",
                "parent": "org",
                "locked": ["git"],
                "default": ["notify"],
                "disabled": ["rm"],
            })
        );

        // A domain with no parent: the `parent` key is JSON `null`.
        let no_parent = ResolvedPolicy {
            source: "inline".to_string(),
            domain: Some(DomainSummary {
                name: "repo".to_string(),
                parent: None,
                locked: Vec::new(),
                defaults: Vec::new(),
                disabled: Vec::new(),
            }),
        };
        assert_eq!(
            domain_json(&no_parent),
            json!({
                "name": "repo",
                "parent": Value::Null,
                "locked": [],
                "default": [],
                "disabled": [],
            })
        );
    }

    #[test]
    fn format_rule_list_joins_or_reports_none() {
        assert_eq!(format_rule_list(&[]), "none");
        assert_eq!(format_rule_list(&["a".into(), "b".into()]), "a, b");
    }

    #[test]
    fn format_domain_policy_rules_lists_locked_then_defaults() {
        let domain = DomainSummary {
            name: "work".into(),
            parent: None,
            disabled: vec!["d".into()],
            locked: vec!["locked1".into()],
            defaults: vec!["default1".into(), "default2".into()],
        };
        assert_eq!(
            format_domain_policy_rules(&domain),
            "locked1, default1, default2"
        );
        let empty = DomainSummary {
            name: "work".into(),
            parent: None,
            disabled: Vec::new(),
            locked: Vec::new(),
            defaults: Vec::new(),
        };
        assert_eq!(format_domain_policy_rules(&empty), "none");
    }

    #[test]
    fn rollout_clause_signatures_keys_by_rule_and_source_index() {
        let policy = Policy {
            labels: Vec::new(),
            sources: Vec::new(),
            rules: vec![crate::dsl::ast::Rule {
                name: "r".into(),
                reason: String::new(),
                clauses: vec![Clause {
                    op: Op::Exec,
                    target: crate::dsl::ast::Target {
                        kind: Kind::Exec,
                        pattern: "git".into(),
                        arg: Some("push".into()),
                    },
                    when: Expr::True,
                    unless: None,
                    effect: Effect::Block,
                    source_index: 3,
                }],
            }],
            xforms: Vec::new(),
        };
        let signatures = rollout_clause_signatures(&policy);
        assert_eq!(signatures.len(), 1);
        let signature = signatures.get(&("r".to_string(), 3)).unwrap();
        assert_eq!(signature.clause_op, "exec");
        assert_eq!(signature.target_kind, "exec");
        assert_eq!(signature.target_pattern, "git");
        assert_eq!(signature.target_arg.as_deref(), Some("push"));
        assert_eq!(signature.clause_text, "  notify exec \"git\" \"push\"");
        assert!(!signature.clause_hash.is_empty());
    }
    #[test]
    fn dsl_literal_flattens_whitespace_and_single_quotes() {
        // `dsl_literal` flattens newlines and carriage returns into spaces
        // and swaps double quotes for single quotes, so a value can be
        // embedded in a DSL string literal. No base or branch test pins
        // this formatter directly.
        assert_eq!(dsl_literal("plain"), "plain");
        assert_eq!(dsl_literal("a\nb\rc"), "a b c");
        assert_eq!(dsl_literal("say \"hi\""), "say 'hi'");
        // Both substitutions apply to the same value.
        assert_eq!(dsl_literal("a\n\"b\""), "a 'b'");
    }

    #[test]
    fn render_dsl_expr_nests_and_chains_operators() {
        assert_eq!(render_dsl_expr(&Expr::True), "true");
        assert_eq!(render_dsl_expr(&Expr::Label("T".into())), "T");
        assert_eq!(render_dsl_expr(&Expr::Not("T".into())), "not T");
        let nested = Expr::And(
            Box::new(Expr::Label("A".into())),
            Box::new(Expr::Or(
                Box::new(Expr::Label("B".into())),
                Box::new(Expr::Label("C".into())),
            )),
        );
        assert_eq!(render_dsl_expr(&nested), "A and B or C");
    }

    #[test]
    fn render_dsl_event_appends_optional_argument() {
        assert_eq!(render_dsl_event(Op::Exec, "git", None), "exec \"git\"");
        assert_eq!(
            render_dsl_event(Op::Exec, "git", Some("push")),
            "exec \"git\" \"push\""
        );
    }

    #[test]
    fn render_dsl_cond_covers_lineage_target_and_after() {
        assert_eq!(
            render_dsl_cond(&Cond::Target {
                negate: false,
                pattern: "host".into()
            }),
            "target \"host\""
        );
        assert_eq!(
            render_dsl_cond(&Cond::Target {
                negate: true,
                pattern: "host".into()
            }),
            "target not \"host\""
        );
        assert_eq!(
            render_dsl_cond(&Cond::LineageIncludes { exec: "git".into() }),
            "lineage-includes exec \"git\""
        );
        assert_eq!(
            render_dsl_cond(&Cond::After {
                gate_op: Op::Exec,
                gate_pattern: "git".into(),
                gate_exit: Some(1),
                since: vec![(Op::Write, "f.txt".into(), None)],
            }),
            "after exec \"git\" exits 1 since write \"f.txt\""
        );
    }

    #[test]
    fn expr_summary_labels_boolean_structure() {
        let nested = Expr::And(
            Box::new(Expr::Label("A".into())),
            Box::new(Expr::Or(
                Box::new(Expr::Label("B".into())),
                Box::new(Expr::Label("C".into())),
            )),
        );
        assert_eq!(expr_summary(&nested), "(A and (B or C))");
    }

    #[test]
    fn cond_summary_covers_target_after_and_empty_since() {
        assert_eq!(
            cond_summary(&Cond::Target {
                negate: false,
                pattern: "host".into()
            }),
            "target \"host\""
        );
        assert_eq!(
            cond_summary(&Cond::After {
                gate_op: Op::Exec,
                gate_pattern: "git".into(),
                gate_exit: None,
                since: vec![],
            }),
            "after exec \"git\""
        );
        assert_eq!(
            cond_summary(&Cond::After {
                gate_op: Op::Exec,
                gate_pattern: "git".into(),
                gate_exit: Some(2),
                since: vec![
                    (Op::Write, "a".into(), None),
                    (Op::Write, "b".into(), Some("x".into())),
                ],
            }),
            "after exec \"git\" exits 2 since write \"a\" or write \"b\" \"x\""
        );
    }
    #[test]
    fn effect_name_maps_every_enforcement_effect_to_its_name() {
        // `effect_name` renders each `Effect` variant to the short name the
        // report and support-detail paths use. No base or branch test pins
        // this mapping directly.
        assert_eq!(effect_name(Effect::Notify), "notify");
        assert_eq!(effect_name(Effect::Block), "block");
        assert_eq!(effect_name(Effect::Kill), "kill");
    }

    fn compiled_with_endpoints_c2(entries: &[(&str, Vec<&str>)]) -> dsl::Compiled {
        let mut resolutions = std::collections::HashMap::new();
        for (pattern, addrs) in entries {
            resolutions.insert(
                (*pattern).to_string(),
                addrs.iter().map(|a| (*a).to_string()).collect(),
            );
        }
        dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: resolutions,
        }
    }

    #[test]
    fn source_support_detail_covers_each_kind() {
        let compiled = compiled_with_endpoints_c2(&[]);
        let (ok, reason, f_lim) = source_support_detail(&compiled, Kind::Exec, "git");
        assert!(ok && reason.contains("exec"));
        assert!(f_lim.is_empty());
        let (ok, _, f_lim) = source_support_detail(&compiled, Kind::File, "**/.env");
        assert!(ok && !f_lim.is_empty());
        let (ok, _, _) = source_support_detail(&compiled, Kind::Endpoint, "10.0.0.1");
        assert!(ok);
    }

    #[test]
    fn endpoint_support_detail_distinguishes_numeric_resolved_and_unknown() {
        let compiled = compiled_with_endpoints_c2(&[
            ("host.example", vec!["10.0.0.1"]),
            ("empty.example", vec![]),
        ]);
        let (ok, _, _) = endpoint_support_detail(&compiled, "10.0.0.1", "target");
        assert!(ok);
        let (ok, reason, _) = endpoint_support_detail(&compiled, "host.example", "source");
        assert!(ok && reason.contains("resolved"));
        let (ok, reason, _) = endpoint_support_detail(&compiled, "empty.example", "target");
        assert!(!ok && reason.contains("did not resolve"));
        let (ok, reason, _) = endpoint_support_detail(&compiled, "*.example", "target");
        assert!(!ok && reason.contains("not numeric IPv4"));
    }

    #[test]
    fn endpoint_limitations_tracks_resolution_state() {
        let compiled = compiled_with_endpoints_c2(&[("host.example", vec!["10.0.0.1"])]);
        assert_eq!(
            endpoint_limitations(&compiled, "10.0.0.1"),
            vec!["IPv4 only"]
        );
        assert!(
            endpoint_limitations(&compiled, "host.example")
                .contains(&"DNS changes require policy reload")
        );
        assert_eq!(
            endpoint_limitations(&compiled, "unknown.example"),
            vec!["IPv4 only"]
        );
        let with_extra = endpoint_limitations_with(&compiled, "unknown.example", "extra note");
        assert_eq!(with_extra.last(), Some(&"extra note"));
    }

    #[test]
    fn clause_support_detail_rejects_argv_block_and_unsupported_endpoints() {
        let compiled = compiled_with_endpoints_c2(&[]);
        let argv = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Exec,
            Kind::Exec,
            "git",
            Some("push"),
            true,
        );
        assert!(!argv.supported && argv.reason.contains("argv"));
        let no_lsm = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Exec,
            Kind::Exec,
            "git",
            None,
            false,
        );
        assert!(!no_lsm.supported && no_lsm.reason.contains("BPF-LSM is not active"));
        let endpoint = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Connect,
            Kind::Endpoint,
            "*.example",
            None,
            true,
        );
        assert!(!endpoint.supported && endpoint.status == "unsupported");
    }

    #[test]
    fn clause_support_detail_marks_supported_effects() {
        let compiled = compiled_with_endpoints_c2(&[]);
        let block = clause_support_detail(
            &compiled,
            Effect::Block,
            Op::Exec,
            Kind::Exec,
            "git",
            None,
            true,
        );
        assert!(block.supported && block.mode == "bpf-lsm" && block.pre_op);
        let notify = clause_support_detail(
            &compiled,
            Effect::Notify,
            Op::Read,
            Kind::File,
            "**/.env",
            None,
            false,
        );
        assert!(notify.supported && notify.mode == "tracepoint" && !notify.pre_op);
        let kill = clause_support_detail(
            &compiled,
            Effect::Kill,
            Op::Connect,
            Kind::Endpoint,
            "10.0.0.1",
            None,
            false,
        );
        assert!(kill.supported && kill.mode == "tracepoint");
    }
    #[test]
    fn endpoint_limitations_reports_ipv4_only_and_hostname_caveats() {
        // `endpoint_limitations` returns the enforcement caveats for an
        // endpoint pattern: a single "IPv4 only" caveat for numeric IPv4 and
        // unresolved patterns, and three caveats for a hostname that
        // resolved to an address at compile/load time. No base or branch
        // test pins this function directly.
        use std::collections::HashMap;

        fn empty_compiled() -> dsl::Compiled {
            dsl::Compiled {
                bytes: Vec::new(),
                reasons: Vec::new(),
                meta: Vec::new(),
                labels: HashMap::new(),
                endpoint_resolutions: HashMap::new(),
            }
        }

        // Numeric IPv4 patterns carry only the "IPv4 only" caveat.
        let empty = empty_compiled();
        assert_eq!(
            endpoint_limitations(&empty, "93.184.215.14"),
            vec!["IPv4 only"]
        );
        assert_eq!(endpoint_limitations(&empty, "*"), vec!["IPv4 only"]);

        // An unresolved hostname carries only the "IPv4 only" caveat.
        assert_eq!(
            endpoint_limitations(&empty, "api.example.com"),
            vec!["IPv4 only"]
        );

        // A hostname that resolved carries the resolution caveats plus
        // "IPv4 only".
        let mut resolved = empty_compiled();
        resolved
            .endpoint_resolutions
            .insert("api.example.com".into(), vec!["93.184.215.14".into()]);
        assert_eq!(
            endpoint_limitations(&resolved, "api.example.com"),
            vec![
                "hostname resolved at policy compile/load time",
                "DNS changes require policy reload",
                "IPv4 only",
            ]
        );
    }
    #[test]
    fn endpoint_limitations_with_appends_the_extra_limitation() {
        // `endpoint_limitations_with` computes the endpoint limitations for a
        // pattern (delegating to `endpoint_limitations`) and appends one extra
        // caller-supplied limitation. No base or branch test pins this
        // wrapper directly.
        use std::collections::HashMap;

        let mk = |resolutions: HashMap<String, Vec<String>>| dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: resolutions,
        };

        // A numeric IPv4 pattern yields the single "IPv4 only" limitation,
        // with the extra appended.
        let compiled = mk(HashMap::new());
        assert_eq!(
            endpoint_limitations_with(&compiled, "10.0.0.7", "evidence-backed"),
            vec!["IPv4 only", "evidence-backed"]
        );

        // A hostname with a non-empty compile-time resolution gets the DNS
        // caveats plus the extra.
        let compiled = mk(HashMap::from([(
            "example.com".to_string(),
            vec!["93.184.215.14".to_string(), "93.184.215.15".to_string()],
        )]));
        assert_eq!(
            endpoint_limitations_with(&compiled, "example.com", "evidence-backed"),
            vec![
                "hostname resolved at policy compile/load time",
                "DNS changes require policy reload",
                "IPv4 only",
                "evidence-backed",
            ]
        );

        // A hostname with no resolution falls back to the single limitation.
        let compiled = mk(HashMap::new());
        assert_eq!(
            endpoint_limitations_with(&compiled, "example.com", "evidence-backed"),
            vec!["IPv4 only", "evidence-backed"]
        );
    }
    #[test]
    fn endpoint_pattern_supported_detects_numeric_ipv4_or_resolved_hostname() {
        // `endpoint_pattern_supported` reports whether an endpoint pattern is
        // supported: either a numeric IPv4 pattern or a hostname that resolved
        // to at least one address at compile/load time. No base or branch
        // test pins this predicate directly.
        use std::collections::HashMap;

        fn empty_compiled() -> dsl::Compiled {
            dsl::Compiled {
                bytes: Vec::new(),
                reasons: Vec::new(),
                meta: Vec::new(),
                labels: HashMap::new(),
                endpoint_resolutions: HashMap::new(),
            }
        }

        // Numeric IPv4 patterns are always supported, with an empty backend.
        let empty = empty_compiled();
        assert!(endpoint_pattern_supported(&empty, "*"));
        assert!(endpoint_pattern_supported(&empty, "93.184.215.14"));

        // A hostname with no resolution entry is not supported.
        assert!(!endpoint_pattern_supported(&empty, "api.example.com"));

        // A hostname that resolved to at least one address is supported.
        let mut resolved = empty_compiled();
        resolved
            .endpoint_resolutions
            .insert("api.example.com".into(), vec!["93.184.215.14".into()]);
        assert!(endpoint_pattern_supported(&resolved, "api.example.com"));

        // A hostname whose resolution yielded no address is not supported.
        resolved
            .endpoint_resolutions
            .insert("stale.example.com".into(), Vec::new());
        assert!(!endpoint_pattern_supported(&resolved, "stale.example.com"));
    }
    #[test]
    fn endpoint_support_detail_covers_all_resolution_branches() {
        // `endpoint_support_detail` reports support for an endpoint pattern:
        // numeric IPv4, a hostname that resolved to IPv4, a hostname with an
        // empty resolution, and an unresolvable pattern. No base or branch
        // test pins this directly.
        use std::collections::HashMap;

        let empty = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        // Numeric IPv4.
        assert_eq!(
            endpoint_support_detail(&empty, "10.0.0.7", "source"),
            (
                true,
                "endpoint source matches numeric IPv4 connect and recv paths".to_string(),
                vec!["IPv6 is not enforced in-kernel"]
            )
        );

        // A hostname that resolved to IPv4 addresses.
        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::from([(
                "example.com".to_string(),
                vec!["93.184.215.14".to_string(), "93.184.215.15".to_string()],
            )]),
        };
        assert_eq!(
            endpoint_support_detail(&compiled, "example.com", "source"),
            (
                true,
                "endpoint source hostname resolved to IPv4 address(es): \
                 93.184.215.14, 93.184.215.15"
                    .to_string(),
                vec![
                    "hostname is resolved at policy compile/load time",
                    "DNS changes require policy reload",
                    "IPv6 addresses are ignored",
                ]
            )
        );

        // A hostname with an empty resolution list.
        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::from([("bad.host".to_string(), Vec::new())]),
        };
        assert_eq!(
            endpoint_support_detail(&compiled, "bad.host", "source"),
            (
                false,
                "endpoint source hostname did not resolve to an IPv4 address".to_string(),
                vec![
                    "hostname is resolved at policy compile/load time",
                    "DNS changes require policy reload",
                    "IPv6 addresses are ignored",
                ]
            )
        );

        // A pattern that is neither numeric IPv4 nor a known hostname.
        assert_eq!(
            endpoint_support_detail(&empty, "wildcard.*", "source"),
            (
                false,
                "endpoint source pattern is not numeric IPv4 or an exact \
                 resolvable hostname"
                    .to_string(),
                vec!["wildcard hostnames and IPv6 are not enforced in-kernel"]
            )
        );
    }
    #[test]
    fn enforcement_timing_maps_effect_and_support_to_timing() {
        // `enforcement_timing` renders the enforcement-timing string for an
        // `Effect` given backend support. When the backend does not support
        // enforcement it always reports "not enforceable". No base or branch
        // test pins this mapping directly.
        fn detail(supported: bool, pre_op: bool) -> SupportDetail {
            SupportDetail {
                supported,
                status: "",
                mode: "",
                pre_op,
                reason: String::new(),
                limitations: Vec::new(),
            }
        }

        // Unsupported backend: every effect is not enforceable.
        for effect in [Effect::Notify, Effect::Block, Effect::Kill] {
            assert_eq!(
                enforcement_timing(effect, &detail(false, true)),
                "not enforceable by the current backend selection"
            );
        }

        // Supported backends.
        assert_eq!(
            enforcement_timing(Effect::Notify, &detail(true, true)),
            "post-event report; operation proceeds"
        );
        assert_eq!(
            enforcement_timing(Effect::Kill, &detail(true, true)),
            "post-event termination; the triggering syscall may already have completed"
        );
        // Block with a pre-operation backend.
        assert_eq!(
            enforcement_timing(Effect::Block, &detail(true, true)),
            "pre-operation denial before syscall commit"
        );
        // Block without a pre-operation backend.
        assert_eq!(
            enforcement_timing(Effect::Block, &detail(true, false)),
            "block requested, but no pre-operation backend is available"
        );
    }

    #[test]
    fn doctor_reports_problems_for_a_non_compiling_policy() {
        let cli = PolicyInput {
            policy: None,
            rule: Some("rule :".to_string()),
            domain: None,
            run_as_root: false,
            internal_elevated: false,
        };
        // A policy that fails to compile is always counted as a problem, so the
        // exit status is 1 regardless of the host kernel/privilege checks.
        assert_eq!(doctor(&cli).unwrap(), 1);
    }

    fn compiled_with_endpoints_c3(entries: &[(&str, Vec<&str>)]) -> dsl::Compiled {
        let mut resolutions = std::collections::HashMap::new();
        for (pattern, addrs) in entries {
            resolutions.insert(
                (*pattern).to_string(),
                addrs.iter().map(|a| (*a).to_string()).collect(),
            );
        }
        dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: resolutions,
        }
    }

    #[test]
    fn op_effect_and_kind_names_round_trip_their_enum_values() {
        assert_eq!(op_name(Op::Exec), "exec");
        assert_eq!(op_name(Op::Read), "read");
        assert_eq!(op_name(Op::Write), "write");
        assert_eq!(op_name(Op::Unlink), "unlink");
        assert_eq!(op_name(Op::Connect), "connect");
        assert_eq!(op_name(Op::Recv), "recv");
        assert_eq!(op_name(Op::Open), "open");
        assert_eq!(effect_name(Effect::Notify), "notify");
        assert_eq!(effect_name(Effect::Block), "block");
        assert_eq!(effect_name(Effect::Kill), "kill");
        assert_eq!(kind_name(Kind::File), "file");
        assert_eq!(kind_name(Kind::Endpoint), "endpoint");
        assert_eq!(kind_name(Kind::Exec), "exec");
    }

    #[test]
    fn endpoint_pattern_supported_accepts_numeric_or_resolved_hosts() {
        let compiled = compiled_with_endpoints_c3(&[("api.example", vec!["10.0.0.1"])]);
        assert!(endpoint_pattern_supported(&compiled, "10.0.0.5"));
        assert!(endpoint_pattern_supported(&compiled, "api.example"));
        assert!(!endpoint_pattern_supported(&compiled, "other.example"));
    }

    #[test]
    fn endpoint_pattern_supported_rejects_empty_resolution() {
        let compiled = compiled_with_endpoints_c3(&[("empty.example", vec![])]);
        assert!(!endpoint_pattern_supported(&compiled, "empty.example"));
    }

    fn signature() -> ClauseEventSignature {
        ClauseEventSignature {
            clause_op: "exec",
            target_kind: "exec",
            target_pattern: "git".to_string(),
            target_arg: None,
            clause_text: "block exec \"git\"".to_string(),
            clause_hash: "abc123".to_string(),
        }
    }

    #[test]
    fn event_rule_matches_signature_requires_exact_identity() {
        let sig = signature();
        let ok = serde_json::json!({
            "rule": {
                "effect": "notify",
                "clause_op": "exec",
                "target_kind": "exec",
                "target_pattern": "git",
                "clause_hash": "abc123"
            }
        });
        assert!(event_rule_matches_signature(&ok, &sig));
        let wrong_hash = serde_json::json!({
            "rule": {
                "effect": "notify",
                "clause_op": "exec",
                "target_kind": "exec",
                "target_pattern": "git",
                "clause_hash": "other"
            }
        });
        assert!(!event_rule_matches_signature(&wrong_hash, &sig));
        assert!(!event_rule_matches_signature(&serde_json::json!({}), &sig));
    }

    #[test]
    fn event_clause_identity_matches_prefers_hash_then_text() {
        let sig = signature();
        assert!(event_clause_identity_matches(
            &serde_json::json!({ "clause_hash": "abc123" }),
            &sig
        ));
        assert!(!event_clause_identity_matches(
            &serde_json::json!({ "clause_hash": "nope" }),
            &sig
        ));
        assert!(event_clause_identity_matches(
            &serde_json::json!({ "clause_text": "block exec \"git\"" }),
            &sig
        ));
        assert!(!event_clause_identity_matches(
            &serde_json::json!({ "clause_text": "different" }),
            &sig
        ));
        assert!(!event_clause_identity_matches(&serde_json::json!({}), &sig));
    }

    #[test]
    fn annotation_rule_matches_signature_accepts_notify_and_missing_effect() {
        let sig = signature();
        let notify = serde_json::json!({
            "rule": {
                "effect": "notify",
                "clause_op": "exec",
                "target_kind": "exec",
                "target_pattern": "git",
                "clause_hash": "abc123"
            }
        });
        assert!(annotation_rule_matches_signature(&notify, &sig));
        let no_effect = serde_json::json!({
            "rule": {
                "clause_op": "exec",
                "target_kind": "exec",
                "target_pattern": "git",
                "clause_hash": "abc123"
            }
        });
        assert!(annotation_rule_matches_signature(&no_effect, &sig));
        let enforced = serde_json::json!({
            "rule": {
                "effect": "block",
                "clause_op": "exec",
                "target_kind": "exec",
                "target_pattern": "git",
                "clause_hash": "abc123"
            }
        });
        assert!(!annotation_rule_matches_signature(&enforced, &sig));
    }

    #[test]
    fn annotation_count_reads_or_defaults() {
        let mut observation = ClauseObservation::default();
        assert_eq!(annotation_count(&observation, "blocked"), 0);
        observation.annotations.insert("blocked".to_string(), 3);
        assert_eq!(annotation_count(&observation, "blocked"), 3);
    }

    fn evidence_with_events() -> RolloutEvidence {
        RolloutEvidence {
            event_paths: vec![PathBuf::from("events.jsonl")],
            annotation_paths: Vec::new(),
            total_events: 0,
            total_annotations: 0,
            ignored_lines: 0,
            ignored_annotations: 0,
            warnings: Vec::new(),
            clauses: BTreeMap::new(),
        }
    }

    fn observation_count(count: usize) -> ClauseObservation {
        ClauseObservation {
            count,
            ..ClauseObservation::default()
        }
    }

    fn condition_clause(op: Op, pattern: &str, unless: Option<Cond>) -> crate::dsl::ast::Clause {
        crate::dsl::ast::Clause {
            op,
            target: crate::dsl::ast::Target {
                kind: Kind::Endpoint,
                pattern: pattern.to_string(),
                arg: None,
            },
            when: Expr::True,
            unless,
            effect: Effect::Block,
            source_index: 0,
        }
    }

    fn compiled_with_endpoints_c4(entries: &[(&str, Vec<&str>)]) -> dsl::Compiled {
        let mut resolutions = std::collections::HashMap::new();
        for (pattern, addrs) in entries {
            resolutions.insert(
                (*pattern).to_string(),
                addrs.iter().map(|a| (*a).to_string()).collect(),
            );
        }
        dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: resolutions,
        }
    }

    #[test]
    fn event_backed_promotion_note_returns_none_without_logs() {
        let evidence = RolloutEvidence {
            event_paths: Vec::new(),
            annotation_paths: Vec::new(),
            ..evidence_with_events()
        };
        assert_eq!(
            event_backed_promotion_note(&evidence, None, Effect::Block, true),
            None
        );
    }

    #[test]
    fn event_backed_promotion_note_kill_branches_on_observed_count() {
        let evidence = evidence_with_events();
        let seen =
            event_backed_promotion_note(&evidence, Some(&observation_count(3)), Effect::Kill, true)
                .unwrap();
        assert!(seen.contains("observed 3 matching event(s)"));
        let none = event_backed_promotion_note(&evidence, None, Effect::Kill, true).unwrap();
        assert!(none.contains("0 matching events in supplied logs"));
    }

    #[test]
    fn event_backed_promotion_note_block_branches() {
        let evidence = evidence_with_events();
        let no_backend =
            event_backed_promotion_note(&evidence, None, Effect::Block, false).unwrap();
        assert!(no_backend.contains("backend support is insufficient"));
        let seen = event_backed_promotion_note(
            &evidence,
            Some(&observation_count(2)),
            Effect::Block,
            true,
        )
        .unwrap();
        assert!(seen.contains("observed 2 matching event(s)"));
        let none = event_backed_promotion_note(&evidence, None, Effect::Block, true).unwrap();
        assert!(none.contains("0 matching events in supplied logs"));
    }

    #[test]
    fn clause_condition_warnings_covers_resolution_states() {
        let compiled = compiled_with_endpoints_c4(&[
            ("one.example", vec!["10.0.0.1"]),
            ("multi.example", vec!["10.0.0.1", "10.0.0.2"]),
            ("empty.example", vec![]),
        ]);
        let none = condition_clause(
            Op::Connect,
            "one.example",
            Some(Cond::Target {
                negate: false,
                pattern: "one.example".into(),
            }),
        );
        assert!(clause_condition_warnings(&none, &compiled).is_empty());
        let multi = condition_clause(
            Op::Recv,
            "multi.example",
            Some(Cond::Target {
                negate: true,
                pattern: "multi.example".into(),
            }),
        );
        let warnings = clause_condition_warnings(&multi, &compiled);
        assert_eq!(
            warnings[0].code,
            "endpoint_target_condition_multi_ipv4_hostname"
        );
        assert!(warnings[0].message.contains("not \"multi.example\""));
        let empty = condition_clause(
            Op::Connect,
            "empty.example",
            Some(Cond::Target {
                negate: false,
                pattern: "empty.example".into(),
            }),
        );
        assert_eq!(
            clause_condition_warnings(&empty, &compiled)[0].code,
            "endpoint_target_condition_unresolved_hostname"
        );
        let wildcard = condition_clause(
            Op::Connect,
            "*.example",
            Some(Cond::Target {
                negate: false,
                pattern: "*.example".into(),
            }),
        );
        assert_eq!(
            clause_condition_warnings(&wildcard, &compiled)[0].code,
            "endpoint_target_condition_unsupported_pattern"
        );
    }
    #[test]
    fn event_backed_promotion_note_selects_the_event_or_annotation_branch() {
        // `event_backed_promotion_note` first defers to
        // `annotation_backed_promotion_note`; when that yields nothing (no
        // annotation log, or no recognized class), it falls back to the
        // event count. A Kill effect names the kill path; otherwise an
        // unsupported backend refuses promotion, and a supported one names the
        // observed count. No base or branch test pins this note directly.
        let evidence = |event: bool, annotation: bool| {
            let mut ev = RolloutEvidence {
                event_paths: Vec::new(),
                annotation_paths: Vec::new(),
                total_events: 0,
                total_annotations: 0,
                ignored_lines: 0,
                ignored_annotations: 0,
                warnings: Vec::new(),
                clauses: BTreeMap::new(),
            };
            if event {
                ev.event_paths.push(PathBuf::from("ev.jsonl"));
            }
            if annotation {
                ev.annotation_paths.push(PathBuf::from("an.jsonl"));
            }
            ev
        };
        let observation = |count: usize| ClauseObservation {
            count,
            actions: BTreeMap::new(),
            targets: Vec::new(),
            domains: BTreeMap::new(),
            annotations: BTreeMap::new(),
            annotation_notes: Vec::new(),
        };

        // No logs at all: no note.
        assert!(
            event_backed_promotion_note(&evidence(false, false), None, Effect::Notify, true)
                .is_none()
        );

        // An annotation log defers to the annotation note (empty annotations
        // keep observe mode).
        assert_eq!(
            event_backed_promotion_note(
                &evidence(true, true),
                Some(&observation(0)),
                Effect::Notify,
                true
            ),
            Some(
                "no annotations for this clause; keep observe mode until examples are classified"
                    .into()
            )
        );

        // Event log only + Kill + an observed count names the kill path.
        assert_eq!(
            event_backed_promotion_note(
                &evidence(true, false),
                Some(&observation(4)),
                Effect::Kill,
                true
            ),
            Some(
                "observed 4 matching event(s); keep notify until examples are classified, \
                 and promote to kill only if every observed class should terminate the task"
                    .into()
            )
        );

        // Event log only + Kill + no observation names the kill 0-count path.
        assert_eq!(
            event_backed_promotion_note(&evidence(true, false), None, Effect::Kill, true),
            Some(
                "0 matching events in supplied logs; candidate for limited kill promotion \
                 only after workload coverage and severity review"
                    .into()
            )
        );

        // Event log only + non-Kill + unsupported backend refuses promotion.
        assert_eq!(
            event_backed_promotion_note(
                &evidence(true, false),
                Some(&observation(4)),
                Effect::Notify,
                false
            ),
            Some(
                "do not promote to block from these logs alone; backend support is insufficient"
                    .into()
            )
        );

        // Event log only + non-Kill + supported backend + observed count.
        assert_eq!(
            event_backed_promotion_note(
                &evidence(true, false),
                Some(&observation(4)),
                Effect::Notify,
                true
            ),
            Some(
                "observed 4 matching event(s); keep notify until examples are classified, \
                 and promote only if every observed class is unwanted"
                    .into()
            )
        );

        // Event log only + non-Kill + supported backend + no observation.
        assert_eq!(
            event_backed_promotion_note(&evidence(true, false), None, Effect::Notify, true),
            Some(
                "0 matching events in supplied logs; candidate for limited promotion only after \
                 workload coverage review"
                    .into()
            )
        );
    }
    #[test]
    fn event_clause_identity_matches_hash_preferred_over_text() {
        // `event_clause_identity_matches` decides whether a parsed event/annotation
        // `rule` object refers to the same clause as a `ClauseEventSignature`. A
        // present `clause_hash` takes precedence over `clause_text`, and only a
        // string-valued field is honoured (a non-string is ignored). No base or
        // branch test pins this predicate directly.
        let signature = ClauseEventSignature {
            clause_op: "open",
            target_kind: "file",
            target_pattern: "out.txt".to_string(),
            target_arg: None,
            clause_text: "notify open file \"out.txt\"".to_string(),
            clause_hash: "hash-1".to_string(),
        };

        // A present `clause_hash` matching the signature wins outright.
        assert!(event_clause_identity_matches(
            &json!({ "clause_hash": "hash-1", "clause_text": "ignored" }),
            &signature
        ));
        // A mismatched `clause_hash` fails even when the text matches.
        assert!(!event_clause_identity_matches(
            &json!({ "clause_hash": "other", "clause_text": "notify open file \"out.txt\"" }),
            &signature
        ));

        // No hash: fall back to `clause_text`.
        assert!(event_clause_identity_matches(
            &json!({ "clause_text": "notify open file \"out.txt\"" }),
            &signature
        ));
        assert!(!event_clause_identity_matches(
            &json!({ "clause_text": "something else" }),
            &signature
        ));

        // A non-string `clause_hash` is ignored, so the text is consulted.
        assert!(event_clause_identity_matches(
            &json!({ "clause_hash": 42, "clause_text": "notify open file \"out.txt\"" }),
            &signature
        ));

        // Neither field present: no identity.
        assert!(!event_clause_identity_matches(
            &json!({ "other": "x" }),
            &signature
        ));
    }
    #[test]
    fn event_rule_matches_signature_requires_notify_fields_and_identity() {
        // `event_rule_matches_signature` matches a violation event against a
        // `ClauseEventSignature`: the `rule` object must carry `effect ==
        // "notify"`, the matching `clause_op` / `target_kind` / `target_pattern`
        // / `target_arg`, and a clause identity (hash or text). No base or
        // branch test pins this predicate directly.
        let signature = ClauseEventSignature {
            clause_op: "open",
            target_kind: "file",
            target_pattern: "out.txt".to_string(),
            target_arg: None,
            clause_text: "notify open file \"out.txt\"".to_string(),
            clause_hash: "hash-1".to_string(),
        };

        // A fully-matching event (with a matching clause hash) matches.
        assert!(event_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "notify",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "out.txt",
                    "clause_hash": "hash-1"
                }
            }),
            &signature
        ));

        // No `rule` object at all.
        assert!(!event_rule_matches_signature(
            &json!({ "event": "x" }),
            &signature
        ));

        // A non-notify effect never matches.
        assert!(!event_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "block",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "out.txt",
                    "clause_hash": "hash-1"
                }
            }),
            &signature
        ));

        // A mismatched target pattern fails.
        assert!(!event_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "notify",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "other.txt",
                    "clause_hash": "hash-1"
                }
            }),
            &signature
        ));

        // A supplied `target_arg` when the signature expects none fails.
        assert!(!event_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "notify",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "out.txt",
                    "target_arg": "w",
                    "clause_hash": "hash-1"
                }
            }),
            &signature
        ));

        // All rule fields match but the clause identity is missing.
        assert!(!event_rule_matches_signature(
            &json!({
                "rule": {
                    "effect": "notify",
                    "clause_op": "open",
                    "target_kind": "file",
                    "target_pattern": "out.txt"
                }
            }),
            &signature
        ));
    }
    #[test]
    fn event_summary_renders_op_pattern_and_optional_arg() {
        // `event_summary` renders `<op_name> "<pattern>"`, appending
        // ` "<arg>"` only when a positional argument is present. No base or
        // branch test pins this formatter directly.
        assert_eq!(event_summary(Op::Exec, "agent", None), "exec \"agent\"");
        assert_eq!(
            event_summary(Op::Open, "policy.dsl", Some("r".into())),
            "open \"policy.dsl\" \"r\""
        );
        assert_eq!(
            event_summary(Op::Connect, "10.0.0.0/8", None),
            "connect \"10.0.0.0/8\""
        );
    }

    fn evidence_with_paths(events: bool, annotations: bool) -> RolloutEvidence {
        RolloutEvidence {
            event_paths: if events {
                vec![PathBuf::from("events.jsonl")]
            } else {
                Vec::new()
            },
            annotation_paths: if annotations {
                vec![PathBuf::from("annotations.jsonl")]
            } else {
                Vec::new()
            },
            total_events: 0,
            total_annotations: 0,
            ignored_lines: 0,
            ignored_annotations: 0,
            warnings: Vec::new(),
            clauses: BTreeMap::new(),
        }
    }

    #[test]
    fn append_rollout_evidence_summary_notes_missing_logs() {
        let evidence = evidence_with_paths(false, false);
        let mut out = String::new();
        append_rollout_evidence_summary(&mut out, &evidence);
        assert!(out.contains("observe evidence:"));
        assert!(out.contains("no event or annotation log supplied"));
    }

    #[test]
    fn append_rollout_evidence_summary_reports_counts_and_warnings() {
        let mut evidence = evidence_with_paths(true, true);
        evidence.total_events = 4;
        evidence.total_annotations = 2;
        evidence.ignored_lines = 1;
        evidence.ignored_annotations = 3;
        evidence.warnings.push("a warning".into());
        let mut out = String::new();
        append_rollout_evidence_summary(&mut out, &evidence);
        assert!(out.contains("event log: events.jsonl"));
        assert!(out.contains("annotation log: annotations.jsonl"));
        assert!(out.contains("parsed violation events: 4"));
        assert!(out.contains("parsed rollout annotations: 2"));
        assert!(out.contains("ignored non-violation or malformed lines: 1"));
        assert!(out.contains("ignored malformed or stale annotations: 3"));
        assert!(out.contains("warning: a warning"));
    }

    #[test]
    fn append_clause_observation_returns_early_without_logs() {
        let evidence = evidence_with_paths(false, false);
        let mut out = String::new();
        append_clause_observation(&mut out, &evidence, None);
        assert!(out.is_empty());
    }

    #[test]
    fn append_clause_observation_reports_missing_clause() {
        let evidence = evidence_with_paths(true, true);
        let mut out = String::new();
        append_clause_observation(&mut out, &evidence, None);
        assert!(out.contains("observed events: 0 in supplied logs"));
        assert!(out.contains("annotations: none for this clause"));
    }

    #[test]
    fn push_evidence_warning_caps_after_eight() {
        let mut evidence = evidence_with_paths(false, false);
        for i in 0..8 {
            push_evidence_warning(&mut evidence, format!("w{}", i));
        }
        assert_eq!(evidence.warnings.len(), 8);
        push_evidence_warning(&mut evidence, "ninth".into());
        assert_eq!(evidence.warnings.len(), 9);
        assert_eq!(
            evidence.warnings.last().unwrap(),
            "additional rollout event-log warnings omitted"
        );
        push_evidence_warning(&mut evidence, "tenth".into());
        assert_eq!(evidence.warnings.len(), 9);
    }

    #[test]
    fn format_count_map_reports_none_then_sorted_pairs() {
        let empty = BTreeMap::new();
        assert_eq!(format_count_map(&empty), "none");

        let mut counts = BTreeMap::new();
        counts.insert("zeta".to_string(), 2usize);
        counts.insert("alpha".to_string(), 5usize);
        assert_eq!(format_count_map(&counts), "alpha=5,zeta=2");
    }

    #[cfg(unix)]
    #[test]
    fn is_executable_requires_a_regular_executable_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();

        let plain = tmp.path().join("plain");
        std::fs::write(&plain, "x").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable(&plain));

        let exec = tmp.path().join("exec");
        std::fs::write(&exec, "x").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable(&exec));

        assert!(!is_executable(tmp.path()));
        assert!(!is_executable(&tmp.path().join("missing")));
    }

    #[test]
    #[cfg(unix)]
    fn executable_detection_respects_the_execute_bit() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let exe = tmp.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("mode");
        assert!(is_executable(&exe));

        let data = tmp.path().join("data.txt");
        std::fs::write(&data, b"data").expect("write");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(!is_executable(&data));

        assert!(!is_executable(&tmp.path().join("missing")));

        let dir = tmp.path().to_str().expect("utf8 path");
        let old = std::env::var_os("PATH");
        // SAFETY: single-threaded bin test; no concurrent env readers.
        unsafe { std::env::set_var("PATH", dir) };
        assert_eq!(find_executable_on_path("tool"), Some(exe.clone()));
        assert_eq!(find_executable_on_path("data.txt"), None);
        match old {
            // SAFETY: see above.
            Some(value) => unsafe { std::env::set_var("PATH", value) },
            // SAFETY: see above.
            None => unsafe { std::env::remove_var("PATH") },
        }
    }
    #[test]
    fn expr_summary_renders_every_expr_variant() {
        // `expr_summary` renders an `Expr` to a human-readable string,
        // recursing for the `And`/`Or` composites. No base or branch test
        // pins this formatter directly.
        assert_eq!(expr_summary(&Expr::True), "true");
        assert_eq!(expr_summary(&Expr::Label("secret".into())), "secret");
        assert_eq!(expr_summary(&Expr::Not("public".into())), "not public");
        assert_eq!(
            expr_summary(&Expr::And(
                Box::new(Expr::Label("a".into())),
                Box::new(Expr::Label("b".into())),
            )),
            "(a and b)"
        );
        assert_eq!(
            expr_summary(&Expr::Or(
                Box::new(Expr::Not("a".into())),
                Box::new(Expr::True),
            )),
            "(not a or true)"
        );
    }
    #[test]
    fn format_count_map_renders_sorted_counts_and_none_when_empty() {
        // `format_count_map` renders a count map as `key=value` pairs joined
        // by "," in `BTreeMap` (sorted key) order, or "none" when empty. No
        // base or branch test pins this formatter directly.
        let empty: BTreeMap<String, usize> = BTreeMap::new();
        assert_eq!(format_count_map(&empty), "none");

        let mut counts = BTreeMap::new();
        counts.insert("exec".to_string(), 3);
        counts.insert("open".to_string(), 1);
        counts.insert("connect".to_string(), 2);
        assert_eq!(format_count_map(&counts), "connect=2,exec=3,open=1");

        // A single entry still renders in the same `key=value` form.
        let one = BTreeMap::from([("read".to_string(), 7)]);
        assert_eq!(format_count_map(&one), "read=7");
    }
    #[test]
    fn format_domain_policy_rules_joins_locked_then_defaults() {
        // `format_domain_policy_rules` renders the `locked` rules followed by
        // the `defaults` rules of a domain, joined by `format_rule_list`
        // (`", "` between, `"none"` when empty). No base or branch test
        // pins this formatter directly.
        let domain = DomainSummary {
            name: "root".into(),
            parent: None,
            disabled: Vec::new(),
            locked: vec!["no-git-branch".to_string(), "no-secret-exfil".to_string()],
            defaults: vec!["test-before-commit".to_string()],
        };
        assert_eq!(
            format_domain_policy_rules(&domain),
            "no-git-branch, no-secret-exfil, test-before-commit"
        );

        // An empty domain renders as "none".
        let empty = DomainSummary {
            name: "empty".into(),
            parent: None,
            disabled: Vec::new(),
            locked: Vec::new(),
            defaults: Vec::new(),
        };
        assert_eq!(format_domain_policy_rules(&empty), "none");

        // `defaults` are appended after `locked`.
        let defaults_only = DomainSummary {
            name: "d".into(),
            parent: None,
            disabled: Vec::new(),
            locked: Vec::new(),
            defaults: vec!["a".to_string(), "b".to_string()],
        };
        assert_eq!(format_domain_policy_rules(&defaults_only), "a, b");
    }
    #[test]
    fn format_rule_list_renders_space_comma_join_and_none_when_empty() {
        // `format_rule_list` renders a non-empty rule list as a
        // comma-space-joined string (distinct from `format_sample_list`'s
        // bare comma join), or "none" when empty. No base or branch test
        // pins this formatter directly.
        let empty: Vec<String> = Vec::new();
        assert_eq!(format_rule_list(&empty), "none");

        let rules = vec!["r1".to_string(), "r2".to_string()];
        assert_eq!(format_rule_list(&rules), "r1, r2");

        let one = vec!["only".to_string()];
        assert_eq!(format_rule_list(&one), "only");
    }
    #[test]
    fn format_sample_list_renders_comma_join_and_none_when_empty() {
        // `format_sample_list` renders a non-empty value list as a
        // comma-joined string, or "none" when empty. No base or branch test
        // pins this formatter directly.
        let empty: Vec<String> = Vec::new();
        assert_eq!(format_sample_list(&empty), "none");

        let samples = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(format_sample_list(&samples), "a,b,c");

        let one = vec!["only".to_string()];
        assert_eq!(format_sample_list(&one), "only");
    }

    #[test]
    fn endpoint_pattern_numeric_ipv4_accepts_only_wildcard_or_addresses() {
        assert!(endpoint_pattern_is_numeric_ipv4("*"));
        assert!(endpoint_pattern_is_numeric_ipv4("10.0.0.5"));
        assert!(endpoint_pattern_is_numeric_ipv4("10.0.0."));
        assert!(endpoint_pattern_is_numeric_ipv4("127.0.0.1."));
        assert!(!endpoint_pattern_is_numeric_ipv4("1.2.3.4.5"));
        assert!(!endpoint_pattern_is_numeric_ipv4("api.internal"));
        assert!(!endpoint_pattern_is_numeric_ipv4("10.0.0.256"));
        assert!(!endpoint_pattern_is_numeric_ipv4("10..0.1"));
        assert!(!endpoint_pattern_is_numeric_ipv4(""));
    }

    #[test]
    fn dsl_literal_flattens_newlines_and_replaces_double_quotes() {
        assert_eq!(dsl_literal("plain"), "plain");
        assert_eq!(dsl_literal("line1\nline2"), "line1 line2");
        assert_eq!(dsl_literal("a\r\nb"), "a  b");
        assert_eq!(dsl_literal(r#"say "hi""#), "say 'hi'");
    }

    #[test]
    fn rollout_classification_normalizes_synonyms_and_defaults_to_review() {
        assert_eq!(normalize_rollout_classification("TP"), "true_positive");
        assert_eq!(
            normalize_rollout_classification(" false_positive "),
            "false_positive"
        );
        assert_eq!(normalize_rollout_classification("benign"), "allowed");
        assert_eq!(normalize_rollout_classification("irrelevant"), "noise");
        assert_eq!(
            normalize_rollout_classification("needs-review"),
            "needs_review"
        );
        assert_eq!(
            normalize_rollout_classification("anything-else"),
            "needs_review"
        );
    }

    fn run_meta(name: &str, clause_source_index: usize, kernel_op: &str) -> dsl::RuleMeta {
        dsl::RuleMeta {
            name: name.to_string(),
            reason: "because".to_string(),
            effect: Effect::Block,
            ops: vec!["exec".to_string()],
            clause_op: "exec".to_string(),
            kernel_op: kernel_op.to_string(),
            target_kind: Kind::Exec,
            target_pattern: "git".to_string(),
            target_arg: Some("push".to_string()),
            clause_source_index,
            source: None,
        }
    }

    #[test]
    fn domain_json_renders_domain_or_null() {
        let none = ResolvedPolicy {
            source: "cli".into(),
            domain: None,
        };
        assert_eq!(domain_json(&none), Value::Null);
        let some = ResolvedPolicy {
            source: "cli".into(),
            domain: Some(DomainSummary {
                name: "work".into(),
                parent: Some("root".into()),
                disabled: vec!["x".into()],
                locked: vec!["a".into()],
                defaults: vec!["d".into()],
            }),
        };
        let value = domain_json(&some);
        assert_eq!(value["name"], "work");
        assert_eq!(value["parent"], "root");
        assert_eq!(value["locked"], serde_json::json!(["a"]));
        assert_eq!(value["default"], serde_json::json!(["d"]));
        assert_eq!(value["disabled"], serde_json::json!(["x"]));
    }

    #[test]
    fn render_check_error_json_reports_failure() {
        let resolved = ResolvedPolicy {
            source: "cli".into(),
            domain: None,
        };
        let json_text = render_check_error_json("policy.dsl", Some(&resolved), "bad rule").unwrap();
        let value: Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(value["schema"], "actplane.compile.v1");
        assert_eq!(value["ok"], false);
        assert_eq!(value["policy_ref"], "policy.dsl");
        assert_eq!(value["error"], "bad rule");
        assert!(json_text.ends_with('\n'));
        let no_domain = render_check_error_json("policy.dsl", None, "bad rule").unwrap();
        let value: Value = serde_json::from_str(&no_domain).unwrap();
        assert!(value["domain"].is_null());
    }

    #[test]
    fn rule_meta_json_includes_source_metadata_when_present() {
        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: vec![dsl::RuleMeta {
                source: Some(dsl::lower::RuleSourceMeta {
                    source_ref: "policy.dsl".to_string(),
                    binding_mode: Some("locked".to_string()),
                    start_line: 1,
                    end_line: 3,
                    text: "rule body".to_string(),
                    clause_start_line: Some(2),
                    clause_end_line: Some(2),
                    clause_text: Some("clause body".to_string()),
                }),
                ..run_meta("r", 0, "exec")
            }],
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: std::collections::HashMap::new(),
        };
        let out = rule_meta_json(&compiled);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["rule_id"], 0);
        assert_eq!(out[0]["name"], "r");
        assert_eq!(out[0]["effect"], "block");
        assert_eq!(out[0]["target_kind"], "exec");
        assert_eq!(out[0]["source_ref"], "policy.dsl");
        assert_eq!(out[0]["immutable"], true);
        assert_eq!(out[0]["clause_text"], "clause body");
        assert!(out[0]["clause_hash"].is_string());
    }
    #[test]
    fn kind_name_maps_every_target_kind_to_its_name() {
        // `kind_name` renders each `Kind` variant to the short name the
        // support-detail and source-summary paths use. No base or branch test
        // pins this mapping directly.
        assert_eq!(kind_name(Kind::File), "file");
        assert_eq!(kind_name(Kind::Endpoint), "endpoint");
        assert_eq!(kind_name(Kind::Exec), "exec");
    }

    #[test]
    fn list_domains_handles_legacy_and_domain_policies() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("legacy.yaml");
        std::fs::write(&legacy, "policy: |\n  rule r:\n    notify exec \"git\"\n").unwrap();
        let legacy_cli = PolicyInput {
            policy: Some(legacy),
            rule: None,
            domain: None,
            run_as_root: false,
            internal_elevated: false,
        };
        assert_eq!(list_domains(&legacy_cli).unwrap(), 0);

        let scoped = dir.path().join("scoped.yaml");
        std::fs::write(
            &scoped,
            r#"version: 1
rules:
  no-git-branch:
    ifc: |
      source COMMAND = exec "**"
      rule no-git-branch:
        kill exec "git" "branch" if COMMAND
        because "do not create git branches"
domains:
  session:
    bind:
      - rule: no-git-branch
        mode: locked
"#,
        )
        .unwrap();
        let scoped_cli = PolicyInput {
            policy: Some(scoped),
            rule: None,
            domain: Some("session".to_string()),
            run_as_root: false,
            internal_elevated: false,
        };
        assert_eq!(list_domains(&scoped_cli).unwrap(), 0);
    }
    #[test]
    fn lowered_clause_summary_counts_matched_kernel_matchers() {
        // `lowered_clause_summary` renders the lowered matcher summary for a
        // rule + clause: the count of kernel matchers, their rule_id(s), and
        // the sorted set of kernel_op(s). No base or branch test pins this
        // formatter directly.
        use std::collections::HashMap;

        fn meta(name: &str, kernel_op: &str, index: usize) -> dsl::RuleMeta {
            dsl::RuleMeta {
                name: name.into(),
                reason: String::new(),
                effect: Effect::Notify,
                ops: vec!["exec".into()],
                clause_op: "exec".into(),
                kernel_op: kernel_op.into(),
                target_kind: Kind::Exec,
                target_pattern: "agent".into(),
                target_arg: None,
                clause_source_index: index,
                source: None,
            }
        }

        fn compiled_with(rules: Vec<dsl::RuleMeta>) -> dsl::Compiled {
            dsl::Compiled {
                bytes: Vec::new(),
                reasons: Vec::new(),
                meta: rules,
                labels: HashMap::new(),
                endpoint_resolutions: HashMap::new(),
            }
        }

        // A rule with two lowered matchers under one clause index.
        let compiled = compiled_with(vec![meta("myrule", "exec", 0), meta("myrule", "open", 0)]);
        assert_eq!(
            lowered_clause_summary(&compiled, "myrule", 0),
            "2 kernel matcher(s), rule_id(s) [0, 1], kernel_op(s) [exec, open]"
        );

        // A different clause index only matches the second rule.
        let two_clauses = compiled_with(vec![meta("myrule", "exec", 0), meta("myrule", "open", 1)]);
        assert_eq!(
            lowered_clause_summary(&two_clauses, "myrule", 1),
            "1 kernel matcher(s), rule_id(s) [1], kernel_op(s) [open]"
        );

        // A rule name with no lowered matchers reports zero.
        assert_eq!(
            lowered_clause_summary(&compiled, "other", 0),
            "0 kernel matcher(s)"
        );
    }
    #[test]
    fn numeric_ipv4_endpoint_recognizes_wildcard_and_valid_quads() {
        // `endpoint_pattern_is_numeric_ipv4` short-circuits on the `*`
        // wildcard, then trims a single trailing dot and requires every
        // dot-separated octet to parse as a `u8`, with 1..=4 octets total.
        // No base or branch test pins this predicate directly.
        assert!(endpoint_pattern_is_numeric_ipv4("*"));

        // 1..=4 octets, each within a byte.
        assert!(endpoint_pattern_is_numeric_ipv4("10"));
        assert!(endpoint_pattern_is_numeric_ipv4("1.2.3"));
        assert!(endpoint_pattern_is_numeric_ipv4("1.2.3.4"));

        // `u8` boundary: 255 ok, 256 overflows a byte.
        assert!(endpoint_pattern_is_numeric_ipv4("255.255.255.255"));
        assert!(!endpoint_pattern_is_numeric_ipv4("256"));

        // A single trailing dot is tolerated before splitting.
        assert!(endpoint_pattern_is_numeric_ipv4("1.2.3.4."));

        // Count bound: five octets exceeds the supported width.
        assert!(!endpoint_pattern_is_numeric_ipv4("1.2.3.4.5"));

        // Non-numeric or empty octets are rejected.
        assert!(!endpoint_pattern_is_numeric_ipv4("a.b"));
        assert!(!endpoint_pattern_is_numeric_ipv4("1..3"));
        assert!(!endpoint_pattern_is_numeric_ipv4(""));
    }
    #[test]
    fn render_observe_policy_yaml_downgrades_clauses_to_notify() {
        // `render_observe_policy_yaml` wraps a parsed policy in an observe-first
        // rollout YAML: a header naming the source, an optional domain line, then
        // a `policy: |` block whose rules are re-rendered with every clause
        // downgraded to `notify`. No base or branch test pins this formatter
        // directly.
        use crate::dsl::ast::{Rule, Target, Xform};

        let minimal = Policy {
            labels: Vec::new(),
            sources: vec![Source {
                label: "e1".to_string(),
                kind: Kind::Exec,
                pattern: "python3".to_string(),
            }],
            rules: vec![Rule {
                name: "guard".to_string(),
                clauses: vec![Clause {
                    op: Op::Exec,
                    target: Target {
                        kind: Kind::Exec,
                        pattern: "python3".to_string(),
                        arg: None,
                    },
                    when: Expr::True,
                    unless: None,
                    effect: Effect::Block,
                    source_index: 0,
                }],
                reason: String::new(),
            }],
            xforms: Vec::new(),
        };
        let no_domain = ResolvedPolicy {
            source: "policy.dsl".to_string(),
            domain: None,
        };

        let got = render_observe_policy_yaml("policy.dsl", &no_domain, &minimal);
        let expected = [
            "# ActPlane observe-first policy generated from policy.dsl.",
            "# Every rule clause is downgraded to notify for rollout observation.",
            "version: 1",
            "policy: |",
            "  source e1 = exec \"python3\"",
            "",
            "  rule guard:",
            "    notify exec \"python3\"",
            "    because \"Observe-first rollout for original policy.\"",
        ]
        .join("\n");
        assert_eq!(got, expected + "\n");

        // With a source domain and a non-empty reason, the domain line and the
        // xform/source/endpoint/file clause shapes are all rendered.
        let full = Policy {
            labels: Vec::new(),
            sources: vec![Source {
                label: "net".to_string(),
                kind: Kind::Endpoint,
                pattern: "10.0.0.0/8".to_string(),
            }],
            rules: vec![Rule {
                name: "egress".to_string(),
                clauses: vec![
                    Clause {
                        op: Op::Read,
                        target: Target {
                            kind: Kind::File,
                            pattern: "/etc/passwd".to_string(),
                            arg: None,
                        },
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Block,
                        source_index: 0,
                    },
                    Clause {
                        op: Op::Connect,
                        target: Target {
                            kind: Kind::Endpoint,
                            pattern: "10.0.0.7".to_string(),
                            arg: None,
                        },
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Block,
                        source_index: 0,
                    },
                ],
                reason: "no egress".to_string(),
            }],
            xforms: vec![Xform {
                endorse: true,
                label: "secrecy".to_string(),
                gate: "curl".to_string(),
            }],
        };
        let with_domain = ResolvedPolicy {
            source: "web.dsl".to_string(),
            domain: Some(DomainSummary {
                name: "web".to_string(),
                parent: Some("app".to_string()),
                disabled: Vec::new(),
                locked: Vec::new(),
                defaults: Vec::new(),
            }),
        };

        let got = render_observe_policy_yaml("web.dsl", &with_domain, &full);
        let expected = [
            "# ActPlane observe-first policy generated from web.dsl.",
            "# Every rule clause is downgraded to notify for rollout observation.",
            "# Source domain: web (flattened selected policy).",
            "version: 1",
            "policy: |",
            "  source net = endpoint \"10.0.0.0/8\"",
            "",
            "  endorse secrecy by exec \"curl\"",
            "",
            "  rule egress:",
            "    notify read file \"/etc/passwd\"",
            "    notify connect endpoint \"10.0.0.7\"",
            "    because \"Observe-first rollout for original policy: no egress\"",
        ]
        .join("\n");
        assert_eq!(got, expected + "\n");
    }

    fn run_meta_c2(name: &str, clause_source_index: usize, kernel_op: &str) -> dsl::RuleMeta {
        dsl::RuleMeta {
            name: name.to_string(),
            reason: String::new(),
            effect: Effect::Notify,
            ops: Vec::new(),
            clause_op: "exec".to_string(),
            kernel_op: kernel_op.to_string(),
            target_kind: Kind::Exec,
            target_pattern: "git".to_string(),
            target_arg: None,
            clause_source_index,
            source: None,
        }
    }

    #[test]
    fn render_observe_clause_downgrades_to_notify_and_keeps_conditions() {
        let clause = Clause {
            op: Op::Exec,
            target: crate::dsl::ast::Target {
                kind: Kind::Exec,
                pattern: "git".into(),
                arg: Some("push".into()),
            },
            when: Expr::Label("T".into()),
            unless: Some(Cond::Target {
                negate: false,
                pattern: "host".into(),
            }),
            effect: Effect::Kill,
            source_index: 0,
        };
        assert_eq!(
            render_observe_clause(&clause),
            "notify exec \"git\" \"push\" if T unless target \"host\""
        );

        let file_clause = Clause {
            op: Op::Read,
            target: crate::dsl::ast::Target {
                kind: Kind::File,
                pattern: "**/.env".into(),
                arg: None,
            },
            when: Expr::True,
            unless: None,
            effect: Effect::Block,
            source_index: 0,
        };
        assert_eq!(
            render_observe_clause(&file_clause),
            "notify read file \"**/.env\""
        );
    }

    #[test]
    fn render_observe_dsl_prefixes_sources_and_xforms() {
        let parsed = dsl::ast::Policy {
            labels: vec!["T".into()],
            sources: vec![Source {
                label: "T".into(),
                kind: Kind::File,
                pattern: "**/.env".into(),
            }],
            rules: vec![],
            xforms: vec![],
        };
        let dsl_text = render_observe_dsl(&parsed);
        assert!(dsl_text.contains("source T = file \"**/.env\""));
    }

    #[test]
    fn lowered_clause_summary_reports_zero_then_matching_matchers() {
        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: vec![
                run_meta_c2("r", 0, "exec"),
                run_meta_c2("r", 0, "open"),
                run_meta_c2("r", 1, "write"),
                run_meta_c2("other", 0, "exec"),
            ],
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: std::collections::HashMap::new(),
        };
        assert_eq!(
            lowered_clause_summary(&compiled, "r", 5),
            "0 kernel matcher(s)"
        );
        let summary = lowered_clause_summary(&compiled, "r", 0);
        assert!(summary.contains("2 kernel matcher(s)"));
        assert!(summary.contains("rule_id(s) [0, 1]"));
        assert!(summary.contains("kernel_op(s) [exec, open]"));
    }
    #[test]
    fn op_name_maps_every_operation_to_its_kernel_name() {
        // `op_name` renders each `Op` variant to the short name the report
        // and support-detail paths use. No base or branch test pins this
        // mapping directly.
        assert_eq!(op_name(Op::Exec), "exec");
        assert_eq!(op_name(Op::Read), "read");
        assert_eq!(op_name(Op::Write), "write");
        assert_eq!(op_name(Op::Unlink), "unlink");
        assert_eq!(op_name(Op::Connect), "connect");
        assert_eq!(op_name(Op::Recv), "recv");
        assert_eq!(op_name(Op::Open), "open");
    }

    #[test]
    fn doctor_path_actplane_counts_only_a_missing_executable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin = tmp.path().join("actplane");
        std::fs::write(&bin, "#!/bin/sh\necho 'actplane 9.9.9'\n").expect("write probe");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let empty = tmp.path().join("empty");
        std::fs::create_dir(&empty).expect("empty dir");
        let original = std::env::var_os("PATH");

        unsafe { std::env::set_var("PATH", tmp.path()) };
        let mut problems = 0usize;
        doctor_path_actplane(&mut problems);
        assert_eq!(
            problems, 0,
            "an executable actplane on PATH is not a problem"
        );
        assert_eq!(
            command_version(&bin).as_deref(),
            Some("actplane 9.9.9"),
            "the reported version comes from `--version`"
        );

        // A binary whose `--version` fails is still present, so it is not counted.
        std::fs::write(&bin, "#!/bin/sh\nexit 3\n").expect("rewrite probe");
        let mut problems = 0usize;
        doctor_path_actplane(&mut problems);
        assert_eq!(problems, 0);
        assert_eq!(command_version(&bin), None);

        // Only a PATH with no actplane at all increments the problem count.
        unsafe { std::env::set_var("PATH", &empty) };
        let mut problems = 0usize;
        doctor_path_actplane(&mut problems);
        assert_eq!(problems, 1);

        match original {
            Some(value) => unsafe { std::env::set_var("PATH", value) },
            None => unsafe { std::env::remove_var("PATH") },
        }
    }
    #[test]
    fn policy_ref_for_cli_prefers_explicit_sources_over_auto_discovery() {
        // `policy_ref_for_cli` renders the policy ref for a CLI invocation:
        // an explicit policy path wins, else an inline `--rule` source, else
        // auto-discovery. No base or branch test pins this directly.
        let with_policy = PolicyInput {
            policy: Some(std::path::PathBuf::from("/tmp/web.dsl")),
            rule: Some("rule".to_string()),
            domain: None,
            run_as_root: false,
            internal_elevated: false,
        };
        assert_eq!(policy_ref_for_cli(&with_policy), "/tmp/web.dsl");

        let with_rule_only = PolicyInput {
            policy: None,
            rule: Some("rule".to_string()),
            domain: None,
            run_as_root: false,
            internal_elevated: false,
        };
        assert_eq!(policy_ref_for_cli(&with_rule_only), "--rule");

        let auto = PolicyInput {
            policy: None,
            rule: None,
            domain: None,
            run_as_root: false,
            internal_elevated: false,
        };
        assert_eq!(policy_ref_for_cli(&auto), "auto-discovered policy");
    }

    fn loaded_from_yaml(text: &str, path: Option<&str>) -> LoadedPolicy {
        LoadedPolicy {
            config: serde_yaml::from_str(text).unwrap(),
            root: PathBuf::from("."),
            path: path.map(PathBuf::from),
        }
    }

    #[test]
    fn render_policy_review_for_loaded_renders_and_propagates_errors() {
        let loaded = loaded_from_yaml(
            r#"
policy: |
  source SECRET = file "**/.env"
  rule no-exfil:
    block connect endpoint "*" if SECRET
    because "secret data must not leave the host"
"#,
            Some("policy.yaml"),
        );
        let review = render_policy_review_for_loaded(&loaded, None).unwrap();
        assert!(review.contains("ActPlane policy review"));
        assert!(review.contains("policy: policy.yaml"));
        assert!(review.contains("domain: none (flat policy)"));

        let err = render_policy_review_for_loaded(&loaded, Some("work")).unwrap_err();
        assert!(
            err.to_string()
                .contains("`--domain` requires a policy file")
        );

        let broken = loaded_from_yaml(r#"policy: "rule :""#, None);
        let err = render_policy_review_for_loaded(&broken, None).unwrap_err();
        assert!(err.to_string().contains("policy does not compile"));
    }

    #[test]
    fn render_check_explain_reports_domain_and_flat_modes() {
        let loaded = LoadedPolicy {
            config: crate::config::FileConfig::default(),
            root: PathBuf::from("."),
            path: Some(PathBuf::from("policy.dsl")),
        };
        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: std::collections::HashMap::new(),
        };
        let parsed = Policy {
            labels: Vec::new(),
            sources: Vec::new(),
            rules: Vec::new(),
            xforms: Vec::new(),
        };
        let with_domain = ResolvedPolicy {
            source: "cli".into(),
            domain: Some(DomainSummary {
                name: "work".into(),
                parent: Some("root".into()),
                disabled: Vec::new(),
                locked: vec!["owner-locked".into()],
                defaults: Vec::new(),
            }),
        };
        let out = render_check_explain(
            "policy.dsl",
            &loaded,
            &with_domain,
            &parsed,
            &compiled,
            "",
            false,
            false,
        );
        assert!(out.contains("domain: work"));
        assert!(out.contains("parent: root"));
        assert!(out.contains("policy rules: owner-locked"));
        assert!(out.contains("  - active LSMs: unknown"));
        assert!(out.contains("  - BPF-LSM pre-op block: unavailable"));
        assert!(!out.contains("ACTPLANE_FORCE_TRACEPOINT: set"));
        assert!(out.contains("rules: 0 DSL rule(s), 0 lowered kernel matcher(s)"));

        let flat = ResolvedPolicy {
            source: "cli".into(),
            domain: None,
        };
        let out = render_check_explain(
            "--rule", &loaded, &flat, &parsed, &compiled, "bpf", true, true,
        );
        assert!(out.contains("domain: none (flat policy)"));
        assert!(out.contains("  - BPF-LSM pre-op block: available"));
        assert!(out.contains("ACTPLANE_FORCE_TRACEPOINT: set"));
    }

    fn evidence_with_annotations() -> RolloutEvidence {
        RolloutEvidence {
            event_paths: Vec::new(),
            annotation_paths: vec![PathBuf::from("ann.jsonl")],
            total_events: 0,
            total_annotations: 0,
            ignored_lines: 0,
            ignored_annotations: 0,
            warnings: Vec::new(),
            clauses: BTreeMap::new(),
        }
    }

    fn observation_with(pairs: &[(&str, usize)]) -> ClauseObservation {
        let mut observation = ClauseObservation::default();
        for (key, value) in pairs {
            observation.annotations.insert((*key).to_string(), *value);
        }
        observation
    }

    #[test]
    fn annotation_backed_promotion_note_returns_none_without_paths() {
        let evidence = RolloutEvidence {
            annotation_paths: Vec::new(),
            ..evidence_with_annotations()
        };
        assert_eq!(
            annotation_backed_promotion_note(&evidence, None, Effect::Block),
            None
        );
    }

    #[test]
    fn annotation_backed_promotion_note_flags_negative_classes() {
        let evidence = evidence_with_annotations();
        let missing = annotation_backed_promotion_note(&evidence, None, Effect::Block).unwrap();
        assert!(missing.contains("no annotations for this clause"));
        let empty = observation_with(&[]);
        assert!(
            annotation_backed_promotion_note(&evidence, Some(&empty), Effect::Block)
                .unwrap()
                .contains("no annotations for this clause")
        );
        let negatives = observation_with(&[("false_positive", 2), ("allowed", 1)]);
        let note =
            annotation_backed_promotion_note(&evidence, Some(&negatives), Effect::Block).unwrap();
        assert!(note.contains("do not promote yet"));
        assert!(note.contains("false_positive=2"));
        assert!(note.contains("allowed=1"));
        let review = observation_with(&[("needs_review", 3)]);
        assert!(
            annotation_backed_promotion_note(&evidence, Some(&review), Effect::Block)
                .unwrap()
                .contains("3 annotated example(s) still need review")
        );
    }

    #[test]
    fn annotation_backed_promotion_note_suggests_kill_vs_block_promotion() {
        let evidence = evidence_with_annotations();
        let positives = observation_with(&[("true_positive", 2)]);
        let kill =
            annotation_backed_promotion_note(&evidence, Some(&positives), Effect::Kill).unwrap();
        assert!(kill.contains("limited kill promotion"));
        let block =
            annotation_backed_promotion_note(&evidence, Some(&positives), Effect::Block).unwrap();
        assert!(block.contains("limited promotion"));
        let unrecognized = observation_with(&[("other", 1)]);
        assert!(
            annotation_backed_promotion_note(&evidence, Some(&unrecognized), Effect::Block)
                .unwrap()
                .contains("no recognized promotion class")
        );
    }

    fn detail(supported: bool, reason: &str) -> SupportDetail {
        SupportDetail {
            supported,
            status: if supported {
                "supported"
            } else {
                "unsupported"
            },
            mode: "none",
            pre_op: false,
            reason: reason.to_string(),
            limitations: Vec::new(),
        }
    }

    fn clause_with_effect(effect: Effect) -> Clause {
        Clause {
            op: Op::Exec,
            target: crate::dsl::ast::Target {
                kind: Kind::Exec,
                pattern: "git".into(),
                arg: None,
            },
            when: Expr::True,
            unless: None,
            effect,
            source_index: 0,
        }
    }

    #[test]
    fn rollout_recommendation_notify_branches_on_block_support() {
        let clause = clause_with_effect(Effect::Notify);
        let (_, next, _) =
            rollout_recommendation(&clause, &detail(true, "ok"), &detail(true, "ok"));
        assert!(next.contains("eligible for later block"));
        let (_, next, _) =
            rollout_recommendation(&clause, &detail(true, "ok"), &detail(false, "argv only"));
        assert!(next.contains("do not promote to block yet: argv only"));
    }

    #[test]
    fn rollout_recommendation_block_and_kill_branches() {
        let block = clause_with_effect(Effect::Block);
        let (_, ok_next, _) =
            rollout_recommendation(&block, &detail(true, "ok"), &detail(true, "ok"));
        assert!(ok_next.contains("eligible for block"));
        let (_, bad_next, _) =
            rollout_recommendation(&block, &detail(false, "no lsm"), &detail(false, "no lsm"));
        assert!(bad_next.contains("do not deploy as block yet: no lsm"));
        let kill = clause_with_effect(Effect::Kill);
        let (_, kill_next, caveat) =
            rollout_recommendation(&kill, &detail(true, "ok"), &detail(true, "ok"));
        assert!(kill_next.contains("promote to kill only after manual review"));
        assert!(caveat.contains("syscall may already have completed"));
    }
    #[test]
    fn push_evidence_warning_caps_warnings_with_a_sentinel() {
        // `push_evidence_warning` appends to `evidence.warnings` while fewer
        // than 8 are stored. At exactly 8, the next call appends a single
        // "additional ... omitted" sentinel instead of the warning; further
        // calls are no-ops. No base or branch test pins this saturating
        // accessor directly.
        let mut evidence = RolloutEvidence {
            event_paths: Vec::new(),
            annotation_paths: Vec::new(),
            total_events: 0,
            total_annotations: 0,
            ignored_lines: 0,
            ignored_annotations: 0,
            warnings: Vec::new(),
            clauses: BTreeMap::new(),
        };

        // The first 8 warnings are all stored verbatim.
        for i in 0..8 {
            push_evidence_warning(&mut evidence, format!("warning-{i}"));
        }
        assert_eq!(
            evidence.warnings,
            vec![
                "warning-0",
                "warning-1",
                "warning-2",
                "warning-3",
                "warning-4",
                "warning-5",
                "warning-6",
                "warning-7",
            ]
        );

        // The 9th call substitutes a sentinel for the warning it was given.
        push_evidence_warning(&mut evidence, "warning-8".to_string());
        assert_eq!(
            evidence.warnings,
            vec![
                "warning-0",
                "warning-1",
                "warning-2",
                "warning-3",
                "warning-4",
                "warning-5",
                "warning-6",
                "warning-7",
                "additional rollout event-log warnings omitted",
            ]
        );
        assert!(!evidence.warnings.contains(&"warning-8".to_string()));

        // Further calls are no-ops once the sentinel is in place.
        let before = evidence.warnings.len();
        push_evidence_warning(&mut evidence, "warning-9".to_string());
        assert_eq!(evidence.warnings.len(), before);
    }
    #[test]
    fn render_dsl_cond_escapes_every_variant_through_dsl_literal() {
        // `render_dsl_cond` renders a `Cond` to a DSL string, escaping every
        // literal through `dsl_literal` (unlike `cond_summary`, which uses
        // the raw text), and recurses for the `After` `since` events. No
        // base or branch test pins this renderer directly.
        assert_eq!(
            render_dsl_cond(&Cond::Target {
                negate: false,
                pattern: "out.txt".into()
            }),
            "target \"out.txt\""
        );
        assert_eq!(
            render_dsl_cond(&Cond::Target {
                negate: true,
                pattern: "out.txt".into()
            }),
            "target not \"out.txt\""
        );
        assert_eq!(
            render_dsl_cond(&Cond::LineageIncludes {
                exec: "agent".into()
            }),
            "lineage-includes exec \"agent\""
        );

        // `After` with an exit stamp and no `since`.
        assert_eq!(
            render_dsl_cond(&Cond::After {
                gate_op: Op::Exec,
                gate_pattern: "agent".into(),
                gate_exit: Some(0),
                since: Vec::new(),
            }),
            "after exec \"agent\" exits 0"
        );

        // `After` with two `since` events, escaped through `dsl_literal`.
        assert_eq!(
            render_dsl_cond(&Cond::After {
                gate_op: Op::Open,
                gate_pattern: "policy.dsl".into(),
                gate_exit: None,
                since: vec![
                    (Op::Exec, "agent".into(), None),
                    (Op::Connect, "10.0.0.0/8".into(), Some("r".into())),
                ],
            }),
            "after open \"policy.dsl\" since exec \"agent\" or connect \"10.0.0.0/8\" \"r\""
        );
    }
    #[test]
    fn render_dsl_event_escapes_pattern_and_arg_through_dsl_literal() {
        // `render_dsl_event` renders `<op> "pattern" ["arg"]` for a DSL event
        // source, escaping the pattern and argument through `dsl_literal`
        // (so newlines become spaces and double quotes become single quotes),
        // unlike `event_summary` which uses the raw text. No base or branch
        // test pins this renderer directly.
        assert_eq!(
            render_dsl_event(Op::Open, "policy.dsl", None),
            "open \"policy.dsl\""
        );
        assert_eq!(
            render_dsl_event(Op::Open, "policy.dsl", Some("r")),
            "open \"policy.dsl\" \"r\""
        );
        // A double quote in the pattern becomes a single quote.
        assert_eq!(
            render_dsl_event(Op::Exec, "say \"hi\"", None),
            "exec \"say 'hi'\""
        );
        // A newline in the argument is flattened to a space.
        assert_eq!(
            render_dsl_event(Op::Exec, "agent", Some("a\nb")),
            "exec \"agent\" \"a b\""
        );
    }
    #[test]
    fn render_dsl_expr_joins_composites_without_parentheses() {
        // `render_dsl_expr` renders an `Expr` to a DSL string, unlike
        // `expr_summary` which parenthesizes composites: `True` -> "true",
        // `Label` -> the label, `Not` -> "not <label>", and `And` / `Or`
        // join their operands with " and " / " or " without parentheses.
        // No base or branch test pins this renderer directly.
        assert_eq!(render_dsl_expr(&Expr::True), "true");
        assert_eq!(render_dsl_expr(&Expr::Label("repo".into())), "repo");
        assert_eq!(render_dsl_expr(&Expr::Not("leak".into())), "not leak");
        assert_eq!(
            render_dsl_expr(&Expr::And(
                Box::new(Expr::Label("repo".into())),
                Box::new(Expr::Label("agent".into()))
            )),
            "repo and agent"
        );
        assert_eq!(
            render_dsl_expr(&Expr::Or(
                Box::new(Expr::Label("repo".into())),
                Box::new(Expr::Not("leak".into()))
            )),
            "repo or not leak"
        );
        // A nested composite flattens without introducing parentheses.
        assert_eq!(
            render_dsl_expr(&Expr::And(
                Box::new(Expr::And(
                    Box::new(Expr::Label("a".into())),
                    Box::new(Expr::Label("b".into()))
                )),
                Box::new(Expr::Label("c".into()))
            )),
            "a and b and c"
        );
    }

    #[test]
    fn render_check_explain_reports_flat_policy_review() {
        let src = concat!(
            "source COMMAND = exec \"**\"\n",
            "rule guard:\n",
            "  notify exec \"/bin/true\" if COMMAND\n",
            "  because \"b\"\n",
        );
        let parsed = dsl::parse::parse(src).expect("parse");
        let compiled = dsl::compile_str(src).expect("compile");
        let resolved = ResolvedPolicy {
            source: src.to_string(),
            domain: None,
        };
        let loaded = LoadedPolicy {
            config: crate::config::FileConfig::default(),
            root: PathBuf::new(),
            path: None,
        };

        let out = render_check_explain(
            "--rule", &loaded, &resolved, &parsed, &compiled, "", false, false,
        );
        assert!(out.contains("ActPlane policy review"), "{out}");
        assert!(out.contains("policy: --rule"), "{out}");
        assert!(out.contains("domain: none (flat policy)"), "{out}");
        assert!(
            out.contains("rules: 1 DSL rule(s), 1 lowered kernel matcher(s)"),
            "{out}"
        );
        assert!(out.contains("active LSMs: unknown"), "{out}");
        assert!(out.contains("- BPF-LSM pre-op block: unavailable"), "{out}");
        assert!(out.contains("COMMAND = 0x1"), "{out}");
        assert!(out.contains("1. rule guard"), "{out}");
        assert!(
            out.contains("clause 1: notify exec \"/bin/true\" if COMMAND"),
            "{out}"
        );
        assert!(out.contains("warnings: none"), "{out}");
    }
    #[test]
    fn render_observe_clause_joins_target_when_and_unless() {
        // `render_observe_clause` renders one observe-policy clause as
        // `notify <op> [<kind> ]"<pattern>"[ "<arg>"] [if <expr>] [unless
        // <cond>]`. The `Exec` target renders its optional argument, while
        // `File` / `Endpoint` targets render only the pattern (qualified by
        // `kind_name`). `when` and `unless` are delegated to `render_dsl_expr`
        // and `render_dsl_cond`. No base or branch test pins this renderer
        // directly.
        use crate::dsl::ast::Target;

        let clause =
            |kind: Kind, pattern: &str, arg: Option<String>, when: Expr, unless: Option<Cond>| {
                Clause {
                    op: Op::Open,
                    target: Target {
                        kind,
                        pattern: pattern.to_string(),
                        arg,
                    },
                    when,
                    unless,
                    effect: Effect::Notify,
                    source_index: 0,
                }
            };

        // A bare Exec target with no argument, gate, or condition.
        assert_eq!(
            render_observe_clause(&clause(Kind::Exec, "agent", None, Expr::True, None)),
            "notify open \"agent\""
        );

        // A File target renders its kind qualifier but not the argument.
        assert_eq!(
            render_observe_clause(&clause(
                Kind::File,
                "out.txt",
                Some("w".into()),
                Expr::And(
                    Box::new(Expr::Label("repo".into())),
                    Box::new(Expr::Label("agent".into()))
                ),
                None
            )),
            "notify open file \"out.txt\" if repo and agent"
        );

        // An Endpoint target with a negated condition.
        assert_eq!(
            render_observe_clause(&clause(
                Kind::Endpoint,
                "10.0.0.0/8",
                None,
                Expr::True,
                Some(Cond::After {
                    gate_op: Op::Open,
                    gate_pattern: "policy.dsl".into(),
                    gate_exit: None,
                    since: Vec::new(),
                })
            )),
            "notify open endpoint \"10.0.0.0/8\" unless after open \"policy.dsl\""
        );
    }
    #[test]
    fn render_observe_dsl_renders_sources_xforms_and_rules() {
        // `render_observe_dsl` renders a full observe policy: each `source`,
        // each xform (`endorse` / `declassify`), and each `rule` (its
        // clauses via `render_observe_clause` plus the trailing `because`
        // reason, falling back to a default when empty). No base or branch
        // test pins this top-level renderer directly.
        use crate::dsl::ast::{Clause, Source, Xform};

        let clause = Clause {
            op: Op::Open,
            target: crate::dsl::ast::Target {
                kind: Kind::Exec,
                pattern: "agent".to_string(),
                arg: None,
            },
            when: Expr::True,
            unless: None,
            effect: Effect::Notify,
            source_index: 0,
        };
        let policy = Policy {
            labels: Vec::new(),
            sources: vec![Source {
                label: "agent".to_string(),
                kind: Kind::Exec,
                pattern: "agent".to_string(),
            }],
            xforms: vec![Xform {
                endorse: true,
                label: "repo".to_string(),
                gate: "agent".to_string(),
            }],
            rules: vec![crate::dsl::ast::Rule {
                name: "rule1".to_string(),
                clauses: vec![clause],
                reason: String::new(),
            }],
        };
        assert_eq!(
            render_observe_dsl(&policy),
            "source agent = exec \"agent\"\n\nendorse repo by exec \"agent\"\n\nrule rule1:\n  \
             notify open \"agent\"\n  because \"Observe-first rollout for original policy.\"\n\n"
        );

        // An empty policy renders as the empty string.
        let empty = Policy {
            labels: Vec::new(),
            sources: Vec::new(),
            xforms: Vec::new(),
            rules: Vec::new(),
        };
        assert_eq!(render_observe_dsl(&empty), "");

        // A non-empty reason is appended after the default phrase.
        let mut with_reason = policy.clone();
        with_reason.rules[0].reason = "keep exfil off".to_string();
        assert!(
            render_observe_dsl(&with_reason)
                .contains("because \"Observe-first rollout for original policy: keep exfil off\"")
        );
    }

    const BLOCK_POLICY: &str = concat!(
        "source COMMAND = exec \"**\"\n",
        "rule guard:\n",
        "  block open file \"/etc/secret\" if COMMAND\n",
        "  because \"deny secret reads\"\n",
    );

    #[test]
    fn render_rollout_artifacts_downgrades_effects_to_observe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_path = dir.path().join("actplane.yaml");
        std::fs::write(
            &policy_path,
            format!("version: 1\npolicy: |\n{}", indent_policy(BLOCK_POLICY)),
        )
        .expect("write policy");
        let input = PolicyInput {
            policy: Some(policy_path.clone()),
            ..PolicyInput::default()
        };

        let artifacts = render_rollout_artifacts(&input, &[], &[]).expect("artifacts");

        assert!(
            artifacts.plan.starts_with("ActPlane rollout plan\n"),
            "{}",
            artifacts.plan
        );
        assert!(
            artifacts
                .plan
                .contains(&format!("policy: {}", policy_path.display())),
            "{}",
            artifacts.plan
        );
        assert!(
            artifacts.plan.contains("rules: 1 DSL rule(s)"),
            "{}",
            artifacts.plan
        );
        assert!(
            artifacts
                .plan
                .contains("clause 1: block open file \"/etc/secret\" if COMMAND"),
            "{}",
            artifacts.plan
        );
        assert!(
            artifacts.plan.contains("bpf_lsm_inactive_for_block: guard"),
            "{}",
            artifacts.plan
        );

        assert!(
            artifacts
                .observe_policy_yaml
                .contains("# ActPlane observe-first policy generated from"),
            "{}",
            artifacts.observe_policy_yaml
        );
        assert!(artifacts.observe_policy_yaml.contains("policy: |"));
        assert!(
            artifacts.observe_policy_yaml.contains("notify open file"),
            "{}",
            artifacts.observe_policy_yaml
        );
        assert!(
            !artifacts.observe_policy_yaml.contains("block open file"),
            "{}",
            artifacts.observe_policy_yaml
        );
    }

    fn indent_policy(policy: &str) -> String {
        policy
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
    #[test]
    fn normalize_rollout_classification_maps_alias_spelling_variants() {
        // `normalize_rollout_classification` trims, lowercases, and folds a
        // set of spelling aliases into one of five canonical rollout
        // classes. No base or branch test pins this normalizer directly.
        assert_eq!(
            normalize_rollout_classification("true-positive"),
            "true_positive"
        );
        assert_eq!(
            normalize_rollout_classification("wanted_kill"),
            "true_positive"
        );
        assert_eq!(normalize_rollout_classification("fp"), "false_positive");
        assert_eq!(normalize_rollout_classification("benign"), "allowed");
        assert_eq!(normalize_rollout_classification("noise"), "noise");
        assert_eq!(
            normalize_rollout_classification("needs-review"),
            "needs_review"
        );

        // Whitespace and case are tolerated before matching.
        assert_eq!(normalize_rollout_classification("  FP "), "false_positive");
        assert_eq!(normalize_rollout_classification("Expected"), "allowed");

        // Unknown tokens fall through to needs_review.
        assert_eq!(normalize_rollout_classification("bogus"), "needs_review");
        assert_eq!(normalize_rollout_classification(""), "needs_review");
    }
    #[test]
    fn rollout_clause_signatures_indexes_one_signature_per_clause() {
        // `rollout_clause_signatures` builds a `BTreeMap` keyed by
        // `(rule name, source index)` holding one `ClauseEventSignature` per
        // clause in the policy, where the signature records the clause op,
        // target kind, target pattern, optional target arg, the rendered
        // observe-clause text, and the FNV-1a hash of that text. No base or
        // branch test pins this indexer directly.
        use crate::dsl::ast::{Rule, Target};

        let policy = Policy {
            labels: vec!["repo".to_string()],
            sources: vec![Source {
                label: "repo".to_string(),
                kind: Kind::File,
                pattern: "/repo".to_string(),
            }],
            rules: vec![
                Rule {
                    name: "guard".to_string(),
                    clauses: vec![
                        Clause {
                            op: Op::Write,
                            target: Target {
                                kind: Kind::File,
                                pattern: "out.txt".to_string(),
                                arg: None,
                            },
                            when: Expr::True,
                            unless: None,
                            effect: Effect::Notify,
                            source_index: 0,
                        },
                        Clause {
                            op: Op::Connect,
                            target: Target {
                                kind: Kind::Endpoint,
                                pattern: "10.0.0.7".to_string(),
                                arg: None,
                            },
                            when: Expr::Label("repo".to_string()),
                            unless: None,
                            effect: Effect::Notify,
                            source_index: 1,
                        },
                    ],
                    reason: "guard the repo".to_string(),
                },
                Rule {
                    name: "trace".to_string(),
                    clauses: vec![Clause {
                        op: Op::Exec,
                        target: Target {
                            kind: Kind::Exec,
                            pattern: "python3".to_string(),
                            arg: Some("run".to_string()),
                        },
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Notify,
                        source_index: 0,
                    }],
                    reason: "trace exec".to_string(),
                },
            ],
            xforms: Vec::new(),
        };

        let signatures = rollout_clause_signatures(&policy);
        // One entry per clause, keyed by (rule name, source index).
        assert_eq!(signatures.len(), 3);

        let file_clause = signatures
            .get(&("guard".to_string(), 0))
            .expect("guard clause 0 present");
        assert_eq!(file_clause.clause_op, "write");
        assert_eq!(file_clause.target_kind, "file");
        assert_eq!(file_clause.target_pattern, "out.txt");
        assert_eq!(file_clause.target_arg, None);
        // The observe-clause text is prefixed with "  " and uses the fixed
        // "notify" action verb; the hash is the FNV-1a of that same text.
        assert_eq!(file_clause.clause_text, "  notify write file \"out.txt\"");
        assert_eq!(
            file_clause.clause_hash,
            crate::audit::policy_hash(&file_clause.clause_text)
        );

        let endpoint_clause = signatures
            .get(&("guard".to_string(), 1))
            .expect("guard clause 1 present");
        assert_eq!(endpoint_clause.clause_op, "connect");
        assert_eq!(endpoint_clause.target_kind, "endpoint");
        assert_eq!(endpoint_clause.target_pattern, "10.0.0.7");
        assert_eq!(
            endpoint_clause.clause_text,
            "  notify connect endpoint \"10.0.0.7\" if repo"
        );
        assert_eq!(
            endpoint_clause.clause_hash,
            crate::audit::policy_hash(&endpoint_clause.clause_text)
        );

        let exec_clause = signatures
            .get(&("trace".to_string(), 0))
            .expect("trace clause 0 present");
        assert_eq!(exec_clause.clause_op, "exec");
        assert_eq!(exec_clause.target_kind, "exec");
        assert_eq!(exec_clause.target_pattern, "python3");
        assert_eq!(exec_clause.target_arg, Some("run".to_string()));
        assert_eq!(exec_clause.clause_text, "  notify exec \"python3\" \"run\"");
        assert_eq!(
            exec_clause.clause_hash,
            crate::audit::policy_hash(&exec_clause.clause_text)
        );
    }

    const OBSERVE_POLICY: &str = concat!(
        "source COMMAND = exec \"**\"\n",
        "rule watch:\n",
        "  notify read file \"/etc/secret\" if COMMAND\n",
        "  because \"observe reads\"\n",
    );

    #[test]
    fn normalize_rollout_classification_folds_aliases() {
        assert_eq!(normalize_rollout_classification("TP"), "true_positive");
        assert_eq!(
            normalize_rollout_classification("true-positive"),
            "true_positive"
        );
        assert_eq!(
            normalize_rollout_classification("wanted_kill"),
            "true_positive"
        );
        assert_eq!(normalize_rollout_classification(" FP "), "false_positive");
        assert_eq!(normalize_rollout_classification("benign"), "allowed");
        assert_eq!(normalize_rollout_classification("irrelevant"), "noise");
        assert_eq!(
            normalize_rollout_classification("needs-review"),
            "needs_review"
        );
        assert_eq!(normalize_rollout_classification("???"), "needs_review");
    }

    #[test]
    fn event_rule_matches_signature_requires_exact_metadata() {
        let parsed = dsl::parse::parse(OBSERVE_POLICY).expect("parse");
        let signatures = rollout_clause_signatures(&parsed);
        let signature = signatures
            .get(&("watch".to_string(), 0))
            .expect("signature");
        let matching = json!({
            "rule": {
                "effect": "notify",
                "clause_op": signature.clause_op,
                "target_kind": signature.target_kind,
                "target_pattern": signature.target_pattern,
                "target_arg": signature.target_arg,
                "clause_hash": signature.clause_hash,
            }
        });
        assert!(event_rule_matches_signature(&matching, signature));

        let stale = json!({
            "rule": {
                "effect": "notify",
                "clause_op": signature.clause_op,
                "target_kind": signature.target_kind,
                "target_pattern": "/etc/other",
                "clause_hash": signature.clause_hash,
            }
        });
        assert!(!event_rule_matches_signature(&stale, signature));

        let enforced = json!({
            "rule": {
                "effect": "block",
                "clause_op": signature.clause_op,
                "target_kind": signature.target_kind,
                "target_pattern": signature.target_pattern,
                "clause_hash": signature.clause_hash,
            }
        });
        assert!(!event_rule_matches_signature(&enforced, signature));

        assert!(!event_rule_matches_signature(&json!({}), signature));
    }

    #[test]
    fn load_rollout_evidence_classifies_events_and_annotations() {
        let parsed = dsl::parse::parse(OBSERVE_POLICY).expect("parse");
        let signatures = rollout_clause_signatures(&parsed);
        let signature = signatures
            .get(&("watch".to_string(), 0))
            .expect("signature");
        let dir = tempfile::tempdir().expect("tempdir");
        let events = dir.path().join("events.jsonl");
        let annotations = dir.path().join("annotations.jsonl");
        std::fs::write(
            &events,
            format!(
                concat!(
                    "{{\"schema\":\"actplane.violation.v1\",\"event\":\"taint_violation\",",
                    "\"action\":\"report\",\"effect\":\"notify\",",
                    "\"rule\":{{\"name\":\"watch\",\"clause_source_index\":0,",
                    "\"effect\":\"notify\",\"clause_op\":\"{}\",\"target_kind\":\"{}\",",
                    "\"target_pattern\":\"{}\",\"clause_hash\":\"{}\"}},",
                    "\"target\":\"/etc/secret\",\"domain_id\":3}}\n",
                    "not-json\n",
                    "{{\"schema\":\"actplane.violation.v1\",\"event\":\"taint_violation\",",
                    "\"action\":\"block\",\"effect\":\"block\",\"rule\":{{\"name\":\"watch\"}}}}\n",
                ),
                signature.clause_op,
                signature.target_kind,
                signature.target_pattern,
                signature.clause_hash,
            ),
        )
        .expect("write events");
        std::fs::write(
            &annotations,
            format!(
                concat!(
                    "{{\"schema\":\"actplane.rollout.annotation.v1\",\"class\":\"TP\",",
                    "\"rule\":{{\"name\":\"watch\",\"clause_source_index\":0,",
                    "\"effect\":\"notify\",\"clause_op\":\"{}\",\"target_kind\":\"{}\",",
                    "\"target_pattern\":\"{}\",\"clause_hash\":\"{}\"}},",
                    "\"note\":\"expected read\"}}\n",
                    "{{\"schema\":\"actplane.rollout.annotation.v1\"}}\n",
                ),
                signature.clause_op,
                signature.target_kind,
                signature.target_pattern,
                signature.clause_hash,
            ),
        )
        .expect("write annotations");

        let evidence = load_rollout_evidence(&[events.clone()], &[annotations.clone()], &parsed)
            .expect("load");
        assert_eq!(evidence.total_events, 1);
        assert_eq!(evidence.total_annotations, 1);
        assert_eq!(evidence.ignored_lines, 2);
        assert_eq!(evidence.ignored_annotations, 1);
        assert_eq!(evidence.event_paths, vec![events]);
        assert_eq!(evidence.annotation_paths, vec![annotations]);
        assert!(
            evidence.warnings.iter().any(|w| w.contains("is not JSON")),
            "{:?}",
            evidence.warnings
        );

        let observation = evidence
            .clauses
            .get(&("watch".to_string(), 0))
            .expect("observation");
        assert_eq!(observation.count, 1);
        assert_eq!(observation.actions.get("report"), Some(&1));
        assert_eq!(observation.targets, vec!["/etc/secret".to_string()]);
        assert_eq!(observation.domains.get("3"), Some(&1));
        assert_eq!(observation.annotations.get("true_positive"), Some(&1));
        assert_eq!(
            observation.annotation_notes,
            vec!["expected read".to_string()]
        );
    }
    #[test]
    fn render_rollout_plan_reports_host_support_and_per_clause_stages() {
        // `render_rollout_plan` renders a host/backend support summary and a
        // per-clause observe/promote/risk recommendation for a rollout. No base
        // or branch test pins this formatter directly.
        use crate::dsl::ast::{Rule, Target};
        use std::collections::HashMap;

        let parsed = Policy {
            labels: Vec::new(),
            sources: vec![Source {
                label: "e1".to_string(),
                kind: Kind::Exec,
                pattern: "python3".to_string(),
            }],
            rules: vec![Rule {
                name: "guard".to_string(),
                clauses: vec![Clause {
                    op: Op::Exec,
                    target: Target {
                        kind: Kind::Exec,
                        pattern: "python3".to_string(),
                        arg: None,
                    },
                    when: Expr::True,
                    unless: None,
                    effect: Effect::Block,
                    source_index: 0,
                }],
                reason: "guard exec".to_string(),
            }],
            xforms: Vec::new(),
        };
        let no_domain = ResolvedPolicy {
            source: "policy.dsl".to_string(),
            domain: None,
        };
        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };
        let evidence = RolloutEvidence::default();

        let plan = render_rollout_plan(
            "policy.dsl",
            &no_domain,
            &parsed,
            &compiled,
            "lockdown,capability,bpf",
            true,
            false,
            &evidence,
        );

        // Header + host/backend block, pinned line by line.
        assert!(plan.contains("ActPlane rollout plan\n"));
        assert!(plan.contains("policy: policy.dsl\n"));
        assert!(plan.contains("domain: none (flat policy)\n"));
        assert!(plan.contains("rules: 1 DSL rule(s), 0 lowered kernel matcher(s)\n"));
        assert!(plan.contains("\nhost/backend:\n"));
        assert!(plan.contains("  - active LSMs: lockdown,capability,bpf\n"));
        assert!(plan.contains("  - BPF-LSM pre-op block: available\n"));
        // No evidence supplied: the observe-evidence section says so and the
        // per-clause observation stays silent.
        assert!(plan.contains("\nobserve evidence:\n"));
        assert!(plan.contains(
            "  - no event or annotation log supplied; pass --events .actplane/events.jsonl after an observe run and --annotations <annotations.jsonl> after classification"
        ));
        // Recommended sequence is always emitted.
        assert!(plan.contains("\nrecommended rollout sequence:\n"));
        assert!(plan.contains(
            "  1. Static review: run `actplane compile --explain --report-out <review.txt>` and inspect warnings."
        ));
        // Per-clause recommendation for a bpf-lsm block exec clause.
        assert!(plan.contains("  1. rule guard\n     reason: guard exec\n"));
        assert!(plan.contains("     clause 1: block exec \"python3\" if true\n"));
        assert!(plan.contains(
            "       current: block; supported; timing=pre-operation denial before syscall commit\n"
        ));
        assert!(plan.contains(
            "       observe stage: use notify-only observe policy for this clause before enforcement\n"
        ));
        assert!(plan.contains(
            "       promotion: eligible for block after observe period and false-positive review\n"
        ));
        assert!(plan.contains(
            "       residual risk: block denies before syscall commit only on hosts with matching BPF-LSM and hook profile\n"
        ));
        // With an active bpf-lsm and a supported block exec, no static warnings.
        assert!(!plan.contains("static warnings to resolve before promotion"));
    }
    #[test]
    fn rollout_recommendation_selects_the_effect_and_support_branch() {
        // `rollout_recommendation` returns a 3-tuple (observe note, readiness
        // note, promotion rationale) that depends on the clause `effect` and
        // whether the current / block backend is supported. No base or branch
        // test pins this recommender directly.
        use crate::dsl::ast::Target;

        let clause = |effect: Effect| Clause {
            op: Op::Open,
            target: Target {
                kind: Kind::File,
                pattern: "out.txt".to_string(),
                arg: None,
            },
            when: Expr::True,
            unless: None,
            effect,
            source_index: 0,
        };
        let detail = |supported: bool, reason: &str| SupportDetail {
            supported,
            status: "ok",
            mode: "bpf-lsm",
            pre_op: true,
            reason: reason.to_string(),
            limitations: Vec::new(),
        };

        // Notify + block backend supported: collect a baseline, then allow a
        // later promotion.
        let (observe, ready, why) = rollout_recommendation(
            &clause(Effect::Notify),
            &detail(true, "ok"),
            &detail(true, "ok"),
        );
        assert_eq!(observe, "already notify; collect baseline event volume");
        assert_eq!(
            ready,
            "eligible for later block if the observed events are all unwanted"
        );
        assert_eq!(
            why,
            "promotion changes timing from post-event report to pre-operation denial"
        );

        // Notify + block backend unsupported: keep observe, and name the reason.
        let (observe, ready, why) = rollout_recommendation(
            &clause(Effect::Notify),
            &detail(true, "ok"),
            &detail(false, "no bpf-lsm"),
        );
        assert_eq!(observe, "already notify; keep as observe/report-only");
        assert_eq!(ready, "do not promote to block yet: no bpf-lsm");
        assert_eq!(why, "promotion would overclaim backend support");

        // Block + current backend supported: observe first, then block is
        // eligible.
        let (observe, ready, why) = rollout_recommendation(
            &clause(Effect::Block),
            &detail(true, "ok"),
            &detail(true, "ok"),
        );
        assert_eq!(
            observe,
            "use notify-only observe policy for this clause before enforcement"
        );
        assert_eq!(
            ready,
            "eligible for block after observe period and false-positive review"
        );
        assert_eq!(
            why,
            "block denies before syscall commit only on hosts with matching BPF-LSM and hook profile"
        );

        // Block + current backend unsupported: do not deploy as block yet.
        let (observe, ready, why) = rollout_recommendation(
            &clause(Effect::Block),
            &detail(false, "no bpf-lsm"),
            &detail(false, "no bpf-lsm"),
        );
        assert_eq!(
            observe,
            "use notify-only observe policy for this clause before enforcement"
        );
        assert_eq!(ready, "do not deploy as block yet: no bpf-lsm");
        assert_eq!(
            why,
            "the declared block effect is not enforceable by the current backend selection"
        );

        // Kill is constant regardless of backend support.
        let (observe, ready, why) = rollout_recommendation(
            &clause(Effect::Kill),
            &detail(true, "ok"),
            &detail(true, "ok"),
        );
        assert_eq!(
            observe,
            "use notify-only observe policy for this clause before enforcement"
        );
        assert_eq!(
            ready,
            "promote to kill only after manual review; kill is post-event termination"
        );
        assert_eq!(
            why,
            "the triggering syscall may already have completed before termination"
        );
    }
    #[test]
    fn rule_meta_json_renders_base_fields_and_source_provenance() {
        // `rule_meta_json` renders one JSON object per `RuleMeta`: the base rule
        // fields, and the source-provenance block (source ref, line spans, the
        // FNV-1a policy/clause hashes, clause text, binding mode, and the
        // derived immutable flag) when the meta carries a source. No base or
        // branch test pins this serializer directly.
        use crate::dsl::{RuleMeta, RuleSourceMeta};
        use std::collections::HashMap;

        let meta = vec![
            RuleMeta {
                name: "guard".to_string(),
                reason: "guard exec".to_string(),
                effect: Effect::Notify,
                ops: vec!["exec".to_string()],
                clause_op: "exec".to_string(),
                kernel_op: "execve".to_string(),
                target_kind: Kind::Exec,
                target_pattern: "python3".to_string(),
                target_arg: None,
                clause_source_index: 0,
                source: None,
            },
            RuleMeta {
                name: "egress".to_string(),
                reason: "guard egress".to_string(),
                effect: Effect::Block,
                ops: vec!["connect".to_string()],
                clause_op: "connect".to_string(),
                kernel_op: "connect".to_string(),
                target_kind: Kind::Endpoint,
                target_pattern: "10.0.0.7".to_string(),
                target_arg: None,
                clause_source_index: 1,
                source: Some(RuleSourceMeta {
                    source_ref: "policy.dsl".to_string(),
                    binding_mode: Some("locked".to_string()),
                    start_line: 5,
                    end_line: 9,
                    text: "rule egress block connect 10.0.0.7\n".to_string(),
                    clause_start_line: Some(6),
                    clause_end_line: Some(8),
                    clause_text: Some("block connect 10.0.0.7".to_string()),
                }),
            },
        ];
        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta,
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        let got = rule_meta_json(&compiled);

        // Rule 0 has no source: only the base fields are rendered.
        assert_eq!(
            got[0],
            json!({
                "rule_id": 0,
                "name": "guard",
                "effect": "notify",
                "ops": ["exec"],
                "clause_op": "exec",
                "clause_source_index": 0,
                "kernel_op": "execve",
                "target_kind": "exec",
                "target_pattern": "python3",
                "target_arg": null,
                "reason": "guard exec",
            })
        );

        // Rule 1 carries a source: the base fields plus the source-provenance
        // block. The source/clause hashes are asserted against the same FNV-1a
        // routine the serializer calls, so the test stays hash-invariant.
        let expected = json!({
            "rule_id": 1,
            "name": "egress",
            "effect": "block",
            "ops": ["connect"],
            "clause_op": "connect",
            "clause_source_index": 1,
            "kernel_op": "connect",
            "target_kind": "endpoint",
            "target_pattern": "10.0.0.7",
            "target_arg": null,
            "reason": "guard egress",
            "source_ref": "policy.dsl",
            "source_start_line": 5,
            "source_end_line": 9,
            "source_hash": crate::audit::policy_hash("rule egress block connect 10.0.0.7\n"),
            "source_text": "rule egress block connect 10.0.0.7\n",
            "clause_start_line": 6,
            "clause_end_line": 8,
            "clause_hash": crate::audit::policy_hash("block connect 10.0.0.7"),
            "clause_text": "block connect 10.0.0.7",
            "binding_mode": "locked",
            "immutable": true,
        });
        assert_eq!(got[1], expected);
    }
    #[test]
    fn source_flow_summary_describes_label_flow_per_kind() {
        // `source_flow_summary` renders the human-readable label-flow
        // description for each `Kind`. No base or branch test pins this
        // summary text directly.
        assert_eq!(
            source_flow_summary(Kind::Exec),
            "matching exec adds the label to the process and fork descendants"
        );
        assert_eq!(
            source_flow_summary(Kind::File),
            "matching file carries the label; reads copy it into the process, \
             writes copy process labels into the file"
        );
        assert_eq!(
            source_flow_summary(Kind::Endpoint),
            "matching IPv4 endpoint carries the label; recv copies it into the \
             process, connect records egress labels"
        );
    }
    #[test]
    fn source_summary_renders_label_kind_and_pattern() {
        // `source_summary` renders `source <label> = <kind> "<pattern>"`,
        // routing the kind through `kind_name`. No base or branch test pins
        // this summary directly.
        let file = Source {
            label: "repo".to_string(),
            kind: Kind::File,
            pattern: "policy.dsl".to_string(),
        };
        assert_eq!(source_summary(&file), "source repo = file \"policy.dsl\"");

        let endpoint = Source {
            label: "egress".to_string(),
            kind: Kind::Endpoint,
            pattern: "10.0.0.0/8".to_string(),
        };
        assert_eq!(
            source_summary(&endpoint),
            "source egress = endpoint \"10.0.0.0/8\""
        );
    }
    #[test]
    fn source_support_detail_reports_each_kind() {
        // `source_support_detail` reports whether a source of a given kind is
        // enforceable: `Exec` is applied on exec, `File` is applied through the
        // open/read flow with a conservative open-time caveat, and `Endpoint`
        // delegates to the endpoint support detail (numeric IPv4 vs hostname
        // resolution). No base or branch test pins this directly.
        use std::collections::HashMap;

        let empty = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        assert_eq!(
            source_support_detail(&empty, Kind::Exec, "python3"),
            (
                true,
                "exec source labels are applied on process exec".to_string(),
                Vec::new()
            )
        );

        assert_eq!(
            source_support_detail(&empty, Kind::File, "/repo"),
            (
                true,
                "file source labels are applied through file open/read flow".to_string(),
                vec!["open-time file source handling is conservative"]
            )
        );

        // A numeric IPv4 endpoint source is supported with the IPv6 caveat.
        assert_eq!(
            source_support_detail(&empty, Kind::Endpoint, "10.0.0.7"),
            (
                true,
                "endpoint source matches numeric IPv4 connect and recv paths".to_string(),
                vec!["IPv6 is not enforced in-kernel"]
            )
        );

        // A hostname source with a non-empty resolution reports the address.
        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::from([(
                "example.com".to_string(),
                vec!["93.184.215.14".to_string()],
            )]),
        };
        assert_eq!(
            source_support_detail(&compiled, Kind::Endpoint, "example.com"),
            (
                true,
                "endpoint source hostname resolved to IPv4 address(es): \
                 93.184.215.14"
                    .to_string(),
                vec![
                    "hostname is resolved at policy compile/load time",
                    "DNS changes require policy reload",
                    "IPv6 addresses are ignored",
                ]
            )
        );
    }
    #[test]
    fn source_support_json_renders_one_object_per_source() {
        // `source_support_json` renders one JSON object per policy source,
        // projecting `source_support_detail` into label / kind / pattern /
        // supported / reason / limitations. No base or branch test pins this
        // serializer directly.
        use std::collections::HashMap;

        let compiled = dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: HashMap::new(),
            endpoint_resolutions: HashMap::new(),
        };

        let policy = Policy {
            labels: Vec::new(),
            sources: vec![
                Source {
                    label: "e1".to_string(),
                    kind: Kind::Exec,
                    pattern: "python3".to_string(),
                },
                Source {
                    label: "f1".to_string(),
                    kind: Kind::File,
                    pattern: "/tmp/x".to_string(),
                },
                Source {
                    label: "n1".to_string(),
                    kind: Kind::Endpoint,
                    pattern: "10.0.0.7".to_string(),
                },
            ],
            rules: Vec::new(),
            xforms: Vec::new(),
        };

        let got = source_support_json(&policy, &compiled);
        let expected = vec![
            json!({
                "label": "e1",
                "kind": "exec",
                "pattern": "python3",
                "supported": true,
                "reason": "exec source labels are applied on process exec",
                "limitations": [],
            }),
            json!({
                "label": "f1",
                "kind": "file",
                "pattern": "/tmp/x",
                "supported": true,
                "reason": "file source labels are applied through file open/read flow",
                "limitations": ["open-time file source handling is conservative"],
            }),
            json!({
                "label": "n1",
                "kind": "endpoint",
                "pattern": "10.0.0.7",
                "supported": true,
                "reason": "endpoint source matches numeric IPv4 connect and recv paths",
                "limitations": ["IPv6 is not enforced in-kernel"],
            }),
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn format_sample_list_joins_or_reports_none() {
        assert_eq!(format_sample_list(&[]), "none");
        assert_eq!(format_sample_list(&["a".into(), "b".into()]), "a,b");
    }

    #[test]
    fn source_summary_renders_label_kind_and_pattern_c2() {
        assert_eq!(
            source_summary(&Source {
                label: "UNTRUST".into(),
                kind: Kind::File,
                pattern: "**/.env".into(),
            }),
            "source UNTRUST = file \"**/.env\""
        );
    }

    #[test]
    fn source_flow_summary_describes_each_kind() {
        assert!(source_flow_summary(Kind::Exec).contains("fork descendants"));
        assert!(source_flow_summary(Kind::File).contains("reads copy"));
        assert!(source_flow_summary(Kind::Endpoint).contains("egress labels"));
    }

    #[test]
    fn clause_summary_renders_target_and_conditions() {
        let clause = Clause {
            op: Op::Exec,
            target: crate::dsl::ast::Target {
                kind: Kind::Exec,
                pattern: "git".into(),
                arg: Some("push".into()),
            },
            when: Expr::Label("T".into()),
            unless: Some(Cond::Target {
                negate: false,
                pattern: "host".into(),
            }),
            effect: Effect::Block,
            source_index: 0,
        };
        assert_eq!(
            clause_summary(&clause),
            "block exec \"git\" \"push\" if T unless target \"host\""
        );
    }

    #[test]
    fn policy_ref_for_cli_prefers_policy_then_rule_then_discovery() {
        let mut cli = PolicyInput {
            policy: None,
            rule: None,
            domain: None,
            run_as_root: false,
            internal_elevated: false,
        };
        assert_eq!(policy_ref_for_cli(&cli), "auto-discovered policy");
        cli.rule = Some("exec git".into());
        assert_eq!(policy_ref_for_cli(&cli), "--rule");
        cli.policy = Some(PathBuf::from("/tmp/p.yaml"));
        assert_eq!(policy_ref_for_cli(&cli), "/tmp/p.yaml");
    }

    fn compiled_with_endpoints_c5(entries: &[(&str, Vec<&str>)]) -> dsl::Compiled {
        let mut resolutions = std::collections::HashMap::new();
        for (pattern, addrs) in entries {
            resolutions.insert(
                (*pattern).to_string(),
                addrs.iter().map(|a| (*a).to_string()).collect(),
            );
        }
        dsl::Compiled {
            bytes: Vec::new(),
            reasons: Vec::new(),
            meta: Vec::new(),
            labels: std::collections::HashMap::new(),
            endpoint_resolutions: resolutions,
        }
    }

    fn target_c2(kind: Kind, pattern: &str, arg: Option<&str>) -> crate::dsl::ast::Target {
        crate::dsl::ast::Target {
            kind,
            pattern: pattern.to_string(),
            arg: arg.map(str::to_string),
        }
    }

    #[test]
    fn source_support_json_serializes_each_source() {
        let compiled = compiled_with_endpoints_c5(&[]);
        let policy = Policy {
            labels: Vec::new(),
            sources: vec![Source {
                label: "T".into(),
                kind: Kind::File,
                pattern: "**/.env".into(),
            }],
            rules: Vec::new(),
            xforms: Vec::new(),
        };
        let out = source_support_json(&policy, &compiled);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["label"], "T");
        assert_eq!(out[0]["kind"], "file");
        assert_eq!(out[0]["supported"], true);
    }

    #[test]
    fn clause_support_json_reports_status_and_condition_warnings() {
        let compiled =
            compiled_with_endpoints_c5(&[("multi.example", vec!["10.0.0.1", "10.0.0.2"])]);
        let policy = Policy {
            labels: Vec::new(),
            sources: Vec::new(),
            rules: vec![crate::dsl::ast::Rule {
                name: "r".into(),
                reason: String::new(),
                clauses: vec![
                    Clause {
                        op: Op::Connect,
                        target: target_c2(Kind::Endpoint, "multi.example", None),
                        when: Expr::True,
                        unless: Some(Cond::Target {
                            negate: false,
                            pattern: "multi.example".into(),
                        }),
                        effect: Effect::Block,
                        source_index: 0,
                    },
                    Clause {
                        op: Op::Exec,
                        target: target_c2(Kind::Exec, "git", None),
                        when: Expr::True,
                        unless: None,
                        effect: Effect::Notify,
                        source_index: 1,
                    },
                ],
            }],
            xforms: Vec::new(),
        };
        let out = clause_support_json(&policy, &compiled, true);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["rule"], "r");
        assert_eq!(out[0]["clause_index"], 0);
        assert_eq!(out[0]["op"], "connect");
        assert_eq!(out[0]["target_pattern"], "multi.example");
        assert_eq!(out[0]["supported"], true);
        let warnings = out[0]["condition_warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0]["code"],
            "endpoint_target_condition_multi_ipv4_hostname"
        );
    }
}
