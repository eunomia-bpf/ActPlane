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
    for line in backend_support_lines(&parsed, lsm_bpf) {
        println!("  - {}", line);
    }
    let warns = backend_support_warnings(&parsed, lsm_bpf);
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
        "  4. Fail closed only after proving the policy and hook budget on the deployment host."
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
                clause.effect,
                clause.op,
                clause.target.kind,
                &clause.target.pattern,
                clause.target.arg.as_deref(),
                lsm_bpf,
            );
            let block = clause_support_detail(
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
            for warning in clause_condition_warnings(clause) {
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

    let warns = backend_support_warnings(parsed, lsm_bpf);
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
                    "block denies before syscall commit only on hosts with matching BPF-LSM and hook budget".into(),
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
    let warnings = backend_support_warnings(parsed, lsm_bpf)
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
        "matrix_scope": "static_initial_policy_host_support",
        "matrix_note": "This reports static host/backend support for the selected initial policy. Runtime budgets can reject later deltas that require hook classes or path matcher classes not enabled when the engine was loaded.",
        "environment": {
            "ACTPLANE_FORCE_TRACEPOINT": std::env::var("ACTPLANE_FORCE_TRACEPOINT").ok(),
            "ACTPLANE_HOOK_PROFILE": std::env::var("ACTPLANE_HOOK_PROFILE").ok(),
            "ACTPLANE_ENABLE_ADVANCED_HOOKS": std::env::var("ACTPLANE_ENABLE_ADVANCED_HOOKS").ok(),
            "ACTPLANE_RESERVE_FILE_FLOW": std::env::var("ACTPLANE_RESERVE_FILE_FLOW").ok(),
        },
        "rule_count": compiled.meta.len(),
        "rules": rule_meta_json(compiled),
        "backend_support": {
            "sources": source_support_json(parsed),
            "clauses": clause_support_json(parsed, lsm_bpf),
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
        "  - feature budget: policy-budgeted attach; runtime deltas cannot add hook classes or path contains/suffix matcher classes after load"
    )
    .unwrap();
    writeln!(
        &mut out,
        "  - review scope: selected initial policy and current host support, not a live loaded-engine guarantee"
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
                source_support_detail(source.kind, &source.pattern);
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
        "  - coverage note: ordinary flows are hook-budgeted; advanced mmap/mprotect, SCM_RIGHTS, Unix-socket IPC, pipe/socketpair, sendfile, copy_file_range, and splice coverage requires advanced hooks or the full hook profile"
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
            for warning in clause_condition_warnings(clause) {
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
        "  - reload is a trusted admin path; append policy delta is the authority-checked append-only mutation path"
    )
    .unwrap();

    let warns = backend_support_warnings(parsed, lsm_bpf);
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

fn source_support_json(policy: &Policy) -> Vec<Value> {
    policy
        .sources
        .iter()
        .map(|source| {
            let (supported, reason, limitations) =
                source_support_detail(source.kind, &source.pattern);
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

fn clause_support_json(policy: &Policy, lsm_bpf: bool) -> Vec<Value> {
    let mut out = Vec::new();
    for rule in &policy.rules {
        for (clause_index, clause) in rule.clauses.iter().enumerate() {
            let support = clause_support_detail(
                clause.effect,
                clause.op,
                clause.target.kind,
                &clause.target.pattern,
                clause.target.arg.as_deref(),
                lsm_bpf,
            );
            let condition_warnings = clause_condition_warnings(clause)
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

fn source_support_detail(kind: Kind, pattern: &str) -> (bool, &'static str, Vec<&'static str>) {
    match kind {
        Kind::Exec => (
            true,
            "exec source labels are applied on process exec",
            vec![],
        ),
        Kind::File => (
            true,
            "file source labels are applied through file open/read flow",
            vec!["open-time file source handling is conservative"],
        ),
        Kind::Endpoint if endpoint_pattern_is_numeric_ipv4(pattern) => (
            true,
            "endpoint source labels match numeric IPv4 connect and recv paths",
            vec!["IPv6 and hostname patterns are not enforced in-kernel"],
        ),
        Kind::Endpoint => (
            false,
            "endpoint source pattern is not numeric IPv4",
            vec!["IPv6 and hostname patterns are not enforced in-kernel"],
        ),
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
    effect: Effect,
    op: Op,
    kind: Kind,
    pattern: &str,
    arg: Option<&str>,
    lsm_bpf: bool,
) -> SupportDetail {
    if matches!(op, Op::Connect | Op::Recv)
        && kind == Kind::Endpoint
        && !endpoint_pattern_is_numeric_ipv4(pattern)
    {
        return SupportDetail {
            supported: false,
            status: "unsupported",
            mode: "none",
            pre_op: false,
            reason: "endpoint target pattern is not numeric IPv4".into(),
            limitations: vec!["IPv6 and hostname patterns are not enforced in-kernel"],
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
                        vec!["numeric IPv4 only"],
                    ),
                    Op::Recv => (
                        "pre-op block via BPF-LSM socket_recvmsg",
                        vec!["connected numeric IPv4 only"],
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
                    vec!["numeric IPv4 only", "post-receive in tracepoint mode"],
                ),
                Op::Exec => ("post-exec tracepoint report", vec![]),
                Op::Read | Op::Open | Op::Write | Op::Unlink => ("tracepoint report", vec![]),
                Op::Connect => ("connect tracepoint report", vec!["numeric IPv4 only"]),
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
                    vec!["numeric IPv4 only", "post-receive in tracepoint mode"],
                ),
                Op::Exec => ("post-exec tracepoint kill", vec![]),
                Op::Read | Op::Open | Op::Write | Op::Unlink => ("tracepoint kill", vec![]),
                Op::Connect => ("connect tracepoint kill", vec!["numeric IPv4 only"]),
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

fn backend_support_lines(policy: &Policy, lsm_bpf: bool) -> Vec<String> {
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
                    lsm_bpf
                )
            ));
        }
    }
    lines
}

fn clause_condition_warnings(clause: &Clause) -> Vec<ClauseConditionWarning> {
    let mut warnings = Vec::new();
    if matches!(clause.op, Op::Connect | Op::Recv)
        && clause.target.kind == Kind::Endpoint
        && let Some(Cond::Target { negate, pattern }) = &clause.unless
        && !endpoint_pattern_is_numeric_ipv4(pattern)
    {
        let consequence = if *negate {
            "a `target not` condition is evaluated after the non-numeric pattern matches nothing, which may suppress the rule more broadly than intended"
        } else {
            "the exception condition matches nothing; the rule will not exempt that endpoint"
        };
        warnings.push(ClauseConditionWarning {
            code: "endpoint_target_condition_non_numeric_ipv4",
            message: format!(
                "unless target{} \"{}\" uses a hostname or IPv6 pattern; endpoint target conditions currently match numeric IPv4 only, and {}.",
                if *negate { " not" } else { "" },
                pattern,
                consequence
            ),
        });
    }
    warnings
}

fn backend_support_warnings(policy: &Policy, lsm_bpf: bool) -> Vec<BackendWarning> {
    let mut warnings = Vec::new();
    for source in &policy.sources {
        if source.kind == Kind::Endpoint && !endpoint_pattern_is_numeric_ipv4(&source.pattern) {
            warnings.push(BackendWarning {
                code: "endpoint_source_non_numeric_ipv4",
                message: format!(
                    "source {} = endpoint \"{}\" uses a hostname or IPv6 pattern; endpoint sources currently match numeric IPv4 only.",
                    source.label, source.pattern
                ),
            });
        }
    }
    for rule in &policy.rules {
        for clause in &rule.clauses {
            if matches!(clause.op, Op::Connect | Op::Recv)
                && clause.target.kind == Kind::Endpoint
                && !endpoint_pattern_is_numeric_ipv4(&clause.target.pattern)
            {
                warnings.push(BackendWarning {
                    code: "endpoint_target_non_numeric_ipv4",
                    message: format!(
                        "{} {} endpoint \"{}\" uses a hostname or IPv6 pattern; the kernel matches numeric IPv4 only, so this rule will not fire.",
                        effect_name(clause.effect),
                        op_name(clause.op),
                        clause.target.pattern
                    ),
                });
            }
            warnings.extend(
                clause_condition_warnings(clause)
                    .into_iter()
                    .map(|warning| BackendWarning {
                        code: warning.code,
                        message: format!("{}: {}", rule.name, warning.message),
                    }),
            );
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
    lsm_bpf: bool,
) -> String {
    let detail = clause_support_detail(effect, op, kind, pattern, arg, lsm_bpf);
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
}
