use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use crate::audit;
use crate::{dsl, feedback};
use serde_json::json;

#[derive(Clone)]
pub struct RuleFeedbackContext {
    pub meta: dsl::RuleMeta,
    pub labels: HashMap<String, u64>,
}

#[derive(serde::Deserialize)]
pub struct Violation {
    pid: i32,
    ppid: i32,
    comm: String,
    target: String,
    rule_id: usize,
    #[serde(default)]
    op: Option<u32>,
    #[serde(default)]
    domain_id: Option<u32>,
    #[serde(default)]
    session_root: Option<i32>,
    #[allow(dead_code)]
    effect: Option<String>,
    blocked: Option<bool>,
    killed: Option<bool>,
    #[allow(dead_code)]
    taint_label: u64,
    #[allow(dead_code)]
    matched_label: u64,
    #[serde(default)]
    matched_labels: Option<u64>,
    provenance: Option<ViolationProvenance>,
}

impl Violation {
    pub fn rule_id(&self) -> usize {
        self.rule_id
    }

    pub fn domain_id(&self) -> Option<u32> {
        self.domain_id
    }
}

#[derive(Clone, serde::Deserialize)]
struct ViolationProvenance {
    label: u64,
    timestamp_ns: u64,
    pid: i32,
    op: u32,
    target: String,
}

/// Map the eBPF crate's violation into the collector's reporting struct.
pub fn to_violation(v: &ebpf_ifc_engine::Violation) -> Violation {
    Violation {
        pid: v.pid,
        ppid: v.ppid,
        comm: v.comm.clone(),
        target: v.target.clone(),
        rule_id: v.rule_id as usize,
        op: Some(v.op),
        domain_id: Some(v.domain_id),
        session_root: Some(v.session_root),
        effect: Some(
            match v.effect {
                0 => "notify",
                1 => "block",
                2 => "kill",
                _ => "unknown",
            }
            .to_string(),
        ),
        blocked: Some(v.blocked),
        killed: Some(v.killed),
        taint_label: v.label,
        matched_label: v.matched_label,
        matched_labels: Some(v.matched_labels),
        provenance: v.provenance.as_ref().map(|p| ViolationProvenance {
            label: p.label,
            timestamp_ns: p.timestamp_ns,
            pid: p.pid,
            op: p.op,
            target: p.target.clone(),
        }),
    }
}

/// Report a violation: a human one-liner to stdout, plus the structured
/// corrective-feedback payload appended to the reason file.
pub fn report(
    meta: &[dsl::RuleMeta],
    labels: &HashMap<String, u64>,
    v: &Violation,
    feedback_file: Option<&Path>,
    event_file: Option<&Path>,
) {
    let ctx = meta.get(v.rule_id).map(|m| RuleFeedbackContext {
        meta: m.clone(),
        labels: labels.clone(),
    });
    report_with_context(ctx.as_ref(), v, feedback_file, event_file);
}

pub fn contexts_from_compiled(compiled: &dsl::Compiled) -> Vec<RuleFeedbackContext> {
    compiled
        .meta
        .iter()
        .cloned()
        .map(|meta| RuleFeedbackContext {
            meta,
            labels: compiled.labels.clone(),
        })
        .collect()
}

pub fn report_with_context(
    ctx: Option<&RuleFeedbackContext>,
    v: &Violation,
    feedback_file: Option<&Path>,
    event_file: Option<&Path>,
) {
    let verb = if v.killed.unwrap_or(false) {
        "KILLED"
    } else if v.blocked.unwrap_or(false) {
        "BLOCKED"
    } else {
        "VIOLATION"
    };
    let m = ctx.map(|ctx| &ctx.meta);
    let reason = m.map(|m| m.reason.as_str()).unwrap_or("");
    let effect = v
        .effect
        .as_deref()
        .or_else(|| m.map(|m| effect_name(m.effect)))
        .unwrap_or("");
    println!(
        "🚫 {}: process '{}' (pid {}, ppid {}) — {}",
        verb, v.comm, v.pid, v.ppid, v.target
    );
    if !effect.is_empty() {
        println!("   effect: {}", effect);
    }
    if !reason.is_empty() {
        println!("   reason: {}", reason);
    }
    if let Some(p) = &v.provenance {
        println!(
            "   provenance: pid {} {} {} -> label {}",
            p.pid,
            kernel_op_name(p.op),
            p.target,
            ctx.map(|ctx| label_name(&ctx.labels, p.label))
                .unwrap_or_else(|| format!("0x{:x}", p.label))
        );
    }

    if let Some(path) = feedback_file {
        append_violation_feedback_context(ctx, v, path);
    }
    if let Some(path) = event_file {
        append_violation_event_context(ctx, v, path);
    }
}

pub fn append_violation_feedback_context(
    ctx: Option<&RuleFeedbackContext>,
    v: &Violation,
    path: &Path,
) {
    let Some(ctx) = ctx else {
        return;
    };
    let m = &ctx.meta;
    let op = matched_op_name(v)
        .or_else(|| m.ops.first().map(|s| s.as_str()))
        .unwrap_or("op");
    let provenance = v.provenance.as_ref().map(|p| feedback::Provenance {
        label: label_name(&ctx.labels, p.label),
        origin_pid: p.pid,
        origin_op: kernel_op_name(p.op).to_string(),
        origin_target: if p.target.is_empty() {
            "<unknown>".to_string()
        } else {
            p.target.clone()
        },
        origin_timestamp_ns: p.timestamp_ns,
    });
    let payload = feedback::format_payload(feedback::PayloadInput {
        name: &m.name,
        op,
        target: &v.target,
        reason: &m.reason,
        effect: m.effect,
        blocked: v.blocked.unwrap_or(false),
        killed: v.killed.unwrap_or(false),
        provenance: provenance.as_ref(),
    });
    if let Err(e) = append_feedback(path, &payload) {
        eprintln!("ActPlane: writing feedback file {}: {}", path.display(), e);
    }
}

pub fn append_violation_event_context(
    ctx: Option<&RuleFeedbackContext>,
    v: &Violation,
    path: &Path,
) {
    let m = ctx.map(|ctx| &ctx.meta);
    let action = if v.killed.unwrap_or(false) {
        "kill"
    } else if v.blocked.unwrap_or(false) {
        "block"
    } else if m.is_some_and(|m| m.effect == dsl::ast::Effect::Block) {
        "unsupported"
    } else {
        "report"
    };
    let mut record = json!({
        "event": "taint_violation",
        "pid": v.pid,
        "ppid": v.ppid,
        "comm": &v.comm,
        "target": &v.target,
        "rule_id": v.rule_id,
        "effect": v.effect.as_deref().or_else(|| m.map(|m| effect_name(m.effect))).unwrap_or(""),
        "action": action,
        "blocked": v.blocked.unwrap_or(false),
        "killed": v.killed.unwrap_or(false),
        "taint_label": format!("0x{:x}", v.taint_label),
        "matched_label": format!("0x{:x}", v.matched_label),
    });
    if let Some(op) = v.op {
        record["op"] = json!(kernel_op_name(op));
        record["op_code"] = json!(op);
    }
    if let Some(domain_id) = v.domain_id {
        record["domain_id"] = json!(domain_id);
    }
    if let Some(session_root) = v.session_root {
        record["session_root"] = json!(session_root);
    }
    if let Some(matched_labels) = v.matched_labels {
        record["matched_labels"] = json!(format!("0x{matched_labels:x}"));
    }
    let matched_label_mask = v.matched_labels.unwrap_or(v.matched_label);
    record["matched_label_details"] = matched_label_details(ctx, v, matched_label_mask);
    record["provenance_model"] = json!({
        "matched_labels_enumerated": v.matched_labels.is_some(),
        "reported_origin_available": v.provenance.is_some(),
        "reported_origin_scope": "first_available_matched_label",
        "causal_chain_scope": "single_hop_origin",
        "full_causal_chain": false,
    });
    if let Some(m) = m {
        let mut rule = json!({
            "name": &m.name,
            "reason": &m.reason,
            "effect": effect_name(m.effect),
            "ops": &m.ops,
            "clause_op": &m.clause_op,
            "clause_source_index": m.clause_source_index,
            "kernel_op": &m.kernel_op,
            "target_kind": kind_name(m.target_kind),
            "target_pattern": &m.target_pattern,
            "target_arg": &m.target_arg,
        });
        if let Some(source) = &m.source {
            rule["source_ref"] = json!(&source.source_ref);
            rule["source_start_line"] = json!(source.start_line);
            rule["source_end_line"] = json!(source.end_line);
            rule["source_hash"] = json!(audit::policy_hash(&source.text));
            if let Some(line) = source.clause_start_line {
                rule["clause_start_line"] = json!(line);
            }
            if let Some(line) = source.clause_end_line {
                rule["clause_end_line"] = json!(line);
            }
            if let Some(text) = &source.clause_text {
                rule["clause_hash"] = json!(audit::policy_hash(text));
                rule["clause_text"] = json!(text);
            }
            if let Some(mode) = &source.binding_mode {
                rule["binding_mode"] = json!(mode);
            }
            rule["immutable"] = json!(source.binding_mode.as_deref() == Some("locked"));
        }
        record["rule"] = rule;
    }
    if let Some(ctx) = ctx {
        record["matched_label_name"] = json!(label_name(&ctx.labels, v.matched_label));
        if let Some(matched_labels) = v.matched_labels {
            record["matched_label_names"] =
                json!(label_names_for_mask(&ctx.labels, matched_labels));
        }
    }
    if let Some(p) = &v.provenance {
        record["provenance"] = provenance_json(ctx, p);
    }
    if let Err(e) = audit::append_with_schema(path, "actplane.violation.v1", &mut record) {
        eprintln!("ActPlane: writing event log {}: {}", path.display(), e);
    }
}

fn matched_label_details(
    ctx: Option<&RuleFeedbackContext>,
    v: &Violation,
    matched_label_mask: u64,
) -> serde_json::Value {
    let mut details = Vec::new();
    for i in 0..64 {
        let bit = 1u64 << i;
        if matched_label_mask & bit == 0 {
            continue;
        }
        let label = ctx
            .map(|ctx| label_name(&ctx.labels, bit))
            .unwrap_or_else(|| format!("0x{bit:x}"));
        let mut detail = json!({
            "label": label,
            "label_mask": format!("0x{bit:x}"),
            "provenance_status": "not_reported",
            "provenance": serde_json::Value::Null,
            "causal_chain": [],
            "causal_chain_complete": false,
        });
        if let Some(p) = &v.provenance
            && p.label == bit
        {
            let origin = provenance_json(ctx, p);
            detail["provenance_status"] = json!("reported_first_origin");
            detail["provenance"] = origin.clone();
            detail["causal_chain"] = json!([origin]);
        }
        details.push(detail);
    }
    json!(details)
}

fn provenance_json(
    ctx: Option<&RuleFeedbackContext>,
    p: &ViolationProvenance,
) -> serde_json::Value {
    let label = ctx
        .map(|ctx| label_name(&ctx.labels, p.label))
        .unwrap_or_else(|| format!("0x{:x}", p.label));
    json!({
        "label": label,
        "label_mask": format!("0x{:x}", p.label),
        "origin_pid": p.pid,
        "origin_op": kernel_op_name(p.op),
        "origin_target": &p.target,
        "origin_timestamp_ns": p.timestamp_ns,
    })
}

fn matched_op_name(v: &Violation) -> Option<&'static str> {
    v.op.map(kernel_op_name)
}

fn label_name(labels: &HashMap<String, u64>, label: u64) -> String {
    labels
        .iter()
        .find_map(|(name, bit)| (*bit == label).then(|| name.clone()))
        .unwrap_or_else(|| format!("0x{label:x}"))
}

fn label_names_for_mask(labels: &HashMap<String, u64>, mask: u64) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..64 {
        let bit = 1u64 << i;
        if mask & bit != 0 {
            out.push(label_name(labels, bit));
        }
    }
    out
}

fn kernel_op_name(op: u32) -> &'static str {
    match op {
        0 => "exec",
        1 => "read",
        2 => "write",
        3 => "connect",
        4 => "recv",
        _ => "op",
    }
}

fn append_feedback(path: &Path, payload: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}\n----", payload)
}

fn effect_name(effect: dsl::ast::Effect) -> &'static str {
    match effect {
        dsl::ast::Effect::Notify => "notify",
        dsl::ast::Effect::Block => "block",
        dsl::ast::Effect::Kill => "kill",
    }
}

fn kind_name(kind: dsl::ast::Kind) -> &'static str {
    match kind {
        dsl::ast::Kind::File => "file",
        dsl::ast::Kind::Endpoint => "endpoint",
        dsl::ast::Kind::Exec => "exec",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::ast::Effect;

    #[test]
    fn feedback_context_resolves_domain_local_label_names() {
        let path = std::env::temp_dir().join(format!(
            "actplane-report-context-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let mut labels = HashMap::new();
        labels.insert("LOCAL_SECRET".to_string(), 1);
        labels.insert("LOCAL_TOKEN".to_string(), 2);
        let ctx = RuleFeedbackContext {
            meta: dsl::RuleMeta {
                name: "local-rule".to_string(),
                reason: "local reason".to_string(),
                effect: Effect::Notify,
                ops: vec!["exec".to_string()],
                clause_op: "exec".to_string(),
                clause_source_index: 0,
                kernel_op: "exec".to_string(),
                target_kind: dsl::ast::Kind::Exec,
                target_pattern: "git".to_string(),
                target_arg: None,
                source: None,
            },
            labels,
        };
        let v = Violation {
            pid: 10,
            ppid: 1,
            comm: "git".to_string(),
            target: "git".to_string(),
            rule_id: 0,
            op: Some(0),
            domain_id: Some(23),
            session_root: Some(10),
            effect: Some("notify".to_string()),
            blocked: Some(false),
            killed: Some(false),
            taint_label: 1,
            matched_label: 1,
            matched_labels: Some(1),
            provenance: Some(ViolationProvenance {
                label: 1,
                timestamp_ns: 42,
                pid: 9,
                op: 1,
                target: "/tmp/local".to_string(),
            }),
        };

        append_violation_feedback_context(Some(&ctx), &v, &path);
        let text = std::fs::read_to_string(&path).expect("feedback file");
        assert!(text.contains("acquired label LOCAL_SECRET"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn violation_event_context_writes_structured_jsonl() {
        let path = std::env::temp_dir().join(format!(
            "actplane-event-context-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let mut labels = HashMap::new();
        labels.insert("LOCAL_SECRET".to_string(), 1);
        labels.insert("LOCAL_TOKEN".to_string(), 2);
        let ctx = RuleFeedbackContext {
            meta: dsl::RuleMeta {
                name: "local-rule".to_string(),
                reason: "local reason".to_string(),
                effect: Effect::Kill,
                ops: vec!["exec".to_string()],
                clause_op: "exec".to_string(),
                clause_source_index: 0,
                kernel_op: "exec".to_string(),
                target_kind: dsl::ast::Kind::Exec,
                target_pattern: "git".to_string(),
                target_arg: Some("commit".to_string()),
                source: Some(dsl::RuleSourceMeta {
                    source_ref: "rules.local.ifc".to_string(),
                    binding_mode: Some("locked".to_string()),
                    start_line: 4,
                    end_line: 6,
                    text: "rule local-rule:\n  kill exec \"git\"\n  because \"local reason\""
                        .to_string(),
                    clause_start_line: Some(5),
                    clause_end_line: Some(5),
                    clause_text: Some("  kill exec \"git\"".to_string()),
                }),
            },
            labels,
        };
        let v = Violation {
            pid: 10,
            ppid: 1,
            comm: "git".to_string(),
            target: "git".to_string(),
            rule_id: 7,
            op: Some(0),
            domain_id: Some(23),
            session_root: Some(10),
            effect: Some("kill".to_string()),
            blocked: Some(false),
            killed: Some(true),
            taint_label: 1,
            matched_label: 1,
            matched_labels: Some(3),
            provenance: Some(ViolationProvenance {
                label: 1,
                timestamp_ns: 42,
                pid: 9,
                op: 1,
                target: "/tmp/local".to_string(),
            }),
        };

        append_violation_event_context(Some(&ctx), &v, &path);
        let text = std::fs::read_to_string(&path).expect("event file");
        let value: serde_json::Value = serde_json::from_str(text.trim()).expect("json line");
        assert_eq!(value["schema"], "actplane.violation.v1");
        assert_eq!(value["event"], "taint_violation");
        assert_eq!(value["rule"]["name"], "local-rule");
        assert_eq!(value["rule"]["reason"], "local reason");
        assert_eq!(value["rule"]["clause_op"], "exec");
        assert_eq!(value["rule"]["clause_source_index"], 0);
        assert_eq!(value["rule"]["kernel_op"], "exec");
        assert_eq!(value["rule"]["target_kind"], "exec");
        assert_eq!(value["rule"]["target_pattern"], "git");
        assert_eq!(value["rule"]["target_arg"], "commit");
        assert_eq!(value["rule_id"], 7);
        assert_eq!(value["action"], "kill");
        assert_eq!(value["op"], "exec");
        assert_eq!(value["op_code"], 0);
        assert_eq!(value["domain_id"], 23);
        assert_eq!(value["session_root"], 10);
        assert_eq!(value["matched_labels"], "0x3");
        assert_eq!(value["matched_label_name"], "LOCAL_SECRET");
        assert_eq!(value["matched_label_names"][0], "LOCAL_SECRET");
        assert_eq!(value["matched_label_names"][1], "LOCAL_TOKEN");
        assert_eq!(value["matched_label_details"][0]["label"], "LOCAL_SECRET");
        assert_eq!(
            value["matched_label_details"][0]["provenance_status"],
            "reported_first_origin"
        );
        assert_eq!(
            value["matched_label_details"][0]["provenance"]["origin_target"],
            "/tmp/local"
        );
        assert_eq!(
            value["matched_label_details"][0]["causal_chain"][0]["label"],
            "LOCAL_SECRET"
        );
        assert_eq!(
            value["matched_label_details"][0]["causal_chain_complete"],
            false
        );
        assert_eq!(value["matched_label_details"][1]["label"], "LOCAL_TOKEN");
        assert_eq!(
            value["matched_label_details"][1]["provenance_status"],
            "not_reported"
        );
        assert_eq!(
            value["matched_label_details"][1]["provenance"],
            serde_json::Value::Null
        );
        assert_eq!(value["provenance_model"]["matched_labels_enumerated"], true);
        assert_eq!(value["provenance_model"]["reported_origin_available"], true);
        assert_eq!(
            value["provenance_model"]["reported_origin_scope"],
            "first_available_matched_label"
        );
        assert_eq!(
            value["provenance_model"]["causal_chain_scope"],
            "single_hop_origin"
        );
        assert_eq!(value["provenance_model"]["full_causal_chain"], false);
        assert_eq!(value["provenance"]["label"], "LOCAL_SECRET");
        assert_eq!(value["rule"]["source_ref"], "rules.local.ifc");
        assert_eq!(value["rule"]["binding_mode"], "locked");
        assert_eq!(value["rule"]["immutable"], true);
        assert_eq!(value["rule"]["source_start_line"], 4);
        assert_eq!(value["rule"]["clause_start_line"], 5);
        assert_eq!(value["rule"]["clause_text"], "  kill exec \"git\"");
        assert!(
            value["rule"]["clause_hash"]
                .as_str()
                .unwrap()
                .starts_with("fnv1a64:")
        );
        assert!(
            value["rule"]["source_hash"]
                .as_str()
                .unwrap()
                .starts_with("fnv1a64:")
        );

        let _ = std::fs::remove_file(&path);
    }
}
