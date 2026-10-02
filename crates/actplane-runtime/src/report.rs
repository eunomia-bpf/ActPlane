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

    fn meta_for(name: &str, reason: &str) -> dsl::RuleMeta {
        dsl::RuleMeta {
            name: name.to_string(),
            reason: reason.to_string(),
            effect: Effect::Notify,
            ops: vec!["exec".to_string()],
            clause_op: "exec".to_string(),
            clause_source_index: 0,
            kernel_op: "exec".to_string(),
            target_kind: dsl::ast::Kind::Exec,
            target_pattern: "git".to_string(),
            target_arg: None,
            source: None,
        }
    }

    #[test]
    fn contexts_from_compiled_copies_meta_and_labels() {
        // `contexts_from_compiled` builds one feedback context per compiled rule
        // over the shared label table; no base or branch test calls it.
        let compiled = dsl::Compiled {
            bytes: vec![1, 2, 3],
            reasons: vec!["reason-a".to_string(), "reason-b".to_string()],
            meta: vec![meta_for("r-a", "why a"), meta_for("r-b", "why b")],
            labels: HashMap::from([("SECRET".to_string(), 1u64), ("TOKEN".to_string(), 2u64)]),
            endpoint_resolutions: HashMap::new(),
        };
        let contexts = contexts_from_compiled(&compiled);
        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0].meta.name, "r-a");
        assert_eq!(contexts[0].meta.reason, "why a");
        assert_eq!(contexts[1].meta.name, "r-b");
        assert_eq!(contexts[1].meta.reason, "why b");
        // Both contexts share the compiled label table.
        assert_eq!(contexts[0].labels.get("SECRET"), Some(&1));
        assert_eq!(contexts[1].labels.get("TOKEN"), Some(&2));
    }
    #[test]
    fn effect_name_maps_each_effect_to_its_feedback_verb() {
        // `effect_name` maps a rule effect to the feedback verb string
        // written into violation payloads. No base or branch test pins this
        // mapping directly.
        assert_eq!(effect_name(Effect::Notify), "notify");
        assert_eq!(effect_name(Effect::Block), "block");
        assert_eq!(effect_name(Effect::Kill), "kill");
    }
    #[test]
    fn kernel_op_name_maps_each_kernel_op_byte_to_its_feedback_verb() {
        // `kernel_op_name` maps a kernel op byte (the `op` field carried by a
        // `Violation`) to the human-readable feedback verb. This is a
        // byte-for-byte ABI surface: the kernel packs ops as 0..=4, and any
        // other value falls back to the generic "op" so a future op byte can
        // never panic the feedback formatter. No base or branch test pins
        // these mappings directly.
        assert_eq!(kernel_op_name(0), "exec");
        assert_eq!(kernel_op_name(1), "read");
        assert_eq!(kernel_op_name(2), "write");
        assert_eq!(kernel_op_name(3), "connect");
        assert_eq!(kernel_op_name(4), "recv");
        assert_eq!(kernel_op_name(5), "op");
    }
    #[test]
    fn kind_name_maps_each_kind_to_its_feedback_verb() {
        // `kind_name` maps a target node kind to the feedback verb string
        // written into violation payloads. No base or branch test pins this
        // mapping directly.
        assert_eq!(kind_name(dsl::ast::Kind::File), "file");
        assert_eq!(kind_name(dsl::ast::Kind::Endpoint), "endpoint");
        assert_eq!(kind_name(dsl::ast::Kind::Exec), "exec");
    }
    #[test]
    fn label_name_resolves_a_known_bit_and_falls_back_to_hex() {
        // `label_name` resolves a single label bit to its name; an unknown
        // bit falls back to the `0x…` hex form so an unrecognized bit can
        // never panic the feedback formatter. No base or branch test pins
        // this behavior directly.
        let mut labels = HashMap::new();
        labels.insert("LOCAL_SECRET".to_string(), 1);
        labels.insert("LOCAL_TOKEN".to_string(), 2);

        // A known bit resolves to its declared name.
        assert_eq!(label_name(&labels, 1), "LOCAL_SECRET");
        assert_eq!(label_name(&labels, 2), "LOCAL_TOKEN");

        // An unknown bit falls back to its hex form.
        assert_eq!(label_name(&labels, 4), "0x4");

        // An empty map has no resolvable names; the zero bit is `0x0`.
        let empty = HashMap::new();
        assert_eq!(label_name(&empty, 0), "0x0");
    }
    #[test]
    fn label_names_for_mask_decomposes_a_mask_low_to_high_with_hex_fallback() {
        // `label_names_for_mask` walks bits 0..64 low-to-high and emits a
        // name per set bit, falling back to the `0x…` hex form for bits with
        // no declared label. No base or branch test pins this decomposition
        // order or fallback directly.
        let mut labels = HashMap::new();
        labels.insert("LOCAL_SECRET".to_string(), 1);
        labels.insert("LOCAL_TOKEN".to_string(), 4);

        // Both bits resolve to their declared names, in low-to-high order.
        assert_eq!(
            label_names_for_mask(&labels, 5),
            vec!["LOCAL_SECRET", "LOCAL_TOKEN"]
        );

        // A set bit with no declared label falls back to its hex form,
        // still in low-to-high position.
        assert_eq!(
            label_names_for_mask(&labels, 7),
            vec!["LOCAL_SECRET", "0x2", "LOCAL_TOKEN"]
        );

        // An empty map yields only hex names for every set bit.
        assert_eq!(label_names_for_mask(&HashMap::new(), 3), vec!["0x1", "0x2"]);

        // The all-zero mask decomposes to nothing.
        assert!(label_names_for_mask(&labels, 0).is_empty());
    }
    #[test]
    fn matched_op_name_maps_a_violation_op_byte_to_its_feedback_verb() {
        // `matched_op_name` lifts the optional kernel op byte carried by a
        // `Violation` into its feedback verb via `kernel_op_name`. No base or
        // branch test pins this pass-through (including the `None` case)
        // directly.
        let mk = |op: Option<u32>| Violation {
            pid: 10,
            ppid: 1,
            comm: "git".to_string(),
            target: "git".to_string(),
            rule_id: 0,
            op,
            domain_id: Some(23),
            session_root: Some(10),
            effect: None,
            blocked: None,
            killed: None,
            taint_label: 1,
            matched_label: 1,
            matched_labels: Some(1),
            provenance: None,
        };

        assert_eq!(matched_op_name(&mk(Some(0))), Some("exec"));
        assert_eq!(matched_op_name(&mk(Some(3))), Some("connect"));
        assert_eq!(matched_op_name(&mk(Some(5))), Some("op"));
        assert_eq!(matched_op_name(&mk(None)), None);
    }

    #[test]
    fn provenance_details_resolve_labels_and_gate_on_matching_origin() {
        // `provenance_json` and `matched_label_details` build the corrective
        // feedback payload; neither is called by any base or branch test.
        let mut labels = HashMap::new();
        labels.insert("TOKEN_A".to_string(), 1);
        labels.insert("TOKEN_B".to_string(), 2);
        let ctx = RuleFeedbackContext {
            meta: dsl::RuleMeta {
                name: "r".to_string(),
                reason: "why".to_string(),
                effect: Effect::Block,
                ops: vec!["read".to_string()],
                clause_op: "read".to_string(),
                clause_source_index: 0,
                kernel_op: "read".to_string(),
                target_kind: dsl::ast::Kind::File,
                target_pattern: "x".to_string(),
                target_arg: None,
                source: None,
            },
            labels: labels.clone(),
        };
        let prov = ViolationProvenance {
            label: 1,
            timestamp_ns: 4242,
            pid: 77,
            op: 3,
            target: "10.0.0.1".to_string(),
        };

        // Known label -> resolved name; unknown -> hex fallback.
        let pj = provenance_json(Some(&ctx), &prov);
        assert_eq!(pj["label"], "TOKEN_A");
        assert_eq!(pj["label_mask"], "0x1");
        assert_eq!(pj["origin_pid"], 77);
        assert_eq!(pj["origin_op"], "connect");
        assert_eq!(pj["origin_target"], "10.0.0.1");
        assert_eq!(pj["origin_timestamp_ns"], 4242);
        let unknown = ViolationProvenance {
            label: 4,
            ..prov.clone()
        };
        assert_eq!(provenance_json(None, &unknown)["label"], "0x4");

        // matched_label_details walks the mask and attaches provenance only to
        // the bit that matches the reported origin.
        let v = Violation {
            pid: 5,
            ppid: 1,
            comm: "c".to_string(),
            target: "t".to_string(),
            rule_id: 0,
            op: Some(3),
            domain_id: None,
            session_root: None,
            effect: None,
            blocked: None,
            killed: None,
            taint_label: 3,
            matched_label: 3,
            matched_labels: Some(3),
            provenance: Some(prov),
        };
        let details = matched_label_details(Some(&ctx), &v, 0b11);
        let arr = details.as_array().expect("array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["label"], "TOKEN_A");
        assert_eq!(arr[0]["provenance_status"], "reported_first_origin");
        assert_eq!(arr[0]["causal_chain_complete"], false);
        assert_eq!(arr[0]["provenance"]["origin_op"], "connect");
        assert_eq!(arr[1]["label"], "TOKEN_B");
        assert_eq!(arr[1]["provenance_status"], "not_reported");
        assert!(arr[1]["provenance"].is_null());
        assert_eq!(arr[1]["causal_chain"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn to_violation_maps_kernel_effects_and_provenance() {
        // `to_violation` translates the eBPF crate's violation into the runtime
        // reporting struct; no base or branch test calls it.
        let kernel = |effect, provenance| ebpf_ifc_engine::Violation {
            effect,
            blocked: true,
            killed: false,
            comm: "git".to_string(),
            pid: 11,
            ppid: 1,
            target: "/usr/bin/git".to_string(),
            rule_id: 7,
            op: 2,
            domain_id: 5,
            session_root: 11,
            label: 4,
            matched_label: 4,
            matched_labels: 4,
            provenance,
            timestamp_ns: 99,
        };

        let no_prov = to_violation(&kernel(2, None));
        assert_eq!(no_prov.rule_id, 7);
        assert_eq!(no_prov.op, Some(2));
        assert_eq!(no_prov.domain_id, Some(5));
        assert_eq!(no_prov.session_root, Some(11));
        assert_eq!(no_prov.effect.as_deref(), Some("kill"));
        assert_eq!(no_prov.blocked, Some(true));
        assert_eq!(no_prov.killed, Some(false));
        assert_eq!(no_prov.matched_labels, Some(4));
        assert!(no_prov.provenance.is_none());

        // Effect code 3 is outside the known set.
        assert_eq!(
            to_violation(&kernel(3, None)).effect.as_deref(),
            Some("unknown")
        );

        let with_prov = to_violation(&kernel(
            1,
            Some(ebpf_ifc_engine::Provenance {
                label: 4,
                timestamp_ns: 123,
                pid: 42,
                op: 3,
                target: "10.0.0.1".to_string(),
            }),
        ));
        assert_eq!(with_prov.effect.as_deref(), Some("block"));
        let p = with_prov.provenance.expect("provenance");
        assert_eq!(p.label, 4);
        assert_eq!(p.pid, 42);
        assert_eq!(p.op, 3);
        assert_eq!(p.target, "10.0.0.1");
        assert_eq!(p.timestamp_ns, 123);
    }

    #[test]
    fn violation_accessors_expose_rule_and_domain_id() {
        // `Violation::rule_id` / `domain_id` exposes the kernel fields; no base
        // or branch test calls them.
        let mut value = serde_json::json!({
            "pid": 10,
            "ppid": 1,
            "comm": "git",
            "target": "git",
            "rule_id": 7,
            "taint_label": 1u64,
            "matched_label": 1u64,
        });
        let v: Violation = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(v.rule_id(), 7);
        assert_eq!(v.domain_id(), None);

        value["domain_id"] = serde_json::json!(23);
        let v: Violation = serde_json::from_value(value).unwrap();
        assert_eq!(v.rule_id(), 7);
        assert_eq!(v.domain_id(), Some(23));
    }

    #[test]
    fn report_with_context_writes_feedback_and_event_files() {
        // `report` derives feedback context from the rule id and
        // `report_with_context` appends both the human feedback file and the
        // structured event log; `append_feedback` creates parent dirs. None has
        // a direct caller in the base or branch tests.

        let root = std::env::temp_dir().join(format!("actplane-report-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let feedback_path = root.join("nested/feedback.txt");
        let event_path = root.join("events.jsonl");

        let mut labels = HashMap::new();
        labels.insert("LOCAL_SECRET".to_string(), 1);
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
                target_arg: None,
                source: None,
            },
            labels: labels.clone(),
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
            effect: Some("kill".to_string()),
            blocked: Some(false),
            killed: Some(true),
            taint_label: 1,
            matched_label: 1,
            matched_labels: Some(1),
            provenance: None,
        };

        report_with_context(Some(&ctx), &v, Some(&feedback_path), Some(&event_path));
        let feedback_text = std::fs::read_to_string(&feedback_path).expect("feedback file created");
        assert!(feedback_text.contains("Operation killed by rule `local-rule`"));
        assert!(feedback_text.contains("----"));
        let event_text = std::fs::read_to_string(&event_path).expect("event file");
        let value: serde_json::Value = serde_json::from_str(event_text.trim()).expect("event json");
        assert_eq!(value["schema"], "actplane.violation.v1");
        assert_eq!(value["rule"]["name"], "local-rule");

        // `report` maps rule_id -> context and appends the feedback file.
        let via_report = root.join("via-report.txt");
        let meta = vec![ctx.meta.clone()];
        report(&meta, &labels, &v, Some(&via_report), None);
        let report_text = std::fs::read_to_string(&via_report).expect("report feedback");
        assert!(report_text.contains("local-rule"));

        // A None context short-circuits: no feedback file is written.
        let none_path = root.join("none.txt");
        report_with_context(None, &v, Some(&none_path), None);
        assert!(!none_path.exists());

        // append_feedback appends rather than truncating.
        append_feedback(&feedback_path, "second").expect("append");
        let appended = std::fs::read_to_string(&feedback_path).expect("appended");
        assert!(appended.contains("second\n----"));
        assert!(appended.matches("----").count() >= 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    fn context_for_rule(rule_id: usize, effect: Effect) -> RuleFeedbackContext {
        RuleFeedbackContext {
            meta: dsl::RuleMeta {
                name: format!("rule-{rule_id}"),
                reason: format!("reason-{rule_id}"),
                effect,
                ops: vec!["exec".to_string()],
                clause_op: "exec".to_string(),
                clause_source_index: 0,
                kernel_op: "exec".to_string(),
                target_kind: dsl::ast::Kind::Exec,
                target_pattern: "git".to_string(),
                target_arg: None,
                source: None,
            },
            labels: HashMap::from([("LOCAL_SECRET".to_string(), 1u64)]),
        }
    }

    #[test]
    fn report_routes_meta_and_labels_and_writes_both_files() {
        // `report` looks up the rule context from the compiled meta and labels
        // and forwards it to `report_with_context`; no base or branch test calls
        // either.
        let dir = tempfile::tempdir().expect("tempdir");
        let feedback = dir.path().join("feedback.txt");
        let events = dir.path().join("events.jsonl");

        let meta = vec![
            context_for_rule(0, Effect::Notify).meta,
            context_for_rule(1, Effect::Kill).meta,
        ];
        let labels = HashMap::from([("LOCAL_SECRET".to_string(), 1u64)]);
        let violation = |rule_id: usize| Violation {
            pid: 10,
            ppid: 1,
            comm: "git".to_string(),
            target: "git".to_string(),
            rule_id,
            op: Some(0),
            domain_id: Some(4),
            session_root: Some(10),
            effect: None,
            blocked: Some(false),
            killed: Some(rule_id == 1),
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

        // In-range rule id -> feedback + event files populated from the meta.
        report(
            &meta,
            &labels,
            &violation(1),
            Some(&feedback),
            Some(&events),
        );
        let fb = std::fs::read_to_string(&feedback).expect("feedback");
        assert!(fb.contains("killed by rule `rule-1`"), "{fb}");
        assert!(fb.contains("acquired label LOCAL_SECRET"), "{fb}");
        let ev = std::fs::read_to_string(&events).expect("events");
        assert!(ev.contains("\"name\":\"rule-1\""));
        assert!(ev.contains("\"action\":\"kill\""));

        // Out-of-range rule id -> no context, so no feedback file is written
        // (the event file still records the raw violation).
        let orphan = dir.path().join("orphan-feedback.txt");
        report(&meta, &labels, &violation(9), Some(&orphan), None);
        assert!(!orphan.exists());
    }

    fn bare_violation(rule_id: usize, op: Option<u32>) -> Violation {
        Violation {
            pid: 10,
            ppid: 1,
            comm: "git".to_string(),
            target: "git".to_string(),
            rule_id,
            op,
            domain_id: Some(23),
            session_root: Some(10),
            effect: None,
            blocked: Some(false),
            killed: Some(false),
            taint_label: 1,
            matched_label: 1,
            matched_labels: Some(1),
            provenance: None,
        }
    }

    #[test]
    fn event_context_without_rule_meta_stays_well_formed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let v = bare_violation(0, Some(9));
        append_violation_event_context(None, &v, &path);
        let text = std::fs::read_to_string(&path).expect("event file");
        let value: serde_json::Value = serde_json::from_str(text.trim()).expect("json line");
        assert_eq!(value["schema"], "actplane.violation.v1");
        assert_eq!(value["rule_id"], 0);
        assert_eq!(value["effect"], "");
        assert_eq!(value["action"], "report");
        assert_eq!(value["op"], "op");
        assert_eq!(value["op_code"], 9);
        assert_eq!(value["rule"], serde_json::Value::Null);
        assert_eq!(value["provenance"], serde_json::Value::Null);
    }
}
