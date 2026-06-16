// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! Corrective-feedback payload (docs/feedback-design.md §6).
//!
//! Turns a violation the *kernel* detected (rule + target, looked up via
//! `RuleMeta`) into the model-facing, actionable feedback string written to the
//! `actplane run` feedback file (channel a1). The kernel — eBPF taint
//! propagation + LSM — is the sole detector; this module only formats what it
//! reports. There is no userspace re-detection here.

use crate::dsl::ast::Effect;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub label: String,
    pub origin_pid: i32,
    pub origin_op: String,
    pub origin_target: String,
    pub origin_timestamp_ns: u64,
}

pub struct PayloadInput<'a> {
    pub name: &'a str,
    pub op: &'a str,
    pub target: &'a str,
    pub reason: &'a str,
    pub effect: Effect,
    pub blocked: bool,
    pub killed: bool,
    pub provenance: Option<&'a Provenance>,
}

/// Build the model-facing corrective-feedback string (docs/feedback-design.md §6).
/// `op`/`target` describe the blocked operation; the rest comes from the rule.
pub fn format_payload(input: PayloadInput<'_>) -> String {
    let PayloadInput {
        name,
        op,
        target,
        reason,
        effect,
        blocked,
        killed,
        provenance,
    } = input;
    let action = if killed {
        "kill"
    } else if blocked {
        "block"
    } else if effect == Effect::Block {
        "unsupported"
    } else {
        "report"
    };
    let prov = provenance_line(provenance, op, target);
    let body = match (effect, action) {
        (Effect::Notify, _) => {
            format!(
                "[ActPlane] Operation `{op} {target}` matched notify rule `{name}`. The operation was not blocked.\n\
                 - Reason: {reason}\n\
                 {prov}\
                 - Next step: avoid repeating this action unchanged; choose a compliant alternative."
            )
        }
        (Effect::Block, "block") => {
            format!(
                "[ActPlane] Operation blocked by rule `{name}`.\n\
                 - Target operation: {op} {target}\n\
                 - Reason: {reason}\n\
                 {prov}\
                 - The BPF-LSM hook returned EPERM before the operation committed; retrying the same operation will not succeed.\n\
                 - Next step: use an equivalent path that satisfies the policy, or explain to the user why no compliant alternative exists."
            )
        }
        (Effect::Block, _) => {
            format!(
                "[ActPlane] Rule `{name}` requested block, but this backend cannot block the operation.\n\
                 - Target operation: {op} {target}\n\
                 - Reason: {reason}\n\
                 {prov}\
                 - Blocking requires the BPF-LSM pre-operation hook; this backend did not downgrade the rule to notify or kill.\n\
                 - Next step: enable BPF-LSM or change this rule to notify/kill."
            )
        }
        (Effect::Kill, _) => {
            format!(
                "[ActPlane] Operation killed by rule `{name}`.\n\
                 - Target operation: {op} {target}\n\
                 - Reason: {reason}\n\
                 {prov}\
                 - The policy terminated the violating process; retrying the same operation will not succeed.\n\
                 - Next step: stop this path and use a compliant alternative, or explain to the user why no compliant alternative exists."
            )
        }
    };
    let tier = match effect {
        Effect::Notify => "notify",
        Effect::Block => "block",
        Effect::Kill => "kill",
    };
    // "retry_useful" means retrying the same operation as-is. Notify already
    // succeeded, and block/kill need a different path or a satisfied gate.
    let retry_useful = false;
    // §6.6: a machine-readable copy for SDK / supervisor consumption.
    let tag = format!(
        "{{\"actplane_rule\":{},\"effect\":\"{}\",\"action\":\"{}\",\"retry_useful\":{}}}",
        json_str(name),
        tier,
        action,
        retry_useful
    );
    format!("{body}\n{tag}")
}

fn provenance_line(p: Option<&Provenance>, op: &str, target: &str) -> String {
    match p {
        Some(p) => format!(
            "- Provenance: PID {} acquired label {} at kernel timestamp {} ns via `{}` `{}`; that label propagated through process state to the current `{}` `{}` operation.\n",
            p.origin_pid, p.label, p.origin_timestamp_ns, p.origin_op, p.origin_target, op, target
        ),
        None => String::new(),
    }
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_has_prefix_and_tag() {
        let s = format_payload(PayloadInput {
            name: "no-git",
            op: "exec",
            target: "git",
            reason: "no git allowed",
            effect: Effect::Block,
            blocked: true,
            killed: false,
            provenance: None,
        });
        assert!(s.starts_with("[ActPlane]"));
        assert!(s.contains("\"action\":\"block\""));
        assert!(s.contains("\"retry_useful\":false"));
    }

    #[test]
    fn notify_payload_is_soft() {
        let s = format_payload(PayloadInput {
            name: "t",
            op: "exec",
            target: "git",
            reason: "run tests first",
            effect: Effect::Notify,
            blocked: false,
            killed: false,
            provenance: None,
        });
        assert!(s.contains("run tests first"));
        assert!(s.contains("\"retry_useful\":false"));
    }

    #[test]
    fn block_without_lsm_is_unsupported_not_reported_as_blocked() {
        let s = format_payload(PayloadInput {
            name: "no-git",
            op: "exec",
            target: "git",
            reason: "no git allowed",
            effect: Effect::Block,
            blocked: false,
            killed: false,
            provenance: None,
        });
        assert!(s.contains("this backend cannot block"));
        assert!(s.contains("\"effect\":\"block\""));
        assert!(s.contains("\"action\":\"unsupported\""));
    }

    #[test]
    fn payload_includes_taint_provenance() {
        let p = Provenance {
            label: "SECRET".to_string(),
            origin_pid: 1234,
            origin_op: "read".to_string(),
            origin_target: "/repo/.env".to_string(),
            origin_timestamp_ns: 42,
        };
        let s = format_payload(PayloadInput {
            name: "no-secret-exfil",
            op: "connect",
            target: "1.2.3.4",
            reason: "secret data must not leave",
            effect: Effect::Kill,
            blocked: false,
            killed: true,
            provenance: Some(&p),
        });
        assert!(s.contains("PID 1234"));
        assert!(s.contains("acquired label SECRET"));
        assert!(s.contains("current `connect` `1.2.3.4` operation"));
    }
}
