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

/// Build the model-facing corrective-feedback string (docs/feedback-design.md §6).
/// `op`/`target` describe the blocked operation; the rest comes from the rule.
pub fn format_payload(
    name: &str,
    op: &str,
    target: &str,
    reason: &str,
    effect: Effect,
    blocked: bool,
    killed: bool,
    provenance: Option<&Provenance>,
) -> String {
    let enforcement = if killed {
        "kill"
    } else if blocked {
        "block"
    } else if effect == Effect::Block {
        "unsupported"
    } else {
        "report"
    };
    let prov = provenance_line(provenance, op, target);
    let body = match (effect, enforcement) {
        (Effect::Notify, _) => {
            format!(
                "[ActPlane] 操作「{op} {target}」触发了通知规则「{name}」（操作未被拦截）。\n\
                 - 原因：{reason}\n\
                 {prov}\
                 - 建议：后续请避免该操作。"
            )
        }
        (Effect::Block, "block") => {
            format!(
                "[ActPlane] 操作被规则「{name}」拒绝。\n\
                 - 目标操作：{op} {target}\n\
                 - 触发原因：{reason}\n\
                 {prov}\
                 - BPF-LSM 已在内核提交前返回 EPERM；重试相同操作不会成功。\n\
                 - 如何继续：请改用不触发该约束的等价方式完成任务；若确无替代路径，请向用户说明并确认。"
            )
        }
        (Effect::Block, _) => {
            format!(
                "[ActPlane] 规则「{name}」要求 block，但当前 backend 不支持 block。\n\
                 - 目标操作：{op} {target}\n\
                 - 触发原因：{reason}\n\
                 {prov}\
                 - block 只由 BPF-LSM pre-op hook 实现；tracepoint backend 不支持 block，也不会把它降级成 notify 或 kill。\n\
                 - 如何继续：启用 BPF-LSM，或把这条规则改成 notify / kill。"
            )
        }
        (Effect::Kill, _) => {
            format!(
                "[ActPlane] 操作被规则「{name}」终止。\n\
                 - 目标操作：{op} {target}\n\
                 - 触发原因：{reason}\n\
                 {prov}\
                 - 该规则显式要求终止当前违规进程，重试相同操作不会成功。\n\
                 - 如何继续：请停止该路径，改用不触发该约束的等价方式；若确无替代路径，请向用户说明并确认。"
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
        "{{\"actplane_rule\":{},\"effect\":\"{}\",\"enforcement\":\"{}\",\"retry_useful\":{}}}",
        json_str(name),
        tier,
        enforcement,
        retry_useful
    );
    format!("{body}\n{tag}")
}

fn provenance_line(p: Option<&Provenance>, op: &str, target: &str) -> String {
    match p {
        Some(p) => format!(
            "- 污点来源：PID {} 在内核时间戳 {} ns 通过「{} {}」获得 {} label；该 label 随进程状态传播到当前「{} {}」操作。\n",
            p.origin_pid, p.origin_timestamp_ns, p.origin_op, p.origin_target, p.label, op, target
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
        let s = format_payload(
            "no-git",
            "exec",
            "git",
            "no git allowed",
            Effect::Block,
            true,
            false,
            None,
        );
        assert!(s.starts_with("[ActPlane]"));
        assert!(s.contains("\"enforcement\":\"block\""));
        assert!(s.contains("\"retry_useful\":false"));
    }

    #[test]
    fn notify_payload_is_soft() {
        let s = format_payload(
            "t",
            "exec",
            "git",
            "run tests first",
            Effect::Notify,
            false,
            false,
            None,
        );
        assert!(s.contains("run tests first"));
        assert!(s.contains("\"retry_useful\":false"));
    }

    #[test]
    fn block_without_lsm_is_unsupported_not_reported_as_blocked() {
        let s = format_payload(
            "no-git",
            "exec",
            "git",
            "no git allowed",
            Effect::Block,
            false,
            false,
            None,
        );
        assert!(s.contains("当前 backend 不支持 block"));
        assert!(s.contains("\"effect\":\"block\""));
        assert!(s.contains("\"enforcement\":\"unsupported\""));
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
        let s = format_payload(
            "no-secret-exfil",
            "connect",
            "1.2.3.4",
            "secret data must not leave",
            Effect::Kill,
            false,
            true,
            Some(&p),
        );
        assert!(s.contains("PID 1234"));
        assert!(s.contains("通过「read /repo/.env」获得 SECRET label"));
        assert!(s.contains("传播到当前「connect 1.2.3.4」操作"));
    }
}
