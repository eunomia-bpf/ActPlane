// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! Corrective-feedback payload (docs/feedback-design.md §6).
//!
//! Turns a violation the *kernel* detected (rule + target, looked up via
//! `RuleMeta`) into the model-facing, actionable feedback string written to the
//! `--feedback-file` reason file (channel a1). The kernel — eBPF taint
//! propagation + LSM — is the sole detector; this module only formats what it
//! reports. There is no userspace re-detection here.

use crate::dsl::ast::Effect;

/// Build the model-facing corrective-feedback string (docs/feedback-design.md §6).
/// `op`/`target` describe the blocked operation; the rest comes from the rule.
pub fn format_payload(
    name: &str,
    op: &str,
    target: &str,
    reason: &str,
    remediation: Option<&str>,
    effect: Effect,
) -> String {
    let body = match effect {
        Effect::Audit => {
            let rem = remediation.unwrap_or("后续请避免该操作");
            format!(
                "[ActPlane] 操作「{op} {target}」触发了审计规则「{name}」（操作未被拦截）。\n\
                 - 原因：{reason}\n\
                 - 建议：{rem}。"
            )
        }
        Effect::Block => {
            let rem = remediation.unwrap_or(
                "请改用不触发该约束的等价方式完成任务；若确无替代路径，请向用户说明并确认",
            );
            format!(
                "[ActPlane] 操作被规则「{name}」拒绝。\n\
                 - 目标操作：{op} {target}\n\
                 - 触发原因：{reason}\n\
                 - 这是一条 OS 层 harness 约束，无论用工具、bash 还是直接调用都会失败，重试相同操作不会成功。\n\
                 - 如何继续：{rem}。"
            )
        }
        Effect::Kill => {
            let rem = remediation.unwrap_or(
                "请停止该路径，改用不触发该约束的等价方式；若确无替代路径，请向用户说明并确认",
            );
            format!(
                "[ActPlane] 操作被规则「{name}」终止。\n\
                 - 目标操作：{op} {target}\n\
                 - 触发原因：{reason}\n\
                 - 该规则会终止当前违规进程，重试相同操作不会成功。\n\
                 - 如何继续：{rem}。"
            )
        }
    };
    let tier = match effect {
        Effect::Audit => "audit",
        Effect::Block => "block",
        Effect::Kill => "kill",
    };
    // "retry_useful" means retrying the same operation as-is. Audit already
    // succeeded, and block/kill need a different path or a satisfied gate.
    let retry_useful = false;
    // §6.6: a machine-readable copy for SDK / supervisor consumption.
    let tag = format!(
        "{{\"actplane_rule\":{},\"effect\":\"{}\",\"enforcement\":\"{}\",\"retry_useful\":{}}}",
        json_str(name),
        tier,
        tier,
        retry_useful
    );
    format!("{body}\n{tag}")
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
            None,
            Effect::Block,
        );
        assert!(s.starts_with("[ActPlane]"));
        assert!(s.contains("\"enforcement\":\"block\""));
        assert!(s.contains("\"retry_useful\":false"));
    }

    #[test]
    fn audit_payload_is_soft() {
        let s = format_payload(
            "t",
            "exec",
            "git",
            "run tests",
            Some("先跑 pytest"),
            Effect::Audit,
        );
        assert!(s.contains("先跑 pytest"));
        assert!(s.contains("\"retry_useful\":false"));
    }
}
