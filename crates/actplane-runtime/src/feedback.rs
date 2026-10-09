// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! Corrective-feedback payload (docs/design/feedback-design.md).
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

/// Build the model-facing corrective-feedback string (docs/design/feedback-design.md).
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

/// Resolve the feedback file the runtime would write, without starting an
/// engine. It honors the same `ACTPLANE_FEEDBACK_FILE` override the hook uses
/// (`hook.rs:37`), then prefers the newest `.actplane/runs/*/feedback.txt` the
/// runtime writes (`runtime.rs:1750` `scoped_feedback_paths`), then the
/// `feedback.path` config key, then the default. This is the same shape as
/// `audit::resolve_log_path`, so the two run artifacts resolve together.
pub fn resolve_file_path(project_dir: &std::path::Path) -> std::path::PathBuf {
    if let Ok(path) = std::env::var("ACTPLANE_FEEDBACK_FILE") {
        if !path.trim().is_empty() {
            return std::path::PathBuf::from(path);
        }
    }
    let Some(policy) = crate::config::discover_policy(project_dir) else {
        return project_dir.join(crate::config::DEFAULT_FEEDBACK_FILE);
    };
    let root = policy
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| project_dir.to_path_buf());
    if let Some(path) = latest_run_feedback(&root) {
        return path;
    }
    std::fs::read_to_string(&policy)
        .ok()
        .and_then(|src| serde_yaml::from_str::<serde_yaml::Value>(&src).ok())
        .and_then(|yaml| {
            yaml.get("feedback")
                .and_then(|v| v.get("path"))
                .and_then(|v| v.as_str())
                .map(std::path::PathBuf::from)
        })
        .map(|p| if p.is_absolute() { p } else { root.join(p) })
        .unwrap_or_else(|| root.join(crate::config::DEFAULT_FEEDBACK_FILE))
}

fn latest_run_feedback(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let runs = root.join(".actplane").join("runs");
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(runs).ok()?.flatten() {
        let path = entry.path().join("feedback.txt");
        let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
        candidates.push((modified, path));
    }
    candidates.sort_by_key(|(modified, _)| *modified);
    candidates.pop().map(|(_, path)| path)
}

/// The structured fields of one corrective-feedback payload.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedFeedback {
    pub rule: Option<String>,
    pub effect: Option<String>,
    pub action: Option<String>,
    pub retry_useful: Option<bool>,
    /// The human-readable payload, with the machine-readable tag line removed.
    pub body: String,
}

/// Split the append-only feedback file into its payloads. `append_feedback`
/// (`report.rs:396`) writes each payload followed by a `----` separator on its
/// own line, so a blank separator line never ends an entry.
pub fn read_entries(path: &std::path::Path) -> crate::Result<Vec<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading {}: {}", path.display(), e).into()),
    };
    let mut entries = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.trim() == "----" {
            if !current.trim().is_empty() {
                entries.push(std::mem::take(&mut current));
            }
            current.clear();
            continue;
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.trim().is_empty() {
        entries.push(current);
    }
    Ok(entries)
}

/// Parse the machine-readable tag `format_payload` appends (the trailing
/// `{"actplane_rule":...}` line) out of a payload, leaving the prose in
/// `body`.
pub fn parse_entry(entry: &str) -> ParsedFeedback {
    let trimmed = entry.trim_end();
    let mut parsed = ParsedFeedback {
        body: trimmed.to_string(),
        ..ParsedFeedback::default()
    };
    let Some((body, tag)) = trimmed.rsplit_once('\n') else {
        return parsed;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(tag.trim()) else {
        return parsed;
    };
    if value.get("actplane_rule").is_none() {
        return parsed;
    }
    parsed.rule = value
        .get("actplane_rule")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    parsed.effect = value
        .get("effect")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    parsed.action = value
        .get("action")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    parsed.retry_useful = value.get("retry_useful").and_then(|v| v.as_bool());
    parsed.body = body.trim_end().to_string();
    parsed
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
    fn machine_tag_carries_no_process_identity() {
        // docs/design/feedback-design.md: the violating process's own comm and
        // pid live in the `.actplane/events.jsonl` event record, not the
        // trailing machine tag. Guard the tag's key set so the doc sentence
        // stays true when the tag grows.
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
        let tag = s.lines().last().expect("trailing tag line");
        let value: serde_json::Value = serde_json::from_str(tag).expect("tag is one JSON object");
        let mut keys: Vec<&str> = value
            .as_object()
            .expect("tag object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["action", "actplane_rule", "effect", "retry_useful"]);
        assert!(value.get("pid").is_none() && value.get("comm").is_none());
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

    #[test]
    fn read_entries_splits_payloads_on_the_separator_only() {
        // `append_feedback` writes `{payload}\n----\n`, so one payload spans its
        // own blank lines and only the `----` line ends an entry. Parsing a
        // blank line as a boundary would truncate the payload the agent reads.
        let path = std::env::temp_dir().join(format!(
            "actplane-feedback-entries-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "first line\n\nsecond line\n----\nthird line\n----\n")
            .expect("write feedback");
        let entries = read_entries(&path).expect("read entries");
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0], "first line\n\nsecond line\n");
        assert_eq!(entries[1], "third line\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_entry_extracts_the_machine_tag_and_keeps_the_prose() {
        let payload = format_payload(PayloadInput {
            name: "no-git-branch",
            op: "exec",
            target: "git branch",
            reason: "create a branch via the host",
            effect: Effect::Block,
            blocked: true,
            killed: false,
            provenance: None,
        });
        let parsed = parse_entry(&payload);
        assert_eq!(parsed.rule.as_deref(), Some("no-git-branch"));
        assert_eq!(parsed.effect.as_deref(), Some("block"));
        assert_eq!(parsed.action.as_deref(), Some("block"));
        assert_eq!(parsed.retry_useful, Some(false));
        assert!(parsed.body.contains("blocked by rule `no-git-branch`"));
        // The tag line itself is stripped from the prose.
        assert!(!parsed.body.contains("\"actplane_rule\""));
    }

    #[test]
    fn parse_entry_leaves_an_untagged_payload_alone() {
        let parsed = parse_entry("plain feedback without a tag");
        assert_eq!(parsed.rule, None);
        assert_eq!(parsed.body, "plain feedback without a tag");
    }
}
