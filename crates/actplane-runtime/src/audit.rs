use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::Result;

pub fn policy_hash(src: &str) -> String {
    policy_hash_bytes(src.as_bytes())
}

/// Hash of a policy's lowered kernel config blob. Two policies whose DSL text
/// differs only in whitespace or comments lower to the same matchers and so
/// share this identity, which is what an "effective policy" hash should key on;
/// `policy_hash` over the DSL source remains for layer-provenance records.
pub fn policy_hash_bytes(bytes: &[u8]) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{h:016x}")
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub proc_start_time: Option<u64>,
    pub stable_id: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub comm: Option<String>,
    pub exe: Option<String>,
}

impl ProcessIdentity {
    pub fn capture(pid: i32, uid: Option<u32>, gid: Option<u32>) -> Self {
        let start_time = proc_start_time_for_pid(pid);
        let (status_uid, status_gid) = proc_status_uid_gid(pid);
        Self {
            pid,
            proc_start_time: start_time,
            stable_id: process_stable_id(pid, start_time),
            uid: uid.or(status_uid),
            gid: gid.or(status_gid),
            comm: proc_comm(pid),
            exe: proc_exe(pid),
        }
    }

    pub fn to_json(&self) -> Value {
        json!(self)
    }
}

fn process_stable_id(pid: i32, start_time: Option<u64>) -> String {
    match start_time {
        Some(start) => format!("pid:{pid}:start:{start}"),
        None => format!("pid:{pid}:start:unknown"),
    }
}

fn proc_start_time_for_pid(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(") ")?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn proc_status_uid_gid(pid: i32) -> (Option<u32>, Option<u32>) {
    let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status,
        Err(_) => return (None, None),
    };
    let uid = status_numeric_field(&status, "Uid:");
    let gid = status_numeric_field(&status, "Gid:");
    (uid, gid)
}

fn status_numeric_field(status: &str, key: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix(key)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn proc_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string())
        .filter(|s| !s.is_empty())
}

fn proc_exe(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.display().to_string())
}

/// Resolve the audit log a project's runtime would write, without starting an
/// engine. It mirrors `config::feedback_paths` (`config.rs:440`): the
/// `feedback.audit` key when set, else the latest `.actplane/runs/*/audit.jsonl`
/// when a run exists, else the default `.actplane/audit.jsonl`. A path under
/// `feedback.audit` is resolved against the policy root, so the walk starts at
/// the discovered policy file.
pub fn resolve_log_path(project_dir: &Path) -> std::path::PathBuf {
    let Some(policy) = crate::config::discover_policy(project_dir) else {
        return project_dir.join(crate::config::DEFAULT_AUDIT_FILE);
    };
    let root = policy
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| project_dir.to_path_buf());
    if let Some(path) = latest_run_audit(&root) {
        return path;
    }
    std::fs::read_to_string(&policy)
        .ok()
        .and_then(|src| serde_yaml::from_str::<serde_yaml::Value>(&src).ok())
        .and_then(|yaml| {
            yaml.get("feedback")
                .and_then(|v| v.get("audit"))
                .and_then(|v| v.as_str())
                .map(std::path::PathBuf::from)
        })
        .map(|p| if p.is_absolute() { p } else { root.join(p) })
        .unwrap_or_else(|| root.join(crate::config::DEFAULT_AUDIT_FILE))
}

fn latest_run_audit(root: &Path) -> Option<std::path::PathBuf> {
    let runs = root.join(".actplane").join("runs");
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(runs).ok()?.flatten() {
        let path = entry.path().join("audit.jsonl");
        let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
        candidates.push((modified, path));
    }
    candidates.sort_by_key(|(modified, _)| *modified);
    candidates.pop().map(|(_, path)| path)
}

/// Read an audit log into its records. A malformed line is kept as a JSON
/// string so `record_count` stays the true line count rather than silently
/// dropping the record. A missing file is `Ok(vec![])`; a present but
/// unreadable file is an error.
pub fn read_records(path: &Path) -> Result<Vec<Value>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading {}: {}", path.display(), e).into()),
    };
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| Value::String(l.to_string())))
        .collect())
}

/// One step on the replayed timeline: an audit record reduced to the fields the
/// replay tells a story with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayStep {
    pub kind: ReplayKind,
    /// `timestamp_unix_ns` as a number when the record carried one.
    pub timestamp_ns: Option<i128>,
    pub summary: String,
    /// The record as read, kept so a caller can present more than the summary.
    pub record: Value,
}

/// The kinds of audit record the replay distinguishes. A record whose `event`
/// is unknown keeps its literal name in `summary` and classifies as `Other`, so
/// a new event still appears on the timeline rather than being dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayKind {
    EngineAttach,
    PolicyDelta,
    ChildDomain,
    Violation,
    Delegation,
    GateToken,
    Other,
}

impl ReplayKind {
    fn of(event: &str) -> Self {
        match event {
            "engine_attach" | "attach" => Self::EngineAttach,
            "append_policy_delta" => Self::PolicyDelta,
            "bind_child_domain"
            | "launch_child_domain"
            | "restart_child_domain"
            | "adopt_child_domain" => Self::ChildDomain,
            "taint_violation" => Self::Violation,
            "delegate" => Self::Delegation,
            "issue_gate_token" => Self::GateToken,
            _ => Self::Other,
        }
    }

    /// Short word for the `--json` step objects and the text prefix.
    pub fn label(self) -> &'static str {
        match self {
            Self::EngineAttach => "attach",
            Self::PolicyDelta => "delta",
            Self::ChildDomain => "child",
            Self::Violation => "violation",
            Self::Delegation => "delegate",
            Self::GateToken => "gate_token",
            Self::Other => "other",
        }
    }
}

/// Reduce an audit log to an ordered timeline. Records keep their file order,
/// because the log is append-only and its own order is the causal order when
/// timestamps repeat or a legacy record has none. A record whose timestamp
/// parses as a number beyond `i128` (or as no number at all) simply carries
/// `None` rather than dropping the line.
pub fn replay_steps(records: &[Value]) -> Vec<ReplayStep> {
    records
        .iter()
        .map(|record| {
            let obj = record.as_object();
            let event = obj
                .and_then(|o| o.get("event"))
                .and_then(Value::as_str)
                .unwrap_or("?");
            let kind = ReplayKind::of(event);
            let timestamp_ns = obj.and_then(|o| o.get("timestamp_unix_ns")).and_then(|v| {
                v.as_i64()
                    .map(i128::from)
                    .or_else(|| v.as_str().and_then(|s| s.parse::<i128>().ok()))
            });
            ReplayStep {
                kind,
                timestamp_ns,
                summary: summarize(event, obj),
                record: record.clone(),
            }
        })
        .collect()
}

/// The one-line description of a record: the event name plus the fields that
/// make it legible without the rest of the JSON.
fn summarize(event: &str, obj: Option<&serde_json::Map<String, Value>>) -> String {
    let field = |key: &str| {
        obj.and_then(|o| o.get(key)).map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    };
    let mut parts = vec![event.to_string()];
    if let Some(status) = field("status") {
        parts.push(status);
    }
    match event {
        "append_policy_delta" => {
            if let Some(target) = field("target_id") {
                parts.push(format!("target {target}"));
            }
        }
        "taint_violation" => {
            for (key, prefix) in [("op", ""), ("action", "action "), ("target", "target ")] {
                if let Some(value) = field(key) {
                    parts.push(format!("{prefix}{value}"));
                }
            }
        }
        "bind_child_domain"
        | "launch_child_domain"
        | "restart_child_domain"
        | "adopt_child_domain" => {
            if let Some(pid) = field("pid") {
                parts.push(format!("pid {pid}"));
            }
            if let Some(domain) = field("child_domain_id") {
                parts.push(format!("domain {domain}"));
            }
        }
        "delegate" => {
            if let Some(principal) = field("principal") {
                parts.push(format!("principal {principal}"));
            }
            if let Some(scope) = field("scope") {
                parts.push(format!("scope {scope}"));
            }
            if let Some(workspace) = field("workspace") {
                parts.push(format!("workspace {workspace}"));
            }
            if let Some(contract) = field("contract_ref") {
                parts.push(format!("contract {contract}"));
            }
        }
        "issue_gate_token" => {
            if let Some(token) = field("token") {
                parts.push(format!("token {token}"));
            }
            if let Some(approved_by) = field("approved_by") {
                parts.push(format!("approved_by {approved_by}"));
            }
        }
        _ => {}
    }
    parts.join(" ")
}

pub fn append(path: &Path, mut record: Value) -> Result<()> {
    append_with_schema(path, "actplane.audit.v1", &mut record)
}

pub fn append_with_schema(path: &Path, schema: &str, record: &mut Value) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let Some(obj) = record.as_object_mut() else {
        return Err("JSONL record must be a JSON object".into());
    };
    obj.entry("timestamp_unix_ns")
        .or_insert_with(|| json!(now.to_string()));
    obj.entry("schema").or_insert_with(|| json!(schema));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    serde_json::to_writer(&mut f, &record)?;
    writeln!(f)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_keeps_append_order_and_classifies_each_event() {
        // The log is append-only, so its line order is the causal order and the
        // replay must not re-sort on timestamps that repeat or are missing. An
        // unknown event still gets a step, because a reader watching the
        // timeline should not have a record silently vanish when a producer
        // adds one.
        let records = vec![
            json!({"event": "engine_attach", "timestamp_unix_ns": "5"}),
            json!({"event": "append_policy_delta", "status": "accepted", "target_id": 42,
                   "timestamp_unix_ns": "5"}),
            json!({"event": "taint_violation", "op": "open", "action": "block",
                   "target": "/etc/shadow"}),
            json!({"event": "brand_new_event", "timestamp_unix_ns": 9}),
            Value::String("not json".to_string()),
        ];
        let steps = replay_steps(&records);

        assert_eq!(steps.len(), 5);
        assert_eq!(steps[0].kind, ReplayKind::EngineAttach);
        assert_eq!(steps[1].kind, ReplayKind::PolicyDelta);
        assert_eq!(steps[2].kind, ReplayKind::Violation);
        assert_eq!(steps[3].kind, ReplayKind::Other);
        assert_eq!(steps[4].kind, ReplayKind::Other);
        assert_eq!(steps[0].timestamp_ns, Some(5));
        assert_eq!(steps[2].timestamp_ns, None);
        assert_eq!(steps[1].summary, "append_policy_delta accepted target 42");
        assert_eq!(
            steps[2].summary,
            "taint_violation open action block target /etc/shadow"
        );
        assert_eq!(steps[3].summary, "brand_new_event");
        // The unparsed line keeps its step and its raw text.
        assert_eq!(steps[4].summary, "?");
        assert_eq!(steps[4].record, Value::String("not json".to_string()));
    }

    #[test]
    fn replay_classifies_the_delegate_record() {
        // `delegate` records are first-class timeline steps: a record written
        // by `actplane delegate` must classify as Delegation, not fall through
        // to Other, and its summary must name the principal, the scope label,
        // and the contract ref (each only when the record carries it).
        let records = vec![
            json!({"event": "delegate", "status": "accepted", "principal": "reviewer",
                   "scope": "readonly", "contract_ref": "template `readonly-review`",
                   "timestamp_unix_ns": "5"}),
            json!({"event": "delegate", "status": "accepted", "principal": "builder",
                   "workspace": "/work/repo", "contract_ref": "template `workspace-confinement`",
                   "timestamp_unix_ns": "6"}),
            json!({"event": "delegate", "status": "rejected", "principal": "builder",
                   "error": "template `x` failed"}),
        ];
        let steps = replay_steps(&records);

        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].kind, ReplayKind::Delegation);
        assert_eq!(steps[1].kind, ReplayKind::Delegation);
        assert_eq!(steps[2].kind, ReplayKind::Delegation);
        assert_eq!(ReplayKind::Delegation.label(), "delegate");
        assert_eq!(
            steps[0].summary,
            "delegate accepted principal reviewer scope readonly contract template `readonly-review`"
        );
        // A workspace confinement renders between the scope label and the
        // contract ref, and a bare principal (no scope/workspace) shows only
        // the principal and status.
        assert_eq!(
            steps[1].summary,
            "delegate accepted principal builder workspace /work/repo contract template `workspace-confinement`"
        );
        // No scope, workspace, or contract ref on the rejected record, so the
        // summary stops after the status; the error field is not part of it.
        assert_eq!(steps[2].summary, "delegate rejected principal builder");
    }

    #[test]
    fn replay_classifies_the_gate_token_record() {
        // `issue_gate_token` records are first-class timeline steps: a record
        // written by `actplane control gate issue` must classify as GateToken,
        // not fall through to Other, and its summary must name the token and
        // the approver (the approver only when the record carries it).
        let records = vec![
            json!({"event": "issue_gate_token", "status": "accepted",
                   "token": "GATE-123", "approved_by": "alice",
                   "timestamp_unix_ns": "7"}),
            json!({"event": "issue_gate_token", "status": "accepted",
                   "token": "GATE-456"}),
        ];
        let steps = replay_steps(&records);

        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].kind, ReplayKind::GateToken);
        assert_eq!(steps[1].kind, ReplayKind::GateToken);
        assert_eq!(ReplayKind::GateToken.label(), "gate_token");
        assert_eq!(
            steps[0].summary,
            "issue_gate_token accepted token GATE-123 approved_by alice"
        );
        // No approver on the second record, so the summary stops after the
        // token.
        assert_eq!(steps[1].summary, "issue_gate_token accepted token GATE-456");
    }
    #[test]
    fn audit_appends_jsonl_with_schema_and_timestamp() {
        let path =
            std::env::temp_dir().join(format!("actplane-audit-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);

        append(
            &path,
            json!({
                "event": "append_policy_delta",
                "status": "accepted",
                "target_id": 42
            }),
        )
        .expect("append audit");

        let text = std::fs::read_to_string(&path).expect("read audit");
        let value: Value = serde_json::from_str(text.trim()).expect("json line");
        assert_eq!(value["schema"], "actplane.audit.v1");
        assert_eq!(value["event"], "append_policy_delta");
        assert_eq!(value["status"], "accepted");
        assert_eq!(value["target_id"], 42);
        assert!(value["timestamp_unix_ns"].as_str().is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_hash_is_stable_and_content_sensitive() {
        assert_eq!(policy_hash("abc"), policy_hash("abc"));
        assert_ne!(policy_hash("abc"), policy_hash("abcd"));
        assert!(policy_hash("abc").starts_with("fnv1a64:"));
    }

    #[test]
    fn process_identity_uses_proc_start_time_when_available() {
        let pid = std::process::id() as i32;
        let identity = ProcessIdentity::capture(pid, None, None);
        assert_eq!(identity.pid, pid);
        assert!(identity.stable_id.starts_with(&format!("pid:{pid}:start:")));
        assert!(identity.comm.as_deref().is_some());
    }

    #[test]
    fn process_identity_prefers_peer_uid_gid() {
        let pid = std::process::id() as i32;
        let identity = ProcessIdentity::capture(pid, Some(123), Some(456));
        assert_eq!(identity.uid, Some(123));
        assert_eq!(identity.gid, Some(456));
    }

    #[test]
    fn status_numeric_field_reads_first_status_number() {
        let status = "Name:\ttest\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n";
        assert_eq!(status_numeric_field(status, "Uid:"), Some(1000));
        assert_eq!(status_numeric_field(status, "Gid:"), Some(1001));
        assert_eq!(status_numeric_field(status, "Nope:"), None);
    }

    #[test]
    fn read_records_keeps_malformed_lines_and_counts_true_total() {
        // The CLI and the `actplane:///audit` resource both go through this, so
        // a malformed line must not be dropped: `record_count` stays the true
        // line count and the bad line survives as a JSON string, so a client
        // sees a gap rather than a shorter clean history.
        let path =
            std::env::temp_dir().join(format!("actplane-audit-read-{}.jsonl", std::process::id()));
        std::fs::write(&path, "{\"event\":\"a\"}\n\nnot json\n{\"event\":\"b\"}\n")
            .expect("write log");

        let records = read_records(&path).expect("read records");
        assert_eq!(records.len(), 3, "{records:?}");
        assert_eq!(records[0]["event"], "a");
        assert_eq!(records[1], Value::String("not json".into()));
        assert_eq!(records[2]["event"], "b");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_records_treats_a_missing_file_as_empty() {
        let path = std::env::temp_dir().join(format!(
            "actplane-audit-missing-{}-{}.jsonl",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&path);
        assert!(read_records(&path).expect("missing is empty").is_empty());
    }

    #[test]
    fn resolve_log_path_prefers_the_latest_run_log() {
        // The resolver must match the runtime's scoped path (runtime.rs
        // `scoped_feedback_paths`) rather than the default, so the CLI and the
        // MCP resource read the log the engine actually wrote.
        let project_dir = std::env::temp_dir().join(format!(
            "actplane-audit-resolve-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&project_dir).expect("project dir");
        std::fs::write(
            project_dir.join("actplane.yaml"),
            "version: 1\npolicy: |\n  rule noop:\n    notify exec \"__never__\"\n    because \"noop\"\n",
        )
        .expect("policy");
        let run_dir = project_dir.join(".actplane").join("runs").join("run-1");
        std::fs::create_dir_all(&run_dir).expect("run dir");
        std::fs::write(run_dir.join("audit.jsonl"), "{\"event\":\"a\"}\n").expect("run log");

        let resolved = resolve_log_path(&project_dir);
        assert_eq!(resolved, run_dir.join("audit.jsonl"));

        let _ = std::fs::remove_dir_all(project_dir);
    }
}
