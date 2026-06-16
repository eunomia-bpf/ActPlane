use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::Result;

pub fn policy_hash(src: &str) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for b in src.as_bytes() {
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
}
