// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane MCP server — watches `actplane.yaml` for changes, validates the
//! policy on every save, exposes the latest feedback file, and pushes updates
//! to the MCP client via resource updates and logging notifications.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};

use rmcp::model::*;
use rmcp::transport::io::stdio;
use rmcp::{Peer, RoleServer, ServerHandler, ServiceExt};
use serde_json::Value;

use crate::control as local_control;
use crate::runtime::{EngineControl, PolicyAuditMeta, mark_non_stdio_fds_cloexec};
use crate::{audit, dsl};
use ebpf_ifc_engine::ChildDomainSpec;
use ebpf_ifc_engine::capability::{AUTH_BIND_RULE, TARGET_SELF};

const POLICY_RESOURCE_URI: &str = "actplane:///policy";
const FEEDBACK_RESOURCE_URI: &str = "actplane:///feedback";
const DEFAULT_FEEDBACK_FILE: &str = ".actplane/last-violation.txt";
const WATCH_INTERVAL: Duration = Duration::from_secs(2);
const SUPERVISOR_INTERVAL: Duration = Duration::from_millis(500);
const DEFAULT_RESTART_LIMIT: u32 = 3;
const DEFAULT_RESTART_BACKOFF_MS: u64 = 1000;

// ── Server state ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ActPlaneMcp {
    project_dir: PathBuf,
    control: Option<Arc<EngineControl>>,
    children: Arc<Mutex<HashMap<u32, ChildRecord>>>,
}

#[derive(Clone)]
struct ChildRecord {
    launch_id: String,
    pid: i32,
    child_id: u32,
    scope_id: u32,
    cmd: Vec<String>,
    stdout: PathBuf,
    stderr: PathBuf,
    meta: PathBuf,
    proc_start_time: Option<u64>,
    policy: Option<String>,
    policy_audit_meta: PolicyAuditMeta,
    restart_policy: RestartPolicy,
    restart_count: u32,
    restart_limit: u32,
    restart_backoff_ms: u64,
    last_exit_unix_ms: Option<u64>,
    restart_alerted_unix_ms: Option<u64>,
    adopted_unix_ms: Option<u64>,
    restarted_from: Option<u32>,
    replacement_child_id: Option<u32>,
    status: Arc<Mutex<ChildStatus>>,
}

struct LaunchOutcome {
    pid: i32,
    child_id: u32,
}

#[derive(Clone, Copy)]
struct RestartSettings {
    policy: RestartPolicy,
    count: u32,
    limit: u32,
    backoff_ms: u64,
}

pub struct ActPlaneControlGuard {
    _control: local_control::LocalControlGuard,
    _supervisor: SupervisorGuard,
}

struct SupervisorGuard {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for SupervisorGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestartPolicy {
    Never,
    OnExit,
}

impl RestartPolicy {
    fn as_str(self) -> &'static str {
        match self {
            RestartPolicy::Never => "never",
            RestartPolicy::OnExit => "on_exit",
        }
    }
}

impl ChildRecord {
    fn next_restart_settings(&self) -> RestartSettings {
        RestartSettings {
            policy: self.restart_policy,
            count: self.restart_count.saturating_add(1),
            limit: self.restart_limit,
            backoff_ms: self.restart_backoff_ms,
        }
    }

    fn next_restart_after_unix_ms(&self) -> Option<u64> {
        if self.restart_policy != RestartPolicy::OnExit || self.replacement_child_id.is_some() {
            return None;
        }
        self.last_exit_unix_ms
            .map(|t| t.saturating_add(self.restart_backoff_ms))
    }
}

#[derive(Clone)]
enum ChildStatus {
    Running,
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
    Terminated,
}

impl ActPlaneMcp {
    pub fn new_with_control_and_project_dir(
        control: Option<Arc<EngineControl>>,
        project_dir: Option<PathBuf>,
    ) -> Self {
        let project_dir = project_dir.unwrap_or_else(default_project_dir);
        let loaded = load_child_records_with_adoptions(&project_dir);
        let adopted = loaded.adopted;
        let this = Self {
            project_dir,
            control,
            children: Arc::new(Mutex::new(loaded.records)),
        };
        if let Some(control) = this.control.as_ref() {
            for record in adopted {
                let _ = control.audit_child_adoption(
                    record.pid,
                    record.child_id,
                    &record.cmd,
                    record.policy.is_some(),
                    record.restart_policy.as_str(),
                    record.restart_count,
                    record.restart_limit,
                    record.adopted_unix_ms,
                );
            }
        }
        this
    }

    fn discover_policy_file(&self) -> Option<PathBuf> {
        let candidates = ["actplane.yaml", ".actplane/policy.yaml"];
        let mut dir = Some(self.project_dir.as_path());
        while let Some(d) = dir {
            for name in &candidates {
                let p = d.join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
            dir = d.parent();
        }
        None
    }

    fn load_and_validate(&self) -> String {
        let path = match self.discover_policy_file() {
            Some(p) => p,
            None => return "No actplane.yaml found.".into(),
        };
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => return format!("Cannot read {}: {}", path.display(), e),
        };
        let config: serde_yaml::Value = match serde_yaml::from_str(&src) {
            Ok(v) => v,
            Err(e) => return format!("YAML parse error in {}: {}", path.display(), e),
        };
        let dsl_src = match config.get("policy").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return format!("{} has no `policy:` field", path.display()),
        };
        match dsl::compile_str(dsl_src) {
            Ok(compiled) => {
                let mut out = format!(
                    "Policy valid ({}, {} rules):\n",
                    path.display(),
                    compiled.meta.len()
                );
                for (i, m) in compiled.meta.iter().enumerate() {
                    let eff = format!("{:?}", m.effect).to_lowercase();
                    let ops = if m.ops.is_empty() {
                        "—".into()
                    } else {
                        m.ops.join("/")
                    };
                    out.push_str(&format!(
                        "  {}. {} — {} {} ({})\n",
                        i + 1,
                        m.name,
                        eff,
                        ops,
                        m.reason
                    ));
                }
                out
            }
            Err(e) => format!("Policy compile error: {}", e),
        }
    }

    fn feedback_file(&self) -> PathBuf {
        if let Ok(path) = std::env::var("ACTPLANE_FEEDBACK_FILE") {
            return PathBuf::from(path);
        }
        let Some(policy) = self.discover_policy_file() else {
            return self.project_dir.join(DEFAULT_FEEDBACK_FILE);
        };
        let root = policy
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.project_dir.clone());
        let Ok(src) = std::fs::read_to_string(&policy) else {
            return root.join(DEFAULT_FEEDBACK_FILE);
        };
        let Ok(config) = serde_yaml::from_str::<serde_yaml::Value>(&src) else {
            return root.join(DEFAULT_FEEDBACK_FILE);
        };
        if let Some(path) = latest_run_feedback(&root) {
            return path;
        }
        config
            .get("feedback")
            .and_then(|v| v.get("path"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .map(|p| if p.is_absolute() { p } else { root.join(p) })
            .unwrap_or_else(|| root.join(DEFAULT_FEEDBACK_FILE))
    }

    fn load_feedback(&self) -> String {
        let path = self.feedback_file();
        match std::fs::read_to_string(&path) {
            Ok(s) if !s.trim().is_empty() => {
                format!("Latest ActPlane feedback ({}):\n{}", path.display(), s)
            }
            Ok(_) => format!(
                "No ActPlane feedback has been written yet ({}).",
                path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                format!("No ActPlane feedback file yet ({}).", path.display())
            }
            Err(e) => format!("Cannot read {}: {}", path.display(), e),
        }
    }

    fn policy_mtime(&self) -> Option<SystemTime> {
        self.discover_policy_file()
            .and_then(|p| std::fs::metadata(&p).ok())
            .and_then(|m| m.modified().ok())
    }

    fn feedback_mtime(&self) -> Option<SystemTime> {
        std::fs::metadata(self.feedback_file())
            .ok()
            .and_then(|m| m.modified().ok())
    }

    fn do_bind_child_domain(
        &self,
        args: Option<serde_json::Map<String, Value>>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let control = self.control.as_ref().ok_or_else(|| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                "No eBPF engine attached (MCP not started with --auto-attach-parent)",
                None::<Value>,
            )
        })?;
        if !control.parent_domain_allows_runtime_mutation() {
            return Err(invalid_params(
                control.parent_domain_mutation_error("bind child domain"),
            ));
        }
        let args = args.unwrap_or_default();
        let pid = json_i32(&args, "pid")?;
        if pid <= 0 {
            return Err(invalid_params("pid must be positive"));
        }
        let child_id = match json_optional_u32(&args, "child_id")? {
            Some(id) => id,
            None => pid as u32,
        };
        let scope_id = json_optional_u32(&args, "scope_id")?.unwrap_or(0);
        control
            .bind_child_domain(ChildDomainSpec {
                parent_pid: control.parent_pid,
                parent_id: control.parent_domain_id,
                child_id,
                pid,
                scope_id,
                authority_mask: AUTH_BIND_RULE,
                target_mask: TARGET_SELF,
                ..ChildDomainSpec::default()
            })
            .map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Bind child domain failed: {e}"),
                    None::<Value>,
                )
            })?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Bound pid {pid} to child domain {child_id} under parent domain {}",
            control.parent_domain_id
        ))]))
    }

    fn do_append_policy_delta(
        &self,
        args: Option<serde_json::Map<String, Value>>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.do_append_policy_delta_for_actor(args, None, None)
    }

    fn do_append_policy_delta_for_actor(
        &self,
        args: Option<serde_json::Map<String, Value>>,
        actor_pid: Option<i32>,
        actor_identity: Option<crate::audit::ProcessIdentity>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let control = self.control.as_ref().ok_or_else(|| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                "No eBPF engine attached (MCP not started with --auto-attach-parent)",
                None::<Value>,
            )
        })?;
        let args = args.unwrap_or_default();
        let target_id = match json_optional_u32(&args, "target_id")? {
            Some(id) => id,
            None => json_optional_u32(&args, "domain_id")?.unwrap_or(control.parent_domain_id),
        };
        if target_id == 0 {
            return Err(invalid_params("target_id must be nonzero"));
        }
        if target_id == control.parent_domain_id && !control.parent_domain_allows_runtime_mutation()
        {
            return Err(invalid_params(
                control.parent_domain_mutation_error("append policy delta"),
            ));
        }
        let policy = json_string(&args, "policy")?;
        let audit_meta = policy_audit_meta_from_args(&args)?;
        let actor_pid = actor_pid.unwrap_or(control.submitter_pid());
        let (base, n_rules) = control
            .append_policy_delta_dsl_for_actor_with_identity_and_audit(
                actor_pid,
                actor_identity,
                target_id,
                policy,
                &audit_meta,
            )
            .map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Append policy delta failed: {e}"),
                    None::<Value>,
                )
            })?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Appended policy delta to domain {target_id}: {n_rules} rule metadata entries starting at rule_id {base}"
        ))]))
    }

    fn do_launch_child_domain(
        &self,
        args: Option<serde_json::Map<String, Value>>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args = args.unwrap_or_default();
        let cmd = json_string_vec(&args, "cmd")?;
        if cmd.is_empty() {
            return Err(invalid_params("cmd must not be empty"));
        }
        let child_id = json_optional_u32(&args, "child_id")?;
        let scope_id = json_optional_u32(&args, "scope_id")?.unwrap_or(0);
        let policy = json_optional_string(&args, "policy")?.map(ToString::to_string);
        let policy_audit_meta = if policy.is_some() {
            policy_audit_meta_from_args(&args)?
        } else {
            PolicyAuditMeta::default()
        };
        let restart_policy =
            json_optional_restart_policy(&args, "restart_policy")?.unwrap_or(RestartPolicy::Never);
        let restart_limit =
            json_optional_u32(&args, "restart_limit")?.unwrap_or(DEFAULT_RESTART_LIMIT);
        let restart_backoff_ms =
            json_optional_u64(&args, "restart_backoff_ms")?.unwrap_or(DEFAULT_RESTART_BACKOFF_MS);
        let outcome = self.launch_child_domain_inner(
            cmd,
            child_id,
            scope_id,
            policy,
            policy_audit_meta,
            None,
            RestartSettings {
                policy: restart_policy,
                count: 0,
                limit: restart_limit,
                backoff_ms: restart_backoff_ms,
            },
        )?;

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Launched pid {} in child domain {}",
            outcome.pid, outcome.child_id
        ))]))
    }

    fn launch_child_domain_inner(
        &self,
        cmd: Vec<String>,
        child_id: Option<u32>,
        scope_id: u32,
        policy: Option<String>,
        policy_audit_meta: PolicyAuditMeta,
        restarted_from: Option<u32>,
        restart: RestartSettings,
    ) -> Result<LaunchOutcome, rmcp::ErrorData> {
        let control = self.control.as_ref().ok_or_else(|| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                "No eBPF engine attached (MCP not started with --auto-attach-parent)",
                None::<Value>,
            )
        })?;
        if !control.parent_domain_allows_runtime_mutation() {
            return Err(invalid_params(
                control.parent_domain_mutation_error("launch child domain"),
            ));
        }
        let launch_id = child_launch_id();
        let log_dir = self
            .project_dir
            .join(".actplane")
            .join("children")
            .join(&launch_id);
        let mut child = spawn_stopped_child(&cmd, &self.project_dir, &log_dir)?;
        let pid = child.id() as i32;
        let child_id = child_id.unwrap_or(pid as u32);
        let policy_attached = policy.is_some();

        if let Err(e) = control.bind_child_domain(ChildDomainSpec {
            parent_pid: control.parent_pid,
            parent_id: control.parent_domain_id,
            child_id,
            pid,
            scope_id,
            authority_mask: AUTH_BIND_RULE,
            target_mask: TARGET_SELF,
            ..ChildDomainSpec::default()
        }) {
            kill_and_wait(child);
            let _ = control.audit_child_launch(
                pid,
                child_id,
                &cmd,
                policy_attached,
                "rejected",
                Some(&e.to_string()),
            );
            return Err(rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Bind launched child domain failed: {e}"),
                None::<Value>,
            ));
        }

        if let Some(policy) = policy.as_deref() {
            if let Err(e) =
                control.append_policy_delta_dsl_with_audit(child_id, policy, &policy_audit_meta)
            {
                kill_and_wait(child);
                let _ = control.audit_child_launch(
                    pid,
                    child_id,
                    &cmd,
                    policy_attached,
                    "rejected",
                    Some(&e.to_string()),
                );
                return Err(rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Append launched child policy failed: {e}"),
                    None::<Value>,
                ));
            }
        }

        if let Err(e) = send_signal(pid, libc::SIGCONT) {
            kill_and_wait(child);
            let _ = control.audit_child_launch(
                pid,
                child_id,
                &cmd,
                policy_attached,
                "rejected",
                Some(&e.to_string()),
            );
            return Err(rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Resume launched child failed: {e}"),
                None::<Value>,
            ));
        }
        let status = Arc::new(Mutex::new(ChildStatus::Running));
        let record = ChildRecord {
            launch_id,
            pid,
            child_id,
            scope_id,
            cmd: cmd.clone(),
            stdout: log_dir.join("stdout.log"),
            stderr: log_dir.join("stderr.log"),
            meta: log_dir.join("meta.json"),
            proc_start_time: proc_start_time(pid),
            policy: policy.clone(),
            policy_audit_meta,
            restart_policy: restart.policy,
            restart_count: restart.count,
            restart_limit: restart.limit,
            restart_backoff_ms: restart.backoff_ms,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from,
            replacement_child_id: None,
            status: status.clone(),
        };
        persist_child_record(&record).map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Persist child registry failed: {e}"),
                None::<Value>,
            )
        })?;
        self.children
            .lock()
            .map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Child registry lock poisoned: {e}"),
                    None::<Value>,
                )
            })?
            .insert(child_id, record.clone());
        control
            .audit_child_launch(pid, child_id, &cmd, policy_attached, "accepted", None)
            .map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Launch succeeded but audit write failed: {e}"),
                    None::<Value>,
                )
            })?;
        std::thread::spawn(move || {
            let mut record = record;
            match child.wait() {
                Ok(exit) => {
                    if let Ok(mut st) = status.lock() {
                        *st = ChildStatus::Exited {
                            code: exit.code(),
                            signal: exit.signal(),
                        };
                    }
                    record.last_exit_unix_ms = Some(unix_time_ms());
                    let _ = persist_child_record(&record);
                }
                Err(_) => {
                    if let Ok(mut st) = status.lock() {
                        *st = ChildStatus::Terminated;
                    }
                    record.last_exit_unix_ms = Some(unix_time_ms());
                    let _ = persist_child_record(&record);
                }
            }
        });

        Ok(LaunchOutcome { pid, child_id })
    }

    fn do_list_child_domains(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut children = self.children.lock().map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Child registry lock poisoned: {e}"),
                None::<Value>,
            )
        })?;
        for record in children.values_mut() {
            refresh_child_record_status(record);
        }
        let mut rows: Vec<serde_json::Value> = children.values().map(child_record_json).collect();
        rows.sort_by_key(|v| v["child_id"].as_u64().unwrap_or(0));
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string()),
        )]))
    }

    fn do_read_child_domain_logs(
        &self,
        args: Option<serde_json::Map<String, Value>>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args = args.unwrap_or_default();
        let child_id = child_id_arg(&args)?;
        let stream = json_optional_string(&args, "stream")?.unwrap_or("both");
        if !matches!(stream, "stdout" | "stderr" | "both") {
            return Err(invalid_params(
                "`stream` must be one of stdout, stderr, or both",
            ));
        }
        let max_bytes = json_optional_usize(&args, "max_bytes")?
            .unwrap_or(8192)
            .clamp(1, 65536);
        let record = {
            let mut children = self.children.lock().map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Child registry lock poisoned: {e}"),
                    None::<Value>,
                )
            })?;
            let record = children
                .get_mut(&child_id)
                .ok_or_else(|| invalid_params(format!("unknown child domain {child_id}")))?;
            refresh_child_record_status(record);
            record.clone()
        };
        let mut value = serde_json::json!({
            "pid": record.pid,
            "child_id": record.child_id,
            "status": record.status.lock().map(|s| child_status_json(&s)).unwrap_or_else(|_| serde_json::json!({ "state": "unknown" })),
            "max_bytes": max_bytes,
        });
        if stream == "stdout" || stream == "both" {
            value["stdout"] = read_log_json(&record.stdout, max_bytes)?;
        }
        if stream == "stderr" || stream == "both" {
            value["stderr"] = read_log_json(&record.stderr, max_bytes)?;
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string()),
        )]))
    }

    fn do_terminate_child_domain(
        &self,
        args: Option<serde_json::Map<String, Value>>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args = args.unwrap_or_default();
        let child_id = child_id_arg(&args)?;
        let record = {
            let mut children = self.children.lock().map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Child registry lock poisoned: {e}"),
                    None::<Value>,
                )
            })?;
            let record = children
                .get_mut(&child_id)
                .ok_or_else(|| invalid_params(format!("unknown child domain {child_id}")))?;
            refresh_child_record_status(record);
            record.clone()
        };
        if let Ok(status) = record.status.lock() {
            match &*status {
                ChildStatus::Exited { .. } => {
                    return Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                        "Child domain {child_id} already exited"
                    ))]));
                }
                ChildStatus::Terminated => {
                    return Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                        "Child domain {child_id} was already terminated"
                    ))]));
                }
                ChildStatus::Running => {}
            }
        }
        let next_status = match terminate_process_group(record.pid) {
            Ok(()) => ChildStatus::Terminated,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => ChildStatus::Exited {
                code: None,
                signal: None,
            },
            Err(e) => {
                return Err(rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Terminate child domain failed: {e}"),
                    None::<Value>,
                ));
            }
        };
        let terminated = matches!(next_status, ChildStatus::Terminated);
        if let Ok(mut status) = record.status.lock() {
            *status = next_status;
        }
        persist_child_record(&record).map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Persist child registry failed: {e}"),
                None::<Value>,
            )
        })?;
        let msg = if terminated {
            format!("Terminated child domain {child_id} (pid {})", record.pid)
        } else {
            format!("Child domain {child_id} already exited")
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(msg)]))
    }

    fn do_restart_child_domain(
        &self,
        args: Option<serde_json::Map<String, Value>>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let control = self.control.as_ref().ok_or_else(|| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                "No eBPF engine attached (MCP not started with --auto-attach-parent)",
                None::<Value>,
            )
        })?;
        let args = args.unwrap_or_default();
        let old_child_id = child_id_arg(&args)?;
        let new_child_id = json_optional_u32(&args, "new_child_id")?;
        if new_child_id == Some(old_child_id) {
            return Err(invalid_params(
                "restart requires a fresh new_child_id; omit it to use the new pid",
            ));
        }
        let terminate_existing = json_optional_bool(&args, "terminate_existing")?.unwrap_or(false);

        let old_record = {
            let mut children = self.children.lock().map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Child registry lock poisoned: {e}"),
                    None::<Value>,
                )
            })?;
            let record = children
                .get_mut(&old_child_id)
                .ok_or_else(|| invalid_params(format!("unknown child domain {old_child_id}")))?;
            refresh_child_record_status(record);
            if child_record_running(record) {
                if !terminate_existing {
                    let msg = format!(
                        "child domain {old_child_id} is still running; pass terminate_existing=true to replace it"
                    );
                    let _ = control.audit_child_restart(
                        old_child_id,
                        0,
                        new_child_id,
                        &record.cmd,
                        record.policy.is_some(),
                        "rejected",
                        Some(&msg),
                    );
                    return Err(invalid_params(msg));
                }
                let next_status = match terminate_process_group(record.pid) {
                    Ok(()) => ChildStatus::Terminated,
                    Err(e) if e.raw_os_error() == Some(libc::ESRCH) => ChildStatus::Exited {
                        code: None,
                        signal: None,
                    },
                    Err(e) => {
                        let msg = format!("Terminate old child before restart failed: {e}");
                        let _ = control.audit_child_restart(
                            old_child_id,
                            0,
                            new_child_id,
                            &record.cmd,
                            record.policy.is_some(),
                            "rejected",
                            Some(&msg),
                        );
                        return Err(rmcp::ErrorData::new(
                            ErrorCode::INTERNAL_ERROR,
                            msg,
                            None::<Value>,
                        ));
                    }
                };
                if let Ok(mut status) = record.status.lock() {
                    *status = next_status;
                }
                persist_child_record(record).map_err(|e| {
                    rmcp::ErrorData::new(
                        ErrorCode::INTERNAL_ERROR,
                        format!("Persist old child registry failed: {e}"),
                        None::<Value>,
                    )
                })?;
            }
            record.clone()
        };

        let outcome = match self.launch_child_domain_inner(
            old_record.cmd.clone(),
            new_child_id,
            old_record.scope_id,
            old_record.policy.clone(),
            old_record.policy_audit_meta.clone(),
            Some(old_child_id),
            old_record.next_restart_settings(),
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                let msg = e.to_string();
                let _ = control.audit_child_restart(
                    old_child_id,
                    0,
                    new_child_id,
                    &old_record.cmd,
                    old_record.policy.is_some(),
                    "rejected",
                    Some(&msg),
                );
                return Err(e);
            }
        };
        control
            .audit_child_restart(
                old_child_id,
                outcome.pid,
                Some(outcome.child_id),
                &old_record.cmd,
                old_record.policy.is_some(),
                "accepted",
                None,
            )
            .map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Restart succeeded but audit write failed: {e}"),
                    None::<Value>,
                )
            })?;
        {
            let mut children = self.children.lock().map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Child registry lock poisoned: {e}"),
                    None::<Value>,
                )
            })?;
            if let Some(record) = children.get_mut(&old_child_id) {
                record.replacement_child_id = Some(outcome.child_id);
                persist_child_record(record).map_err(|e| {
                    rmcp::ErrorData::new(
                        ErrorCode::INTERNAL_ERROR,
                        format!("Persist old child replacement metadata failed: {e}"),
                        None::<Value>,
                    )
                })?;
            }
        }

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Restarted child domain {old_child_id} as pid {} in child domain {}",
            outcome.pid, outcome.child_id
        ))]))
    }

    fn do_reconcile_child_domains(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let (restart_candidates, restart_alerts) = {
            let mut children = self.children.lock().map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Child registry lock poisoned: {e}"),
                    None::<Value>,
                )
            })?;
            let now = unix_time_ms();
            let mut restart_alerts = Vec::new();
            for record in children.values_mut() {
                refresh_child_record_status(record);
                if child_restart_blocked_reason(record).is_some()
                    && record.restart_alerted_unix_ms.is_none()
                {
                    record.restart_alerted_unix_ms = Some(now);
                    let _ = persist_child_record(record);
                    restart_alerts.push(record.clone());
                }
            }
            let restart_candidates = children
                .values()
                .filter(|record| child_record_should_relaunch(record))
                .cloned()
                .collect::<Vec<_>>();
            (restart_candidates, restart_alerts)
        };

        let mut alerts = Vec::new();
        for record in restart_alerts {
            let reason = child_restart_blocked_reason(&record).unwrap_or("restart blocked");
            if let Some(control) = self.control.as_ref() {
                let _ = control.audit_child_restart(
                    record.child_id,
                    0,
                    None,
                    &record.cmd,
                    record.policy.is_some(),
                    "blocked",
                    Some(reason),
                );
            }
            alerts.push(serde_json::json!({
                "child_id": record.child_id,
                "status": "blocked",
                "reason": reason,
                "restart_count": record.restart_count,
                "restart_limit": record.restart_limit,
                "alerted_unix_ms": record.restart_alerted_unix_ms,
            }));
        }

        let mut restarted = Vec::new();
        for old in restart_candidates {
            let launch = self.launch_child_domain_inner(
                old.cmd.clone(),
                None,
                old.scope_id,
                old.policy.clone(),
                old.policy_audit_meta.clone(),
                Some(old.child_id),
                old.next_restart_settings(),
            );
            match launch {
                Ok(outcome) => {
                    if let Some(control) = self.control.as_ref() {
                        let _ = control.audit_child_restart(
                            old.child_id,
                            outcome.pid,
                            Some(outcome.child_id),
                            &old.cmd,
                            old.policy.is_some(),
                            "accepted",
                            None,
                        );
                    }
                    let mut children = self.children.lock().map_err(|e| {
                        rmcp::ErrorData::new(
                            ErrorCode::INTERNAL_ERROR,
                            format!("Child registry lock poisoned: {e}"),
                            None::<Value>,
                        )
                    })?;
                    if let Some(record) = children.get_mut(&old.child_id) {
                        record.replacement_child_id = Some(outcome.child_id);
                        let _ = persist_child_record(record);
                    }
                    restarted.push(serde_json::json!({
                        "old_child_id": old.child_id,
                        "new_child_id": outcome.child_id,
                        "pid": outcome.pid,
                        "status": "accepted",
                    }));
                }
                Err(e) => {
                    if let Some(control) = self.control.as_ref() {
                        let _ = control.audit_child_restart(
                            old.child_id,
                            0,
                            None,
                            &old.cmd,
                            old.policy.is_some(),
                            "rejected",
                            Some(&e.to_string()),
                        );
                    }
                    restarted.push(serde_json::json!({
                        "old_child_id": old.child_id,
                        "status": "rejected",
                        "error": e.to_string(),
                    }));
                }
            }
        }

        let mut children = self.children.lock().map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Child registry lock poisoned: {e}"),
                None::<Value>,
            )
        })?;
        for record in children.values_mut() {
            refresh_child_record_status(record);
        }
        let mut rows: Vec<serde_json::Value> = children.values().map(child_record_json).collect();
        rows.sort_by_key(|v| v["child_id"].as_u64().unwrap_or(0));
        let running = children
            .values()
            .filter(|r| child_record_running(r))
            .count();
        let exited = children.values().filter(|r| child_record_exited(r)).count();
        let terminated = children
            .values()
            .filter(|r| child_record_terminated(r))
            .count();
        let value = serde_json::json!({
            "total": children.len(),
            "running": running,
            "exited": exited,
            "terminated": terminated,
            "alerts": alerts,
            "restarted": restarted,
            "children": rows,
        });
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string()),
        )]))
    }

    fn control_parent(&self) -> Option<(i32, u32)> {
        self.control
            .as_ref()
            .map(|c| (c.parent_pid, c.parent_domain_id))
    }

    fn handle_local_control_request(
        &self,
        request: Value,
        peer: Option<local_control::PeerCred>,
    ) -> Value {
        let Some(args) = request.as_object().cloned() else {
            return serde_json::json!({
                "ok": false,
                "error": "control request must be a JSON object",
            });
        };
        let Some(op) = args.get("op").and_then(Value::as_str) else {
            return serde_json::json!({
                "ok": false,
                "error": "control request missing string `op`",
            });
        };
        match op {
            "status" => self.local_control_status(),
            "bind_child_domain" => {
                if let Err(e) = self.ensure_local_parent_peer(peer) {
                    return serde_json::json!({ "ok": false, "error": e });
                }
                local_tool_response(self.do_bind_child_domain(Some(args)))
            }
            "append_policy_delta" => {
                let Some(peer) = peer else {
                    return serde_json::json!({
                        "ok": false,
                        "error": "local control peer credentials are unavailable",
                    });
                };
                local_tool_response(self.do_append_policy_delta_for_actor(
                    Some(args),
                    Some(peer.pid),
                    Some(peer.identity),
                ))
            }
            "launch_child_domain" => {
                if let Err(e) = self.ensure_local_parent_peer(peer) {
                    return serde_json::json!({ "ok": false, "error": e });
                }
                local_tool_response(self.do_launch_child_domain(Some(args)))
            }
            "list_child_domains" => {
                if let Err(e) = self.ensure_local_parent_peer(peer) {
                    return serde_json::json!({ "ok": false, "error": e });
                }
                local_tool_response(self.do_list_child_domains())
            }
            "read_child_domain_logs" => {
                if let Err(e) = self.ensure_local_parent_peer(peer) {
                    return serde_json::json!({ "ok": false, "error": e });
                }
                local_tool_response(self.do_read_child_domain_logs(Some(args)))
            }
            "terminate_child_domain" => {
                if let Err(e) = self.ensure_local_parent_peer(peer) {
                    return serde_json::json!({ "ok": false, "error": e });
                }
                local_tool_response(self.do_terminate_child_domain(Some(args)))
            }
            "restart_child_domain" => {
                if let Err(e) = self.ensure_local_parent_peer(peer) {
                    return serde_json::json!({ "ok": false, "error": e });
                }
                local_tool_response(self.do_restart_child_domain(Some(args)))
            }
            "reconcile_child_domains" => {
                if let Err(e) = self.ensure_local_parent_peer(peer) {
                    return serde_json::json!({ "ok": false, "error": e });
                }
                local_tool_response(self.do_reconcile_child_domains())
            }
            _ => serde_json::json!({
                "ok": false,
                "error": format!("unknown ActPlane control op `{op}`"),
            }),
        }
    }

    fn ensure_local_parent_peer(
        &self,
        peer: Option<local_control::PeerCred>,
    ) -> Result<(), String> {
        let peer =
            peer.ok_or_else(|| "local control peer credentials are unavailable".to_string())?;
        let Some(control) = self.control.as_ref() else {
            return Ok(());
        };
        control
            .ensure_parent_or_external_control_actor(peer.pid)
            .map_err(|e| e.to_string())
    }

    fn local_control_status(&self) -> Value {
        let child_count = self.children.lock().map(|c| c.len()).unwrap_or(0);
        let control = self.control.as_ref().map(|c| {
            serde_json::json!({
                "parent_pid": c.parent_pid,
                "parent_domain_id": c.parent_domain_id,
            })
        });
        serde_json::json!({
            "ok": true,
            "result": {
                "attached": self.control.is_some(),
                "project_dir": self.project_dir.display().to_string(),
                "control": control,
                "child_count": child_count,
            }
        })
    }
}

fn default_project_dir() -> PathBuf {
    std::env::var("ACTPLANE_PROJECT_DIR")
        .or_else(|_| std::env::var("CODEX_PROJECT_DIR"))
        .or_else(|_| std::env::var("CODEX_WORKSPACE"))
        .or_else(|_| std::env::var("CLAUDE_PROJECT_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn local_tool_response(result: Result<CallToolResult, rmcp::ErrorData>) -> Value {
    match result {
        Ok(result) => {
            let value = serde_json::to_value(&result).unwrap_or_else(|e| {
                serde_json::json!({
                    "serialization_error": e.to_string()
                })
            });
            let text = first_tool_text(&value);
            serde_json::json!({
                "ok": true,
                "text": text,
                "result": value,
            })
        }
        Err(e) => serde_json::json!({
            "ok": false,
            "error": e.to_string(),
        }),
    }
}

fn first_tool_text(value: &Value) -> Option<String> {
    value
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(|entry| entry.get("text"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn invalid_params(msg: impl Into<String>) -> rmcp::ErrorData {
    rmcp::ErrorData::new(ErrorCode::INVALID_PARAMS, msg.into(), None::<Value>)
}

fn json_i32(args: &serde_json::Map<String, Value>, key: &str) -> Result<i32, rmcp::ErrorData> {
    let value = args
        .get(key)
        .ok_or_else(|| invalid_params(format!("missing `{key}`")))?;
    let n = value
        .as_i64()
        .ok_or_else(|| invalid_params(format!("`{key}` must be an integer")))?;
    i32::try_from(n).map_err(|_| invalid_params(format!("`{key}` is out of range")))
}

fn json_string<'a>(
    args: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, rmcp::ErrorData> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params(format!("missing string `{key}`")))
}

fn json_optional_string<'a>(
    args: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, rmcp::ErrorData> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| invalid_params(format!("`{key}` must be a string")))
}

fn json_string_vec(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, rmcp::ErrorData> {
    let value = args
        .get(key)
        .ok_or_else(|| invalid_params(format!("missing `{key}`")))?;
    let arr = value
        .as_array()
        .ok_or_else(|| invalid_params(format!("`{key}` must be an array of strings")))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| invalid_params(format!("`{key}` must be an array of strings")))
        })
        .collect()
}

fn json_optional_u32(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<u32>, rmcp::ErrorData> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    let n = value
        .as_u64()
        .ok_or_else(|| invalid_params(format!("`{key}` must be a non-negative integer")))?;
    Ok(Some(u32::try_from(n).map_err(|_| {
        invalid_params(format!("`{key}` is out of range"))
    })?))
}

fn json_optional_usize(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<usize>, rmcp::ErrorData> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    let n = value
        .as_u64()
        .ok_or_else(|| invalid_params(format!("`{key}` must be a non-negative integer")))?;
    Ok(Some(usize::try_from(n).map_err(|_| {
        invalid_params(format!("`{key}` is out of range"))
    })?))
}

fn json_optional_u64(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, rmcp::ErrorData> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| invalid_params(format!("`{key}` must be a non-negative integer")))
}

fn json_optional_bool(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, rmcp::ErrorData> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| invalid_params(format!("`{key}` must be a boolean")))
}

fn policy_audit_meta_from_args(
    args: &serde_json::Map<String, Value>,
) -> Result<PolicyAuditMeta, rmcp::ErrorData> {
    Ok(PolicyAuditMeta {
        policy_ref: json_optional_string(args, "policy_ref")?.map(ToString::to_string),
        approved_by: json_optional_string(args, "approved_by")?.map(ToString::to_string),
        approval_ref: json_optional_string(args, "approval_ref")?.map(ToString::to_string),
        generated_by: json_optional_string(args, "generated_by")?.map(ToString::to_string),
    })
}

fn json_optional_restart_policy(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<RestartPolicy>, rmcp::ErrorData> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    let Some(text) = value.as_str() else {
        return Err(invalid_params(format!("`{key}` must be a string")));
    };
    match text {
        "never" => Ok(Some(RestartPolicy::Never)),
        "on_exit" | "on-exit" => Ok(Some(RestartPolicy::OnExit)),
        _ => Err(invalid_params(format!(
            "`{key}` must be one of never or on_exit"
        ))),
    }
}

fn child_id_arg(args: &serde_json::Map<String, Value>) -> Result<u32, rmcp::ErrorData> {
    match json_optional_u32(args, "child_id")? {
        Some(id) => Ok(id),
        None => json_optional_u32(args, "domain_id")?
            .ok_or_else(|| invalid_params("missing `child_id`")),
    }
}

fn latest_run_feedback(root: &std::path::Path) -> Option<PathBuf> {
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

fn child_launch_id() -> String {
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("child-{}-{now}", std::process::id())
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn child_record_json(record: &ChildRecord) -> serde_json::Value {
    let status = record
        .status
        .lock()
        .map(|s| child_status_json(&s))
        .unwrap_or_else(|_| serde_json::json!({ "state": "unknown" }));
    let mut value = serde_json::json!({
        "launch_id": record.launch_id,
        "pid": record.pid,
        "child_id": record.child_id,
        "scope_id": record.scope_id,
        "cmd": &record.cmd,
        "stdout": record.stdout.display().to_string(),
        "stderr": record.stderr.display().to_string(),
        "meta": record.meta.display().to_string(),
        "proc_start_time": record.proc_start_time,
        "policy_attached": record.policy.is_some(),
        "policy_hash": record.policy.as_deref().map(audit::policy_hash),
        "restart_policy": record.restart_policy.as_str(),
        "restart_count": record.restart_count,
        "restart_limit": record.restart_limit,
        "restart_backoff_ms": record.restart_backoff_ms,
        "next_restart_after_unix_ms": record.next_restart_after_unix_ms(),
        "last_exit_unix_ms": record.last_exit_unix_ms,
        "restart_alerted_unix_ms": record.restart_alerted_unix_ms,
        "restart_blocked_reason": child_restart_blocked_reason(record),
        "adopted_unix_ms": record.adopted_unix_ms,
        "supervision": child_supervision_json(record),
        "restarted_from": record.restarted_from,
        "replacement_child_id": record.replacement_child_id,
        "status": status,
    });
    if let Some(policy_approval) = policy_audit_meta_json(&record.policy_audit_meta) {
        value["policy_approval"] = policy_approval;
    }
    value
}

fn child_record_meta_json(record: &ChildRecord) -> serde_json::Value {
    let mut value = child_record_json(record);
    if let Some(policy) = &record.policy {
        value["policy"] = serde_json::json!(policy);
    }
    value
}

fn policy_audit_meta_json(meta: &PolicyAuditMeta) -> Option<serde_json::Value> {
    if meta.policy_ref.is_none()
        && meta.approved_by.is_none()
        && meta.approval_ref.is_none()
        && meta.generated_by.is_none()
    {
        return None;
    }
    let mut value = serde_json::json!({});
    if let Some(policy_ref) = &meta.policy_ref {
        value["policy_ref"] = serde_json::json!(policy_ref);
    }
    if let Some(approved_by) = &meta.approved_by {
        value["approved_by"] = serde_json::json!(approved_by);
    }
    if let Some(approval_ref) = &meta.approval_ref {
        value["approval_ref"] = serde_json::json!(approval_ref);
    }
    if let Some(generated_by) = &meta.generated_by {
        value["generated_by"] = serde_json::json!(generated_by);
    }
    Some(value)
}

fn policy_audit_meta_from_json(value: &Value) -> Option<PolicyAuditMeta> {
    let object = value.as_object()?;
    Some(PolicyAuditMeta {
        policy_ref: object
            .get("policy_ref")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        approved_by: object
            .get("approved_by")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        approval_ref: object
            .get("approval_ref")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        generated_by: object
            .get("generated_by")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    })
}

fn child_status_json(status: &ChildStatus) -> serde_json::Value {
    match status {
        ChildStatus::Running => serde_json::json!({ "state": "running" }),
        ChildStatus::Exited { code, signal } => serde_json::json!({
            "state": "exited",
            "code": code,
            "signal": signal,
        }),
        ChildStatus::Terminated => serde_json::json!({ "state": "terminated" }),
    }
}

fn persist_child_record(record: &ChildRecord) -> std::io::Result<()> {
    if let Some(parent) = record.meta.parent() {
        std::fs::create_dir_all(parent)?;
        secure_child_registry_dir(parent)?;
    }
    let text = serde_json::to_string_pretty(&child_record_meta_json(record))
        .map_err(std::io::Error::other)?;
    std::fs::write(&record.meta, text)?;
    secure_child_registry_file(&record.meta)?;
    Ok(())
}

#[cfg(unix)]
fn secure_child_registry_dir(path: &std::path::Path) -> std::io::Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        chown_path(path, 0, 0)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_child_registry_dir(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_child_registry_file(path: &std::path::Path) -> std::io::Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        chown_path(path, 0, 0)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_child_registry_file(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

struct LoadedChildRecords {
    records: HashMap<u32, ChildRecord>,
    adopted: Vec<ChildRecord>,
}

fn load_child_records_with_adoptions(project_dir: &std::path::Path) -> LoadedChildRecords {
    let root = project_dir.join(".actplane").join("children");
    let mut records = HashMap::new();
    let mut adopted = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return LoadedChildRecords { records, adopted };
    };
    for entry in entries.flatten() {
        let log_dir = entry.path();
        let meta = log_dir.join("meta.json");
        if !child_record_meta_trusted(&meta) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&meta) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(mut record) = child_record_from_meta(&value, log_dir) else {
            continue;
        };
        refresh_child_record_status(&mut record);
        if adopt_running_child_record(&mut record) {
            adopted.push(record.clone());
        }
        records.insert(record.child_id, record);
    }
    LoadedChildRecords { records, adopted }
}

#[cfg(unix)]
fn child_record_meta_trusted(meta: &std::path::Path) -> bool {
    if unsafe { libc::geteuid() } != 0 {
        #[cfg(test)]
        {
            return true;
        }
        #[cfg(not(test))]
        {
            return false;
        }
    }
    child_record_meta_trusted_root(meta)
}

#[cfg(unix)]
fn child_record_meta_trusted_root(meta: &std::path::Path) -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return true;
    }
    let Some(log_dir) = meta.parent() else {
        return false;
    };
    let Some(children_dir) = log_dir.parent() else {
        return false;
    };
    [children_dir, log_dir, meta].into_iter().all(|path| {
        let Ok(st) = std::fs::metadata(path) else {
            return false;
        };
        st.uid() == 0 && st.mode() & 0o022 == 0
    })
}

#[cfg(not(unix))]
fn child_record_meta_trusted(_meta: &std::path::Path) -> bool {
    true
}

fn child_record_from_meta(value: &Value, log_dir: PathBuf) -> Option<ChildRecord> {
    let pid = i32::try_from(value.get("pid")?.as_i64()?).ok()?;
    let child_id = u32::try_from(value.get("child_id")?.as_u64()?).ok()?;
    let scope_id = value
        .get("scope_id")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0);
    let launch_id = value
        .get("launch_id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            log_dir
                .file_name()
                .and_then(|s| s.to_str())
                .map(ToString::to_string)
        })?;
    let cmd = value
        .get("cmd")
        .and_then(Value::as_array)?
        .iter()
        .map(|v| v.as_str().map(ToString::to_string))
        .collect::<Option<Vec<_>>>()?;
    let stdout = value
        .get("stdout")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| log_dir.join("stdout.log"));
    let stderr = value
        .get("stderr")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| log_dir.join("stderr.log"));
    let meta = value
        .get("meta")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| log_dir.join("meta.json"));
    let proc_start_time = value.get("proc_start_time").and_then(Value::as_u64);
    let policy = value
        .get("policy")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let policy_audit_meta = value
        .get("policy_approval")
        .and_then(policy_audit_meta_from_json)
        .unwrap_or_default();
    let restart_policy = value
        .get("restart_policy")
        .and_then(Value::as_str)
        .map(parse_restart_policy_str)
        .unwrap_or(RestartPolicy::Never);
    let restart_count = value
        .get("restart_count")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0);
    let restart_limit = value
        .get("restart_limit")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(DEFAULT_RESTART_LIMIT);
    let restart_backoff_ms = value
        .get("restart_backoff_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_RESTART_BACKOFF_MS);
    let last_exit_unix_ms = value.get("last_exit_unix_ms").and_then(Value::as_u64);
    let restart_alerted_unix_ms = value.get("restart_alerted_unix_ms").and_then(Value::as_u64);
    let adopted_unix_ms = value.get("adopted_unix_ms").and_then(Value::as_u64);
    let restarted_from = value
        .get("restarted_from")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());
    let replacement_child_id = value
        .get("replacement_child_id")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());
    let status = value
        .get("status")
        .and_then(child_status_from_json)
        .unwrap_or(ChildStatus::Running);
    Some(ChildRecord {
        launch_id,
        pid,
        child_id,
        scope_id,
        cmd,
        stdout,
        stderr,
        meta,
        proc_start_time,
        policy,
        policy_audit_meta,
        restart_policy,
        restart_count,
        restart_limit,
        restart_backoff_ms,
        last_exit_unix_ms,
        restart_alerted_unix_ms,
        adopted_unix_ms,
        restarted_from,
        replacement_child_id,
        status: Arc::new(Mutex::new(status)),
    })
}

fn parse_restart_policy_str(text: &str) -> RestartPolicy {
    match text {
        "on_exit" | "on-exit" => RestartPolicy::OnExit,
        _ => RestartPolicy::Never,
    }
}

fn child_status_from_json(value: &Value) -> Option<ChildStatus> {
    match value.get("state")?.as_str()? {
        "running" => Some(ChildStatus::Running),
        "exited" => Some(ChildStatus::Exited {
            code: value
                .get("code")
                .and_then(Value::as_i64)
                .and_then(|n| i32::try_from(n).ok()),
            signal: value
                .get("signal")
                .and_then(Value::as_i64)
                .and_then(|n| i32::try_from(n).ok()),
        }),
        "terminated" => Some(ChildStatus::Terminated),
        _ => None,
    }
}

fn child_supervision_json(record: &ChildRecord) -> serde_json::Value {
    if let Some(adopted_unix_ms) = record.adopted_unix_ms {
        serde_json::json!({
            "mode": "adopted_polling",
            "adopted_unix_ms": adopted_unix_ms,
            "exit_status_precise": false,
        })
    } else {
        serde_json::json!({
            "mode": "wait_handle",
            "adopted_unix_ms": serde_json::Value::Null,
            "exit_status_precise": true,
        })
    }
}

fn adopt_running_child_record(record: &mut ChildRecord) -> bool {
    if !child_record_running(record) || record.adopted_unix_ms.is_some() {
        return false;
    }
    record.adopted_unix_ms = Some(unix_time_ms());
    let _ = persist_child_record(record);
    true
}

fn refresh_child_record_status(record: &mut ChildRecord) {
    let Ok(mut status) = record.status.lock() else {
        return;
    };
    if !matches!(*status, ChildStatus::Running) {
        return;
    }
    if process_identity_matches(record) {
        return;
    }
    *status = ChildStatus::Exited {
        code: None,
        signal: None,
    };
    if record.last_exit_unix_ms.is_none() {
        record.last_exit_unix_ms = Some(unix_time_ms());
    }
    drop(status);
    let _ = persist_child_record(record);
}

fn child_record_running(record: &ChildRecord) -> bool {
    record
        .status
        .lock()
        .map(|status| matches!(*status, ChildStatus::Running))
        .unwrap_or(false)
}

fn child_record_exited(record: &ChildRecord) -> bool {
    record
        .status
        .lock()
        .map(|status| matches!(*status, ChildStatus::Exited { .. }))
        .unwrap_or(false)
}

fn child_record_terminated(record: &ChildRecord) -> bool {
    record
        .status
        .lock()
        .map(|status| matches!(*status, ChildStatus::Terminated))
        .unwrap_or(false)
}

fn child_record_should_relaunch(record: &ChildRecord) -> bool {
    if record.restart_policy != RestartPolicy::OnExit
        || record.replacement_child_id.is_some()
        || !child_record_exited(record)
        || child_restart_blocked_reason(record).is_some()
    {
        return false;
    }
    record
        .next_restart_after_unix_ms()
        .map(|due| unix_time_ms() >= due)
        .unwrap_or(true)
}

fn child_restart_blocked_reason(record: &ChildRecord) -> Option<&'static str> {
    if record.restart_policy == RestartPolicy::OnExit
        && record.replacement_child_id.is_none()
        && child_record_exited(record)
        && record.restart_count >= record.restart_limit
    {
        Some("restart limit reached")
    } else {
        None
    }
}

fn process_identity_matches(record: &ChildRecord) -> bool {
    if record.pid <= 0 {
        return false;
    }
    match (record.proc_start_time, proc_start_time(record.pid)) {
        (Some(expected), Some(actual)) => expected == actual,
        (Some(_), None) => false,
        (None, _) => process_exists(record.pid),
    }
}

fn process_exists(pid: i32) -> bool {
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    err.raw_os_error() != Some(libc::ESRCH)
}

fn proc_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(") ")?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn read_log_json(path: &std::path::Path, max_bytes: usize) -> Result<Value, rmcp::ErrorData> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(serde_json::json!({
                "path": path.display().to_string(),
                "content": "",
                "truncated": false,
                "missing": true,
            }));
        }
        Err(e) => {
            return Err(rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Read child log failed: {e}"),
                None::<Value>,
            ));
        }
    };
    let len = file
        .metadata()
        .map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Read child log metadata failed: {e}"),
                None::<Value>,
            )
        })?
        .len();
    let start = len.saturating_sub(max_bytes as u64);
    file.seek(SeekFrom::Start(start)).map_err(|e| {
        rmcp::ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            format!("Seek child log failed: {e}"),
            None::<Value>,
        )
    })?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| {
        rmcp::ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            format!("Read child log failed: {e}"),
            None::<Value>,
        )
    })?;
    Ok(serde_json::json!({
        "path": path.display().to_string(),
        "content": String::from_utf8_lossy(&buf),
        "truncated": start > 0,
        "missing": false,
    }))
}

fn spawn_stopped_child(
    cmd: &[String],
    cwd: &std::path::Path,
    log_dir: &std::path::Path,
) -> Result<Child, rmcp::ErrorData> {
    std::fs::create_dir_all(log_dir).map_err(|e| {
        rmcp::ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            format!("Create child log dir failed: {e}"),
            None::<Value>,
        )
    })?;
    if let Some(children_dir) = log_dir.parent() {
        secure_child_registry_dir(children_dir).map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Secure child registry directory failed: {e}"),
                None::<Value>,
            )
        })?;
    }
    secure_child_registry_dir(log_dir).map_err(|e| {
        rmcp::ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            format!("Secure child registry directory failed: {e}"),
            None::<Value>,
        )
    })?;
    let stdout_path = log_dir.join("stdout.log");
    let stderr_path = log_dir.join("stderr.log");
    let stdout = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stdout_path)
        .map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Open child stdout log failed: {e}"),
                None::<Value>,
            )
        })?;
    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stderr_path)
        .map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Open child stderr log failed: {e}"),
                None::<Value>,
            )
        })?;
    let drop_to = sudo_target_user();
    if let Some((uid, gid)) = drop_to {
        for path in [stdout_path.as_path(), stderr_path.as_path()] {
            chown_path(path, uid, gid).map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Set child log ownership failed: {e}"),
                    None::<Value>,
                )
            })?;
        }
    }
    let mut child = Command::new("/bin/sh");
    child.arg("-c");
    child.arg("kill -STOP $$; exec \"$@\"");
    child.arg("actplane-child");
    child.args(cmd);
    if cwd.is_dir() {
        child.current_dir(cwd);
    }
    child.stdin(Stdio::null());
    child.stdout(Stdio::from(stdout));
    child.stderr(Stdio::from(stderr));
    #[cfg(unix)]
    unsafe {
        child.pre_exec(move || {
            mark_non_stdio_fds_cloexec()?;
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some((uid, gid)) = drop_to {
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = child.spawn().map_err(|e| {
        rmcp::ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            format!("Spawn child failed: {e}"),
            None::<Value>,
        )
    })?;
    let pid = child.id() as i32;
    if let Err(e) = wait_for_stopped_process(pid, Duration::from_secs(5)) {
        let _ = terminate_process_group_with(pid, libc::SIGKILL);
        let _ = child.wait();
        return Err(rmcp::ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            format!("Spawned child {pid} did not enter stopped state before domain bind: {e}"),
            None::<Value>,
        ));
    }
    Ok(child)
}

fn kill_and_wait(mut child: Child) {
    let _ = terminate_process_group_with(child.id() as i32, libc::SIGKILL);
    let _ = child.wait();
}

fn send_signal(pid: i32, sig: i32) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(pid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn terminate_process_group(pid: i32) -> std::io::Result<()> {
    terminate_process_group_with(pid, libc::SIGTERM)
}

fn terminate_process_group_with(pid: i32, sig: i32) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(-pid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn wait_for_stopped_process(pid: i32, timeout: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let state = proc_state_code(pid)?;
        if matches!(state, 'T' | 't') {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("last observed process state was {state}"),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn proc_state_code(pid: i32) -> std::io::Result<char> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("State:")
                .and_then(|state| state.split_whitespace().next())
                .and_then(|state| state.chars().next())
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing process State line",
            )
        })
}

fn sudo_target_user() -> Option<(libc::uid_t, libc::gid_t)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let uid = std::env::var("SUDO_UID")
        .ok()?
        .parse::<libc::uid_t>()
        .ok()?;
    let gid = std::env::var("SUDO_GID")
        .ok()?
        .parse::<libc::gid_t>()
        .ok()?;
    Some((uid, gid))
}

fn chown_path(path: &std::path::Path, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

// ── ServerHandler ───────────────────────────────────────────────────

impl ServerHandler for ActPlaneMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_tools()
                .build(),
        )
        .with_instructions(
            "ActPlane: OS-level agent harness. This server exposes policy \
                 validation and the latest corrective feedback from the kernel \
                 enforcer.",
        )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_
    {
        let empty_schema: serde_json::Map<String, Value> =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": {},
            }))
            .unwrap();
        let bind_schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
            "type": "object",
            "properties": {
                "pid": {
                    "type": "integer",
                    "description": "Linux pid of the already-started subagent root process to bind."
                },
                "child_id": {
                    "type": "integer",
                    "description": "Optional runtime domain id. Defaults to pid."
                },
                "scope_id": {
                    "type": "integer",
                    "description": "Optional narrower scope id. Defaults to the parent scope."
                }
            },
            "required": ["pid"]
        }))
        .unwrap();
        let append_schema: serde_json::Map<String, Value> =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": {
                    "target_id": {
                        "type": "integer",
                        "description": "Runtime domain id to receive the delta. Defaults to the auto-attached parent domain."
                    },
                    "policy": {
                        "type": "string",
                        "description": "Append-only ActPlane DSL fragment to compile and submit to the target domain."
                    },
                    "policy_ref": {
                        "type": "string",
                        "description": "Optional source reference for audit, such as a file path or generator id."
                    },
                    "approved_by": {
                        "type": "string",
                        "description": "Optional approval metadata checked against the static append-delta allowlist when configured."
                    },
                    "approval_ref": {
                        "type": "string",
                        "description": "Optional ticket, review, or decision id for this delta."
                    },
                    "generated_by": {
                        "type": "string",
                        "description": "Optional tool or agent identity that generated this delta."
                    }
                },
                "required": ["policy"]
            }))
            .unwrap();
        let launch_schema: serde_json::Map<String, Value> =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": {
                    "cmd": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command argv to launch as the child-domain root process."
                    },
                    "child_id": {
                        "type": "integer",
                        "description": "Optional runtime domain id. Defaults to the launched pid."
                    },
                    "scope_id": {
                        "type": "integer",
                        "description": "Optional narrower scope id. Defaults to the parent scope."
                    },
                    "policy": {
                        "type": "string",
                        "description": "Optional append-only ActPlane DSL fragment installed into the child domain before resume."
                    },
                    "policy_ref": {
                        "type": "string",
                        "description": "Optional source reference for the child policy audit record."
                    },
                    "approved_by": {
                        "type": "string",
                        "description": "Optional approval metadata checked against the static append-delta allowlist when configured."
                    },
                    "approval_ref": {
                        "type": "string",
                        "description": "Optional ticket, review, or decision id for the child policy."
                    },
                    "generated_by": {
                        "type": "string",
                        "description": "Optional tool or agent identity that generated the child policy."
                    },
                    "restart_policy": {
                        "type": "string",
                        "enum": ["never", "on_exit"],
                        "description": "Whether reconcile_child_domains should relaunch this child after an unexpected exit. Defaults to never."
                    },
                    "restart_limit": {
                        "type": "integer",
                        "description": "Maximum number of automatic relaunches for this child lineage. Defaults to 3."
                    },
                    "restart_backoff_ms": {
                        "type": "integer",
                        "description": "Delay before an automatic relaunch after exit, in milliseconds. Defaults to 1000."
                    }
                },
                "required": ["cmd"]
            }))
            .unwrap();
        let child_id_schema: serde_json::Map<String, Value> =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": {
                    "child_id": {
                        "type": "integer",
                        "description": "Child runtime domain id returned by launch_child_domain."
                    },
                    "domain_id": {
                        "type": "integer",
                        "description": "Alias for child_id."
                    }
                },
                "oneOf": [
                    { "required": ["child_id"] },
                    { "required": ["domain_id"] }
                ]
            }))
            .unwrap();
        let restart_schema: serde_json::Map<String, Value> =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": {
                    "child_id": {
                        "type": "integer",
                        "description": "Existing child runtime domain id to restart."
                    },
                    "domain_id": {
                        "type": "integer",
                        "description": "Alias for child_id."
                    },
                    "new_child_id": {
                        "type": "integer",
                        "description": "Optional fresh runtime domain id for the restarted process. Defaults to the new pid."
                    },
                    "terminate_existing": {
                        "type": "boolean",
                        "description": "Terminate the existing process group first if it is still running. Defaults to false."
                    }
                },
                "oneOf": [
                    { "required": ["child_id"] },
                    { "required": ["domain_id"] }
                ]
            }))
            .unwrap();
        let read_logs_schema: serde_json::Map<String, Value> =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": {
                    "child_id": {
                        "type": "integer",
                        "description": "Child runtime domain id returned by launch_child_domain."
                    },
                    "domain_id": {
                        "type": "integer",
                        "description": "Alias for child_id."
                    },
                    "stream": {
                        "type": "string",
                        "enum": ["stdout", "stderr", "both"],
                        "description": "Which detached log stream to read. Defaults to both."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "Maximum bytes to return per stream, clamped to 65536. Defaults to 8192."
                    }
                },
                "oneOf": [
                    { "required": ["child_id"] },
                    { "required": ["domain_id"] }
                ]
            }))
            .unwrap();
        let tools = vec![
            Tool::new(
                "bind_child_domain",
                "Bind a subagent root pid to a child runtime policy domain under \
                 the auto-attached repo agent. The child can bind rules for its \
                 own domain but does not receive label-creation authority.",
                bind_schema,
            ),
            Tool::new(
                "append_policy_delta",
                "Append a scoped DSL policy delta to a runtime domain through \
                 the kernel-admitted path. The server preserves rule metadata \
                 so future kernel violations report the appended rule reason.",
                append_schema,
            ),
            Tool::new(
                "launch_child_domain",
                "Launch a subagent command stopped, bind it to a child runtime \
                 policy domain, optionally append its local policy, then resume \
                 it. Child stdout/stderr are detached from MCP stdio. Set \
                 restart_policy=on_exit for long-lived subagents that should be \
                 relaunched during reconciliation after an unexpected exit.",
                launch_schema,
            ),
            Tool::new(
                "list_child_domains",
                "List subagents launched by this MCP server, including child \
                 domain id, root pid, detached log paths, command argv, and \
                 current exit status.",
                empty_schema.clone(),
            ),
            Tool::new(
                "read_child_domain_logs",
                "Read bounded stdout/stderr logs for a subagent launched by \
                 launch_child_domain.",
                read_logs_schema,
            ),
            Tool::new(
                "terminate_child_domain",
                "Terminate the process group for a subagent launched by \
                 launch_child_domain and mark it in the local lifecycle \
                 registry.",
                child_id_schema,
            ),
            Tool::new(
                "restart_child_domain",
                "Restart a subagent recorded in the local lifecycle registry. \
                 The restarted process is launched stopped, placed in a fresh \
                 child runtime domain, receives the recorded local policy if \
                 one exists, then resumes.",
                restart_schema,
            ),
            Tool::new(
                "reconcile_child_domains",
                "Refresh the persisted child-domain registry against /proc and \
                 relaunch exited children whose restart_policy is on_exit.",
                empty_schema,
            ),
        ];
        std::future::ready(Ok(ListToolsResult {
            tools,
            ..Default::default()
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResponse, rmcp::ErrorData>> + Send + '_
    {
        let result = match request.name.as_ref() {
            "bind_child_domain" => self.do_bind_child_domain(request.arguments),
            "append_policy_delta" => self.do_append_policy_delta(request.arguments),
            "launch_child_domain" => self.do_launch_child_domain(request.arguments),
            "list_child_domains" => self.do_list_child_domains(),
            "read_child_domain_logs" => self.do_read_child_domain_logs(request.arguments),
            "terminate_child_domain" => self.do_terminate_child_domain(request.arguments),
            "restart_child_domain" => self.do_restart_child_domain(request.arguments),
            "reconcile_child_domains" => self.do_reconcile_child_domains(),
            _ => Err(rmcp::ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                format!("Unknown tool: {}", request.name),
                None::<Value>,
            )),
        };
        std::future::ready(result.map(Into::into))
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_
    {
        let resources = vec![
            Resource::new(POLICY_RESOURCE_URI, "actplane-policy")
                .with_title("ActPlane Policy Status")
                .with_description("Current policy validation result from actplane.yaml")
                .with_mime_type("text/plain"),
            Resource::new(FEEDBACK_RESOURCE_URI, "actplane-feedback")
                .with_title("ActPlane Feedback")
                .with_description("Latest corrective feedback from .actplane/last-violation.txt")
                .with_mime_type("text/plain"),
        ];
        std::future::ready(Ok(ListResourcesResult {
            resources,
            ..Default::default()
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResponse, rmcp::ErrorData>> + Send + '_
    {
        let result = if request.uri == POLICY_RESOURCE_URI {
            let text = self.load_and_validate();
            Ok(ReadResourceResult::new(vec![
                ResourceContents::TextResourceContents {
                    uri: POLICY_RESOURCE_URI.into(),
                    mime_type: Some("text/plain".into()),
                    text,
                    meta: None,
                },
            ]))
        } else if request.uri == FEEDBACK_RESOURCE_URI {
            let text = self.load_feedback();
            Ok(ReadResourceResult::new(vec![
                ResourceContents::TextResourceContents {
                    uri: FEEDBACK_RESOURCE_URI.into(),
                    mime_type: Some("text/plain".into()),
                    text,
                    meta: None,
                },
            ]))
        } else {
            Err(rmcp::ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                format!("Unknown resource: {}", request.uri),
                None::<Value>,
            ))
        };
        std::future::ready(result.map(Into::into))
    }
}

// ── File watcher ────────────────────────────────────────────────────

#[allow(deprecated)]
async fn watch_policy_file(server: Arc<ActPlaneMcp>, peer: Peer<RoleServer>) {
    let mut last_policy_mtime = server.policy_mtime();
    let mut last_feedback_mtime = server.feedback_mtime();

    // Send initial validation on startup.
    let initial = server.load_and_validate();
    let _ = peer
        .notify_logging_message(LoggingMessageNotificationParam::new(
            LoggingLevel::Info,
            Value::String(initial),
        ))
        .await;

    loop {
        tokio::time::sleep(WATCH_INTERVAL).await;

        let current_policy_mtime = server.policy_mtime();
        if current_policy_mtime != last_policy_mtime {
            last_policy_mtime = current_policy_mtime;

            let result = server.load_and_validate();
            let level = if result.contains("error") || result.contains("No actplane") {
                LoggingLevel::Error
            } else {
                LoggingLevel::Info
            };

            let _ = peer
                .notify_logging_message(LoggingMessageNotificationParam::new(
                    level,
                    Value::String(result),
                ))
                .await;

            let _ = peer
                .notify_resource_updated(ResourceUpdatedNotificationParam::new(POLICY_RESOURCE_URI))
                .await;
        }

        let current_feedback_mtime = server.feedback_mtime();
        if current_feedback_mtime != last_feedback_mtime {
            last_feedback_mtime = current_feedback_mtime;
            let result = server.load_feedback();

            let _ = peer
                .notify_logging_message(LoggingMessageNotificationParam::new(
                    LoggingLevel::Info,
                    Value::String(result),
                ))
                .await;

            let _ = peer
                .notify_resource_updated(ResourceUpdatedNotificationParam::new(
                    FEEDBACK_RESOURCE_URI,
                ))
                .await;
        }
    }
}

pub async fn run_mcp_server_with_control(
    control: Option<Arc<EngineControl>>,
    project_dir: Option<PathBuf>,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = ActPlaneMcp::new_with_control_and_project_dir(control, project_dir);
    let control_guard = if server.control.is_some() {
        Some(start_local_control_server_for_server(server.clone())?)
    } else {
        None
    };
    let server_arc = Arc::new(server.clone());
    let transport = stdio();
    let service = server.serve(transport).await?;

    let peer = service.peer().clone();
    tokio::spawn(watch_policy_file(server_arc, peer));

    service.waiting().await?;
    drop(control_guard);
    Ok(())
}

pub fn start_local_control_server(
    control: Arc<EngineControl>,
    project_dir: PathBuf,
) -> crate::Result<ActPlaneControlGuard> {
    let server = ActPlaneMcp::new_with_control_and_project_dir(Some(control), Some(project_dir));
    start_local_control_server_for_server(server)
}

fn start_local_control_server_for_server(
    server: ActPlaneMcp,
) -> crate::Result<ActPlaneControlGuard> {
    let (parent_pid, parent_domain_id) = server
        .control_parent()
        .ok_or("local control server requires an attached engine")?;
    let server_for_control = server.clone();
    let control = local_control::start_server(
        &server.project_dir,
        parent_pid,
        parent_domain_id,
        move |request, peer| server_for_control.handle_local_control_request(request, peer),
    )?;
    let supervisor = start_supervisor(server);
    Ok(ActPlaneControlGuard {
        _control: control,
        _supervisor: supervisor,
    })
}

fn start_supervisor(server: ActPlaneMcp) -> SupervisorGuard {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let thread = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::SeqCst) {
            std::thread::sleep(SUPERVISOR_INTERVAL);
            if stop_thread.load(Ordering::SeqCst) {
                break;
            }
            if let Err(e) = server.do_reconcile_child_domains() {
                eprintln!("ActPlane: child-domain supervisor reconcile failed: {e}");
            }
        }
    });
    SupervisorGuard {
        stop,
        thread: Some(thread),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_and_feedback_mtimes_follow_project_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = dir.path().join("actplane.yaml");
        std::fs::write(
            &policy,
            "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule r:\n    notify exec \"/bin/true\" if COMMAND\n    because \"b\"\n",
        )
        .expect("policy");

        let server = ActPlaneMcp::new_with_control_and_project_dir(None, Some(dir.path().into()));
        assert!(server.policy_mtime().is_some());

        let feedback = server.feedback_file();
        assert_eq!(feedback, dir.path().join(".actplane/last-violation.txt"));
        assert!(server.feedback_mtime().is_none());
        std::fs::create_dir_all(feedback.parent().expect("parent")).expect("mkdir");
        std::fs::write(&feedback, "TAINT_VIOLATION: read /etc/secret\n").expect("feedback");
        assert!(server.feedback_mtime().is_some());
    }

    #[test]
    fn policy_mtime_is_none_without_a_policy_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = ActPlaneMcp::new_with_control_and_project_dir(None, Some(dir.path().into()));
        assert!(server.policy_mtime().is_none());
    }

    #[test]
    fn bind_child_domain_args_parse_required_and_optional_fields() {
        let args = serde_json::json!({
            "pid": 1234,
            "child_id": 5678,
            "scope_id": 9,
            "cmd": ["/bin/true", "--flag"],
            "policy": "rule r:\n  notify exec \"git\"\n  because \"test\""
        })
        .as_object()
        .expect("object")
        .clone();

        assert_eq!(json_i32(&args, "pid").expect("pid"), 1234);
        assert_eq!(
            json_optional_u32(&args, "child_id").expect("child_id"),
            Some(5678)
        );
        assert_eq!(
            json_optional_u32(&args, "scope_id").expect("scope_id"),
            Some(9)
        );
        assert_eq!(json_optional_u32(&args, "missing").expect("missing"), None);
        assert_eq!(
            json_string(&args, "policy").expect("policy"),
            "rule r:\n  notify exec \"git\"\n  because \"test\""
        );
        assert_eq!(
            json_optional_string(&args, "policy").expect("optional policy"),
            Some("rule r:\n  notify exec \"git\"\n  because \"test\"")
        );
        assert_eq!(
            json_string_vec(&args, "cmd").expect("cmd"),
            vec!["/bin/true".to_string(), "--flag".to_string()]
        );
    }

    #[test]
    fn bind_child_domain_args_reject_bad_types_and_ranges() {
        let string_pid = serde_json::json!({ "pid": "1234" })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_i32(&string_pid, "pid").is_err());

        let negative_child = serde_json::json!({ "child_id": -1 })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_optional_u32(&negative_child, "child_id").is_err());

        let huge_scope = serde_json::json!({ "scope_id": u64::MAX })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_optional_u32(&huge_scope, "scope_id").is_err());

        let numeric_policy = serde_json::json!({ "policy": 7 })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_string(&numeric_policy, "policy").is_err());
        assert!(json_optional_string(&numeric_policy, "policy").is_err());

        let bad_cmd = serde_json::json!({ "cmd": ["/bin/true", 7] })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_string_vec(&bad_cmd, "cmd").is_err());
    }

    fn json_args(json: serde_json::Value) -> serde_json::Map<String, Value> {
        json.as_object().expect("object").clone()
    }

    #[test]
    fn json_accessors_name_the_offending_key() {
        let empty = json_args(serde_json::json!({}));
        assert_eq!(
            json_i32(&empty, "pid").unwrap_err().message,
            "missing `pid`"
        );
        assert_eq!(
            json_string(&empty, "policy").unwrap_err().message,
            "missing string `policy`"
        );
        assert_eq!(
            json_string_vec(&empty, "cmd").unwrap_err().message,
            "missing `cmd`"
        );

        assert_eq!(
            json_i32(&json_args(serde_json::json!({ "pid": 1.5 })), "pid")
                .unwrap_err()
                .message,
            "`pid` must be an integer"
        );
        assert_eq!(
            json_i32(
                &json_args(serde_json::json!({ "pid": 2147483648i64 })),
                "pid"
            )
            .unwrap_err()
            .message,
            "`pid` is out of range"
        );
        assert_eq!(
            json_optional_string(&json_args(serde_json::json!({ "stream": 5 })), "stream")
                .unwrap_err()
                .message,
            "`stream` must be a string"
        );
        assert_eq!(
            json_string_vec(&json_args(serde_json::json!({ "cmd": "true" })), "cmd")
                .unwrap_err()
                .message,
            "`cmd` must be an array of strings"
        );
        assert_eq!(
            json_optional_u32(
                &json_args(serde_json::json!({ "child_id": u64::MAX })),
                "child_id"
            )
            .unwrap_err()
            .message,
            "`child_id` is out of range"
        );
        assert_eq!(
            json_optional_bool(
                &json_args(serde_json::json!({ "terminate_existing": "yes" })),
                "terminate_existing"
            )
            .unwrap_err()
            .message,
            "`terminate_existing` must be a boolean"
        );

        let absent = json_args(serde_json::json!({}));
        assert_eq!(
            json_optional_bool(&absent, "missing").expect("absent"),
            None
        );
        assert_eq!(json_optional_u64(&absent, "missing").expect("absent"), None);
        assert_eq!(
            json_optional_usize(&absent, "missing").expect("absent"),
            None
        );
    }

    #[test]
    fn child_status_json_round_trips_through_its_parser() {
        for status in [
            ChildStatus::Running,
            ChildStatus::Exited {
                code: Some(3),
                signal: None,
            },
            ChildStatus::Terminated,
        ] {
            let parsed = child_status_from_json(&child_status_json(&status)).expect("round trip");
            let same = match (&status, &parsed) {
                (ChildStatus::Running, ChildStatus::Running) => true,
                (ChildStatus::Terminated, ChildStatus::Terminated) => true,
                (
                    ChildStatus::Exited { code, signal },
                    ChildStatus::Exited {
                        code: pcode,
                        signal: psignal,
                    },
                ) => code == pcode && signal == psignal,
                _ => false,
            };
            assert!(same, "round trip changed the status variant");
        }
        assert!(child_status_from_json(&serde_json::json!({ "state": "gone" })).is_none());
    }

    #[test]
    fn spawn_stopped_child_can_be_killed_without_stdio_inheritance() {
        let cmd = vec!["/bin/true".to_string()];
        let log_dir = std::env::temp_dir().join(child_launch_id());
        let mut child = spawn_stopped_child(&cmd, &std::env::current_dir().expect("cwd"), &log_dir)
            .expect("spawn child");
        let state = proc_state_code(child.id() as i32).expect("child process state");
        assert!(
            matches!(state, 'T' | 't'),
            "spawn helper returned before child stopped; state={state}"
        );
        terminate_process_group_with(child.id() as i32, libc::SIGKILL).expect("kill child group");
        let _ = child.wait().expect("wait child");
        assert!(log_dir.join("stdout.log").is_file());
        assert!(log_dir.join("stderr.log").is_file());
        let _ = std::fs::remove_dir_all(log_dir);
    }

    #[test]
    fn child_record_json_includes_status_and_log_paths() {
        let status = Arc::new(Mutex::new(ChildStatus::Exited {
            code: Some(7),
            signal: None,
        }));
        let record = ChildRecord {
            launch_id: "child-test".to_string(),
            pid: 123,
            child_id: 456,
            scope_id: 3,
            cmd: vec!["/bin/echo".to_string(), "hello".to_string()],
            stdout: PathBuf::from("/tmp/stdout.log"),
            stderr: PathBuf::from("/tmp/stderr.log"),
            meta: PathBuf::from("/tmp/meta.json"),
            proc_start_time: Some(99),
            policy: Some("rule r:\n  notify exec \"x\"\n  because \"x\"".to_string()),
            policy_audit_meta: PolicyAuditMeta {
                policy_ref: Some("child-policy.dsl".to_string()),
                approved_by: Some("repo-supervisor".to_string()),
                approval_ref: Some("ticket-7".to_string()),
                generated_by: Some("template/no-network".to_string()),
            },
            restart_policy: RestartPolicy::OnExit,
            restart_count: 2,
            restart_limit: 5,
            restart_backoff_ms: 250,
            last_exit_unix_ms: Some(1234),
            restart_alerted_unix_ms: Some(5678),
            adopted_unix_ms: Some(9012),
            restarted_from: Some(111),
            replacement_child_id: Some(222),
            status,
        };
        let value = child_record_json(&record);
        assert_eq!(value["launch_id"], "child-test");
        assert_eq!(value["pid"], 123);
        assert_eq!(value["child_id"], 456);
        assert_eq!(value["scope_id"], 3);
        assert_eq!(value["cmd"][1], "hello");
        assert_eq!(value["stdout"], "/tmp/stdout.log");
        assert_eq!(value["proc_start_time"], 99);
        assert_eq!(value["policy_attached"], true);
        assert!(value["policy_hash"].as_str().is_some());
        assert!(value.get("policy").is_none());
        assert_eq!(value["policy_approval"]["approved_by"], "repo-supervisor");
        assert_eq!(value["policy_approval"]["approval_ref"], "ticket-7");
        assert_eq!(value["restart_policy"], "on_exit");
        assert_eq!(value["restart_count"], 2);
        assert_eq!(value["restart_limit"], 5);
        assert_eq!(value["restart_backoff_ms"], 250);
        assert_eq!(value["last_exit_unix_ms"], 1234);
        assert_eq!(value["restart_alerted_unix_ms"], 5678);
        assert_eq!(value["restart_blocked_reason"], serde_json::Value::Null);
        assert_eq!(value["adopted_unix_ms"], 9012);
        assert_eq!(value["supervision"]["mode"], "adopted_polling");
        assert_eq!(value["supervision"]["exit_status_precise"], false);
        assert_eq!(value["next_restart_after_unix_ms"], serde_json::Value::Null);
        assert_eq!(value["restarted_from"], 111);
        assert_eq!(value["replacement_child_id"], 222);
        assert_eq!(value["status"]["state"], "exited");
        assert_eq!(value["status"]["code"], 7);
    }

    #[test]
    fn restart_policy_args_parse_aliases_and_reject_bad_values() {
        let never = serde_json::json!({ "restart_policy": "never" })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(
            json_optional_restart_policy(&never, "restart_policy").expect("never"),
            Some(RestartPolicy::Never)
        );

        let on_exit = serde_json::json!({ "restart_policy": "on-exit" })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(
            json_optional_restart_policy(&on_exit, "restart_policy").expect("on-exit"),
            Some(RestartPolicy::OnExit)
        );

        let bad = serde_json::json!({ "restart_policy": "always" })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_optional_restart_policy(&bad, "restart_policy").is_err());
    }

    #[test]
    fn child_relaunch_honors_backoff_and_limit() {
        let status = Arc::new(Mutex::new(ChildStatus::Exited {
            code: Some(1),
            signal: None,
        }));
        let mut record = ChildRecord {
            launch_id: "child-restart-test".to_string(),
            pid: 123,
            child_id: 456,
            scope_id: 0,
            cmd: vec!["/bin/false".to_string()],
            stdout: PathBuf::from("/tmp/stdout.log"),
            stderr: PathBuf::from("/tmp/stderr.log"),
            meta: PathBuf::from("/tmp/meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::OnExit,
            restart_count: 0,
            restart_limit: 2,
            restart_backoff_ms: 1000,
            last_exit_unix_ms: Some(unix_time_ms().saturating_add(60_000)),
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status,
        };
        assert!(
            !child_record_should_relaunch(&record),
            "future exit timestamp should delay relaunch"
        );

        record.last_exit_unix_ms = Some(unix_time_ms().saturating_sub(2_000));
        assert!(
            child_record_should_relaunch(&record),
            "expired backoff should allow relaunch"
        );

        record.restart_count = 2;
        assert!(
            !child_record_should_relaunch(&record),
            "restart limit should stop relaunch"
        );
        assert_eq!(
            child_restart_blocked_reason(&record),
            Some("restart limit reached")
        );
        let value = child_record_json(&record);
        assert_eq!(value["restart_blocked_reason"], "restart limit reached");
    }

    #[test]
    fn read_log_json_returns_bounded_tail() {
        let path = std::env::temp_dir().join(format!(
            "actplane-mcp-log-test-{}-{}.log",
            std::process::id(),
            child_launch_id()
        ));
        std::fs::write(&path, "0123456789").expect("write log");
        let value = read_log_json(&path, 4).expect("read log");
        assert_eq!(value["content"], "6789");
        assert_eq!(value["truncated"], true);
        assert_eq!(value["missing"], false);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn child_registry_adopts_running_records_on_load() {
        let project_dir = std::env::temp_dir().join(format!(
            "actplane-mcp-adopt-test-{}-{}",
            std::process::id(),
            child_launch_id()
        ));
        let log_dir = project_dir
            .join(".actplane")
            .join("children")
            .join("child-adopt-test");
        let record = ChildRecord {
            launch_id: "child-adopt-test".to_string(),
            pid: std::process::id() as i32,
            child_id: 778,
            scope_id: 5,
            cmd: vec!["/bin/sleep".to_string(), "30".to_string()],
            stdout: log_dir.join("stdout.log"),
            stderr: log_dir.join("stderr.log"),
            meta: log_dir.join("meta.json"),
            proc_start_time: proc_start_time(std::process::id() as i32),
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::OnExit,
            restart_count: 0,
            restart_limit: 1,
            restart_backoff_ms: 100,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(ChildStatus::Running)),
        };
        persist_child_record(&record).expect("persist record");

        let loaded = load_child_records_with_adoptions(&project_dir);
        assert_eq!(loaded.adopted.len(), 1);
        let loaded_record = loaded.records.get(&778).expect("loaded child record");
        assert!(loaded_record.adopted_unix_ms.is_some());
        let value = child_record_json(loaded_record);
        assert_eq!(value["supervision"]["mode"], "adopted_polling");
        assert_eq!(value["supervision"]["exit_status_precise"], false);
        let meta = std::fs::read_to_string(log_dir.join("meta.json")).expect("read meta");
        let meta_value: Value = serde_json::from_str(&meta).expect("meta JSON");
        assert!(meta_value["adopted_unix_ms"].as_u64().is_some());

        let _ = std::fs::remove_dir_all(project_dir);
    }

    #[test]
    fn child_registry_persists_and_loads_records() {
        let project_dir = std::env::temp_dir().join(format!(
            "actplane-mcp-registry-test-{}-{}",
            std::process::id(),
            child_launch_id()
        ));
        let log_dir = project_dir
            .join(".actplane")
            .join("children")
            .join("child-persist-test");
        let status = Arc::new(Mutex::new(ChildStatus::Running));
        let record = ChildRecord {
            launch_id: "child-persist-test".to_string(),
            pid: std::process::id() as i32,
            child_id: 777,
            scope_id: 5,
            cmd: vec!["/bin/true".to_string()],
            stdout: log_dir.join("stdout.log"),
            stderr: log_dir.join("stderr.log"),
            meta: log_dir.join("meta.json"),
            proc_start_time: proc_start_time(std::process::id() as i32),
            policy: Some("rule persisted:\n  notify exec \"true\"\n  because \"x\"".to_string()),
            policy_audit_meta: PolicyAuditMeta {
                policy_ref: Some("persisted-policy.dsl".to_string()),
                approved_by: Some("repo-supervisor".to_string()),
                approval_ref: Some("ticket-9".to_string()),
                generated_by: Some("template/readonly".to_string()),
            },
            restart_policy: RestartPolicy::OnExit,
            restart_count: 1,
            restart_limit: 4,
            restart_backoff_ms: 125,
            last_exit_unix_ms: Some(42),
            restart_alerted_unix_ms: Some(43),
            adopted_unix_ms: Some(44),
            restarted_from: Some(700),
            replacement_child_id: Some(778),
            status,
        };
        persist_child_record(&record).expect("persist record");

        let loaded = load_child_records_with_adoptions(&project_dir);
        let loaded_record = loaded.records.get(&777).expect("loaded child record");
        assert_eq!(loaded_record.launch_id, "child-persist-test");
        assert_eq!(loaded_record.scope_id, 5);
        assert_eq!(loaded_record.cmd, vec!["/bin/true".to_string()]);
        assert_eq!(loaded_record.stdout, log_dir.join("stdout.log"));
        assert_eq!(
            loaded_record.policy.as_deref().unwrap(),
            "rule persisted:\n  notify exec \"true\"\n  because \"x\""
        );
        assert_eq!(
            loaded_record.policy_audit_meta.approved_by.as_deref(),
            Some("repo-supervisor")
        );
        assert_eq!(
            loaded_record.policy_audit_meta.approval_ref.as_deref(),
            Some("ticket-9")
        );
        assert_eq!(
            loaded_record.policy_audit_meta.generated_by.as_deref(),
            Some("template/readonly")
        );
        assert_eq!(loaded_record.restart_policy, RestartPolicy::OnExit);
        assert_eq!(loaded_record.restart_count, 1);
        assert_eq!(loaded_record.restart_limit, 4);
        assert_eq!(loaded_record.restart_backoff_ms, 125);
        assert_eq!(loaded_record.last_exit_unix_ms, Some(42));
        assert_eq!(loaded_record.restart_alerted_unix_ms, Some(43));
        assert_eq!(loaded_record.adopted_unix_ms, Some(44));
        assert_eq!(loaded_record.restarted_from, Some(700));
        assert_eq!(loaded_record.replacement_child_id, Some(778));
        assert!(matches!(
            *loaded_record.status.lock().expect("status"),
            ChildStatus::Running
        ));
        let _ = std::fs::remove_dir_all(project_dir);
    }

    fn seeded_server(project_dir: PathBuf, records: Vec<ChildRecord>) -> ActPlaneMcp {
        let mut children = HashMap::new();
        for record in records {
            children.insert(record.child_id, record);
        }
        ActPlaneMcp {
            project_dir,
            control: None,
            children: Arc::new(Mutex::new(children)),
        }
    }

    fn domain_record(
        child_id: u32,
        pid: i32,
        status: ChildStatus,
        log_dir: &std::path::Path,
    ) -> ChildRecord {
        ChildRecord {
            launch_id: format!("child-{child_id}"),
            pid,
            child_id,
            scope_id: 0,
            cmd: vec!["/bin/true".to_string()],
            stdout: log_dir.join("stdout.log"),
            stderr: log_dir.join("stderr.log"),
            meta: log_dir.join("meta.json"),
            proc_start_time: proc_start_time(pid),
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: DEFAULT_RESTART_LIMIT,
            restart_backoff_ms: DEFAULT_RESTART_BACKOFF_MS,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(status)),
        }
    }

    fn tool_text(result: &CallToolResult) -> String {
        match result.content.first() {
            Some(ContentBlock::Text(t)) => t.text.clone(),
            other => panic!("expected text content, got {other:?}"),
        }
    }

    #[test]
    fn list_child_domains_reports_every_registered_child_sorted_by_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_dir = tmp.path().join(".actplane/children/child-2");
        std::fs::create_dir_all(&log_dir).expect("mkdir");
        let server = seeded_server(
            tmp.path().to_path_buf(),
            vec![
                domain_record(2, std::process::id() as i32, ChildStatus::Running, &log_dir),
                domain_record(
                    1,
                    99_999_999,
                    ChildStatus::Exited {
                        code: Some(3),
                        signal: None,
                    },
                    &log_dir,
                ),
            ],
        );
        let result = server.do_list_child_domains().expect("list");
        let rows: Vec<Value> = serde_json::from_str(&tool_text(&result)).expect("json");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["child_id"], 1);
        assert_eq!(rows[0]["status"]["state"], "exited");
        assert_eq!(rows[0]["status"]["code"], 3);
        assert_eq!(rows[1]["child_id"], 2);
    }

    #[test]
    fn list_child_domains_refreshes_a_dead_running_child() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_dir = tmp.path().join(".actplane/children/child-9");
        std::fs::create_dir_all(&log_dir).expect("mkdir");
        // A "running" pid that no longer exists must be reconciled on read.
        let server = seeded_server(
            tmp.path().to_path_buf(),
            vec![domain_record(9, 99_999_999, ChildStatus::Running, &log_dir)],
        );
        let result = server.do_list_child_domains().expect("list");
        let rows: Vec<Value> = serde_json::from_str(&tool_text(&result)).expect("json");
        assert_eq!(rows[0]["status"]["state"], "exited");
    }

    #[test]
    fn read_child_domain_logs_bounds_and_filters_streams() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_dir = tmp.path().join(".actplane/children/child-5");
        std::fs::create_dir_all(&log_dir).expect("mkdir");
        std::fs::write(log_dir.join("stdout.log"), "0123456789").expect("write stdout");
        std::fs::write(log_dir.join("stderr.log"), "abcdefghij").expect("write stderr");
        let server = seeded_server(
            tmp.path().to_path_buf(),
            vec![domain_record(
                5,
                99_999_999,
                ChildStatus::Terminated,
                &log_dir,
            )],
        );

        let mut args = serde_json::Map::new();
        args.insert("child_id".to_string(), serde_json::json!(5));
        args.insert("stream".to_string(), serde_json::json!("stdout"));
        args.insert("max_bytes".to_string(), serde_json::json!(4));
        let result = server
            .do_read_child_domain_logs(Some(args))
            .expect("read logs");
        let value: Value = serde_json::from_str(&tool_text(&result)).expect("json");
        assert_eq!(value["stdout"]["content"], "6789");
        assert_eq!(value["stdout"]["truncated"], true);
        assert!(value.get("stderr").is_none(), "stdout-only request");

        let mut unknown = serde_json::Map::new();
        unknown.insert("child_id".to_string(), serde_json::json!(404));
        assert!(server.do_read_child_domain_logs(Some(unknown)).is_err());

        let mut bad_stream = serde_json::Map::new();
        bad_stream.insert("child_id".to_string(), serde_json::json!(5));
        bad_stream.insert("stream".to_string(), serde_json::json!("sideways"));
        assert!(server.do_read_child_domain_logs(Some(bad_stream)).is_err());
    }

    fn tool_text_c2(result: &CallToolResult) -> String {
        match result.content.first() {
            Some(ContentBlock::Text(t)) => t.text.clone(),
            other => panic!("expected text content, got {other:?}"),
        }
    }

    fn terminate_server(log_dir: &std::path::Path, status: ChildStatus) -> ActPlaneMcp {
        let record = ChildRecord {
            launch_id: "child-term".to_string(),
            pid: 99_999_999,
            child_id: 3,
            scope_id: 0,
            cmd: vec!["/bin/true".to_string()],
            stdout: log_dir.join("stdout.log"),
            stderr: log_dir.join("stderr.log"),
            meta: log_dir.join("meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: DEFAULT_RESTART_LIMIT,
            restart_backoff_ms: DEFAULT_RESTART_BACKOFF_MS,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(status)),
        };
        ActPlaneMcp {
            project_dir: log_dir
                .parent()
                .and_then(|p| p.parent())
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf(),
            control: None,
            children: Arc::new(Mutex::new(HashMap::from([(3u32, record)]))),
        }
    }

    fn terminate_args(child_id: u32) -> Option<serde_json::Map<String, Value>> {
        Some(serde_json::Map::from_iter([(
            "child_id".to_string(),
            serde_json::json!(child_id),
        )]))
    }

    fn status_of(server: &ActPlaneMcp, child_id: u32) -> ChildStatus {
        let children = server.children.lock().unwrap();
        children[&child_id].status.lock().unwrap().clone()
    }

    #[test]
    fn terminate_child_domain_reports_the_early_exit_arms() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_dir = tmp.path().join(".actplane/children/child-3");
        std::fs::create_dir_all(&log_dir).expect("mkdir");

        let exited = terminate_server(
            &log_dir,
            ChildStatus::Exited {
                code: Some(0),
                signal: None,
            },
        );
        let out = exited.do_terminate_child_domain(terminate_args(3)).unwrap();
        assert!(tool_text_c2(&out).contains("already exited"));

        let terminated = terminate_server(&log_dir, ChildStatus::Terminated);
        let out = terminated
            .do_terminate_child_domain(terminate_args(3))
            .unwrap();
        assert!(tool_text_c2(&out).contains("was already terminated"));
    }

    #[test]
    fn terminate_child_domain_reconciles_a_dead_running_pid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_dir = tmp.path().join(".actplane/children/child-3");
        std::fs::create_dir_all(&log_dir).expect("mkdir");
        let server = terminate_server(&log_dir, ChildStatus::Running);

        // The recorded pid is dead, so the refresh flips it to Exited before the
        // terminate path runs and reports the exit rather than signalling.
        let out = server.do_terminate_child_domain(terminate_args(3)).unwrap();
        assert!(tool_text_c2(&out).contains("already exited"));
        assert!(matches!(
            status_of(&server, 3),
            ChildStatus::Exited {
                code: None,
                signal: None
            }
        ));
        assert!(log_dir.join("meta.json").is_file(), "record persisted");

        // Unknown child id is an invalid-params error.
        assert!(
            server
                .do_terminate_child_domain(terminate_args(404))
                .is_err()
        );
        // Missing child id is rejected before lookup.
        assert!(server.do_terminate_child_domain(None).is_err());
    }

    fn record_with_status(status: ChildStatus) -> ChildRecord {
        ChildRecord {
            launch_id: "status-predicate-test".to_string(),
            pid: std::process::id() as i32,
            child_id: 900,
            scope_id: 1,
            cmd: vec!["/bin/true".to_string()],
            stdout: PathBuf::from("/tmp/actplane-status-out.log"),
            stderr: PathBuf::from("/tmp/actplane-status-err.log"),
            meta: PathBuf::from("/tmp/actplane-status-meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: 0,
            restart_backoff_ms: 0,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(status)),
        }
    }

    #[test]
    fn child_status_predicates_classify_each_variant() {
        // `child_record_running/exited/terminated` each lock the record status
        // and test exactly one `ChildStatus` variant. No base or branch test
        // calls these predicates directly.
        let running = record_with_status(ChildStatus::Running);
        assert!(child_record_running(&running));
        assert!(!child_record_exited(&running));
        assert!(!child_record_terminated(&running));

        let exited = record_with_status(ChildStatus::Exited {
            code: Some(0),
            signal: None,
        });
        assert!(!child_record_running(&exited));
        assert!(child_record_exited(&exited));
        assert!(!child_record_terminated(&exited));

        let terminated = record_with_status(ChildStatus::Terminated);
        assert!(!child_record_running(&terminated));
        assert!(!child_record_exited(&terminated));
        assert!(child_record_terminated(&terminated));
    }

    #[test]
    fn adopt_running_child_record_stamps_once_and_persists() {
        // `adopt_running_child_record` adopts a running, not-yet-adopted record
        // by stamping `adopted_unix_ms` and persisting the meta file; it skips
        // records that are already adopted and records that are not running.
        // No base or branch test calls it directly.
        let project_dir = std::env::temp_dir().join(format!(
            "actplane-mcp-adopt-test-{}-{}",
            std::process::id(),
            child_launch_id()
        ));
        let log_dir = project_dir
            .join(".actplane")
            .join("children")
            .join("adopt-test");
        let make = |status: ChildStatus, adopted: Option<u64>| ChildRecord {
            launch_id: "adopt-test".to_string(),
            pid: std::process::id() as i32,
            child_id: 901,
            scope_id: 5,
            cmd: vec!["/bin/true".to_string()],
            stdout: log_dir.join("stdout.log"),
            stderr: log_dir.join("stderr.log"),
            meta: log_dir.join("meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: 0,
            restart_backoff_ms: 0,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: adopted,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(status)),
        };

        let mut running = make(ChildStatus::Running, None);
        assert!(adopt_running_child_record(&mut running));
        let stamp = running.adopted_unix_ms.expect("adoption stamp");
        let persisted: Value =
            serde_json::from_str(&std::fs::read_to_string(&running.meta).expect("persisted meta"))
                .expect("meta json");
        assert_eq!(persisted["adopted_unix_ms"].as_u64(), Some(stamp));
        let loaded = load_child_records_with_adoptions(&project_dir);
        assert_eq!(
            loaded
                .records
                .get(&901)
                .expect("loaded record")
                .adopted_unix_ms,
            Some(stamp)
        );

        // Re-adoption is a no-op and preserves the original stamp.
        assert!(!adopt_running_child_record(&mut running));
        assert_eq!(running.adopted_unix_ms, Some(stamp));

        // A non-running record is skipped.
        let mut exited = make(
            ChildStatus::Exited {
                code: Some(0),
                signal: None,
            },
            None,
        );
        assert!(!adopt_running_child_record(&mut exited));
        assert!(exited.adopted_unix_ms.is_none());

        let _ = std::fs::remove_dir_all(project_dir);
    }

    fn unattached_server() -> ActPlaneMcp {
        ActPlaneMcp {
            project_dir: PathBuf::from("."),
            control: None,
            children: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn args(pairs: &[(&str, Value)]) -> Option<serde_json::Map<String, Value>> {
        Some(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        )
    }

    fn err_message(result: Result<CallToolResult, rmcp::ErrorData>) -> String {
        result.expect_err("expected error").message.to_string()
    }

    #[test]
    fn engine_backed_handlers_require_an_attached_control() {
        let server = unattached_server();
        for message in [
            err_message(server.do_bind_child_domain(args(&[("pid", serde_json::json!(1))]))),
            err_message(server.do_append_policy_delta_for_actor(None, None, None)),
            err_message(
                server.do_launch_child_domain(args(&[("cmd", serde_json::json!(["/bin/true"]))])),
            ),
            err_message(
                server.do_restart_child_domain(args(&[("child_id", serde_json::json!(1))])),
            ),
        ] {
            assert!(
                message.contains("No eBPF engine attached"),
                "unexpected message: {message}"
            );
        }
    }

    #[test]
    fn bind_checks_the_engine_before_its_arguments_but_launch_does_not() {
        let server = unattached_server();
        // bind resolves the control first, so the attachment error wins.
        assert!(err_message(server.do_bind_child_domain(None)).contains("No eBPF engine attached"));
        // launch validates `cmd` (and its emptiness) before the control lookup.
        assert_eq!(
            err_message(server.do_launch_child_domain(None)),
            "missing `cmd`"
        );
        assert!(
            err_message(server.do_launch_child_domain(args(&[("cmd", serde_json::json!([]))])))
                .contains("cmd must not be empty")
        );
        assert!(
            err_message(
                server.do_launch_child_domain(args(&[("cmd", serde_json::json!(["/bin/true"]),)]))
            )
            .contains("No eBPF engine attached")
        );
    }
    #[test]
    fn child_id_arg_prefers_child_id_and_falls_back_to_domain_id() {
        // `child_id_arg` resolves the target child id from tool-call args,
        // preferring an explicit `child_id` and falling back to a legacy
        // `domain_id` when no `child_id` is present. No base or branch test
        // pins this precedence directly.
        let both = serde_json::json!({ "child_id": 7, "domain_id": 9 })
            .as_object()
            .expect("object")
            .clone();
        // An explicit `child_id` wins over a `domain_id` that is also present.
        assert_eq!(child_id_arg(&both).unwrap(), 7);

        let domain_only = serde_json::json!({ "domain_id": 42 })
            .as_object()
            .expect("object")
            .clone();
        // With no `child_id`, it falls back to `domain_id`.
        assert_eq!(child_id_arg(&domain_only).unwrap(), 42);

        let empty = serde_json::json!({}).as_object().expect("object").clone();
        // Neither key present is an error.
        assert!(child_id_arg(&empty).is_err());
    }
    #[test]
    fn child_record_from_meta_decodes_full_and_minimal_metas() {
        // `child_record_from_meta` is the decode inverse of `child_record_json`:
        // a meta object becomes a `ChildRecord`, with `None`/missing fields
        // falling back to their defaults (`log_dir`-relative paths, the
        // restart-policy defaults, `Running` status). No base or branch test
        // pins this helper directly.
        // A full meta decodes every field.
        let log_dir = PathBuf::from("/tmp/child-reg/4242");
        let full = serde_json::json!({
            "pid": 777,
            "child_id": 8,
            "scope_id": 9,
            "launch_id": "L-1",
            "cmd": ["/bin/true", "x"],
            "stdout": "/s/out.log",
            "stderr": "/s/err.log",
            "meta": "/s/meta.json",
            "proc_start_time": 55,
            "policy": "rule r:",
            "restart_policy": "on_exit",
            "restart_count": 1,
            "restart_limit": 5,
            "restart_backoff_ms": 250,
            "last_exit_unix_ms": 12,
            "restarted_from": 7,
            "status": { "state": "exited", "code": 2, "signal": 1 },
        });
        let record = child_record_from_meta(&full, log_dir.clone()).expect("full meta");
        assert_eq!(record.launch_id, "L-1");
        assert_eq!(record.pid, 777);
        assert_eq!(record.child_id, 8);
        assert_eq!(record.scope_id, 9);
        assert_eq!(record.cmd, vec!["/bin/true".to_string(), "x".to_string()]);
        assert_eq!(record.stdout, PathBuf::from("/s/out.log"));
        assert_eq!(record.stderr, PathBuf::from("/s/err.log"));
        assert_eq!(record.meta, PathBuf::from("/s/meta.json"));
        assert_eq!(record.proc_start_time, Some(55));
        assert_eq!(record.policy, Some("rule r:".to_string()));
        assert_eq!(record.restart_policy, RestartPolicy::OnExit);
        assert_eq!(record.restart_count, 1);
        assert_eq!(record.restart_limit, 5);
        assert_eq!(record.restart_backoff_ms, 250);
        assert_eq!(record.last_exit_unix_ms, Some(12));
        assert_eq!(record.restarted_from, Some(7));
        assert!(matches!(
            *record.status.lock().expect("status"),
            ChildStatus::Exited {
                code: Some(2),
                signal: Some(1)
            }
        ));

        // A minimal meta relies on every default: `launch_id` falls back to
        // the log directory's file name, the three log paths are derived from
        // it, and the restart fields take their defaults.
        let minimal = serde_json::json!({
            "pid": 3,
            "child_id": 4,
            "cmd": ["bin"],
        });
        let rec = child_record_from_meta(&minimal, log_dir.clone()).expect("minimal meta");
        assert_eq!(rec.launch_id, "4242");
        assert_eq!(rec.scope_id, 0);
        assert_eq!(rec.stdout, log_dir.join("stdout.log"));
        assert_eq!(rec.stderr, log_dir.join("stderr.log"));
        assert_eq!(rec.meta, log_dir.join("meta.json"));
        assert_eq!(rec.proc_start_time, None);
        assert_eq!(rec.policy, None);
        assert_eq!(rec.restart_policy, RestartPolicy::Never);
        assert_eq!(rec.restart_count, 0);
        assert_eq!(rec.restart_limit, DEFAULT_RESTART_LIMIT);
        assert_eq!(rec.restart_backoff_ms, DEFAULT_RESTART_BACKOFF_MS);
        assert!(matches!(
            *rec.status.lock().expect("status"),
            ChildStatus::Running
        ));

        // A meta missing the required `pid` cannot be decoded.
        let no_pid = serde_json::json!({ "child_id": 4, "cmd": ["bin"] });
        assert!(child_record_from_meta(&no_pid, log_dir.clone()).is_none());

        // A meta missing the required `cmd` cannot be decoded.
        let no_cmd = serde_json::json!({ "pid": 3, "child_id": 4 });
        assert!(child_record_from_meta(&no_cmd, log_dir).is_none());
    }

    fn meta_json_record(policy: Option<String>) -> ChildRecord {
        ChildRecord {
            launch_id: "meta-json-test".to_string(),
            pid: 4242,
            child_id: 902,
            scope_id: 3,
            cmd: vec!["/bin/echo".to_string(), "hi".to_string()],
            stdout: PathBuf::from("/tmp/actplane-meta-out.log"),
            stderr: PathBuf::from("/tmp/actplane-meta-err.log"),
            meta: PathBuf::from("/tmp/actplane-meta.json"),
            proc_start_time: Some(999),
            policy: policy.clone(),
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: 0,
            restart_backoff_ms: 0,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(ChildStatus::Running)),
        }
    }

    #[test]
    fn child_record_meta_json_adds_policy_only_when_attached() {
        // `child_record_meta_json` wraps `child_record_json` and conditionally
        // embeds the policy text; no base or branch test calls it.
        let with_policy = meta_json_record(Some("rule r:\n  notify exec \"x\"\n".to_string()));
        let value = child_record_meta_json(&with_policy);
        assert_eq!(value["launch_id"], "meta-json-test");
        assert_eq!(value["child_id"], 902);
        assert_eq!(value["policy"], "rule r:\n  notify exec \"x\"\n");
        assert_eq!(value["policy_attached"], true);
        assert_eq!(value["status"]["state"], "running");

        let without_policy = meta_json_record(None);
        let value = child_record_meta_json(&without_policy);
        assert_eq!(value["policy_attached"], false);
        assert!(value.get("policy").is_none());
    }
    #[test]
    fn child_status_json_encodes_each_state_variant() {
        // `child_status_json` is the forward builder of `child_status_from_json`:
        // each `ChildStatus` variant encodes to a JSON object with its `state`
        // tag (and, for `Exited`, its optional code/signal). No base or branch
        // test pins this builder directly.
        let running = child_status_json(&ChildStatus::Running);
        assert_eq!(running, serde_json::json!({ "state": "running" }));

        let terminated = child_status_json(&ChildStatus::Terminated);
        assert_eq!(terminated, serde_json::json!({ "state": "terminated" }));

        // An exited child carries its optional code and signal.
        let exited = child_status_json(&ChildStatus::Exited {
            code: Some(3),
            signal: Some(15),
        });
        assert_eq!(
            exited,
            serde_json::json!({
                "state": "exited",
                "code": 3,
                "signal": 15,
            })
        );

        // An exited child with no code/signal emits nulls.
        let exited_bare = child_status_json(&ChildStatus::Exited {
            code: None,
            signal: None,
        });
        assert_eq!(
            exited_bare,
            serde_json::json!({
                "state": "exited",
                "code": null,
                "signal": null,
            })
        );
    }
    #[test]
    fn child_status_from_json_parses_state_and_rejects_unknown() {
        // `child_status_from_json` turns a child record's `state` field into
        // a `ChildStatus`: `"running"`/`"terminated"` map to their variants,
        // `"exited"` maps to `Exited` carrying the optional code/signal, and
        // any other (or missing) state yields `None`. No base or branch test
        // pins this helper directly.
        let running = child_status_from_json(&serde_json::json!({ "state": "running" }));
        assert!(matches!(running, Some(ChildStatus::Running)));

        let terminated = child_status_from_json(&serde_json::json!({ "state": "terminated" }));
        assert!(matches!(terminated, Some(ChildStatus::Terminated)));

        // An exited child carries its optional exit code and signal.
        let exited = child_status_from_json(&serde_json::json!({
            "state": "exited",
            "code": 2,
            "signal": 9,
        }));
        assert!(matches!(
            exited,
            Some(ChildStatus::Exited {
                code: Some(2),
                signal: Some(9)
            })
        ));

        // An exited child with no code/signal carries `None` for both.
        let exited_bare = child_status_from_json(&serde_json::json!({ "state": "exited" }));
        assert!(matches!(
            exited_bare,
            Some(ChildStatus::Exited {
                code: None,
                signal: None
            })
        ));

        // An unknown state is not a known variant.
        let unknown = child_status_from_json(&serde_json::json!({ "state": "paused" }));
        assert!(unknown.is_none());

        // A missing state field yields `None`.
        assert!(child_status_from_json(&serde_json::json!({})).is_none());
    }
    #[test]
    fn child_supervision_json_reports_adopted_or_wait_handle() {
        // `child_supervision_json` describes how a child's exit status will
        // be observed: an adopted child (non-`None` `adopted_unix_ms`) polls
        // with coarse exit-status precision, a wait-handle child reports a
        // precise status. No base or branch test pins this helper directly.
        fn record(adopted_unix_ms: Option<u64>) -> ChildRecord {
            ChildRecord {
                launch_id: "L".to_string(),
                pid: 1,
                child_id: 1,
                scope_id: 1,
                cmd: vec![],
                stdout: PathBuf::from("/tmp/out.log"),
                stderr: PathBuf::from("/tmp/err.log"),
                meta: PathBuf::from("/tmp/meta.json"),
                proc_start_time: None,
                policy: None,
                policy_audit_meta: PolicyAuditMeta::default(),
                restart_policy: RestartPolicy::Never,
                restart_count: 0,
                restart_limit: 0,
                restart_backoff_ms: 0,
                last_exit_unix_ms: None,
                restart_alerted_unix_ms: None,
                adopted_unix_ms,
                restarted_from: None,
                replacement_child_id: None,
                status: Arc::new(Mutex::new(ChildStatus::Running)),
            }
        }

        // An adopted child reports adopted-polling mode with coarse precision.
        let adopted = child_supervision_json(&record(Some(12345)));
        assert_eq!(adopted["mode"], serde_json::json!("adopted_polling"));
        assert_eq!(adopted["adopted_unix_ms"], serde_json::json!(12345));
        assert_eq!(adopted["exit_status_precise"], serde_json::json!(false));

        // A wait-handle child reports null adoption with precise precision.
        let wait_handle = child_supervision_json(&record(None));
        assert_eq!(wait_handle["mode"], serde_json::json!("wait_handle"));
        assert_eq!(wait_handle["adopted_unix_ms"], serde_json::Value::Null);
        assert_eq!(wait_handle["exit_status_precise"], serde_json::json!(true));
    }

    #[test]
    fn default_project_dir_honors_env_priority() {
        // `default_project_dir` reads the first set of a documented env chain;
        // the ctor with no explicit dir consumes it. No base or branch test
        // calls it directly.
        let keys = [
            "ACTPLANE_PROJECT_DIR",
            "CODEX_PROJECT_DIR",
            "CODEX_WORKSPACE",
            "CLAUDE_PROJECT_DIR",
        ];
        for key in keys {
            unsafe { std::env::remove_var(key) };
        }

        // Highest-priority override wins over the lower ones.
        unsafe { std::env::set_var("CLAUDE_PROJECT_DIR", "/tmp/plan-claude") };
        unsafe { std::env::set_var("CODEX_WORKSPACE", "/tmp/plan-codex-ws") };
        unsafe { std::env::set_var("CODEX_PROJECT_DIR", "/tmp/plan-codex") };
        unsafe { std::env::set_var("ACTPLANE_PROJECT_DIR", "/tmp/plan-actplane") };
        assert_eq!(default_project_dir(), PathBuf::from("/tmp/plan-actplane"));

        // Dropping the top key falls through to the next in priority order.
        unsafe { std::env::remove_var("ACTPLANE_PROJECT_DIR") };
        assert_eq!(default_project_dir(), PathBuf::from("/tmp/plan-codex"));

        // With no keys set, the current directory is used.
        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
        assert_eq!(default_project_dir(), std::env::current_dir().expect("cwd"));
    }

    #[test]
    fn ensure_local_parent_peer_requires_credentials() {
        // `ensure_local_parent_peer` rejects a missing peer credential and
        // otherwise delegates to control-plane actor checks (a no-op when the
        // server has no engine attached); no base or branch test calls it.
        let project =
            std::env::temp_dir().join(format!("actplane-local-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&project);
        std::fs::create_dir_all(&project).unwrap();
        let server = ActPlaneMcp::new_with_control_and_project_dir(None, Some(project.clone()));

        let err = server
            .ensure_local_parent_peer(None)
            .expect_err("missing peer");
        assert!(err.contains("peer credentials are unavailable"), "{err}");

        let peer = local_control::PeerCred {
            pid: std::process::id() as i32,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            identity: crate::audit::ProcessIdentity::capture(std::process::id() as i32, None, None),
        };
        // No engine attached -> the delegation short-circuits to Ok.
        server
            .ensure_local_parent_peer(Some(peer))
            .expect("no engine");

        let _ = std::fs::remove_dir_all(&project);
    }

    #[cfg(unix)]
    #[test]
    fn load_feedback_reports_each_file_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let feedback = tmp.path().join("feedback.txt");
        let prior = std::env::var("ACTPLANE_FEEDBACK_FILE").ok();
        unsafe {
            std::env::set_var("ACTPLANE_FEEDBACK_FILE", &feedback);
        }
        let server = ActPlaneMcp {
            project_dir: tmp.path().to_path_buf(),
            control: None,
            children: Arc::new(Mutex::new(HashMap::new())),
        };

        // Missing file.
        let missing = server.load_feedback();
        assert!(
            missing.contains("No ActPlane feedback file yet"),
            "{missing}"
        );

        // Empty file.
        std::fs::write(&feedback, "  \n").expect("write empty");
        let empty = server.load_feedback();
        assert!(
            empty.contains("No ActPlane feedback has been written yet"),
            "{empty}"
        );

        // Populated file includes the path and the content.
        std::fs::write(&feedback, "blocked: run tests first").expect("write content");
        let loaded = server.load_feedback();
        assert!(loaded.contains("Latest ActPlane feedback"), "{loaded}");
        assert!(loaded.contains("blocked: run tests first"), "{loaded}");
        assert!(loaded.contains(&feedback.display().to_string()), "{loaded}");

        match prior {
            Some(v) => unsafe { std::env::set_var("ACTPLANE_FEEDBACK_FILE", v) },
            None => unsafe { std::env::remove_var("ACTPLANE_FEEDBACK_FILE") },
        }
    }

    #[test]
    fn feedback_file_resolves_from_policy_and_discovery() {
        // `discover_policy_file` walks up for actplane.yaml /
        // .actplane/policy.yaml, and `feedback_file` derives the feedback path
        // from the policy root, its config, or a latest run; no base or branch
        // test calls either.
        let root =
            std::env::temp_dir().join(format!("actplane-feedback-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let nested = project.join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        let server = ActPlaneMcp::new_with_control_and_project_dir(None, Some(project.clone()));

        // No policy anywhere -> default under the project dir.
        assert!(server.discover_policy_file().is_none());
        assert_eq!(
            server.feedback_file(),
            project.join(".actplane/last-violation.txt")
        );

        // A policy with an explicit feedback path resolves relative to its root.
        std::fs::write(
            project.join("actplane.yaml"),
            "policy: \"rule r:\\n  notify exec \\\"ls\\\"\\n  because \\\"x\\\"\\n\"\nfeedback:\n  path: custom/feedback.txt\n",
        )
        .unwrap();
        assert_eq!(
            server.discover_policy_file(),
            Some(project.join("actplane.yaml"))
        );
        assert_eq!(server.feedback_file(), project.join("custom/feedback.txt"));

        // A child directory's server discovers the ancestor policy and falls
        // back to the default under that policy's root when none is configured.
        std::fs::write(
            project.join("actplane.yaml"),
            "policy: \"rule r:\\n  notify exec \\\"ls\\\"\\n  because \\\"x\\\"\\n\"\n",
        )
        .unwrap();
        let child = ActPlaneMcp::new_with_control_and_project_dir(None, Some(nested));
        assert_eq!(
            child.discover_policy_file(),
            Some(project.join("actplane.yaml"))
        );
        assert_eq!(
            child.feedback_file(),
            project.join(".actplane/last-violation.txt")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    fn bare_server(project_dir: std::path::PathBuf) -> ActPlaneMcp {
        ActPlaneMcp {
            project_dir,
            control: None,
            children: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[test]
    fn discover_policy_file_walks_up_to_the_nearest_actplane_yaml() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&nested).expect("mkdir");
        let server = bare_server(nested.clone());
        assert!(server.discover_policy_file().is_none(), "no yaml yet");

        // `.actplane/policy.yaml` in the cwd wins over a parent `actplane.yaml`.
        let dot = nested.join(".actplane");
        std::fs::create_dir_all(&dot).expect("mkdir");
        let nested_yaml = dot.join("policy.yaml");
        std::fs::write(&nested_yaml, "policy: \"\"\n").expect("write");
        std::fs::write(tmp.path().join("actplane.yaml"), "policy: \"\"\n").expect("write");
        assert_eq!(
            server.discover_policy_file().as_deref(),
            Some(nested_yaml.as_path())
        );

        // Removing the nested candidate falls back to the ancestor file.
        std::fs::remove_file(&nested_yaml).expect("rm");
        assert_eq!(
            server.discover_policy_file().as_deref(),
            Some(tmp.path().join("actplane.yaml").as_path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn feedback_file_prefers_env_then_runs_then_config_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("actplane.yaml"), "policy: \"\"\n").expect("write");
        let server = bare_server(tmp.path().to_path_buf());
        let prior = std::env::var("ACTPLANE_FEEDBACK_FILE").ok();
        unsafe {
            std::env::remove_var("ACTPLANE_FEEDBACK_FILE");
        }

        // No runs dir, no feedback.path -> the default beside the policy.
        assert_eq!(
            server.feedback_file(),
            tmp.path().join(DEFAULT_FEEDBACK_FILE)
        );

        // A `feedback.path` in the config is honored, relative to the root.
        std::fs::write(
            tmp.path().join("actplane.yaml"),
            "policy: \"\"\nfeedback:\n  path: custom-feedback.txt\n",
        )
        .expect("write config");
        assert_eq!(
            server.feedback_file(),
            tmp.path().join("custom-feedback.txt")
        );

        // The most recent `.actplane/runs/*/feedback.txt` wins over the config.
        let run = tmp.path().join(".actplane/runs/run-1");
        std::fs::create_dir_all(&run).expect("mkdir");
        let run_feedback = run.join("feedback.txt");
        std::fs::write(&run_feedback, "hooked").expect("write");
        assert_eq!(server.feedback_file(), run_feedback);

        // The environment override short-circuits everything else.
        let env_path = tmp.path().join("env-feedback.txt");
        unsafe {
            std::env::set_var("ACTPLANE_FEEDBACK_FILE", &env_path);
        }
        assert_eq!(server.feedback_file(), env_path);

        match prior {
            Some(v) => unsafe { std::env::set_var("ACTPLANE_FEEDBACK_FILE", v) },
            None => unsafe { std::env::remove_var("ACTPLANE_FEEDBACK_FILE") },
        }
    }
    #[test]
    fn first_tool_text_reads_the_first_content_text() {
        // `first_tool_text` pulls the first content entry's `text` out of a
        // tool-call value, or `None` when the shape is absent. No base or
        // branch test pins this helper directly.
        // A well-formed content array with a text entry yields that text.
        let ok = serde_json::json!({
            "content": [ { "text": "first" }, { "text": "second" } ]
        });
        assert_eq!(first_tool_text(&ok).as_deref(), Some("first"));

        // A nested content array with no text field yields None.
        let no_text = serde_json::json!({
            "content": [ { "data": "x" } ]
        });
        assert_eq!(first_tool_text(&no_text), None);

        // No content array at all yields None.
        assert_eq!(first_tool_text(&serde_json::json!({})), None);

        // An empty content array has no first entry.
        let empty = serde_json::json!({ "content": [] });
        assert_eq!(first_tool_text(&empty), None);
    }
    #[test]
    fn json_optional_bool_parses_or_rejects_wrong_types() {
        // `json_optional_bool` reads an optional boolean tool-call arg: absent
        // keys yield `Ok(None)`, booleans yield `Ok(Some(..))`, and a
        // non-boolean value is rejected. No base or branch test pins this
        // helper directly.
        let absent = serde_json::json!({ "other": true })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(json_optional_bool(&absent, "flag").unwrap(), None);

        let true_val = serde_json::json!({ "flag": true })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(json_optional_bool(&true_val, "flag").unwrap(), Some(true));

        let false_val = serde_json::json!({ "flag": false })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(json_optional_bool(&false_val, "flag").unwrap(), Some(false));

        let wrong = serde_json::json!({ "flag": 1 })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_optional_bool(&wrong, "flag").is_err());
    }
    #[test]
    fn json_optional_u64_parses_or_rejects_non_integers() {
        // `json_optional_u64` reads an optional u64 tool-call arg: an absent
        // key yields `Ok(None)`, a non-negative integer yields `Ok(Some(..))`,
        // and any other JSON value (negative, string, object) is rejected.
        // No base or branch test pins this helper directly.
        let absent = serde_json::json!({ "other": 1 })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(json_optional_u64(&absent, "max").unwrap(), None);

        let good = serde_json::json!({ "max": 4096u64 })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(json_optional_u64(&good, "max").unwrap(), Some(4096));

        let zero = serde_json::json!({ "max": 0 })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(json_optional_u64(&zero, "max").unwrap(), Some(0));

        let negative = serde_json::json!({ "max": -1 })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_optional_u64(&negative, "max").is_err());

        let string = serde_json::json!({ "max": "4096" })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_optional_u64(&string, "max").is_err());
    }
    #[test]
    fn json_optional_usize_reads_in_range_integers_and_rejects_the_rest() {
        // `json_optional_usize` reads an optional non-negative integer from
        // tool args into a `usize`: an absent key is `None`, an in-range
        // value is `Some(n)`, and a non-integer or negative value is an
        // error. No base or branch test pins this helper directly.
        let args = serde_json::json!({ "max_bytes": 4096, "absent_flag": "x" })
            .as_object()
            .expect("object")
            .clone();

        assert_eq!(
            json_optional_usize(&args, "max_bytes").expect("max_bytes"),
            Some(4096)
        );
        assert_eq!(
            json_optional_usize(&args, "missing").expect("missing"),
            None
        );

        // A string value is not an integer.
        let string_arg = serde_json::json!({ "max_bytes": "4096" })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_optional_usize(&string_arg, "max_bytes").is_err());

        // A negative value has no non-negative reading.
        let negative_arg = serde_json::json!({ "max_bytes": -1 })
            .as_object()
            .expect("object")
            .clone();
        assert!(json_optional_usize(&negative_arg, "max_bytes").is_err());
    }

    #[test]
    fn latest_run_feedback_picks_most_recently_modified_run() {
        // `latest_run_feedback` scans .actplane/runs and returns the run whose
        // feedback.txt was modified last; no base or branch test calls it.
        let root =
            std::env::temp_dir().join(format!("actplane-latest-feedback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert!(latest_run_feedback(&root).is_none());

        let old = root.join(".actplane/runs/run-old");
        let new = root.join(".actplane/runs/run-new");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(old.join("feedback.txt"), "old").unwrap();
        std::fs::write(new.join("feedback.txt"), "new").unwrap();

        set_mtime(&old.join("feedback.txt"), 1_000);
        set_mtime(&new.join("feedback.txt"), 2_000);
        assert_eq!(latest_run_feedback(&root), Some(new.join("feedback.txt")));

        // Flipping the timestamps flips the winner.
        set_mtime(&old.join("feedback.txt"), 3_000);
        assert_eq!(latest_run_feedback(&root), Some(old.join("feedback.txt")));

        fn set_mtime(path: &std::path::Path, secs: i64) {
            let times = [
                libc::timespec {
                    tv_sec: secs,
                    tv_nsec: 0,
                },
                libc::timespec {
                    tv_sec: secs,
                    tv_nsec: 0,
                },
            ];
            let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
            assert_eq!(rc, 0, "utimensat failed");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    fn bare_server_c2(project_dir: std::path::PathBuf) -> ActPlaneMcp {
        ActPlaneMcp {
            project_dir,
            control: None,
            children: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[test]
    fn load_and_validate_reports_one_line_per_compiled_rule() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("nested")).expect("mkdir");
        let server = bare_server_c2(tmp.path().join("nested"));

        // No policy file anywhere in the ancestor chain.
        assert_eq!(server.load_and_validate(), "No actplane.yaml found.");

        let yaml = tmp.path().join("actplane.yaml");
        std::fs::write(
            &yaml,
            "policy: |\n  rule r1:\n    notify exec \"git\"\n    because \"c1\"\n  rule r2:\n    notify exec \"cargo\"\n    because \"c2\"\n",
        )
        .expect("write");
        let ok = server.load_and_validate();
        assert!(ok.contains("Policy valid"), "{ok}");
        assert!(ok.contains("2 rules"), "{ok}");
        assert!(ok.contains("1. r1"), "{ok}");
        assert!(ok.contains("2. r2"), "{ok}");
        assert!(ok.contains("notify"), "{ok}");
        assert!(ok.contains("c1"), "{ok}");

        // A file without a `policy:` field is rejected by name.
        std::fs::write(&yaml, "domains: []\n").expect("write");
        let missing = server.load_and_validate();
        assert!(missing.contains("has no `policy:` field"), "{missing}");
        assert!(missing.contains("actplane.yaml"), "{missing}");

        // Invalid DSL inside a valid YAML wrapper reports a compile error.
        std::fs::write(&yaml, "policy: \"rule broken\"\n").expect("write");
        let bad = server.load_and_validate();
        assert!(bad.starts_with("Policy compile error:"), "{bad}");

        // Malformed YAML is reported as a parse error with the path.
        std::fs::write(&yaml, "policy: [unterminated\n").expect("write");
        let yamlerr = server.load_and_validate();
        assert!(yamlerr.contains("YAML parse error in"), "{yamlerr}");
    }

    fn detached_server() -> (ActPlaneMcp, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let server = ActPlaneMcp::new_with_control_and_project_dir(None, Some(tmp.path().into()));
        (server, tmp)
    }

    #[test]
    fn local_control_request_rejects_non_object_and_missing_op() {
        let (server, _tmp) = detached_server();

        let value = server.handle_local_control_request(serde_json::json!([1, 2]), None);
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "control request must be a JSON object");

        let value = server.handle_local_control_request(serde_json::json!({ "op": 7 }), None);
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "control request missing string `op`");

        let value = server.handle_local_control_request(serde_json::json!({ "op": "frob" }), None);
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "unknown ActPlane control op `frob`");
    }

    #[test]
    fn local_control_status_reports_project_dir_and_attachment() {
        let (server, tmp) = detached_server();
        let value =
            server.handle_local_control_request(serde_json::json!({ "op": "status" }), None);
        assert_eq!(value["ok"], true);
        assert_eq!(value["result"]["attached"], false);
        assert_eq!(value["result"]["child_count"], 0);
        assert!(value["result"]["control"].is_null());
        assert_eq!(
            value["result"]["project_dir"],
            tmp.path().display().to_string()
        );
        assert_eq!(server.control_parent(), None);
    }

    #[test]
    fn local_control_peer_requiring_ops_reject_missing_credentials() {
        let (server, _tmp) = detached_server();
        for op in [
            "bind_child_domain",
            "append_policy_delta",
            "launch_child_domain",
            "list_child_domains",
            "read_child_domain_logs",
            "terminate_child_domain",
            "restart_child_domain",
            "reconcile_child_domains",
        ] {
            let value = server.handle_local_control_request(serde_json::json!({ "op": op }), None);
            assert_eq!(value["ok"], false, "{op}: {value}");
            assert_eq!(
                value["error"], "local control peer credentials are unavailable",
                "{op}: {value}"
            );
        }
    }

    #[test]
    fn start_local_control_server_for_server_requires_an_attached_control() {
        let server = ActPlaneMcp {
            project_dir: PathBuf::from("."),
            control: None,
            children: Arc::new(Mutex::new(HashMap::new())),
        };
        let err = start_local_control_server_for_server(server)
            .err()
            .expect("unattached control is rejected");
        assert!(
            err.to_string()
                .contains("local control server requires an attached engine"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn local_control_status_reports_attachment_and_project_dir() {
        // `local_control_status` renders the supervisor `status` operation:
        // the project dir, whether a control handle is attached (with its
        // parent pid/domain when so), and the tracked child count. No base or
        // branch test calls it.
        let dir = std::env::temp_dir().join(format!(
            "actplane-status-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let server = ActPlaneMcp::new_with_control_and_project_dir(None, Some(dir.clone()));
        let value = server.local_control_status();
        assert_eq!(value["ok"], true);
        assert_eq!(value["result"]["attached"], false);
        assert_eq!(value["result"]["project_dir"], dir.display().to_string());
        assert_eq!(value["result"]["control"], Value::Null);
        assert_eq!(value["result"]["child_count"], 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn parse_restart_policy_str_maps_on_exit_and_defaults_to_never() {
        // `parse_restart_policy_str` maps a launch arg's restart policy onto
        // a `RestartPolicy`: `"on_exit"` (and its hyphenated spelling) yield
        // `OnExit`, and any other text yields `Never`. No base or branch
        // test pins this helper directly.
        assert_eq!(parse_restart_policy_str("on_exit"), RestartPolicy::OnExit);
        assert_eq!(parse_restart_policy_str("on-exit"), RestartPolicy::OnExit);

        // Anything else (including a bare `Never` spelling and empty) is the
        // no-restart default.
        assert_eq!(parse_restart_policy_str("never"), RestartPolicy::Never);
        assert_eq!(parse_restart_policy_str(""), RestartPolicy::Never);
        assert_eq!(parse_restart_policy_str("bogus"), RestartPolicy::Never);
    }
    #[test]
    fn policy_audit_meta_json_emits_only_present_fields() {
        // `policy_audit_meta_json` builds a child record's policy audit
        // metadata object from a `PolicyAuditMeta`: every `None` field is
        // omitted, so an all-`None` meta yields `None`, and a meta with any
        // field yields an object containing only the present fields. No
        // base or branch test pins this builder directly.
        // An all-None meta is omitted entirely.
        assert!(policy_audit_meta_json(&PolicyAuditMeta::default()).is_none());

        // A single present field yields an object with just that key.
        let ref_only = PolicyAuditMeta {
            policy_ref: Some("repo.yaml".to_string()),
            ..PolicyAuditMeta::default()
        };
        assert_eq!(
            policy_audit_meta_json(&ref_only).as_ref(),
            Some(&serde_json::json!({ "policy_ref": "repo.yaml" }))
        );

        // A fully-populated meta yields every key, in the object.
        let full = PolicyAuditMeta {
            policy_ref: Some("repo.yaml".to_string()),
            approved_by: Some("reviewer".to_string()),
            approval_ref: Some("PR-7".to_string()),
            generated_by: Some("actplane".to_string()),
        };
        let built = policy_audit_meta_json(&full).expect("full meta builds");
        assert_eq!(built["policy_ref"], serde_json::json!("repo.yaml"));
        assert_eq!(built["approved_by"], serde_json::json!("reviewer"));
        assert_eq!(built["approval_ref"], serde_json::json!("PR-7"));
        assert_eq!(built["generated_by"], serde_json::json!("actplane"));
    }
    #[test]
    fn policy_audit_meta_from_args_maps_optional_string_fields() {
        // `policy_audit_meta_from_args` reads the four optional policy audit
        // metadata strings out of tool args into a `PolicyAuditMeta`: each
        // present string maps to `Some`, each absent key to `None`, and a
        // non-string field is an error. No base or branch test pins this
        // helper directly.
        // A fully-populated arg map yields every field set.
        let full = serde_json::json!({
            "policy_ref": "repo.yaml",
            "approved_by": "reviewer",
            "approval_ref": "PR-7",
            "generated_by": "actplane",
        })
        .as_object()
        .expect("object")
        .clone();
        assert_eq!(
            policy_audit_meta_from_args(&full).expect("full args"),
            PolicyAuditMeta {
                policy_ref: Some("repo.yaml".to_string()),
                approved_by: Some("reviewer".to_string()),
                approval_ref: Some("PR-7".to_string()),
                generated_by: Some("actplane".to_string()),
            }
        );

        // An empty arg map yields the all-None default.
        let empty = serde_json::json!({}).as_object().expect("object").clone();
        assert_eq!(
            policy_audit_meta_from_args(&empty).expect("empty args"),
            PolicyAuditMeta::default()
        );

        // A non-string field is rejected.
        let bad_ref = serde_json::json!({ "policy_ref": 7 })
            .as_object()
            .expect("object")
            .clone();
        assert!(policy_audit_meta_from_args(&bad_ref).is_err());
    }
    #[test]
    fn policy_audit_meta_from_json_maps_string_fields_or_rejects_non_object() {
        // `policy_audit_meta_from_json` reads a child record's policy audit
        // metadata object: the four string fields map into the struct, each
        // absent key reads as `None`, and a non-object value yields `None`.
        // No base or branch test pins this helper directly.
        let full = policy_audit_meta_from_json(&serde_json::json!({
            "policy_ref": "repo.yaml",
            "approved_by": "reviewer",
            "approval_ref": "PR-7",
            "generated_by": "actplane",
        }));
        assert_eq!(
            full,
            Some(PolicyAuditMeta {
                policy_ref: Some("repo.yaml".to_string()),
                approved_by: Some("reviewer".to_string()),
                approval_ref: Some("PR-7".to_string()),
                generated_by: Some("actplane".to_string()),
            })
        );

        // An object with no keys reads every field as `None`.
        let empty = policy_audit_meta_from_json(&serde_json::json!({}));
        assert_eq!(empty, Some(PolicyAuditMeta::default()));

        // A non-object value is not a metadata object.
        assert!(policy_audit_meta_from_json(&serde_json::json!("repo.yaml")).is_none());
    }

    fn identity_record(pid: i32, proc_start_time: Option<u64>) -> ChildRecord {
        ChildRecord {
            launch_id: "identity-test".to_string(),
            pid,
            child_id: 903,
            scope_id: 1,
            cmd: vec!["/bin/true".to_string()],
            stdout: PathBuf::from("/tmp/actplane-identity-out.log"),
            stderr: PathBuf::from("/tmp/actplane-identity-err.log"),
            meta: PathBuf::from("/tmp/actplane-identity-meta.json"),
            proc_start_time,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: 0,
            restart_backoff_ms: 0,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(ChildStatus::Running)),
        }
    }

    #[test]
    fn process_identity_matches_guards_pid_and_start_time() {
        // `process_identity_matches` decides whether a persisted pid still
        // refers to the same supervised child; no base or branch test calls it.
        let me = std::process::id() as i32;

        // Non-positive pid never matches.
        assert!(!process_identity_matches(&identity_record(0, None)));
        assert!(!process_identity_matches(&identity_record(-1, None)));

        // No recorded start time falls back to a liveness check.
        assert!(process_identity_matches(&identity_record(me, None)));

        // A recorded start time must equal the live one.
        let live = proc_start_time(me).expect("self start time");
        assert!(process_identity_matches(&identity_record(me, Some(live))));
        assert!(!process_identity_matches(&identity_record(
            me,
            Some(live + 1)
        )));

        // Positive pid with no live /proc entry fails the identity check.
        assert!(!process_identity_matches(&identity_record(
            i32::MAX,
            Some(1)
        )));
    }

    #[test]
    fn process_exists_distinguishes_live_permission_and_reaped_pids() {
        // The current process is alive, so kill(0) must succeed.
        assert!(process_exists(std::process::id() as i32));
        // A pid that cannot exist yields ESRCH, which is the only gone answer.
        assert!(!process_exists(99_999_999));
        // Whether a foreign live pid is visible depends on uid, but a real live
        // pid must never be reported as reaped while the probe is running.
        if unsafe { libc::kill(1, 0) } == 0 {
            assert!(process_exists(1));
        }
    }

    #[cfg(unix)]
    #[test]
    fn child_record_meta_trust_root_requires_root_owned_private_ancestors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let children = tmp.path().join("children");
        let log_dir = children.join("run-1");
        let meta = log_dir.join("child.json");
        std::fs::create_dir_all(&log_dir).expect("dirs");
        std::fs::write(&meta, "{}").expect("meta");

        let current = std::fs::metadata(&children).expect("metadata");
        let owned_by_root = current.uid() == 0;
        let locked = |path: &std::path::Path| {
            let mode = std::fs::metadata(path).expect("metadata").mode();
            mode & 0o022 == 0
        };

        if !owned_by_root {
            // Non-root callers treat every record as trusted without inspecting
            // the tree, because they already trust the invoking user.
            assert!(child_record_meta_trusted_root(&meta));
        } else {
            assert_eq!(
                child_record_meta_trusted_root(&meta),
                locked(&children) && locked(&log_dir) && locked(&meta)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn child_record_meta_trust_root_rejects_a_parentless_path() {
        // The trust predicate requires the record to sit inside two directories
        // it can stat; the filesystem root has no parent, so it is never trusted
        // under the root rule. Non-root callers trust everything by uid.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        assert!(!child_record_meta_trusted_root(std::path::Path::new("/")));
    }

    #[test]
    fn refresh_child_record_status_marks_dead_running_child_exited() {
        // `refresh_child_record_status` flips a Running record to Exited when
        // its process identity no longer matches; no base or branch test calls
        // it.
        let project_dir =
            std::env::temp_dir().join(format!("actplane-refresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&project_dir);
        std::fs::create_dir_all(&project_dir).unwrap();

        let mut record = ChildRecord {
            launch_id: "refresh-test".to_string(),
            pid: i32::MAX,
            child_id: 904,
            scope_id: 1,
            cmd: vec!["/bin/true".to_string()],
            stdout: project_dir.join("stdout.log"),
            stderr: project_dir.join("stderr.log"),
            meta: project_dir.join("meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: 0,
            restart_backoff_ms: 0,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(ChildStatus::Running)),
        };

        refresh_child_record_status(&mut record);
        assert!(matches!(
            *record.status.lock().expect("status"),
            ChildStatus::Exited {
                code: None,
                signal: None
            }
        ));
        assert!(record.last_exit_unix_ms.is_some());
        // The refreshed record was persisted.
        assert!(record.meta.is_file());

        // A non-Running record is left untouched.
        *record.status.lock().unwrap() = ChildStatus::Terminated;
        let before = record.last_exit_unix_ms;
        refresh_child_record_status(&mut record);
        assert!(matches!(
            *record.status.lock().expect("status"),
            ChildStatus::Terminated
        ));
        assert_eq!(record.last_exit_unix_ms, before);

        let _ = std::fs::remove_dir_all(&project_dir);
    }

    #[test]
    #[cfg(unix)]
    fn secure_child_registry_enforces_owner_only_permissions_when_root() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("children");
        std::fs::create_dir(&dir).expect("create dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        secure_child_registry_dir(&dir).expect("secure dir");

        let file = dir.join("record.json");
        std::fs::write(&file, b"{}").expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        secure_child_registry_file(&file).expect("secure file");

        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            assert!(unsafe { libc::getuid() } != 0);
        }
        if euid == 0 {
            let dir_meta = std::fs::metadata(&dir).expect("dir meta");
            assert_eq!(dir_meta.mode() & 0o777, 0o755);
            assert_eq!(dir_meta.uid(), 0);
            let file_meta = std::fs::metadata(&file).expect("file meta");
            assert_eq!(file_meta.mode() & 0o777, 0o644);
            assert_eq!(file_meta.uid(), 0);
        } else {
            // Non-root leaves the existing permissions untouched.
            assert_eq!(
                std::fs::metadata(&dir).expect("dir meta").mode() & 0o777,
                0o777
            );
            assert_eq!(
                std::fs::metadata(&file).expect("file meta").mode() & 0o777,
                0o666
            );
        }
    }

    fn restart_record(
        policy: RestartPolicy,
        last_exit_unix_ms: Option<u64>,
        replacement_child_id: Option<u32>,
    ) -> ChildRecord {
        ChildRecord {
            launch_id: "restart-scheduling-test".to_string(),
            pid: std::process::id() as i32,
            child_id: 901,
            scope_id: 1,
            cmd: vec!["/bin/true".to_string()],
            stdout: PathBuf::from("/tmp/actplane-restart-out.log"),
            stderr: PathBuf::from("/tmp/actplane-restart-err.log"),
            meta: PathBuf::from("/tmp/actplane-restart-meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: policy,
            restart_count: 2,
            restart_limit: 5,
            restart_backoff_ms: 250,
            last_exit_unix_ms,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id,
            status: Arc::new(Mutex::new(ChildStatus::Running)),
        }
    }

    #[test]
    fn restart_scheduling_computes_next_attempt_and_settings() {
        // `next_restart_after_unix_ms`/`next_restart_settings` drive the
        // supervision loop's restart backoff. Neither is called by any base or
        // branch test.
        let rec = restart_record(RestartPolicy::OnExit, Some(1000), None);
        assert_eq!(rec.next_restart_after_unix_ms(), Some(1250));
        let s = rec.next_restart_settings();
        assert_eq!(s.policy, RestartPolicy::OnExit);
        assert_eq!(s.count, 3);
        assert_eq!(s.limit, 5);
        assert_eq!(s.backoff_ms, 250);

        // A replacement child already scheduled suppresses the next restart.
        let replaced = restart_record(RestartPolicy::OnExit, Some(1000), Some(7));
        assert_eq!(replaced.next_restart_after_unix_ms(), None);

        // Never-restart policy suppresses regardless of exit time.
        let never = restart_record(RestartPolicy::Never, Some(1000), None);
        assert_eq!(never.next_restart_after_unix_ms(), None);

        // OnExit without an observed exit time has no due timestamp yet.
        let no_exit = restart_record(RestartPolicy::OnExit, None, None);
        assert_eq!(no_exit.next_restart_after_unix_ms(), None);
    }

    #[test]
    fn server_get_info_advertises_stdio_tools_and_resources() {
        // `ActPlaneMcp::get_info` is the MCP handshake payload: it must
        // advertise exactly the tools and resources capabilities and carry the
        // ActPlane instruction text. No base or branch test calls it.
        let server = ActPlaneMcp::new_with_control_and_project_dir(None, None);
        let info = server.get_info();
        assert!(info.capabilities.tools.is_some(), "tools advertised");
        assert!(
            info.capabilities.resources.is_some(),
            "resources advertised"
        );
        assert!(
            info.capabilities.prompts.is_none(),
            "prompts not advertised"
        );
        let instructions = info.instructions.as_deref().expect("instructions");
        assert!(instructions.starts_with("ActPlane: OS-level agent harness."));
        assert!(instructions.contains("corrective feedback"));
    }

    #[test]
    fn send_signal_reports_esrch_for_missing_pid() {
        // `send_signal` is the thin libc::kill wrapper used to SIGCONT a
        // launched child; it must surface ESRCH rather than panic. A living
        // pid need not be signalable (sandboxes deny non-root SIGCONT), so the
        // positive path is probed empirically before being asserted.
        let err = send_signal(i32::MAX, libc::SIGCONT).expect_err("no such process");
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        if send_signal(pid, libc::SIGCONT).is_ok() {
            assert!(send_signal(pid, libc::SIGCONT).is_ok());
        }
        let _ = send_signal(pid, libc::SIGKILL);
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn secure_child_registry_file_is_a_noop_for_non_root() {
        // Non-root must leave the registry file untouched: only euid 0 chowns
        // to root and forces 0644. Create a 0600 file and confirm the mode
        // survives the call.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("meta.json");
        std::fs::write(&path, b"{}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        assert_ne!(unsafe { libc::geteuid() }, 0, "container runs non-root");
        secure_child_registry_file(&path).expect("secure file");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn sudo_target_user_reads_sudo_uid_and_gid_only_when_root() {
        let uid = std::env::var("SUDO_UID").ok();
        let gid = std::env::var("SUDO_GID").ok();

        if unsafe { libc::geteuid() } != 0 {
            // Non-root callers never adopt a sudo target user.
            assert_eq!(sudo_target_user(), None);
            return;
        }

        unsafe {
            std::env::remove_var("SUDO_UID");
            std::env::remove_var("SUDO_GID");
        }
        assert_eq!(sudo_target_user(), None, "missing vars mean no target user");
        unsafe { std::env::set_var("SUDO_UID", "not-a-number") };
        assert_eq!(sudo_target_user(), None, "unparsable uid is rejected");
        unsafe {
            std::env::set_var("SUDO_UID", "1234");
            std::env::set_var("SUDO_GID", "5678");
        }
        assert_eq!(sudo_target_user(), Some((1234, 5678)));

        match uid {
            Some(v) => unsafe { std::env::set_var("SUDO_UID", v) },
            None => unsafe { std::env::remove_var("SUDO_UID") },
        }
        match gid {
            Some(v) => unsafe { std::env::set_var("SUDO_GID", v) },
            None => unsafe { std::env::remove_var("SUDO_GID") },
        }
    }

    #[cfg(unix)]
    #[test]
    fn chown_path_requires_privilege_to_change_ownership() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("owned.txt");
        std::fs::write(&file, "x").expect("write");

        // A no-op chown to the file's current owner succeeds; a real change to
        // another uid needs CAP_CHOWN, so non-root callers must see an error.
        let meta = std::fs::metadata(&file).expect("metadata");
        assert!(chown_path(&file, meta.uid(), meta.gid()).is_ok());
        if unsafe { libc::geteuid() } != 0 {
            assert!(
                chown_path(&file, meta.uid().wrapping_add(1), meta.gid()).is_err(),
                "changing owner without privilege must fail"
            );
        }
    }

    #[test]
    fn terminate_process_group_signals_the_group() {
        // `terminate_process_group(pid)` sends SIGTERM to the process group
        // `-pid`, so a group leader is terminated while the whole-group target
        // differs from the single-pid target. No base or branch test exercises
        // `terminate_process_group` or the `kill_and_wait` wrapper.
        let leader = |script: &str| {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c")
                .arg(script)
                .process_group(0)
                .stdout(Stdio::null());
            cmd.spawn().expect("spawn")
        };
        let mut child = leader("sleep 3");
        let pid = child.id() as i32;
        assert_eq!(
            unsafe { libc::getpgid(pid) },
            pid,
            "child must lead its own process group"
        );

        // Either way the group-targeted SIGTERM keeps the same contract as a
        // pid kill: it returns without panicking, and a permitted signal
        // terminates the leader while a sandbox that denies non-root `kill`
        // (EPERM) leaves it to exit after its sleep.
        let group_ok = terminate_process_group(pid).is_ok();
        let _ = child.wait();
        assert!(
            group_ok || unsafe { libc::kill(pid, 0) } != 0,
            "a live target with a denied group signal must still be reaped"
        );

        // `kill_and_wait` takes ownership, SIGKILLs the group, and reaps the
        // child (its `Child` is consumed, so no handle remains to observe).
        let caught = leader("sleep 3");
        assert_eq!(
            unsafe { libc::getpgid(caught.id() as i32) },
            caught.id() as i32,
            "kill_and_wait target must lead its group"
        );
        kill_and_wait(caught);
    }

    #[test]
    fn local_tool_response_wraps_ok_and_error() {
        // `local_tool_response` unwraps a successful CallToolResult into an
        // {ok,text,result} envelope and a failure into {ok,error}, while
        // `invalid_params` builds an INVALID_PARAMS ErrorData. Neither has a
        // direct caller in the base or branch tests.
        let ok = CallToolResult::success(vec![ContentBlock::text("hello")]);
        let value = local_tool_response(Ok(ok));
        assert_eq!(value["ok"], true);
        assert_eq!(value["text"], "hello");
        assert_eq!(value["result"]["content"][0]["text"], "hello");

        let err = local_tool_response(Err(invalid_params("bad argument")));
        assert_eq!(err["ok"], false);
        assert!(err["error"].as_str().unwrap().contains("bad argument"));

        let data = invalid_params("missing `foo`");
        assert_eq!(data.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(data.message, "missing `foo`");
    }

    #[test]
    fn unattached_handlers_report_missing_engine_with_internal_error() {
        let project_dir = tempfile::tempdir().expect("tempdir");
        let server = ActPlaneMcp::new_with_control_and_project_dir(
            None,
            Some(project_dir.path().to_path_buf()),
        );

        let err = server
            .do_append_policy_delta(None)
            .expect_err("append must fail without an engine");
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR);
        assert!(err.message.contains("No eBPF engine attached"));

        let err = server
            .launch_child_domain_inner(
                vec!["/bin/true".to_string()],
                Some(9),
                0,
                None,
                PolicyAuditMeta::default(),
                None,
                RestartSettings {
                    policy: RestartPolicy::Never,
                    count: 0,
                    limit: 0,
                    backoff_ms: 0,
                },
            )
            .err()
            .expect("launch must fail without an engine");
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR);
        assert!(err.message.contains("No eBPF engine attached"));
    }

    fn seeded_server_c2(project_dir: PathBuf, records: Vec<ChildRecord>) -> ActPlaneMcp {
        let mut children = HashMap::new();
        for record in records {
            children.insert(record.child_id, record);
        }
        ActPlaneMcp {
            project_dir,
            control: None,
            children: Arc::new(Mutex::new(children)),
        }
    }

    fn tool_text_c3(result: &CallToolResult) -> String {
        match result.content.first() {
            Some(ContentBlock::Text(t)) => t.text.clone(),
            other => panic!("expected text content, got {other:?}"),
        }
    }

    fn reconcile_record(
        child_id: u32,
        status: ChildStatus,
        restart_count: u32,
        restart_limit: u32,
        log_dir: &std::path::Path,
    ) -> ChildRecord {
        ChildRecord {
            launch_id: format!("child-{child_id}"),
            pid: 99_999_999,
            child_id,
            scope_id: 1,
            cmd: vec!["/bin/true".to_string()],
            stdout: log_dir.join("stdout.log"),
            stderr: log_dir.join("stderr.log"),
            meta: log_dir.join("meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::OnExit,
            restart_count,
            restart_limit,
            restart_backoff_ms: DEFAULT_RESTART_BACKOFF_MS,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(status)),
        }
    }

    #[test]
    fn reconcile_marks_exhausted_restarts_as_blocked_alerts_once() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_dir = tmp.path().join(".actplane/children/child-7");
        std::fs::create_dir_all(&log_dir).expect("mkdir");
        // Exited child at its restart limit: no relaunch, one blocked alert.
        let record = reconcile_record(
            7,
            ChildStatus::Exited {
                code: Some(1),
                signal: None,
            },
            DEFAULT_RESTART_LIMIT,
            DEFAULT_RESTART_LIMIT,
            &log_dir,
        );
        let server = seeded_server_c2(tmp.path().to_path_buf(), vec![record]);

        let first = server.do_reconcile_child_domains().expect("reconcile");
        let value: Value = serde_json::from_str(&tool_text_c3(&first)).expect("json");
        assert_eq!(value["total"], 1);
        assert_eq!(value["exited"], 1);
        assert_eq!(value["running"], 0);
        assert_eq!(value["restarted"].as_array().unwrap().len(), 0);
        let alerts = value["alerts"].as_array().expect("alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["child_id"], 7);
        assert_eq!(alerts[0]["status"], "blocked");
        assert_eq!(alerts[0]["reason"], "restart limit reached");

        // The alert is recorded, so a second reconcile does not repeat it.
        let second = server.do_reconcile_child_domains().expect("reconcile");
        let value: Value = serde_json::from_str(&tool_text_c3(&second)).expect("json");
        assert_eq!(value["alerts"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn child_state_predicates_classify_each_status() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_dir = tmp.path().join(".actplane/children/child-11");
        std::fs::create_dir_all(&log_dir).expect("mkdir");
        let mut record = reconcile_record(11, ChildStatus::Running, 0, 3, &log_dir);
        assert!(child_record_running(&record));
        assert!(!child_record_exited(&record));
        assert!(!child_record_terminated(&record));
        assert!(process_exists(std::process::id() as i32));
        assert!(!process_exists(99_999_999));

        *record.status.lock().unwrap() = ChildStatus::Terminated;
        assert!(child_record_terminated(&record));
        assert!(!child_record_running(&record));
        assert!(
            !child_record_should_relaunch(&record),
            "terminated is not relaunched"
        );

        *record.status.lock().unwrap() = ChildStatus::Exited {
            code: Some(0),
            signal: None,
        };
        assert!(child_record_exited(&record));
        record.replacement_child_id = Some(12);
        assert!(!child_record_should_relaunch(&record), "already replaced");
    }

    fn predicate_record(status: ChildStatus) -> ChildRecord {
        ChildRecord {
            launch_id: "child-predicate".to_string(),
            pid: 1,
            child_id: 1,
            scope_id: 0,
            cmd: vec!["/bin/true".to_string()],
            stdout: PathBuf::from("/tmp/stdout.log"),
            stderr: PathBuf::from("/tmp/stderr.log"),
            meta: PathBuf::from("/tmp/meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::OnExit,
            restart_count: 0,
            restart_limit: 2,
            restart_backoff_ms: 1000,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(status)),
        }
    }

    #[test]
    fn child_record_predicates_follow_the_status_variant() {
        let running = predicate_record(ChildStatus::Running);
        let exited = predicate_record(ChildStatus::Exited {
            code: Some(1),
            signal: None,
        });
        let terminated = predicate_record(ChildStatus::Terminated);

        assert!(child_record_running(&running));
        assert!(!child_record_exited(&running));
        assert!(!child_record_terminated(&running));

        assert!(child_record_exited(&exited));
        assert!(!child_record_running(&exited));
        assert!(!child_record_terminated(&exited));

        assert!(child_record_terminated(&terminated));
        assert!(!child_record_running(&terminated));
        assert!(!child_record_exited(&terminated));
    }

    #[test]
    fn adopt_running_child_record_is_idempotent_and_status_scoped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut running = predicate_record(ChildStatus::Running);
        running.meta = dir.path().join("meta.json");
        assert!(adopt_running_child_record(&mut running));
        let first = running.adopted_unix_ms.expect("adopted stamp");
        assert!(!adopt_running_child_record(&mut running), "idempotent");
        assert_eq!(running.adopted_unix_ms, Some(first));

        let mut exited = predicate_record(ChildStatus::Exited {
            code: Some(0),
            signal: None,
        });
        exited.meta = dir.path().join("exited-meta.json");
        assert!(!adopt_running_child_record(&mut exited));
        assert!(exited.adopted_unix_ms.is_none());
    }

    #[test]
    fn restart_blocked_reason_requires_an_exhausted_on_exit_quota() {
        let mut record = predicate_record(ChildStatus::Running);
        record.restart_count = 2;
        assert_eq!(child_restart_blocked_reason(&record), None, "still running");
        assert!(
            !child_record_should_relaunch(&record),
            "running never relaunches"
        );

        *record.status.lock().expect("status") = ChildStatus::Exited {
            code: Some(1),
            signal: None,
        };
        assert_eq!(
            child_restart_blocked_reason(&record),
            Some("restart limit reached")
        );
        assert!(!child_record_should_relaunch(&record));

        record.restart_count = 1;
        assert_eq!(child_restart_blocked_reason(&record), None);
        assert!(child_record_should_relaunch(&record), "quota left");

        record.replacement_child_id = Some(9);
        assert_eq!(child_restart_blocked_reason(&record), None);
        assert!(!child_record_should_relaunch(&record), "replacement wins");

        record.replacement_child_id = None;
        record.restart_policy = RestartPolicy::Never;
        assert_eq!(child_restart_blocked_reason(&record), None);
        assert!(!child_record_should_relaunch(&record), "policy off");
    }

    #[test]
    fn child_record_from_meta_requires_pid_child_id_and_cmd() {
        let log_dir = PathBuf::from("/tmp/children/child-abc");
        let full = serde_json::json!({
            "pid": 42,
            "child_id": 7,
            "scope_id": 3,
            "cmd": ["/bin/true", "--x"],
        });
        let record = child_record_from_meta(&full, log_dir.clone()).expect("record");
        assert_eq!(record.pid, 42);
        assert_eq!(record.child_id, 7);
        assert_eq!(record.scope_id, 3);
        assert_eq!(record.cmd, vec!["/bin/true".to_string(), "--x".to_string()]);
        assert_eq!(record.launch_id, "child-abc");
        assert_eq!(record.stdout, log_dir.join("stdout.log"));
        assert_eq!(record.meta, log_dir.join("meta.json"));
        assert_eq!(record.restart_policy, RestartPolicy::Never);
        assert!(matches!(
            *record.status.lock().expect("status"),
            ChildStatus::Running
        ));

        for missing in ["cmd", "pid", "child_id"] {
            let mut value = full.clone();
            value.as_object_mut().expect("object").remove(missing);
            assert!(
                child_record_from_meta(&value, log_dir.clone()).is_none(),
                "missing {missing} should not parse"
            );
        }
    }

    fn sample_record(adopted_unix_ms: Option<u64>) -> ChildRecord {
        let log_dir = std::env::temp_dir().join(child_launch_id());
        ChildRecord {
            launch_id: "child-supervision-test".to_string(),
            pid: 4242,
            child_id: 909,
            scope_id: 1,
            cmd: vec!["/bin/true".to_string()],
            stdout: log_dir.join("stdout.log"),
            stderr: log_dir.join("stderr.log"),
            meta: log_dir.join("meta.json"),
            proc_start_time: Some(1),
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: 1,
            restart_backoff_ms: 100,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(ChildStatus::Running)),
        }
    }

    #[test]
    fn child_supervision_json_distinguishes_adopted_and_wait_handle() {
        let wait_handle = child_supervision_json(&sample_record(None));
        assert_eq!(wait_handle["mode"], "wait_handle");
        assert_eq!(wait_handle["exit_status_precise"], true);
        assert_eq!(wait_handle["adopted_unix_ms"], serde_json::Value::Null);

        let adopted = child_supervision_json(&sample_record(Some(1234)));
        assert_eq!(adopted["mode"], "adopted_polling");
        assert_eq!(adopted["exit_status_precise"], false);
        assert_eq!(adopted["adopted_unix_ms"], 1234);
    }

    fn child_id_record(status: ChildStatus) -> ChildRecord {
        ChildRecord {
            launch_id: "child-refresh".to_string(),
            pid: i32::MAX,
            child_id: 1,
            scope_id: 0,
            cmd: vec!["/bin/true".to_string()],
            stdout: PathBuf::from("/tmp/stdout.log"),
            stderr: PathBuf::from("/tmp/stderr.log"),
            meta: PathBuf::from("/tmp/meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: 2,
            restart_backoff_ms: 1000,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(status)),
        }
    }

    #[test]
    fn child_id_arg_accepts_child_id_then_domain_id() {
        let both = serde_json::json!({ "child_id": 5, "domain_id": 6 })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(child_id_arg(&both).expect("child_id wins"), 5);

        let alias = serde_json::json!({ "domain_id": 6 })
            .as_object()
            .expect("object")
            .clone();
        assert_eq!(child_id_arg(&alias).expect("domain_id alias"), 6);

        let absent = serde_json::json!({}).as_object().expect("object").clone();
        assert_eq!(
            child_id_arg(&absent).unwrap_err().message,
            "missing `child_id`"
        );
    }

    #[test]
    fn refresh_child_record_status_marks_dead_processes_exited() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut running = child_id_record(ChildStatus::Running);
        running.meta = dir.path().join("running.json");
        refresh_child_record_status(&mut running);
        assert!(child_record_exited(&running), "dead pid becomes exited");
        assert!(running.last_exit_unix_ms.is_some());

        let mut live = child_id_record(ChildStatus::Running);
        live.meta = dir.path().join("live.json");
        live.pid = std::process::id() as i32;
        live.proc_start_time = proc_start_time(live.pid);
        refresh_child_record_status(&mut live);
        assert!(child_record_running(&live), "live pid stays running");

        let mut already = child_id_record(ChildStatus::Terminated);
        already.meta = dir.path().join("already.json");
        refresh_child_record_status(&mut already);
        assert!(
            child_record_terminated(&already),
            "terminal status is left alone"
        );
    }

    #[test]
    fn default_project_dir_honors_actplane_then_codex_variables() {
        let vars = [
            "ACTPLANE_PROJECT_DIR",
            "CODEX_PROJECT_DIR",
            "CODEX_WORKSPACE",
            "CLAUDE_PROJECT_DIR",
        ];
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|v| ((*v).to_string(), std::env::var(v).ok()))
            .collect();
        for v in vars {
            unsafe { std::env::remove_var(v) };
        }

        assert_eq!(default_project_dir(), std::env::current_dir().unwrap());

        unsafe { std::env::set_var("CLAUDE_PROJECT_DIR", "/tmp/claude-dir") };
        assert_eq!(default_project_dir(), PathBuf::from("/tmp/claude-dir"));

        unsafe { std::env::set_var("CODEX_WORKSPACE", "/tmp/codex-ws") };
        assert_eq!(default_project_dir(), PathBuf::from("/tmp/codex-ws"));

        unsafe { std::env::set_var("CODEX_PROJECT_DIR", "/tmp/codex-dir") };
        assert_eq!(default_project_dir(), PathBuf::from("/tmp/codex-dir"));

        unsafe { std::env::set_var("ACTPLANE_PROJECT_DIR", "/tmp/actplane-dir") };
        assert_eq!(default_project_dir(), PathBuf::from("/tmp/actplane-dir"));

        for (key, value) in saved {
            match value {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }

    #[test]
    fn read_log_json_returns_whole_short_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("short.log");
        std::fs::write(&path, "short body").expect("write");
        let value = read_log_json(&path, 1024).expect("read");
        assert_eq!(value["content"], "short body");
        assert_eq!(value["truncated"], false);
        assert_eq!(value["missing"], false);
    }

    #[test]
    fn read_log_json_reports_internal_errors_for_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = read_log_json(dir.path(), 16).err().expect("directory");
        assert!(
            err.message.contains("Read child log"),
            "unexpected: {}",
            err.message
        );
    }

    #[test]
    fn latest_run_feedback_returns_the_newest_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(latest_run_feedback(dir.path()).is_none(), "no runs dir");

        let runs = dir.path().join(".actplane").join("runs");
        for run in ["run-old", "run-new"] {
            let run_dir = runs.join(run);
            std::fs::create_dir_all(&run_dir).expect("run dir");
            std::fs::write(run_dir.join("feedback.txt"), run).expect("feedback");
        }

        let found = latest_run_feedback(dir.path()).expect("feedback");
        assert_eq!(found.file_name().unwrap(), "feedback.txt");
        let run_name = found
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(run_name, "run-new", "newest mtime wins");
    }

    #[test]
    fn latest_run_feedback_aborts_on_a_feedbackless_run_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runs = dir.path().join(".actplane").join("runs");
        let with_feedback = runs.join("run-good");
        std::fs::create_dir_all(&with_feedback).expect("run dir");
        std::fs::write(with_feedback.join("feedback.txt"), "x").expect("feedback");
        assert!(latest_run_feedback(dir.path()).is_some());

        std::fs::create_dir_all(runs.join("run-in-progress")).expect("run dir");
        assert!(
            latest_run_feedback(dir.path()).is_none(),
            "a run dir without feedback.txt aborts resolution"
        );
    }

    fn write_child_meta(project_dir: &std::path::Path, launch_id: &str, value: &Value) -> PathBuf {
        let log_dir = project_dir
            .join(".actplane")
            .join("children")
            .join(launch_id);
        std::fs::create_dir_all(&log_dir).expect("log dir");
        std::fs::write(
            log_dir.join("meta.json"),
            serde_json::to_string_pretty(value).expect("serialize"),
        )
        .expect("write meta");
        log_dir
    }

    #[test]
    fn load_child_records_skips_unreadable_and_malformed_metas() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path();
        assert!(
            load_child_records_with_adoptions(base).records.is_empty(),
            "missing children dir loads nothing"
        );

        let good = write_child_meta(
            base,
            "child-good",
            &serde_json::json!({ "pid": 1, "child_id": 11, "cmd": ["/bin/true"] }),
        );
        assert!(good.join("meta.json").is_file());
        write_child_meta(
            base,
            "child-bad-json",
            &serde_json::json!({ "pid": 1, "child_id": 12, "cmd": ["/bin/true"] }),
        );
        std::fs::write(
            base.join(".actplane/children/child-bad-json/meta.json"),
            "{not json",
        )
        .expect("corrupt meta");
        write_child_meta(
            base,
            "child-no-cmd",
            &serde_json::json!({ "pid": 1, "child_id": 13 }),
        );

        let loaded = load_child_records_with_adoptions(base);
        assert_eq!(loaded.records.len(), 1, "only the well-formed record loads");
        assert_eq!(loaded.records[&11].launch_id, "child-good");
        assert_eq!(loaded.records[&11].meta, good.join("meta.json"));
    }

    fn pid_record(status: ChildStatus) -> ChildRecord {
        ChildRecord {
            launch_id: "child-pid".to_string(),
            pid: i32::MAX,
            child_id: 1,
            scope_id: 0,
            cmd: vec!["/bin/true".to_string()],
            stdout: PathBuf::from("/tmp/stdout.log"),
            stderr: PathBuf::from("/tmp/stderr.log"),
            meta: PathBuf::from("/tmp/meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::Never,
            restart_count: 0,
            restart_limit: 2,
            restart_backoff_ms: 1000,
            last_exit_unix_ms: None,
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(status)),
        }
    }

    #[test]
    fn child_record_meta_trusted_accepts_secure_root_layout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_dir = write_child_meta(
            dir.path(),
            "child-trusted",
            &serde_json::json!({ "pid": 1, "child_id": 14, "cmd": ["/bin/true"] }),
        );
        let meta = log_dir.join("meta.json");
        assert!(child_record_meta_trusted(&meta));
        assert!(
            child_record_meta_trusted(&dir.path().join("absent/meta.json")),
            "non-root callers trust without stat"
        );
    }

    #[test]
    fn process_identity_matches_pid_reuse_without_start_time() {
        assert!(!process_identity_matches(&pid_record(ChildStatus::Running)));
        let mut self_record = pid_record(ChildStatus::Running);
        self_record.pid = std::process::id() as i32;
        assert!(process_identity_matches(&self_record), "live pid");
        self_record.proc_start_time = proc_start_time(self_record.pid);
        assert!(
            process_identity_matches(&self_record),
            "matching start time"
        );
        self_record.proc_start_time = Some(u64::MAX);
        assert!(
            !process_identity_matches(&self_record),
            "start time mismatch"
        );
    }

    #[test]
    fn parse_restart_policy_str_accepts_the_two_aliases() {
        assert_eq!(parse_restart_policy_str("on_exit"), RestartPolicy::OnExit);
        assert_eq!(parse_restart_policy_str("on-exit"), RestartPolicy::OnExit);
        assert_eq!(parse_restart_policy_str("always"), RestartPolicy::Never);
        assert_eq!(parse_restart_policy_str(""), RestartPolicy::Never);
    }

    #[test]
    fn local_tool_response_wraps_success_and_error() {
        let ok = local_tool_response(Ok(CallToolResult::success(vec![ContentBlock::text(
            "hello",
        )])));
        assert_eq!(ok["ok"], true);
        assert_eq!(ok["text"], "hello");
        assert_eq!(ok["result"]["content"][0]["text"], "hello");

        let err = local_tool_response(Err(invalid_params("bad `pid`")));
        assert_eq!(err["ok"], false);
        assert!(
            err["error"].as_str().unwrap().contains("bad `pid`"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn first_tool_text_reads_only_the_first_text_block() {
        let value = serde_json::json!({ "content": [{ "text": "a" }, { "text": "b" }] });
        assert_eq!(first_tool_text(&value), Some("a".to_string()));
        assert_eq!(first_tool_text(&serde_json::json!({ "content": [] })), None);
        assert_eq!(first_tool_text(&serde_json::json!({})), None);
        assert_eq!(
            first_tool_text(&serde_json::json!({ "content": [{ "image": "x" }] })),
            None
        );
    }

    #[test]
    fn policy_audit_meta_json_round_trips_and_omits_defaults() {
        assert!(policy_audit_meta_json(&PolicyAuditMeta::default()).is_none());

        let value = policy_audit_meta_json(&PolicyAuditMeta {
            policy_ref: Some("p.dsl".to_string()),
            ..Default::default()
        })
        .expect("non-default meta");
        assert_eq!(value["policy_ref"], "p.dsl");
        assert!(value.get("approved_by").is_none());

        let parsed = policy_audit_meta_from_json(&value).expect("parse");
        assert_eq!(parsed.policy_ref.as_deref(), Some("p.dsl"));
        assert!(parsed.approved_by.is_none());
        assert!(policy_audit_meta_from_json(&serde_json::json!("nope")).is_none());
    }

    #[test]
    fn read_log_json_reports_missing_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let value = read_log_json(&dir.path().join("nope.log"), 10).expect("missing log");
        assert_eq!(value["missing"], true);
        assert_eq!(value["content"], "");
        assert_eq!(value["truncated"], false);
    }

    fn tool_text_c4(result: &CallToolResult) -> String {
        match result.content.first() {
            Some(ContentBlock::Text(t)) => t.text.clone(),
            other => panic!("expected text content, got {other:?}"),
        }
    }

    #[test]
    fn supervisor_reconciles_without_an_attached_control() {
        // A budgeted relaunch must not try to audit through a missing control.
        let record = ChildRecord {
            launch_id: "child-sup".to_string(),
            pid: 99_999_999,
            child_id: 3,
            scope_id: 0,
            cmd: vec!["/bin/true".to_string()],
            stdout: PathBuf::from("stdout.log"),
            stderr: PathBuf::from("stderr.log"),
            meta: PathBuf::from("meta.json"),
            proc_start_time: None,
            policy: None,
            policy_audit_meta: PolicyAuditMeta::default(),
            restart_policy: RestartPolicy::OnExit,
            restart_count: DEFAULT_RESTART_LIMIT,
            // The restart limit is exhausted so the record is a relaunch
            // candidate whose restart is blocked.
            restart_limit: DEFAULT_RESTART_LIMIT,
            restart_backoff_ms: u64::MAX,
            last_exit_unix_ms: Some(unix_time_ms()),
            restart_alerted_unix_ms: None,
            adopted_unix_ms: None,
            restarted_from: None,
            replacement_child_id: None,
            status: Arc::new(Mutex::new(ChildStatus::Running)),
        };
        let server = ActPlaneMcp {
            project_dir: PathBuf::from("."),
            control: None,
            children: Arc::new(Mutex::new(HashMap::from([(3u32, record)]))),
        };

        let result = server.do_reconcile_child_domains().expect("reconcile");
        let payload: Value =
            serde_json::from_str(&tool_text_c4(&result)).expect("reconcile json payload");
        assert_eq!(payload["total"], 1);
        assert_eq!(payload["exited"], 1);
        assert_eq!(payload["alerts"].as_array().expect("alerts").len(), 1);
        assert_eq!(payload["restarted"].as_array().expect("restarted").len(), 0);
    }

    #[test]
    fn supervisor_guard_drop_signals_and_joins_its_thread() {
        let stop = Arc::new(AtomicBool::new(false));
        let observed = stop.clone();
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            for _ in 0..1000 {
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        assert!(!observed.load(Ordering::SeqCst));
        drop(SupervisorGuard {
            stop,
            thread: Some(thread),
        });
        assert!(
            observed.load(Ordering::SeqCst),
            "dropping the guard must request supervisor shutdown"
        );
    }

    #[test]
    fn wait_for_stopped_process_times_out_on_a_running_child() {
        // The child outlives the short waiter timeout, so the poll loop must
        // give up on a state that is never T/t; `wait` then reaps it as it exits.
        let mut child = std::process::Command::new("sleep")
            .arg("0.2")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        let err = wait_for_stopped_process(pid, Duration::from_millis(20)).expect_err("timeout");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        let _ = child.wait();
    }

    #[test]
    fn proc_state_code_reads_live_pids_and_rejects_missing_ones() {
        let state = proc_state_code(std::process::id() as i32).expect("own state");
        assert!(matches!(state, 'R' | 'S' | 'D' | 'T' | 't'), "got {state}");
        assert!(
            proc_state_code(99_999_999).is_err(),
            "dead pid has no /proc entry"
        );
    }

    #[test]
    fn signal_helpers_report_missing_targets() {
        // Signal delivery to a nonexistent pid/group surfaces ESRCH as an error.
        let err = send_signal(99_999_999, libc::SIGTERM).expect_err("dead pid");
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
        let err = terminate_process_group_with(99_999_999, libc::SIGTERM).expect_err("dead group");
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }
}
