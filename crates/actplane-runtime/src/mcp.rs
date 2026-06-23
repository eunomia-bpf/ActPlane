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

use crate::config::{load_policy_path, policy_source};
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

    fn do_reload_policy(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let control = self.control.as_ref().ok_or_else(|| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                "No eBPF engine attached (MCP not started with --auto-attach-parent)",
                None::<Value>,
            )
        })?;
        let path = self.discover_policy_file().ok_or_else(|| {
            rmcp::ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                "No actplane.yaml found",
                None::<Value>,
            )
        })?;
        let loaded = load_policy_path(&path, false, &self.project_dir).map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Policy load error: {e}"),
                None::<Value>,
            )
        })?;
        let dsl_src = policy_source(&loaded, None).map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                format!("Policy resolve error: {e}"),
                None::<Value>,
            )
        })?;
        let compiled = dsl::compile_str(&dsl_src).map_err(|e| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("Policy compile error: {e}"),
                None::<Value>,
            )
        })?;
        let n_rules = control
            .reload_policy(&compiled, &dsl_src, &path.display().to_string(), &loaded)
            .map_err(|e| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("Reload failed: {e}"),
                    None::<Value>,
                )
            })?;

        let msg = format!(
            "Policy hot-reloaded ({} rule metadata entries) from {}",
            n_rules,
            path.display()
        );
        Ok(CallToolResult::success(vec![Content::text(msg)]))
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
        Ok(CallToolResult::success(vec![Content::text(format!(
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
        Ok(CallToolResult::success(vec![Content::text(format!(
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

        Ok(CallToolResult::success(vec![Content::text(format!(
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
        Ok(CallToolResult::success(vec![Content::text(
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
        Ok(CallToolResult::success(vec![Content::text(
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
                    return Ok(CallToolResult::success(vec![Content::text(format!(
                        "Child domain {child_id} already exited"
                    ))]));
                }
                ChildStatus::Terminated => {
                    return Ok(CallToolResult::success(vec![Content::text(format!(
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
        Ok(CallToolResult::success(vec![Content::text(msg)]))
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

        Ok(CallToolResult::success(vec![Content::text(format!(
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
        Ok(CallToolResult::success(vec![Content::text(
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
            "reload_policy" => {
                if let Err(e) = self.ensure_local_parent_peer(peer) {
                    return serde_json::json!({ "ok": false, "error": e });
                }
                local_tool_response(self.do_reload_policy())
            }
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
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
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
                "reload_policy",
                "Hot-reload the policy from actplane.yaml into the running \
                 eBPF engine without restarting. Accumulated state (process \
                 labels, file labels, session gates) is preserved.",
                empty_schema.clone(),
            ),
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
    ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_
    {
        let result = match request.name.as_ref() {
            "reload_policy" => self.do_reload_policy(),
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
        std::future::ready(result)
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_
    {
        let resources = vec![
            Annotated::new(
                RawResource {
                    uri: POLICY_RESOURCE_URI.into(),
                    name: "actplane-policy".into(),
                    title: Some("ActPlane Policy Status".into()),
                    description: Some("Current policy validation result from actplane.yaml".into()),
                    mime_type: Some("text/plain".into()),
                    size: None,
                    icons: None,
                    meta: None,
                },
                None,
            ),
            Annotated::new(
                RawResource {
                    uri: FEEDBACK_RESOURCE_URI.into(),
                    name: "actplane-feedback".into(),
                    title: Some("ActPlane Feedback".into()),
                    description: Some(
                        "Latest corrective feedback from .actplane/last-violation.txt".into(),
                    ),
                    mime_type: Some("text/plain".into()),
                    size: None,
                    icons: None,
                    meta: None,
                },
                None,
            ),
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
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + Send + '_
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
        std::future::ready(result)
    }
}

// ── File watcher ────────────────────────────────────────────────────

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
}
