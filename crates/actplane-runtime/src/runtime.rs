use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ebpf_ifc_engine::capability::{
    AUTH_ADD_LABEL, AUTH_BIND_RULE, AUTH_DECLASSIFY, AUTH_DELEGATE, AUTH_NARROW_SCOPE,
    AUTH_REQUIRE_GATE, CapState, TARGET_CHILD, TARGET_SELF,
};
use ebpf_ifc_engine::{
    ChildDomainSpec, DomainHandle, GLOBAL_ACTIVE_DOMAIN_ID, PinnedEngine, ReloadHandle,
};
use serde_json::json;
use tokio::process::{Child, Command};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};

use crate::config::{
    AppendDeltaApprovalConfig, FeedbackPaths, LoadedPolicy, feedback_paths, load_policy,
    policy_source,
};
use crate::hook::write_hook_state;
use crate::report::{self, report, to_violation};
use crate::{PolicyInput, Result, audit, dsl};

const ATTACH_PID_ENV: &str = "ACTPLANE_ATTACH_PID";
const CLOEXEC_FALLBACK_FD_LIMIT: i32 = 1024;

fn fresh_runtime_domain_id(pid: i32, salt: u32) -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut x = now.as_nanos() as u64
        ^ ((std::process::id() as u64) << 32)
        ^ ((pid.max(0) as u64) << 1)
        ^ salt as u64;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    let mut id = (x as u32) & 0x7fff_fffe;
    if id == 0 || id == GLOBAL_ACTIVE_DOMAIN_ID {
        id = salt | 1;
    }
    id
}

pub async fn watch_policy(cli: &PolicyInput, parent_domain: bool) -> Result<i32> {
    let attach_pid = attach_pid_from_env_or_parent();
    watch_policy_for_pid(cli, parent_domain, attach_pid).await
}

pub async fn watch_policy_for_pid(
    cli: &PolicyInput,
    parent_domain: bool,
    attach_pid: i32,
) -> Result<i32> {
    if parent_domain {
        return Err(
            "--parent-domain is not supported by the pinned singleton engine yet; it would \
             require a host-global policy replacement path. Start watch without \
             --parent-domain to use an isolated runtime parent domain."
                .into(),
        );
    }
    if attach_pid <= 1 {
        return Err(format!("invalid parent pid for watch attach: {attach_pid}").into());
    }
    require_bpf_caps_or_elevate_with_env(
        cli.internal_elevated,
        &[(ATTACH_PID_ENV, attach_pid.to_string())],
    )?;
    let loaded = load_policy(cli)?;
    let policy = policy_source(&loaded, cli.domain.as_deref())?;
    let compiled = dsl::compile_str(&policy)?;
    let agent_label = runner_label(&compiled)?;
    let submitter_pid = std::process::id() as i32;
    let parent_domain_id = fresh_runtime_domain_id(attach_pid, 0x5741_5443);
    let catalog = Arc::new(RuntimePolicyCatalog::from_compiled(
        &compiled,
        parent_domain_id,
    ));
    let feedback = feedback_paths(&loaded);
    let target_owner = target_user(cli.run_as_root);
    prepare_feedback_files(&feedback, target_owner)?;
    write_hook_state(&feedback.state, &feedback.feedback, attach_pid)?;
    if let Some((uid, gid)) = target_owner {
        chown_path(&feedback.state, uid, gid)?;
    }

    let stop = Arc::new(AtomicBool::new(false));
    type ReadyResult = std::result::Result<(ReloadHandle, DomainHandle), String>;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<ReadyResult>();
    let blob = compiled.bytes;
    let fb = feedback.feedback.clone();
    let ev = feedback.events.clone();
    let run_catalog = catalog.clone();
    let stop_thread = stop.clone();
    let poller = std::thread::spawn(move || {
        let engine = match PinnedEngine::open_or_install_singleton() {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("open ActPlane singleton: {e}")));
                return;
            }
        };
        let _runtime_lock = match engine.try_lock_runtime() {
            Ok(lock) => lock,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("lock ActPlane singleton runtime: {e}")));
                return;
            }
        };
        let rh = match engine.reload_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("create policy delta handle: {e}")));
                return;
            }
        };
        if let Err(e) = engine.protect_pid(submitter_pid) {
            let _ = ready_tx.send(Err(format!("protect control pid {submitter_pid}: {e}")));
            return;
        }
        if let Err(e) = rh.clear_runtime_state() {
            let _ = ready_tx.send(Err(format!("clear singleton runtime state: {e}")));
            return;
        }
        if let Err(e) = engine.seed_label_in_domain(attach_pid, parent_domain_id, agent_label) {
            let _ = ready_tx.send(Err(format!(
                "seed watch pid {attach_pid} in domain {parent_domain_id}: {e}"
            )));
            return;
        }
        if submitter_pid != attach_pid {
            if let Err(e) = engine.bind_state(
                submitter_pid,
                parent_domain_id,
                control_plane_cap_state(agent_label),
            ) {
                let _ = ready_tx.send(Err(format!(
                    "bind control pid {submitter_pid} to watch domain {parent_domain_id}: {e}"
                )));
                return;
            }
        }
        if let Err(e) = rh.append_policy_delta(submitter_pid, parent_domain_id, &blob) {
            let _ = ready_tx.send(Err(format!(
                "install policy in domain {parent_domain_id}: {e}"
            )));
            return;
        }
        let dh = match engine.domain_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("create domain handle: {e}")));
                return;
            }
        };
        let cleanup = match engine.reload_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = rh.clear_runtime_state();
                let _ = ready_tx.send(Err(format!("create policy cleanup handle: {e}")));
                return;
            }
        };
        let _ = ready_tx.send(Ok((rh, dh)));
        let run_result = engine.run(&stop_thread, |v| {
            run_catalog.append_outputs(&to_violation(&v), &fb, &ev);
        });
        if let Err(e) = cleanup.clear_runtime_state() {
            eprintln!("ActPlane: failed to clear singleton runtime state: {e}");
        }
        if let Err(e) = run_result {
            eprintln!("ActPlane: singleton event loop failed: {e}");
        }
    });

    let (reload_handle, domain_handle) = match ready_rx.recv() {
        Ok(Ok(handles)) => handles,
        Ok(Err(e)) => {
            stop.store(true, Ordering::SeqCst);
            let _ = poller.join();
            return Err(e.into());
        }
        Err(_) => {
            stop.store(true, Ordering::SeqCst);
            let _ = poller.join();
            return Err("engine thread exited before readiness".into());
        }
    };
    let control = Arc::new(EngineControl {
        reload_handle: Arc::new(reload_handle),
        domain_handle: Arc::new(domain_handle),
        catalog,
        mutation_lock: Mutex::new(()),
        audit_path: feedback.audit.clone(),
        approval_policy: RwLock::new(RuntimeApprovalPolicy::from_loaded_policy(&loaded)),
        parent_pid: attach_pid,
        parent_domain_id,
        submitter_pid,
    });
    let project_dir = watch_project_dir(&loaded);
    let control_guard = match crate::mcp::start_local_control_server(control, project_dir.clone()) {
        Ok(guard) => guard,
        Err(e) => {
            stop.store(true, Ordering::SeqCst);
            let _ = poller.join();
            return Err(e);
        }
    };
    eprintln!(
        "ActPlane: watching pid {} under COMMAND label 0x{:x}{}; feedback {}; control {}\n",
        attach_pid,
        agent_label,
        if parent_domain {
            " in an isolated singleton domain"
        } else {
            ""
        },
        feedback.feedback.display(),
        crate::control::state_path(&project_dir).display()
    );

    let _ = tokio::signal::ctrl_c().await;
    drop(control_guard);
    stop.store(true, Ordering::SeqCst);
    let _ = poller.join();
    Ok(0)
}

pub struct AttachGuard {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    control: Option<Arc<EngineControl>>,
}

pub struct EngineControl {
    pub reload_handle: Arc<ReloadHandle>,
    pub domain_handle: Arc<DomainHandle>,
    catalog: Arc<RuntimePolicyCatalog>,
    mutation_lock: Mutex<()>,
    audit_path: PathBuf,
    approval_policy: RwLock<RuntimeApprovalPolicy>,
    pub parent_pid: i32,
    pub parent_domain_id: u32,
    submitter_pid: i32,
}

struct RuntimePolicyCatalog {
    inner: RwLock<RuntimePolicyCatalogInner>,
}

struct RuntimePolicyCatalogInner {
    rules: Vec<report::RuleFeedbackContext>,
    domain_labels: HashMap<u32, HashMap<String, u64>>,
}

struct PolicyDeltaOutcome {
    rule_id_base: usize,
    rule_count: usize,
    rule_provenance: Vec<serde_json::Value>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct PolicyAuditMeta {
    pub policy_ref: Option<String>,
    pub approved_by: Option<String>,
    pub approval_ref: Option<String>,
    pub generated_by: Option<String>,
}

#[derive(Clone, Default)]
struct RuntimeApprovalPolicy {
    append_delta: AppendDeltaApprovalGate,
}

#[derive(Clone, Default)]
struct AppendDeltaApprovalGate {
    required: bool,
    require_approval_ref: bool,
    require_generated_by: bool,
    allowed_approvers: Vec<String>,
}

struct ApprovalEvaluation {
    enforced: bool,
    required: bool,
    accepted: bool,
    workflow: &'static str,
    missing_fields: Vec<&'static str>,
    rejection_reason: Option<String>,
    allowed_approvers: Vec<String>,
}

impl RuntimeApprovalPolicy {
    fn from_loaded_policy(loaded: &LoadedPolicy) -> Self {
        Self {
            append_delta: AppendDeltaApprovalGate::from_config(
                &loaded.config.runtime.approval.append_delta,
            ),
        }
    }

    fn evaluate_append_delta(&self, meta: &PolicyAuditMeta) -> ApprovalEvaluation {
        self.append_delta.evaluate(meta)
    }
}

impl ApprovalEvaluation {
    fn internal_rejection(reason: String) -> Self {
        Self {
            enforced: false,
            required: false,
            accepted: false,
            workflow: "append_delta_static_approval",
            missing_fields: Vec::new(),
            rejection_reason: Some(reason),
            allowed_approvers: Vec::new(),
        }
    }
}

impl AppendDeltaApprovalGate {
    fn from_config(config: &AppendDeltaApprovalConfig) -> Self {
        Self {
            required: config.required,
            require_approval_ref: config.require_approval_ref,
            require_generated_by: config.require_generated_by,
            allowed_approvers: config.allowed_approvers.clone(),
        }
    }

    fn evaluate(&self, meta: &PolicyAuditMeta) -> ApprovalEvaluation {
        if !self.required {
            return ApprovalEvaluation {
                enforced: false,
                required: false,
                accepted: true,
                workflow: "declarative_metadata",
                missing_fields: Vec::new(),
                rejection_reason: None,
                allowed_approvers: Vec::new(),
            };
        }

        let mut missing_fields = Vec::new();
        if string_missing(meta.approved_by.as_deref()) {
            missing_fields.push("approved_by");
        }
        if self.require_approval_ref && string_missing(meta.approval_ref.as_deref()) {
            missing_fields.push("approval_ref");
        }
        if self.require_generated_by && string_missing(meta.generated_by.as_deref()) {
            missing_fields.push("generated_by");
        }

        let mut rejection_reason = if missing_fields.is_empty() {
            None
        } else {
            Some(format!(
                "append policy delta requires approval metadata: missing {}",
                missing_fields.join(", ")
            ))
        };

        if rejection_reason.is_none()
            && !self.allowed_approvers.is_empty()
            && let Some(approved_by) = meta.approved_by.as_deref()
            && !self
                .allowed_approvers
                .iter()
                .any(|allowed| allowed == approved_by)
        {
            rejection_reason = Some(format!(
                "append policy delta approved_by `{approved_by}` is not in runtime.approval.append_delta.allowed_approvers"
            ));
        }

        ApprovalEvaluation {
            enforced: true,
            required: true,
            accepted: rejection_reason.is_none(),
            workflow: "append_delta_static_approval",
            missing_fields,
            rejection_reason,
            allowed_approvers: self.allowed_approvers.clone(),
        }
    }
}

fn string_missing(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

impl RuntimePolicyCatalog {
    fn from_compiled(compiled: &dsl::Compiled, domain_id: u32) -> Self {
        let mut domain_labels = HashMap::new();
        domain_labels.insert(domain_id, compiled.labels.clone());
        Self {
            inner: RwLock::new(RuntimePolicyCatalogInner {
                rules: report::contexts_from_compiled(compiled),
                domain_labels,
            }),
        }
    }

    fn register_domain(&self, domain_id: u32) -> Result<()> {
        let mut inner = self
            .inner
            .write()
            .map_err(|e| format!("policy metadata lock poisoned: {e}"))?;
        inner.domain_labels.entry(domain_id).or_default();
        Ok(())
    }

    fn append_outputs(&self, v: &report::Violation, feedback_file: &Path, event_file: &Path) {
        match self.inner.read() {
            Ok(inner) => {
                if v.domain_id()
                    .is_some_and(|domain_id| !inner.domain_labels.contains_key(&domain_id))
                {
                    return;
                }
                report::append_violation_feedback_context(
                    inner.rules.get(v.rule_id()),
                    v,
                    feedback_file,
                );
                report::append_violation_event_context(inner.rules.get(v.rule_id()), v, event_file);
            }
            Err(e) => eprintln!("ActPlane: policy metadata lock poisoned: {e}"),
        }
    }
}

impl EngineControl {
    pub fn bind_child_domain(&self, spec: ebpf_ifc_engine::ChildDomainSpec) -> Result<()> {
        let outcome = self.domain_handle.bind_child_domain(spec);
        match outcome {
            Ok(()) => {
                self.catalog.register_domain(spec.child_id)?;
                self.audit(json!({
                    "event": "bind_child_domain",
                    "status": "accepted",
                    "actor_pid": self.parent_pid,
                    "parent_pid": spec.parent_pid,
                    "parent_domain_id": spec.parent_id,
                    "child_domain_id": spec.child_id,
                    "pid": spec.pid,
                    "scope_id": spec.scope_id,
                    "authority_mask": format!("0x{:x}", spec.authority_mask),
                    "target_mask": format!("0x{:x}", spec.target_mask),
                    "label_mask": format!("0x{:x}", spec.label_mask),
                }))?;
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                self.audit(json!({
                    "event": "bind_child_domain",
                    "status": "rejected",
                    "actor_pid": self.parent_pid,
                    "parent_pid": spec.parent_pid,
                    "parent_domain_id": spec.parent_id,
                    "child_domain_id": spec.child_id,
                    "pid": spec.pid,
                    "scope_id": spec.scope_id,
                    "error": msg,
                }))
                .map_err(|audit_err| format!("{e}; audit write failed: {audit_err}"))?;
                Err(e.into())
            }
        }
    }

    pub fn submitter_pid(&self) -> i32 {
        self.submitter_pid
    }

    pub fn parent_domain_allows_runtime_mutation(&self) -> bool {
        self.parent_domain_id != GLOBAL_ACTIVE_DOMAIN_ID
    }

    pub fn parent_domain_mutation_error(&self, operation: &str) -> String {
        format!(
            "{operation} is unavailable in --parent-domain mode; start watch without \
             --parent-domain, or use mcp --auto-attach-parent, to create an authority-bearing \
             runtime parent domain"
        )
    }

    pub fn ensure_parent_or_external_control_actor(&self, actor_pid: i32) -> Result<()> {
        // Local control supervisor operations are a trusted repo-local admin
        // path. If a peer is already inside this engine, it must be the parent
        // domain; unbound CLI peers are allowed so operators can manage a watch
        // engine attached to a different agent pid.
        match self.reload_handle.domain_for_pid(actor_pid)? {
            Some(domain_id) if domain_id == self.parent_domain_id => Ok(()),
            Some(domain_id) => Err(format!(
                "pid {actor_pid} belongs to runtime domain {domain_id}, not trusted parent domain {}",
                self.parent_domain_id
            )
            .into()),
            None => Ok(()),
        }
    }

    pub fn append_policy_delta_dsl_with_audit(
        &self,
        target_id: u32,
        dsl_src: &str,
        audit_meta: &PolicyAuditMeta,
    ) -> Result<(usize, usize)> {
        self.append_policy_delta_dsl_for_actor_with_audit(
            self.submitter_pid,
            target_id,
            dsl_src,
            audit_meta,
        )
    }

    pub fn append_policy_delta_dsl_for_actor_with_audit(
        &self,
        actor_pid: i32,
        target_id: u32,
        dsl_src: &str,
        audit_meta: &PolicyAuditMeta,
    ) -> Result<(usize, usize)> {
        self.append_policy_delta_dsl_for_actor_with_identity_and_audit(
            actor_pid, None, target_id, dsl_src, audit_meta,
        )
    }

    pub fn append_policy_delta_dsl_for_actor_with_identity_and_audit(
        &self,
        actor_pid: i32,
        actor_identity: Option<audit::ProcessIdentity>,
        target_id: u32,
        dsl_src: &str,
        audit_meta: &PolicyAuditMeta,
    ) -> Result<(usize, usize)> {
        let (approval, outcome): (ApprovalEvaluation, Result<PolicyDeltaOutcome>) =
            match self.mutation_lock.lock() {
                Ok(_mutation) => {
                    let approval = self
                        .approval_policy
                        .read()
                        .map(|policy| policy.evaluate_append_delta(audit_meta))
                        .unwrap_or_else(|e| {
                            ApprovalEvaluation::internal_rejection(format!(
                                "runtime approval policy lock poisoned: {e}"
                            ))
                        });
                    let outcome = if let Some(reason) = &approval.rejection_reason {
                        Err(reason.clone().into())
                    } else {
                        self.append_policy_delta_dsl_inner(actor_pid, target_id, dsl_src)
                    };
                    (approval, outcome)
                }
                Err(e) => {
                    let reason = format!("runtime mutation lock poisoned: {e}");
                    (
                        ApprovalEvaluation::internal_rejection(reason.clone()),
                        Err(reason.into()),
                    )
                }
            };
        match outcome {
            Ok(delta) => {
                let mut record = json!({
                    "event": "append_policy_delta",
                    "status": "accepted",
                    "actor_pid": self.parent_pid,
                    "caller_pid": actor_pid,
                    "target_id": target_id,
                    "rule_id_base": delta.rule_id_base,
                    "rule_count": delta.rule_count,
                    "policy_hash": audit::policy_hash(dsl_src),
                    "rule_provenance": delta.rule_provenance,
                });
                if let Some(identity) = &actor_identity {
                    record["caller_identity"] = identity.to_json();
                }
                apply_policy_audit_meta(&mut record, audit_meta, Some(&approval));
                self.audit(record)?;
                Ok((delta.rule_id_base, delta.rule_count))
            }
            Err(e) => {
                let msg = e.to_string();
                let mut record = json!({
                    "event": "append_policy_delta",
                    "status": "rejected",
                    "actor_pid": self.parent_pid,
                    "caller_pid": actor_pid,
                    "target_id": target_id,
                    "policy_hash": audit::policy_hash(dsl_src),
                    "error": msg,
                });
                if let Some(identity) = &actor_identity {
                    record["caller_identity"] = identity.to_json();
                }
                apply_policy_audit_meta(&mut record, audit_meta, Some(&approval));
                self.audit(record)
                    .map_err(|audit_err| format!("{e}; audit write failed: {audit_err}"))?;
                Err(e)
            }
        }
    }

    fn audit(&self, mut record: serde_json::Value) -> Result<()> {
        if let Some(obj) = record.as_object_mut() {
            obj.entry("actor_pid")
                .or_insert_with(|| json!(self.parent_pid));
            obj.entry("submitter_pid")
                .or_insert_with(|| json!(self.submitter_pid));
            obj.entry("engine_parent_pid")
                .or_insert_with(|| json!(self.parent_pid));
            obj.entry("engine_parent_domain_id")
                .or_insert_with(|| json!(self.parent_domain_id));
            obj.entry("audit_context_id")
                .or_insert_with(|| json!(audit_context_id(&self.audit_path, self.submitter_pid)));
            if let Some(actor_pid) = obj.get("actor_pid").and_then(json_i32) {
                obj.entry("actor_identity").or_insert_with(|| {
                    audit::ProcessIdentity::capture(actor_pid, None, None).to_json()
                });
            }
            if let Some(caller_pid) = obj.get("caller_pid").and_then(json_i32) {
                obj.entry("caller_identity").or_insert_with(|| {
                    audit::ProcessIdentity::capture(caller_pid, None, None).to_json()
                });
            }
            if let Some(submitter_pid) = obj.get("submitter_pid").and_then(json_i32) {
                obj.entry("submitter_identity").or_insert_with(|| {
                    audit::ProcessIdentity::capture(submitter_pid, None, None).to_json()
                });
            }
            if let Some(parent_pid) = obj.get("engine_parent_pid").and_then(json_i32) {
                obj.entry("engine_parent_identity").or_insert_with(|| {
                    audit::ProcessIdentity::capture(parent_pid, None, None).to_json()
                });
            }
            #[cfg(unix)]
            {
                obj.entry("audit_writer_euid")
                    .or_insert_with(|| json!(unsafe { libc::geteuid() }));
                obj.entry("audit_writer_egid")
                    .or_insert_with(|| json!(unsafe { libc::getegid() }));
            }
        }
        audit::append(&self.audit_path, record)
    }

    pub fn audit_child_launch(
        &self,
        pid: i32,
        child_id: u32,
        cmd: &[String],
        policy_attached: bool,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let mut record = json!({
            "event": "launch_child_domain",
            "status": status,
            "actor_pid": self.parent_pid,
            "pid": pid,
            "child_domain_id": child_id,
            "cmd": cmd,
            "policy_attached": policy_attached,
        });
        if let Some(error) = error {
            record["error"] = json!(error);
        }
        self.audit(record)
    }

    pub fn audit_child_restart(
        &self,
        old_child_id: u32,
        new_pid: i32,
        new_child_id: Option<u32>,
        cmd: &[String],
        policy_attached: bool,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let mut record = json!({
            "event": "restart_child_domain",
            "status": status,
            "actor_pid": self.parent_pid,
            "old_child_domain_id": old_child_id,
            "pid": new_pid,
            "cmd": cmd,
            "policy_attached": policy_attached,
        });
        if let Some(new_child_id) = new_child_id {
            record["new_child_domain_id"] = json!(new_child_id);
        }
        if let Some(error) = error {
            record["error"] = json!(error);
        }
        self.audit(record)
    }

    pub fn audit_child_adoption(
        &self,
        pid: i32,
        child_id: u32,
        cmd: &[String],
        policy_attached: bool,
        restart_policy: &str,
        restart_count: u32,
        restart_limit: u32,
        adopted_unix_ms: Option<u64>,
    ) -> Result<()> {
        self.audit(json!({
            "event": "adopt_child_domain",
            "status": "accepted",
            "actor_pid": self.parent_pid,
            "pid": pid,
            "child_domain_id": child_id,
            "cmd": cmd,
            "policy_attached": policy_attached,
            "restart_policy": restart_policy,
            "restart_count": restart_count,
            "restart_limit": restart_limit,
            "adopted_unix_ms": adopted_unix_ms,
            "supervision_mode": "adopted_polling",
        }))
    }

    fn append_policy_delta_dsl_inner(
        &self,
        actor_pid: i32,
        target_id: u32,
        dsl_src: &str,
    ) -> Result<PolicyDeltaOutcome> {
        if target_id == 0 {
            return Err("runtime policy deltas must target a nonzero domain".into());
        }
        let mut inner = self
            .catalog
            .inner
            .write()
            .map_err(|e| format!("policy metadata lock poisoned: {e}"))?;
        let existing_labels = inner
            .domain_labels
            .get(&target_id)
            .cloned()
            .unwrap_or_default();
        let compiled = dsl::compile_str_with_labels(dsl_src, &existing_labels)?;
        let rule_id_base = inner.rules.len();
        let rule_count = compiled.meta.len();
        let rule_provenance = rule_provenance_json(&compiled.meta, rule_id_base);
        self.reload_handle.append_policy_delta_with_rule_id_base(
            actor_pid,
            target_id,
            rule_id_base as u32,
            &compiled.bytes,
        )?;
        inner
            .domain_labels
            .insert(target_id, compiled.labels.clone());
        inner
            .rules
            .extend(report::contexts_from_compiled(&compiled));
        Ok(PolicyDeltaOutcome {
            rule_id_base,
            rule_count,
            rule_provenance,
        })
    }
}

fn audit_context_id(path: &Path, submitter_pid: i32) -> String {
    path.parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != ".actplane")
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("pid-{submitter_pid}"))
}

fn json_i32(value: &serde_json::Value) -> Option<i32> {
    value.as_i64().and_then(|n| i32::try_from(n).ok())
}

fn rule_provenance_json(meta: &[dsl::RuleMeta], rule_id_base: usize) -> Vec<serde_json::Value> {
    meta.iter()
        .enumerate()
        .map(|(offset, rule)| {
            let mut value = json!({
                "rule_id": rule_id_base + offset,
                "name": &rule.name,
                "effect": effect_name(rule.effect),
                "ops": &rule.ops,
                "clause_op": &rule.clause_op,
                "clause_source_index": rule.clause_source_index,
                "kernel_op": &rule.kernel_op,
                "target_kind": kind_name(rule.target_kind),
                "target_pattern": &rule.target_pattern,
                "target_arg": &rule.target_arg,
                "reason": &rule.reason,
            });
            if let Some(source) = &rule.source {
                value["source_ref"] = json!(&source.source_ref);
                value["source_start_line"] = json!(source.start_line);
                value["source_end_line"] = json!(source.end_line);
                value["source_hash"] = json!(audit::policy_hash(&source.text));
                value["source_text"] = json!(&source.text);
                if let Some(line) = source.clause_start_line {
                    value["clause_start_line"] = json!(line);
                }
                if let Some(line) = source.clause_end_line {
                    value["clause_end_line"] = json!(line);
                }
                if let Some(text) = &source.clause_text {
                    value["clause_hash"] = json!(audit::policy_hash(text));
                    value["clause_text"] = json!(text);
                }
                if let Some(mode) = &source.binding_mode {
                    value["binding_mode"] = json!(mode);
                }
                value["immutable"] = json!(source.binding_mode.as_deref() == Some("locked"));
            }
            value
        })
        .collect()
}

fn apply_policy_audit_meta(
    record: &mut serde_json::Value,
    meta: &PolicyAuditMeta,
    approval: Option<&ApprovalEvaluation>,
) {
    let enforced = approval.is_some_and(|approval| approval.enforced);
    let mut approval_chain = json!({
        "enforced": enforced,
        "workflow": approval
            .map(|approval| approval.workflow)
            .unwrap_or("declarative_metadata"),
        "admission_model": if enforced {
            "static_metadata_allowlist"
        } else {
            "metadata_only"
        },
        "external_verified": false,
        "signature": serde_json::Value::Null,
    });
    let mut has_approval_chain = false;
    if let Some(policy_ref) = &meta.policy_ref {
        record["policy_ref"] = json!(policy_ref);
    }
    if let Some(approved_by) = &meta.approved_by {
        record["approved_by"] = json!(approved_by);
        approval_chain["approved_by"] = json!(approved_by);
        has_approval_chain = true;
    }
    if let Some(approval_ref) = &meta.approval_ref {
        record["approval_ref"] = json!(approval_ref);
        approval_chain["approval_ref"] = json!(approval_ref);
        has_approval_chain = true;
    }
    if let Some(generated_by) = &meta.generated_by {
        record["generated_by"] = json!(generated_by);
        approval_chain["generated_by"] = json!(generated_by);
        has_approval_chain = true;
    }
    if let Some(approval) = approval {
        approval_chain["required"] = json!(approval.required);
        approval_chain["decision"] = json!(if approval.accepted {
            "accepted"
        } else {
            "rejected"
        });
        if !approval.missing_fields.is_empty() {
            approval_chain["missing_fields"] = json!(approval.missing_fields);
        }
        if !approval.allowed_approvers.is_empty() {
            approval_chain["allowed_approvers"] = json!(approval.allowed_approvers);
        }
        if let Some(reason) = &approval.rejection_reason {
            approval_chain["rejection_reason"] = json!(reason);
        }
        has_approval_chain = has_approval_chain || approval.enforced;
    }
    if has_approval_chain {
        record["approval_chain"] = approval_chain;
    }
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

impl AttachGuard {
    pub fn engine_control(&self) -> Option<Arc<EngineControl>> {
        self.control.clone()
    }
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn start_mcp_auto_attach(cli: &PolicyInput) -> Result<AttachGuard> {
    let attach_pid = attach_pid_from_env_or_parent();
    if attach_pid <= 1 {
        return Err(format!("invalid parent pid for auto-attach: {attach_pid}").into());
    }

    require_bpf_caps_or_elevate_with_env(
        cli.internal_elevated,
        &[(ATTACH_PID_ENV, attach_pid.to_string())],
    )?;

    let loaded = load_policy(cli)?;
    let policy = policy_source(&loaded, cli.domain.as_deref())?;
    let compiled = dsl::compile_str(&policy)?;
    let agent_label = runner_label(&compiled)?;
    let submitter_pid = std::process::id() as i32;
    let parent_domain_id = fresh_runtime_domain_id(attach_pid, 0x4d43_5041);
    let catalog = Arc::new(RuntimePolicyCatalog::from_compiled(
        &compiled,
        parent_domain_id,
    ));
    let feedback = scoped_feedback_paths(&feedback_paths(&loaded), "mcp");
    prepare_feedback_files(&feedback, target_user(cli.run_as_root))?;
    write_hook_state(&feedback.state, &feedback.feedback, attach_pid)?;
    if let Some((uid, gid)) = target_user(cli.run_as_root) {
        chown_path(&feedback.state, uid, gid)?;
    }

    let stop = Arc::new(AtomicBool::new(false));
    type ReadyResult = std::result::Result<(ReloadHandle, DomainHandle), String>;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<ReadyResult>();
    let blob = compiled.bytes;
    let fb = feedback.feedback.clone();
    let ev = feedback.events.clone();
    let run_catalog = catalog.clone();
    let stop_thread = stop.clone();
    let thread = std::thread::spawn(move || {
        let engine = match PinnedEngine::open_or_install_singleton() {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("open ActPlane singleton: {e}")));
                return;
            }
        };
        let _runtime_lock = match engine.try_lock_runtime() {
            Ok(lock) => lock,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("lock ActPlane singleton runtime: {e}")));
                return;
            }
        };
        let rh = match engine.reload_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("create policy delta handle: {e}")));
                return;
            }
        };
        if let Err(e) = engine.protect_pid(submitter_pid) {
            let _ = ready_tx.send(Err(format!("protect control pid {submitter_pid}: {e}")));
            return;
        }
        if let Err(e) = rh.clear_runtime_state() {
            let _ = ready_tx.send(Err(format!("clear singleton runtime state: {e}")));
            return;
        }
        if let Err(e) = engine.seed_label_in_domain(attach_pid, parent_domain_id, agent_label) {
            let _ = ready_tx.send(Err(format!(
                "seed parent pid {attach_pid} in domain {parent_domain_id}: {e}"
            )));
            return;
        }
        if submitter_pid != attach_pid {
            if let Err(e) = engine.bind_state(
                submitter_pid,
                parent_domain_id,
                control_plane_cap_state(agent_label),
            ) {
                let _ = ready_tx.send(Err(format!(
                    "bind control pid {submitter_pid} to parent domain {parent_domain_id}: {e}"
                )));
                return;
            }
        }
        if let Err(e) = rh.append_policy_delta(submitter_pid, parent_domain_id, &blob) {
            let _ = ready_tx.send(Err(format!(
                "install policy in domain {parent_domain_id}: {e}"
            )));
            return;
        }
        let dh = match engine.domain_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("create domain handle: {e}")));
                return;
            }
        };
        let cleanup = match engine.reload_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = rh.clear_runtime_state();
                let _ = ready_tx.send(Err(format!("create policy cleanup handle: {e}")));
                return;
            }
        };
        let _ = ready_tx.send(Ok((rh, dh)));
        let run_result = engine.run(&stop_thread, |v| {
            run_catalog.append_outputs(&to_violation(&v), &fb, &ev);
        });
        if let Err(e) = cleanup.clear_runtime_state() {
            eprintln!("ActPlane: failed to clear singleton runtime state: {e}");
        }
        if let Err(e) = run_result {
            eprintln!("ActPlane: singleton event loop failed: {e}");
        }
    });

    match ready_rx.recv() {
        Ok(Ok((reload_handle, domain_handle))) => {
            eprintln!(
                "ActPlane: MCP auto-attached pid {} under COMMAND label 0x{:x}; feedback {}",
                attach_pid,
                agent_label,
                feedback.feedback.display()
            );
            Ok(AttachGuard {
                stop,
                thread: Some(thread),
                control: Some(Arc::new(EngineControl {
                    reload_handle: Arc::new(reload_handle),
                    domain_handle: Arc::new(domain_handle),
                    catalog,
                    mutation_lock: Mutex::new(()),
                    audit_path: feedback.audit.clone(),
                    approval_policy: RwLock::new(RuntimeApprovalPolicy::from_loaded_policy(
                        &loaded,
                    )),
                    parent_pid: attach_pid,
                    parent_domain_id,
                    submitter_pid,
                })),
            })
        }
        Ok(Err(e)) => {
            stop.store(true, Ordering::SeqCst);
            let _ = thread.join();
            Err(e.into())
        }
        Err(_) => {
            stop.store(true, Ordering::SeqCst);
            let _ = thread.join();
            Err("engine thread exited before readiness".into())
        }
    }
}

fn parent_pid() -> i32 {
    unsafe { libc::getppid() as i32 }
}

fn attach_pid_from_env_or_parent() -> i32 {
    std::env::var(ATTACH_PID_ENV)
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or_else(parent_pid)
}

fn watch_project_dir(loaded: &crate::config::LoadedPolicy) -> PathBuf {
    loaded
        .path
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| loaded.root.clone())
}

/// Check whether we have BPF capabilities (root or CAP_BPF + CAP_SYS_ADMIN).
pub fn have_bpf_caps() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    let eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|h| u64::from_str_radix(h.trim(), 16).ok())
        })
        .unwrap_or(0);
    let has = |bit: u32| eff & (1u64 << bit) != 0;
    has(39) && has(21)
}

pub fn passwordless_sudo_available() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// If we lack BPF caps, try passwordless sudo to re-exec ourselves elevated.
/// Returns Ok(()) if we already have caps; otherwise re-execs or exits with an error.
fn require_bpf_caps_or_elevate(already_elevated: bool) -> Result<()> {
    require_bpf_caps_or_elevate_with_env(already_elevated, &[])
}

fn require_bpf_caps_or_elevate_with_env(
    already_elevated: bool,
    extra_env: &[(&str, String)],
) -> Result<()> {
    if have_bpf_caps() {
        return Ok(());
    }
    if already_elevated {
        eprintln!("actplane: still lacks BPF caps after elevation attempt");
        std::process::exit(1);
    }
    if passwordless_sudo_available() {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("actplane"));
        let args: Vec<String> = std::env::args().collect();
        let mut cmd = std::process::Command::new("sudo");
        cmd.arg("-E").arg(&exe).arg("--internal-elevated");
        for (name, value) in extra_env {
            cmd.env(name, value);
        }
        for arg in &args[1..] {
            cmd.arg(arg);
        }
        eprintln!("actplane: auto-elevating via passwordless sudo ...");
        #[cfg(unix)]
        {
            let e = cmd.exec();
            Err(format!("sudo exec: {e}").into())
        }
        #[cfg(not(unix))]
        {
            let status = cmd.status().map_err(|e| format!("sudo re-exec: {e}"))?;
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        eprintln!(
            "actplane: this command loads an eBPF engine, which needs root \
                 (or CAP_BPF + CAP_SYS_ADMIN).\n\
                 \n  Re-run with sudo, e.g.:   sudo -E actplane <same args>\n\
                 \n  (sudo-launched ActPlane drops the target command back to your user automatically.)"
        );
        std::process::exit(1);
    }
}

pub async fn run_command(cli: &PolicyInput, cmd: &[String], parent_domain: bool) -> Result<i32> {
    if parent_domain {
        return Err(
            "--parent-domain is not supported by the pinned singleton engine yet; it would \
             require a host-global policy replacement path. Run without --parent-domain to \
             use an isolated command domain."
                .into(),
        );
    }
    require_bpf_caps_or_elevate(cli.internal_elevated)?;
    let loaded = load_policy(cli)?;
    let policy = policy_source(&loaded, cli.domain.as_deref())?;
    let compiled = dsl::compile_str(&policy)?;
    let agent_label = runner_label(&compiled)?;
    let feedback = scoped_feedback_paths(&feedback_paths(&loaded), "run");
    let target_owner = target_user(cli.run_as_root);
    prepare_feedback_files(&feedback, target_owner)?;

    let mut target = spawn_stopped_target(
        cmd,
        &feedback,
        loaded.path.as_deref(),
        cli.run_as_root,
        false,
    )?;
    let target_pid = target.id().ok_or("target process has no pid")?;
    write_hook_state(&feedback.state, &feedback.feedback, target_pid as i32)?;
    if let Some((uid, gid)) = target_owner {
        chown_path(&feedback.state, uid, gid)?;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::result::Result<(), String>>();
    let blob = compiled.bytes;
    let meta = compiled.meta;
    let labels = compiled.labels;
    let fb = feedback.feedback.clone();
    let ev = feedback.events.clone();
    let stop_thread = stop.clone();
    let control_pid = std::process::id() as i32;
    let target_domain_id = fresh_runtime_domain_id(target_pid as i32, 0x5255_4e31);
    let poller = std::thread::spawn(move || {
        let engine = match PinnedEngine::open_or_install_singleton() {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("open ActPlane singleton: {e}")));
                return;
            }
        };
        let _runtime_lock = match engine.try_lock_runtime() {
            Ok(lock) => lock,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("lock ActPlane singleton runtime: {e}")));
                return;
            }
        };
        let rh = match engine.reload_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("create policy delta handle: {e}")));
                return;
            }
        };
        if let Err(e) = engine.protect_pid(control_pid) {
            let _ = ready_tx.send(Err(format!("protect control pid {control_pid}: {e}")));
            return;
        }
        if let Err(e) = rh.clear_runtime_state() {
            let _ = ready_tx.send(Err(format!("clear singleton runtime state: {e}")));
            return;
        }
        if let Err(e) =
            engine.seed_label_in_domain(target_pid as i32, target_domain_id, agent_label)
        {
            let _ = ready_tx.send(Err(format!(
                "seed pid {target_pid} in domain {target_domain_id}: {e}"
            )));
            return;
        }
        if control_pid != target_pid as i32 {
            if let Err(e) = engine.bind_state(
                control_pid,
                target_domain_id,
                control_plane_cap_state(agent_label),
            ) {
                let _ = ready_tx.send(Err(format!(
                    "bind control pid {control_pid} to run domain {target_domain_id}: {e}"
                )));
                return;
            }
        }
        if let Err(e) = rh.append_policy_delta(control_pid, target_domain_id, &blob) {
            let _ = ready_tx.send(Err(format!(
                "install policy in domain {target_domain_id}: {e}"
            )));
            return;
        }
        if control_pid != target_pid as i32 {
            if let Err(e) = engine.unbind_pid_from_domain(control_pid, target_domain_id) {
                let _ = ready_tx.send(Err(format!(
                    "unbind control pid {control_pid} from run domain {target_domain_id}: {e}"
                )));
                return;
            }
        }
        let cleanup = match engine.reload_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = rh.clear_runtime_state();
                let _ = ready_tx.send(Err(format!("create policy cleanup handle: {e}")));
                return;
            }
        };
        let _ = ready_tx.send(Ok(()));
        let run_result = engine.run(&stop_thread, |v| {
            if v.domain_id == target_domain_id {
                report(&meta, &labels, &to_violation(&v), Some(&fb), Some(&ev));
            }
        });
        if let Err(e) = cleanup.clear_runtime_state() {
            eprintln!("ActPlane: failed to clear singleton runtime state: {e}");
        }
        if let Err(e) = run_result {
            eprintln!("ActPlane: singleton event loop failed: {e}");
        }
    });

    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = send_signal(target_pid, libc::SIGKILL);
            let _ = target.wait().await;
            let _ = poller.join();
            return Err(e.into());
        }
        Err(_) => {
            let _ = send_signal(target_pid, libc::SIGKILL);
            let _ = target.wait().await;
            return Err("engine thread exited before readiness".into());
        }
    }

    eprintln!(
        "ActPlane: running pid {} under COMMAND label 0x{:x}{}; feedback {}\n",
        target_pid,
        agent_label,
        if parent_domain {
            " in an isolated singleton domain"
        } else {
            ""
        },
        feedback.feedback.display()
    );
    send_signal(target_pid, libc::SIGCONT)?;

    let status = target.wait().await?;
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::SeqCst);
    let _ = poller.join();
    Ok(exit_code(status))
}

pub async fn run_child_command(
    cli: &PolicyInput,
    child_id: Option<u32>,
    scope_id: u32,
    delta_paths: &[PathBuf],
    delta_texts: &[String],
    audit_meta: &PolicyAuditMeta,
    cmd: &[String],
) -> Result<i32> {
    require_bpf_caps_or_elevate(cli.internal_elevated)?;
    if cmd.is_empty() {
        return Err("run requires a command".into());
    }

    let loaded = load_policy(cli)?;
    let policy = policy_source(&loaded, cli.domain.as_deref())?;
    let compiled = dsl::compile_str(&policy)?;
    let agent_label = runner_label(&compiled)?;
    let deltas = load_child_policy_deltas(delta_paths, delta_texts)?;
    let feedback = scoped_feedback_paths(&feedback_paths(&loaded), "run-child");
    let target_owner = target_user(cli.run_as_root);
    prepare_feedback_files(&feedback, target_owner)?;

    let mut child = spawn_stopped_target(
        cmd,
        &feedback,
        loaded.path.as_deref(),
        cli.run_as_root,
        true,
    )?;
    let child_pid = child.id().ok_or("child process has no pid")?;
    let parent_pid = std::process::id() as i32;
    let parent_domain_id = fresh_runtime_domain_id(parent_pid, 0x5041_524e);
    let child_domain_id =
        child_id.unwrap_or_else(|| fresh_runtime_domain_id(child_pid as i32, 0x4348_4c44));
    if child_domain_id == 0 {
        kill_process_group_and_wait(&mut child).await;
        return Err("child domain id must be nonzero".into());
    }
    write_hook_state(&feedback.state, &feedback.feedback, child_pid as i32)?;
    if let Some((uid, gid)) = target_owner {
        chown_path(&feedback.state, uid, gid)?;
    }

    let catalog = Arc::new(RuntimePolicyCatalog::from_compiled(
        &compiled,
        parent_domain_id,
    ));
    let stop = Arc::new(AtomicBool::new(false));
    type ReadyResult = std::result::Result<(ReloadHandle, DomainHandle), String>;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<ReadyResult>();
    let blob = compiled.bytes;
    let fb = feedback.feedback.clone();
    let ev = feedback.events.clone();
    let run_catalog = catalog.clone();
    let stop_thread = stop.clone();
    let poller = std::thread::spawn(move || {
        let engine = match PinnedEngine::open_or_install_singleton() {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("open ActPlane singleton: {e}")));
                return;
            }
        };
        let _runtime_lock = match engine.try_lock_runtime() {
            Ok(lock) => lock,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("lock ActPlane singleton runtime: {e}")));
                return;
            }
        };
        let rh = match engine.reload_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("create policy delta handle: {e}")));
                return;
            }
        };
        if let Err(e) = engine.protect_pid(parent_pid) {
            let _ = ready_tx.send(Err(format!("protect control pid {parent_pid}: {e}")));
            return;
        }
        if let Err(e) = rh.clear_runtime_state() {
            let _ = ready_tx.send(Err(format!("clear singleton runtime state: {e}")));
            return;
        }
        if let Err(e) = engine.seed_label_in_domain(parent_pid, parent_domain_id, agent_label) {
            let _ = ready_tx.send(Err(format!(
                "seed parent pid {parent_pid} in domain {parent_domain_id}: {e}"
            )));
            return;
        }
        if let Err(e) = rh.append_policy_delta(parent_pid, parent_domain_id, &blob) {
            let _ = ready_tx.send(Err(format!(
                "install policy in domain {parent_domain_id}: {e}"
            )));
            return;
        }
        let dh = match engine.domain_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("create domain handle: {e}")));
                return;
            }
        };
        let cleanup = match engine.reload_handle() {
            Ok(h) => h,
            Err(e) => {
                let _ = rh.clear_runtime_state();
                let _ = ready_tx.send(Err(format!("create policy cleanup handle: {e}")));
                return;
            }
        };
        let _ = ready_tx.send(Ok((rh, dh)));
        let run_result = engine.run(&stop_thread, |v| {
            run_catalog.append_outputs(&to_violation(&v), &fb, &ev);
        });
        if let Err(e) = cleanup.clear_runtime_state() {
            eprintln!("ActPlane: failed to clear singleton runtime state: {e}");
        }
        if let Err(e) = run_result {
            eprintln!("ActPlane: singleton event loop failed: {e}");
        }
    });

    let (reload_handle, domain_handle) = match ready_rx.recv() {
        Ok(Ok(handles)) => handles,
        Ok(Err(e)) => {
            kill_process_group_and_wait(&mut child).await;
            stop.store(true, Ordering::SeqCst);
            let _ = poller.join();
            return Err(e.into());
        }
        Err(_) => {
            kill_process_group_and_wait(&mut child).await;
            stop.store(true, Ordering::SeqCst);
            let _ = poller.join();
            return Err("engine thread exited before readiness".into());
        }
    };

    let control = EngineControl {
        reload_handle: Arc::new(reload_handle),
        domain_handle: Arc::new(domain_handle),
        catalog,
        mutation_lock: Mutex::new(()),
        audit_path: feedback.audit.clone(),
        approval_policy: RwLock::new(RuntimeApprovalPolicy::from_loaded_policy(&loaded)),
        parent_pid,
        parent_domain_id,
        submitter_pid: parent_pid,
    };
    let policy_attached = !deltas.is_empty();

    if let Err(e) = control.bind_child_domain(ChildDomainSpec {
        parent_pid,
        parent_id: parent_domain_id,
        child_id: child_domain_id,
        pid: child_pid as i32,
        scope_id,
        authority_mask: AUTH_BIND_RULE,
        target_mask: TARGET_SELF,
        ..ChildDomainSpec::default()
    }) {
        kill_process_group_and_wait(&mut child).await;
        let _ = control.audit_child_launch(
            child_pid as i32,
            child_domain_id,
            &cmd.to_vec(),
            policy_attached,
            "rejected",
            Some(&e.to_string()),
        );
        stop.store(true, Ordering::SeqCst);
        let _ = poller.join();
        return Err(format!("bind child domain failed: {e}").into());
    }

    for (policy_ref, delta) in &deltas {
        let mut delta_meta = audit_meta.clone();
        delta_meta.policy_ref = Some(policy_ref.clone());
        if let Err(e) =
            control.append_policy_delta_dsl_with_audit(child_domain_id, delta, &delta_meta)
        {
            kill_process_group_and_wait(&mut child).await;
            let _ = control.audit_child_launch(
                child_pid as i32,
                child_domain_id,
                &cmd.to_vec(),
                policy_attached,
                "rejected",
                Some(&format!("{policy_ref}: {e}")),
            );
            stop.store(true, Ordering::SeqCst);
            let _ = poller.join();
            return Err(format!("append child policy delta {policy_ref} failed: {e}").into());
        }
    }

    control.audit_child_launch(
        child_pid as i32,
        child_domain_id,
        &cmd.to_vec(),
        policy_attached,
        "accepted",
        None,
    )?;

    eprintln!(
        "ActPlane: running child pid {} in domain {}; feedback {}",
        child_pid,
        child_domain_id,
        feedback.feedback.display()
    );
    send_signal(child_pid, libc::SIGCONT)?;

    let status = child.wait().await?;
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::SeqCst);
    let _ = poller.join();
    Ok(exit_code(status))
}

fn runner_label(compiled: &dsl::Compiled) -> Result<u64> {
    compiled
        .labels
        .get("COMMAND")
        .or_else(|| compiled.labels.get("AGENT"))
        .copied()
        .ok_or_else(|| {
            "run/auto-attach mode requires the policy to declare or reference label COMMAND \
             (or AGENT for backward compatibility)"
                .into()
        })
}

fn control_plane_cap_state(label: u64) -> CapState {
    CapState {
        scope_id: 1,
        labels: label,
        authority_mask: AUTH_BIND_RULE
            | AUTH_NARROW_SCOPE
            | AUTH_ADD_LABEL
            | AUTH_REQUIRE_GATE
            | AUTH_DECLASSIFY
            | AUTH_DELEGATE,
        target_mask: TARGET_SELF | TARGET_CHILD,
        gate_mask: u64::MAX,
        label_mask: u64::MAX,
        ..CapState::default()
    }
}

fn prepare_feedback_files(
    paths: &FeedbackPaths,
    owner: Option<(libc::uid_t, libc::gid_t)>,
) -> Result<()> {
    if let Some(parent) = paths.feedback.parent() {
        std::fs::create_dir_all(parent)?;
        if let Some((uid, gid)) = owner {
            chown_path(parent, uid, gid)?;
        }
    }
    std::fs::write(&paths.feedback, "")?;
    if let Some((uid, gid)) = owner {
        chown_path(&paths.feedback, uid, gid)?;
    }
    if let Some(parent) = paths.audit.parent() {
        std::fs::create_dir_all(parent)?;
        if let Some((uid, gid)) = owner {
            chown_path(parent, uid, gid)?;
        }
    }
    std::fs::write(&paths.audit, "")?;
    if let Some((uid, gid)) = owner {
        chown_path(&paths.audit, uid, gid)?;
    }
    if let Some(parent) = paths.events.parent() {
        std::fs::create_dir_all(parent)?;
        if let Some((uid, gid)) = owner {
            chown_path(parent, uid, gid)?;
        }
    }
    std::fs::write(&paths.events, "")?;
    if let Some((uid, gid)) = owner {
        chown_path(&paths.events, uid, gid)?;
    }
    match std::fs::remove_file(&paths.state) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn scoped_feedback_paths(base: &FeedbackPaths, prefix: &str) -> FeedbackPaths {
    let root = base
        .feedback
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let run_dir = root.join("runs").join(run_id(prefix));
    FeedbackPaths {
        feedback: run_dir.join("feedback.txt"),
        state: run_dir.join("hook-state.json"),
        audit: run_dir.join("audit.jsonl"),
        events: run_dir.join("events.jsonl"),
    }
}

fn run_id(prefix: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}-{}-{now}", std::process::id())
}

fn load_child_policy_deltas(paths: &[PathBuf], inline: &[String]) -> Result<Vec<(String, String)>> {
    let mut deltas = Vec::new();
    for path in paths {
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read child policy delta {}: {e}", path.display()))?;
        deltas.push((path.display().to_string(), src));
    }
    for (idx, src) in inline.iter().enumerate() {
        deltas.push((format!("--delta-text[{idx}]"), src.clone()));
    }
    Ok(deltas)
}

fn chown_path(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
pub(crate) fn mark_non_stdio_fds_cloexec() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                !0u32,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) {
            return Err(e);
        }
    }

    for fd in 3..CLOEXEC_FALLBACK_FD_LIMIT {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EBADF) {
                return Err(e);
            }
            continue;
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn spawn_stopped_target(
    cmd: &[String],
    feedback: &FeedbackPaths,
    policy_path: Option<&Path>,
    run_as_root: bool,
    new_process_group: bool,
) -> Result<Child> {
    if cmd.is_empty() {
        return Err("run requires a command after `--`".into());
    }
    let drop_to = target_user(run_as_root);
    let mut target = Command::new("/bin/sh");
    target.arg("-c");
    target.arg("kill -STOP $$; exec \"$@\"");
    target.arg("actplane-target");
    target.args(cmd);
    target.stdin(Stdio::inherit());
    target.stdout(Stdio::inherit());
    target.stderr(Stdio::inherit());
    target.env("ACTPLANE_FEEDBACK_FILE", &feedback.feedback);
    target.env("ACTPLANE_HOOK_STATE", &feedback.state);
    if let Some(policy_path) = policy_path {
        target.env("ACTPLANE_POLICY_FILE", policy_path);
    }

    unsafe {
        target.pre_exec(move || {
            mark_non_stdio_fds_cloexec()?;
            if new_process_group && libc::setpgid(0, 0) != 0 {
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
    let mut target = target.spawn()?;
    let pid = target
        .id()
        .ok_or_else(|| "spawned target has no pid".to_string())?;
    if let Err(e) = wait_for_stopped_process(pid, Duration::from_secs(5)) {
        let _ = if new_process_group {
            send_process_group_signal(pid, libc::SIGKILL)
        } else {
            send_signal(pid, libc::SIGKILL)
        };
        let _ = target.start_kill();
        return Err(format!("target {pid} did not enter stopped state before setup: {e}").into());
    }
    Ok(target)
}

async fn kill_process_group_and_wait(child: &mut Child) {
    if let Some(pid) = child.id() {
        let _ = send_process_group_signal(pid, libc::SIGKILL);
    }
    let _ = child.wait().await;
}

fn target_user(run_as_root: bool) -> Option<(libc::uid_t, libc::gid_t)> {
    if run_as_root || unsafe { libc::geteuid() } != 0 {
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

fn send_signal(pid: u32, sig: i32) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn send_process_group_signal(pid: u32, sig: i32) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(-(pid as libc::pid_t), sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn wait_for_stopped_process(pid: u32, timeout: Duration) -> std::io::Result<()> {
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

fn proc_state_code(pid: u32) -> std::io::Result<char> {
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

fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    if let Some(sig) = status.signal() {
        return 128 + sig;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_context_id_uses_run_dir_when_available() {
        assert_eq!(
            audit_context_id(Path::new("/repo/.actplane/runs/mcp-123/audit.jsonl"), 42),
            "mcp-123"
        );
        assert_eq!(
            audit_context_id(Path::new("/repo/.actplane/audit.jsonl"), 42),
            "pid-42"
        );
    }

    #[test]
    fn rule_provenance_json_includes_source_text_and_binding_mode() {
        let meta = vec![dsl::RuleMeta {
            name: "secret".to_string(),
            reason: "review secrets".to_string(),
            effect: dsl::ast::Effect::Block,
            ops: vec!["exec".to_string()],
            clause_op: "exec".to_string(),
            clause_source_index: 0,
            kernel_op: "exec".to_string(),
            target_kind: dsl::ast::Kind::Exec,
            target_pattern: "git".to_string(),
            target_arg: None,
            source: Some(dsl::RuleSourceMeta {
                source_ref: "rules.secret.ifc".to_string(),
                binding_mode: Some("locked".to_string()),
                start_line: 3,
                end_line: 7,
                text: "rule secret:\n  block exec \"git\"\n  because \"review secrets\""
                    .to_string(),
                clause_start_line: Some(4),
                clause_end_line: Some(4),
                clause_text: Some("  block exec \"git\"".to_string()),
            }),
        }];

        let value = rule_provenance_json(&meta, 5);
        assert_eq!(value[0]["rule_id"], 5);
        assert_eq!(value[0]["source_ref"], "rules.secret.ifc");
        assert_eq!(value[0]["binding_mode"], "locked");
        assert_eq!(value[0]["immutable"], true);
        assert_eq!(value[0]["source_start_line"], 3);
        assert_eq!(value[0]["clause_start_line"], 4);
        assert_eq!(value[0]["clause_text"], "  block exec \"git\"");
        assert!(
            value[0]["clause_hash"]
                .as_str()
                .unwrap()
                .starts_with("fnv1a64:")
        );
        assert!(
            value[0]["source_text"]
                .as_str()
                .unwrap()
                .contains("rule secret")
        );
        assert!(
            value[0]["source_hash"]
                .as_str()
                .unwrap()
                .starts_with("fnv1a64:")
        );
    }

    #[test]
    fn append_delta_approval_gate_rejects_missing_and_unknown_approver() {
        let gate = AppendDeltaApprovalGate {
            required: true,
            require_approval_ref: true,
            require_generated_by: false,
            allowed_approvers: vec!["repo-supervisor".to_string()],
        };

        let missing = gate.evaluate(&PolicyAuditMeta::default());
        assert!(missing.enforced);
        assert!(!missing.accepted);
        assert_eq!(missing.missing_fields, vec!["approved_by", "approval_ref"]);
        assert!(
            missing
                .rejection_reason
                .as_deref()
                .unwrap_or("")
                .contains("missing approved_by, approval_ref")
        );

        let wrong = gate.evaluate(&PolicyAuditMeta {
            approved_by: Some("other-reviewer".to_string()),
            approval_ref: Some("ticket-7".to_string()),
            ..PolicyAuditMeta::default()
        });
        assert!(!wrong.accepted);
        assert!(
            wrong
                .rejection_reason
                .as_deref()
                .unwrap_or("")
                .contains("not in runtime.approval.append_delta.allowed_approvers")
        );

        let accepted = gate.evaluate(&PolicyAuditMeta {
            approved_by: Some("repo-supervisor".to_string()),
            approval_ref: Some("ticket-7".to_string()),
            ..PolicyAuditMeta::default()
        });
        assert!(accepted.accepted);
        assert!(accepted.rejection_reason.is_none());
    }

    #[test]
    fn policy_audit_meta_records_enforced_approval_chain() {
        let gate = AppendDeltaApprovalGate {
            required: true,
            require_approval_ref: true,
            require_generated_by: true,
            allowed_approvers: vec!["repo-supervisor".to_string()],
        };
        let meta = PolicyAuditMeta {
            policy_ref: Some("policy-delta.dsl".to_string()),
            approved_by: Some("repo-supervisor".to_string()),
            approval_ref: Some("ticket-7".to_string()),
            generated_by: Some("template/readonly".to_string()),
        };
        let approval = gate.evaluate(&meta);
        let mut record = json!({});
        apply_policy_audit_meta(&mut record, &meta, Some(&approval));

        assert_eq!(record["policy_ref"], "policy-delta.dsl");
        assert_eq!(record["approved_by"], "repo-supervisor");
        assert_eq!(record["approval_chain"]["enforced"], true);
        assert_eq!(record["approval_chain"]["required"], true);
        assert_eq!(record["approval_chain"]["decision"], "accepted");
        assert_eq!(
            record["approval_chain"]["workflow"],
            "append_delta_static_approval"
        );
        assert_eq!(
            record["approval_chain"]["admission_model"],
            "static_metadata_allowlist"
        );
        assert_eq!(record["approval_chain"]["external_verified"], false);
        assert_eq!(
            record["approval_chain"]["signature"],
            serde_json::Value::Null
        );
        assert_eq!(
            record["approval_chain"]["allowed_approvers"][0],
            "repo-supervisor"
        );
    }
}
