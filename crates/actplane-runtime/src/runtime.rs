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
    ChildDomainSpec, CompatibilityLoader, DomainHandle, GLOBAL_ACTIVE_DOMAIN_ID, PinnedEngine,
    ReloadHandle, legacy_kernel_required,
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

fn legacy_shutdown_signals() -> std::io::Result<[tokio::signal::unix::Signal; 2]> {
    use tokio::signal::unix::{SignalKind, signal};
    Ok([
        signal(SignalKind::interrupt())?,
        signal(SignalKind::terminate())?,
    ])
}

async fn run_legacy_command(
    mut target: Child,
    agent_label: u64,
    compiled: dsl::Compiled,
    feedback: FeedbackPaths,
    signals: [tokio::signal::unix::Signal; 2],
) -> Result<i32> {
    let target_pid = target.id().ok_or("target process has no pid")?;
    let [mut interrupt, mut terminate] = signals;
    let mut loader = match CompatibilityLoader::load(
        &compiled.bytes,
        std::process::id() as i32,
        target_pid as i32,
        agent_label,
    ) {
        Ok(loader) => loader,
        Err(error) => {
            target.kill().await?;
            return Err(error.into());
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let (failure_tx, mut failure_rx) = tokio::sync::oneshot::channel();
    let feedback_file = feedback.feedback.clone();
    let poller = std::thread::spawn(move || {
        let result = loader.run(&stop_thread, |v| {
            report(
                &compiled.meta,
                &compiled.labels,
                &to_violation(&v),
                Some(&feedback.feedback),
                Some(&feedback.events),
            )
        });
        if let Err(error) = result {
            let _ = failure_tx.send(format!("compatibility event loop failed: {error}"));
            while !stop_thread.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        drop(loader);
    });

    eprintln!(
        "ActPlane: running pid {target_pid} under COMMAND label 0x{agent_label:x}; feedback {}\n\
         ActPlane: Linux compatibility mode uses a static policy; runtime updates require Linux 6.1+",
        feedback_file.display()
    );
    let outcome: Result<i32> = if let Err(error) =
        send_process_group_signal(target_pid, libc::SIGCONT)
    {
        Err(error.into())
    } else {
        tokio::select! {
            biased;
            failure = &mut failure_rx => Err(failure.unwrap_or_else(|_| "compatibility event loop exited unexpectedly".into()).into()),
            _ = interrupt.recv() => Err("terminated by SIGINT".into()),
            _ = terminate.recv() => Err("terminated by SIGTERM".into()),
            status = target.wait() => status.map(exit_code).map_err(|error| error.into()),
        }
    };
    let _ = send_process_group_signal(target_pid, libc::SIGKILL);
    let _ = target.wait().await;
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::SeqCst);
    let _ = poller.join();
    if let Ok(error) = failure_rx.try_recv() {
        return Err(error.into());
    }
    outcome
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

    let legacy = legacy_kernel_required();
    let shutdown = legacy.then(legacy_shutdown_signals).transpose()?;
    let mut target = spawn_stopped_target(
        cmd,
        &feedback,
        loaded.path.as_deref(),
        cli.run_as_root,
        legacy,
    )?;
    let target_pid = target.id().ok_or("target process has no pid")?;
    write_hook_state(&feedback.state, &feedback.feedback, target_pid as i32)?;
    if let Some((uid, gid)) = target_owner {
        chown_path(&feedback.state, uid, gid)?;
    }

    if legacy {
        return run_legacy_command(target, agent_label, compiled, feedback, shutdown.unwrap())
            .await;
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

    #[test]
    fn attach_guard_drop_signals_and_joins_its_thread() {
        let stop = Arc::new(AtomicBool::new(false));
        let observed = stop.clone();
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            for _ in 0..1000 {
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });
        let guard = AttachGuard {
            stop,
            thread: Some(thread),
            control: None,
        };
        assert!(guard.engine_control().is_none());
        drop(guard);
        assert!(
            observed.load(Ordering::SeqCst),
            "dropping the guard must request the auto-attach watcher to stop"
        );
    }

    #[test]
    fn append_delta_gate_from_config_maps_each_field() {
        // `AppendDeltaApprovalGate::from_config` copies every knob out of the
        // parsed YAML config, so the gate must accept an approver listed in
        // `allowed_approvers` and reject an unknown one. No base or branch test
        // calls `from_config`.
        let config = crate::config::AppendDeltaApprovalConfig {
            required: true,
            require_approval_ref: true,
            require_generated_by: false,
            allowed_approvers: vec!["repo-supervisor".to_string()],
        };
        let gate = AppendDeltaApprovalGate::from_config(&config);

        let accepted = gate.evaluate(&PolicyAuditMeta {
            approved_by: Some("repo-supervisor".to_string()),
            approval_ref: Some("ticket-7".to_string()),
            ..PolicyAuditMeta::default()
        });
        assert!(accepted.accepted, "{:?}", accepted.rejection_reason);
        assert!(accepted.enforced && accepted.required);
        assert!(accepted.missing_fields.is_empty());
        assert_eq!(
            accepted.allowed_approvers,
            vec!["repo-supervisor".to_string()]
        );

        let unknown = gate.evaluate(&PolicyAuditMeta {
            approved_by: Some("someone-else".to_string()),
            approval_ref: Some("ticket-7".to_string()),
            ..PolicyAuditMeta::default()
        });
        assert!(!unknown.accepted);
        assert!(
            unknown.rejection_reason.as_deref().is_some_and(
                |r| r.contains("not in runtime.approval.append_delta.allowed_approvers")
            ),
            "{:?}",
            unknown.rejection_reason
        );
    }

    #[test]
    fn runtime_approval_policy_wires_append_delta_gate_from_config() {
        // `RuntimeApprovalPolicy::from_loaded_policy` (via the
        // `AppendDeltaApprovalGate::from_config` copy) wires the configured
        // append-delta gate; none had any call in the base or branch suite.
        let mut loaded = LoadedPolicy {
            config: crate::config::FileConfig::default(),
            root: PathBuf::new(),
            path: None,
        };
        loaded.config.runtime.approval.append_delta = AppendDeltaApprovalConfig {
            required: true,
            require_approval_ref: true,
            require_generated_by: false,
            allowed_approvers: vec!["repo-supervisor".to_string()],
        };

        let policy = RuntimeApprovalPolicy::from_loaded_policy(&loaded);
        let accepted = policy.evaluate_append_delta(&PolicyAuditMeta {
            approved_by: Some("repo-supervisor".to_string()),
            approval_ref: Some("ticket-7".to_string()),
            ..PolicyAuditMeta::default()
        });
        assert!(accepted.enforced);
        assert!(accepted.accepted);

        let rejected = policy.evaluate_append_delta(&PolicyAuditMeta::default());
        assert!(!rejected.accepted);
        assert_eq!(rejected.missing_fields, vec!["approved_by", "approval_ref"]);

        // A default config yields an unenforced gate.
        let relaxed = RuntimeApprovalPolicy::from_loaded_policy(&LoadedPolicy {
            config: crate::config::FileConfig::default(),
            root: PathBuf::new(),
            path: None,
        });
        let unenforced = relaxed.evaluate_append_delta(&PolicyAuditMeta::default());
        assert!(!unenforced.enforced);
        assert!(unenforced.accepted);
    }
    #[test]
    fn internal_rejection_builds_a_static_rejected_evaluation() {
        // `ApprovalEvaluation::internal_rejection` builds a deterministically
        // rejected evaluation: nothing is enforced/required/accepted, the
        // workflow is the static approval one, and the supplied reason is
        // carried in `rejection_reason`. No base or branch test pins this
        // constructor directly.
        let ev = ApprovalEvaluation::internal_rejection("policy requires an approver".to_string());
        assert!(!ev.enforced);
        assert!(!ev.required);
        assert!(!ev.accepted);
        assert_eq!(ev.workflow, "append_delta_static_approval");
        assert!(ev.missing_fields.is_empty());
        assert!(ev.allowed_approvers.is_empty());
        assert_eq!(
            ev.rejection_reason.as_deref(),
            Some("policy requires an approver")
        );

        // The constructor is total: an empty reason is also carried through.
        let empty = ApprovalEvaluation::internal_rejection(String::new());
        assert_eq!(empty.rejection_reason.as_deref(), Some(""));
        assert!(!empty.accepted);
    }

    #[test]
    fn approval_rejection_records_reason_without_enforcement() {
        let gate = AppendDeltaApprovalGate {
            required: true,
            require_approval_ref: false,
            require_generated_by: false,
            allowed_approvers: Vec::new(),
        };
        let meta = PolicyAuditMeta {
            policy_ref: None,
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        };
        let approval = gate.evaluate(&meta);
        assert_eq!(approval.workflow, "append_delta_static_approval");
        assert_eq!(approval.missing_fields, vec!["approved_by"]);
        assert_eq!(
            approval.rejection_reason.as_deref(),
            Some("append policy delta requires approval metadata: missing approved_by")
        );

        let mut record = json!({});
        apply_policy_audit_meta(&mut record, &meta, Some(&approval));
        assert_eq!(record["approval_chain"]["enforced"], true);
        assert_eq!(record["approval_chain"]["required"], true);
        assert_eq!(record["approval_chain"]["decision"], "rejected");
        assert_eq!(record["approval_chain"]["missing_fields"][0], "approved_by");
        assert_eq!(
            record["approval_chain"]["rejection_reason"],
            "append policy delta requires approval metadata: missing approved_by"
        );
    }

    #[test]
    fn approval_chain_omitted_without_metadata_or_enforcement() {
        let meta = PolicyAuditMeta {
            policy_ref: Some("policy-delta.dsl".to_string()),
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        };
        let mut record = json!({});
        apply_policy_audit_meta(&mut record, &meta, None);
        assert_eq!(record["policy_ref"], "policy-delta.dsl");
        assert!(record.get("approval_chain").is_none());
    }

    #[test]
    fn have_bpf_caps_is_true_for_root_and_tracks_cap_eff_bits() {
        if unsafe { libc::geteuid() } == 0 {
            assert!(have_bpf_caps(), "root always has BPF caps");
            return;
        }
        let eff = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("CapEff:"))
                    .and_then(|h| u64::from_str_radix(h.trim(), 16).ok())
            })
            .unwrap_or(0);
        let expected = eff & (1u64 << 39) != 0 && eff & (1u64 << 21) != 0;
        assert_eq!(have_bpf_caps(), expected, "CapEff {eff:#x} must decide");
    }

    #[test]
    fn bpf_cap_gate_is_a_noop_once_caps_are_present() {
        // Only probe the pass-through arm: without caps the gate either re-execs
        // through sudo or exits the process, so it cannot be observed in-process.
        if !have_bpf_caps() {
            return;
        }
        let extra = [("ACT_PLANE_PROBE", "1".to_string())];
        let result = require_bpf_caps_or_elevate_with_env(false, &extra);
        assert!(
            result.is_ok(),
            "caps present means no elevation: {result:?}"
        );
    }

    #[test]
    fn catalog_from_compiled_gates_and_appends_outputs() {
        // `RuntimePolicyCatalog::from_compiled` seeds rules + labels for one
        // domain and `append_outputs` gates on domain/rule then writes the
        // feedback and event files; none had any call.
        let compiled = dsl::Compiled {
            bytes: vec![],
            reasons: vec!["why".to_string()],
            meta: vec![dsl::RuleMeta {
                name: "r".to_string(),
                reason: "why".to_string(),
                effect: dsl::ast::Effect::Kill,
                ops: vec!["exec".to_string()],
                clause_op: "exec".to_string(),
                clause_source_index: 0,
                kernel_op: "exec".to_string(),
                target_kind: dsl::ast::Kind::Exec,
                target_pattern: "git".to_string(),
                target_arg: None,
                source: None,
            }],
            labels: HashMap::from([("LOCAL_SECRET".to_string(), 1u64)]),
            endpoint_resolutions: HashMap::new(),
        };
        let domain_id = 9u32;
        let catalog = RuntimePolicyCatalog::from_compiled(&compiled, domain_id);

        let dir = std::env::temp_dir().join(format!("actplane-catalog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let feedback = dir.join("feedback.txt");
        let events = dir.join("events.jsonl");

        let violation = |rule_id: usize, domain_id: Option<u32>| {
            let mut value = json!({
                "pid": 10,
                "ppid": 1,
                "comm": "git",
                "target": "git",
                "rule_id": rule_id,
                "op": 0,
                "session_root": 10,
                "effect": "kill",
                "blocked": false,
                "killed": true,
                "taint_label": 1u64,
                "matched_label": 1u64,
            });
            value["domain_id"] = match domain_id {
                Some(id) => json!(id),
                None => serde_json::Value::Null,
            };
            // Provenance label exercises the compiled label table (bit 1 ->
            // LOCAL_SECRET) in the feedback payload.
            value["provenance"] = json!({
                "label": 1u64,
                "timestamp_ns": 42u64,
                "pid": 9,
                "op": 0,
                "target": "git",
            });
            serde_json::from_value::<report::Violation>(value).unwrap()
        };

        // Matching rule + registered domain writes both outputs.
        catalog.append_outputs(&violation(0, Some(domain_id)), &feedback, &events);
        assert!(feedback.is_file());
        assert!(events.is_file());
        assert!(
            std::fs::read_to_string(&feedback)
                .unwrap()
                .contains("LOCAL_SECRET")
        );

        // Unregistered domain is dropped.
        let _ = std::fs::remove_file(&feedback);
        catalog.append_outputs(&violation(0, Some(domain_id + 1)), &feedback, &events);
        assert!(!feedback.exists());

        // Out-of-range rule id has no feedback context, so no feedback is
        // written (only the event file still records the violation).
        catalog.append_outputs(&violation(99, Some(domain_id)), &feedback, &events);
        assert!(!feedback.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn catalog_register_domain_tracks_labels_and_gates_outputs() {
        // `RuntimePolicyCatalog::register_domain` registers a domain's label
        // set only when absent, while `append_outputs` drops violations whose
        // domain was never registered. `register_domain` has no direct caller
        // in the base or branch tests.
        let compiled = dsl::compile_str("rule r:\n  block exec \"x\"\n").expect("compile");
        let catalog = RuntimePolicyCatalog::from_compiled(&compiled, 7);
        let inner = || catalog.inner.read().expect("lock");
        assert_eq!(inner().domain_labels.get(&7).map(HashMap::len), Some(0));
        assert!(!inner().domain_labels.contains_key(&9));

        catalog.register_domain(9).expect("register");
        assert!(inner().domain_labels.contains_key(&9));
        assert_eq!(inner().domain_labels.get(&9).map(HashMap::len), Some(0));

        let dir = tempfile::tempdir().expect("tempdir");
        let feedback = dir.path().join("feedback.txt");
        let events = dir.path().join("events.jsonl");
        let engine_violation = |domain_id: u32| ebpf_ifc_engine::Violation {
            effect: 0,
            blocked: false,
            killed: false,
            comm: "git".to_string(),
            pid: 10,
            ppid: 1,
            target: "git".to_string(),
            rule_id: 0,
            op: 0,
            domain_id,
            session_root: 10,
            label: 1,
            matched_label: 1,
            matched_labels: 1,
            provenance: None,
            timestamp_ns: 0,
        };
        let violation = to_violation(&engine_violation(9));
        catalog.append_outputs(&violation, &feedback, &events);
        assert!(feedback.exists(), "registered domain emits feedback");

        let before = std::fs::read_to_string(&feedback).unwrap();
        let unregistered = to_violation(&engine_violation(1234));
        catalog.append_outputs(&unregistered, &feedback, &events);
        assert_eq!(
            std::fs::read_to_string(&feedback).unwrap(),
            before,
            "unregistered domain is dropped"
        );
    }

    #[test]
    #[cfg(unix)]
    fn chown_path_reports_missing_paths_and_accepts_existing_ones() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("owned.txt");
        std::fs::write(&file, b"x").expect("write");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        chown_path(&file, uid, gid).expect("chown existing file");

        let missing = tmp.path().join("missing.txt");
        let err = chown_path(&missing, uid, gid).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    #[cfg(unix)]
    fn target_user_needs_root_with_sudo_ids() {
        assert_eq!(target_user(true), None);
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(target_user(false), None);
            return;
        }
        // Root without SUDO_UID/SUDO_GID falls back to the real ids.
        let saved = (
            std::env::var("SUDO_UID").ok(),
            std::env::var("SUDO_GID").ok(),
        );
        unsafe {
            std::env::remove_var("SUDO_UID");
            std::env::remove_var("SUDO_GID");
        }
        assert_eq!(target_user(false), None);
        unsafe {
            std::env::set_var("SUDO_UID", "12345");
            std::env::set_var("SUDO_GID", "678");
        }
        assert_eq!(target_user(false), Some((12345, 678)));
        unsafe {
            match saved.0 {
                Some(v) => std::env::set_var("SUDO_UID", v),
                None => std::env::remove_var("SUDO_UID"),
            }
            match saved.1 {
                Some(v) => std::env::set_var("SUDO_GID", v),
                None => std::env::remove_var("SUDO_GID"),
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn mark_non_stdio_fds_cloexec_flags_open_descriptors() {
        use std::os::fd::AsRawFd;

        let file = tempfile::tempfile().expect("tempfile");
        let fd = file.as_raw_fd();
        // Rust opens files with O_CLOEXEC, so clear it to observe the sweep.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );

        mark_non_stdio_fds_cloexec().expect("mark cloexec");
        assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
        for stdio in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            assert_eq!(
                unsafe { libc::fcntl(stdio, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
    }
    #[test]
    fn control_plane_cap_state_grants_the_control_plane_authority_set() {
        // `control_plane_cap_state` builds the capability state the control
        // plane runs with, from a caller's label. It grants a fixed
        // authority set, restricts targets to self + child, and widens the
        // gate/label masks. No base or branch test pins this mapping directly.
        let label = 0b101u64;
        let caps = control_plane_cap_state(label);

        // The caller label is carried through verbatim.
        assert_eq!(caps.labels, label);

        // The control plane always runs in scope 1, from the root.
        assert_eq!(caps.scope_id, 1);
        assert_eq!(caps.parent, 0);

        // The granted authority set: bind/narrow/add-label/require-gate/
        // declassify/delegate, and no other authority.
        let granted = AUTH_BIND_RULE
            | AUTH_NARROW_SCOPE
            | AUTH_ADD_LABEL
            | AUTH_REQUIRE_GATE
            | AUTH_DECLASSIFY
            | AUTH_DELEGATE;
        assert_eq!(caps.authority_mask, granted);
        // Restriction authority is deliberately not granted to the control plane.
        assert_eq!(
            caps.authority_mask & ebpf_ifc_engine::capability::AUTH_ADD_RESTRICTION,
            0
        );

        // Targets are limited to self and children; gate/label masks are wide.
        assert_eq!(caps.target_mask, TARGET_SELF | TARGET_CHILD);
        assert_eq!(caps.gate_mask, u64::MAX);
        assert_eq!(caps.label_mask, u64::MAX);
        // The restrict mask is not touched.
        assert_eq!(caps.restrict_mask, 0);
    }

    #[test]
    fn fresh_runtime_domain_id_is_even_nonzero_and_varies() {
        // `fresh_runtime_domain_id` hashes time/pid/salt into a domain id that
        // avoids the reserved global id and stays non-zero; no base or branch
        // test calls it directly.
        let id = fresh_runtime_domain_id(4242, 7);
        assert!(id != 0 && id != GLOBAL_ACTIVE_DOMAIN_ID);
        assert_eq!(id & 1, 0, "low bit is cleared");
        // The fallback branch (triggered by a zero or reserved id) forces the
        // odd `salt | 1` marker, so it can never collide with the reserved id.
        assert_ne!(fresh_runtime_domain_id(0, 0), GLOBAL_ACTIVE_DOMAIN_ID);
        let a = fresh_runtime_domain_id(100, 1);
        let b = fresh_runtime_domain_id(200, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn target_user_requires_root_euid_and_sudo_env() {
        // `target_user` only consults SUDO_UID/SUDO_GID when running as root;
        // `run_as_root` short-circuits to None immediately. No base or branch
        // test calls it.
        assert_eq!(target_user(true), None);
        let euid = unsafe { libc::geteuid() };
        let saved = (
            std::env::var("SUDO_UID").ok(),
            std::env::var("SUDO_GID").ok(),
        );
        if euid == 0 {
            unsafe { std::env::set_var("SUDO_UID", "1234") };
            unsafe { std::env::set_var("SUDO_GID", "5678") };
            assert_eq!(target_user(false), Some((1234, 5678)));
            unsafe { std::env::set_var("SUDO_UID", "not-a-number") };
            assert_eq!(target_user(false), None);
        } else {
            // Non-root euid short-circuits regardless of the env vars.
            unsafe { std::env::set_var("SUDO_UID", "1234") };
            unsafe { std::env::set_var("SUDO_GID", "5678") };
            assert_eq!(target_user(false), None);
        }
        match saved.0 {
            Some(v) => unsafe { std::env::set_var("SUDO_UID", v) },
            None => unsafe { std::env::remove_var("SUDO_UID") },
        }
        match saved.1 {
            Some(v) => unsafe { std::env::set_var("SUDO_GID", v) },
            None => unsafe { std::env::remove_var("SUDO_GID") },
        }
    }
    #[test]
    fn effect_name_maps_each_effect_to_its_feedback_verb() {
        // `effect_name` maps each `dsl::ast::Effect` to the feedback verb the
        // audit metadata reports for it. No base or branch test pins this
        // mapping directly.
        assert_eq!(effect_name(dsl::ast::Effect::Notify), "notify");
        assert_eq!(effect_name(dsl::ast::Effect::Block), "block");
        assert_eq!(effect_name(dsl::ast::Effect::Kill), "kill");
    }

    #[test]
    fn exit_code_reports_normal_and_signal_termination() {
        // `exit_code` normalizes a process ExitStatus; no base or branch test
        // calls it.
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_code(std::process::ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(std::process::ExitStatus::from_raw(7 << 8)), 7);
        assert_eq!(exit_code(std::process::ExitStatus::from_raw(9)), 137);
    }

    #[test]
    fn scoped_feedback_paths_rebase_under_run_dir() {
        // `scoped_feedback_paths` moves feedback artifacts into a per-run dir;
        // no base or branch test calls it.
        let base = FeedbackPaths {
            feedback: PathBuf::from("/tmp/proj/.actplane/feedback.txt"),
            state: PathBuf::from("/tmp/proj/.actplane/hook-state.json"),
            audit: PathBuf::from("/tmp/proj/.actplane/audit.jsonl"),
            events: PathBuf::from("/tmp/proj/.actplane/events.jsonl"),
        };
        let scoped = scoped_feedback_paths(&base, "mcp");
        let run_dir = PathBuf::from("/tmp/proj/.actplane/runs");
        let child_dir = scoped.feedback.parent().unwrap();
        assert_eq!(child_dir.parent().unwrap(), run_dir);
        assert!(
            child_dir
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("mcp-")
        );
        assert_eq!(scoped.feedback.file_name().unwrap(), "feedback.txt");
        assert_eq!(scoped.state.file_name().unwrap(), "hook-state.json");
        assert_eq!(scoped.audit.file_name().unwrap(), "audit.jsonl");
        assert_eq!(scoped.events.file_name().unwrap(), "events.jsonl");
    }

    #[test]
    fn have_bpf_caps_reflects_euid_and_capeff_bits() {
        // `have_bpf_caps` is root-short-circuited and otherwise requires both
        // CAP_BPF (39) and CAP_SYS_ADMIN (21) to be effective. This recomputes
        // the same predicate from /proc/self/status independently. No base or
        // branch test calls `have_bpf_caps`.
        let euid = unsafe { libc::geteuid() };
        let eff = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("CapEff:"))
                    .and_then(|h| u64::from_str_radix(h.trim(), 16).ok())
            })
            .unwrap_or(0);
        let has = |bit: u32| eff & (1u64 << bit) != 0;
        let expected = euid == 0 || (has(39) && has(21));
        assert_eq!(have_bpf_caps(), expected);
    }

    #[test]
    fn runner_label_prefers_command_then_agent() {
        let command = dsl::compile_str("source COMMAND = exec \"**\"\n").expect("compile");
        assert_eq!(
            runner_label(&command).expect("COMMAND label"),
            command.labels["COMMAND"]
        );

        let both =
            dsl::compile_str("source AGENT = exec \"**/a\"\nsource COMMAND = exec \"**/c\"\n")
                .expect("compile");
        assert_eq!(
            runner_label(&both).expect("COMMAND wins"),
            both.labels["COMMAND"]
        );

        let agent = dsl::compile_str("source AGENT = exec \"**/claude\"\n").expect("compile");
        assert_eq!(
            runner_label(&agent).expect("AGENT fallback"),
            agent.labels["AGENT"]
        );

        let bare = dsl::compile_str("rule r:\n  notify exec \"git\" if true\n  because \"x\"\n")
            .expect("compile");
        let err = runner_label(&bare).err().expect("no runner label");
        assert!(
            err.to_string().contains("label COMMAND"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn load_child_policy_deltas_reads_files_and_labels_inline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("d.dsl");
        std::fs::write(
            &file,
            "rule d:\n  notify exec \"x\" if true\n  because \"y\"\n",
        )
        .expect("write");
        let deltas =
            load_child_policy_deltas(std::slice::from_ref(&file), &["inline-dsl".to_string()])
                .expect("deltas");
        assert_eq!(deltas.len(), 2);
        assert_eq!(deltas[0].0, file.display().to_string());
        assert!(deltas[0].1.contains("rule d:"));
        assert_eq!(deltas[1].0, "--delta-text[0]");
        assert_eq!(deltas[1].1, "inline-dsl");

        let missing = dir.path().join("missing.dsl");
        let err = load_child_policy_deltas(std::slice::from_ref(&missing), &[])
            .err()
            .expect("missing delta");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot read child policy delta"),
            "unexpected: {msg}"
        );
        assert!(
            msg.contains(&missing.display().to_string()),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn json_i32_accepts_only_in_range_integers() {
        assert_eq!(json_i32(&json!(42)), Some(42));
        assert_eq!(json_i32(&json!(-1)), Some(-1));
        assert_eq!(json_i32(&json!(2147483648i64)), None);
        assert_eq!(json_i32(&json!("42")), None);
        assert_eq!(json_i32(&json!(null)), None);
    }

    #[test]
    fn scoped_feedback_paths_scope_under_a_run_directory() {
        let base = FeedbackPaths {
            feedback: PathBuf::from("/repo/run/feedback.txt"),
            state: PathBuf::from("/repo/run/hook-state.json"),
            audit: PathBuf::from("/repo/run/audit.jsonl"),
            events: PathBuf::from("/repo/run/events.jsonl"),
        };
        let scoped = scoped_feedback_paths(&base, "mcp");
        assert!(
            scoped
                .feedback
                .display()
                .to_string()
                .starts_with("/repo/run/runs/mcp-")
        );
        assert_eq!(scoped.feedback.file_name().unwrap(), "feedback.txt");
        assert_eq!(scoped.audit.file_name().unwrap(), "audit.jsonl");
        assert_eq!(scoped.state.file_name().unwrap(), "hook-state.json");
        assert_eq!(scoped.events.file_name().unwrap(), "events.jsonl");
        assert_ne!(scoped.feedback, base.feedback);
    }
    #[test]
    fn json_i32_reads_in_range_integers_and_rejects_the_rest() {
        // `json_i32` narrows a JSON integer to `i32`: an in-range i64 value
        // yields `Some(n)`, an out-of-range i64 yields `None`, and any
        // non-integer JSON value yields `None`. No base or branch test pins
        // this helper directly.
        use serde_json::Value;

        assert_eq!(json_i32(&Value::from(42i64)), Some(42));
        assert_eq!(json_i32(&Value::from(0i64)), Some(0));
        assert_eq!(json_i32(&Value::from(-7i64)), Some(-7));
        // Boundaries: `i32::MAX` and `i32::MIN` fit.
        assert_eq!(json_i32(&Value::from(i32::MAX as i64)), Some(i32::MAX));
        assert_eq!(json_i32(&Value::from(i32::MIN as i64)), Some(i32::MIN));
        // Just outside the i32 range: no fit.
        assert_eq!(json_i32(&Value::from(i32::MAX as i64 + 1)), None);
        assert_eq!(json_i32(&Value::from(i32::MIN as i64 - 1)), None);
        // Non-integer JSON values are not i32.
        assert_eq!(json_i32(&serde_json::json!("7")), None);
        assert_eq!(json_i32(&serde_json::json!(1.5)), None);
        assert_eq!(json_i32(&Value::Null), None);
        assert_eq!(json_i32(&serde_json::json!(true)), None);
    }

    #[test]
    fn kill_process_group_and_wait_reaps_group() {
        // Some sandboxes deny signals to non-root processes (EPERM on `kill`);
        // probe empirically on a short-lived group-led child.
        let can_signal = {
            let mut probe = std::process::Command::new("/bin/sh");
            probe
                .arg("-c")
                .arg("sleep 5")
                .process_group(0)
                .stdout(std::process::Stdio::null());
            let mut child = probe.spawn().expect("probe spawn");
            let pid = child.id() as i32;
            let rc = unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = child.wait().expect("probe wait");
            rc == 0
        };

        // `kill_process_group_and_wait` SIGKILLs the child's whole process
        // group and then reaps the child. No base or branch test calls it.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let mut cmd = tokio::process::Command::new("/bin/sh");
            cmd.arg("-c").arg("sleep 30");
            cmd.process_group(0);
            let mut child = cmd.spawn().expect("spawn");
            let pid = child.id().expect("spawned child has a pid");
            // `process_group(0)` makes the child its own group leader, so
            // `send_process_group_signal(pid)` reaches the whole tree.
            assert_eq!(
                unsafe { libc::getpgid(pid as i32) },
                pid as i32,
                "child must lead its own process group"
            );
            let start = std::time::Instant::now();
            kill_process_group_and_wait(&mut child).await;
            assert!(child.id().is_none(), "child reaped after group SIGKILL");
            if can_signal {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(20),
                    "group SIGKILL terminated the child promptly"
                );
            }
        });
    }
    #[test]
    fn kind_name_maps_each_kind_to_its_feedback_verb() {
        // `kind_name` maps each `dsl::ast::Kind` to the feedback target-kind
        // word the audit metadata reports for it. No base or branch test pins
        // this mapping directly.
        assert_eq!(kind_name(dsl::ast::Kind::File), "file");
        assert_eq!(kind_name(dsl::ast::Kind::Endpoint), "endpoint");
        assert_eq!(kind_name(dsl::ast::Kind::Exec), "exec");
    }

    #[test]
    fn legacy_shutdown_signals_listens_for_term_and_interrupt() {
        // `legacy_shutdown_signals` installs SIGINT and SIGTERM listeners for
        // the legacy command loop. No base or branch test calls it.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let mut signals = legacy_shutdown_signals().expect("install signal listeners");
            let ready =
                tokio::time::timeout(std::time::Duration::from_millis(200), signals[1].recv())
                    .await;
            assert!(ready.is_err(), "no pending SIGTERM before one is delivered");

            let target = std::process::id() as i32;
            if unsafe { libc::kill(target, libc::SIGTERM) } == 0 {
                let seen =
                    tokio::time::timeout(std::time::Duration::from_secs(2), signals[1].recv())
                        .await;
                assert!(
                    seen.is_ok(),
                    "SIGTERM listener observed the delivered signal"
                );
                assert!(seen.unwrap().is_some(), "SIGTERM stream yielded an event");
            }
        });
    }

    #[test]
    fn load_child_policy_deltas_collects_files_then_inline() {
        // `load_child_policy_deltas` collects child policy deltas from files
        // followed by inline sources; no base or branch test calls it.
        let dir = std::env::temp_dir().join(format!("actplane-deltas-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.dsl");
        let b = dir.join("b.dsl");
        std::fs::write(&a, "rule a:\n  block exec \"git\"\n").unwrap();
        std::fs::write(&b, "rule b:\n  kill write file \"/**\"\n").unwrap();

        let deltas = load_child_policy_deltas(
            &[a.clone(), b.clone()],
            &["rule c:\n  notify connect endpoint \"*\"\n".to_string()],
        )
        .expect("deltas");
        assert_eq!(deltas.len(), 3);
        assert_eq!(deltas[0].0, a.display().to_string());
        assert!(deltas[0].1.contains("rule a"));
        assert_eq!(deltas[1].0, b.display().to_string());
        assert!(deltas[1].1.contains("rule b"));
        assert_eq!(deltas[2].0, "--delta-text[0]");
        assert!(deltas[2].1.contains("rule c"));

        // A missing file surfaces a read error naming the path.
        let missing = dir.join("missing.dsl");
        let err = load_child_policy_deltas(&[missing], &[])
            .expect_err("missing file")
            .to_string();
        assert!(err.contains("cannot read child policy delta"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn passwordless_sudo_available_matches_direct_sudo_probe() {
        let expected = std::process::Command::new("sudo")
            .args(["-n", "true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert_eq!(passwordless_sudo_available(), expected);
    }

    #[test]
    fn prepare_feedback_files_creates_empty_owned_files() {
        // `prepare_feedback_files` creates each output's parent chain and
        // truncates the feedback/audit/events files; no base or branch test
        // calls it.
        let dir = std::env::temp_dir().join(format!("actplane-prepare-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = FeedbackPaths {
            feedback: dir.join("run/feedback.txt"),
            state: dir.join("run/state.json"),
            audit: dir.join("logs/audit.jsonl"),
            events: dir.join("logs/events.jsonl"),
        };

        prepare_feedback_files(&paths, None).expect("prepare");
        assert!(paths.feedback.is_file());
        assert!(paths.audit.is_file());
        assert!(paths.events.is_file());
        assert_eq!(std::fs::read_to_string(&paths.feedback).unwrap(), "");

        // Existing content is truncated on a second prepare.
        std::fs::write(&paths.feedback, "stale").unwrap();
        prepare_feedback_files(&paths, None).expect("re-prepare");
        assert_eq!(std::fs::read_to_string(&paths.feedback).unwrap(), "");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // `run_command` rejects a parent-domain request before `require_bpf_caps_or_elevate`,
    // which calls `process::exit(1)` and so is uncatchable. This is the engine-free
    // branch of the launch path and no base or branch test drives it.
    #[test]
    fn run_command_rejects_parent_domain_before_engine() {
        let cli = PolicyInput {
            internal_elevated: true,
            ..PolicyInput::default()
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = rt
            .block_on(run_command(&cli, &[], true))
            .expect_err("parent domain must be rejected");
        assert!(err.to_string().contains("--parent-domain"));
    }

    #[test]
    fn run_id_and_attach_pid_resolution() {
        // `run_id` mints a per-invocation id; `parent_pid` and
        // `attach_pid_from_env_or_parent` resolve the attach target. None had
        // any call in the base or branch suite.
        let me = std::process::id() as i32;
        let run = run_id("watch");
        let suffix = run
            .strip_prefix(&format!("watch-{me}-"))
            .expect("run id shaped <prefix>-<pid>-<nanos>");
        assert!(suffix.parse::<u128>().is_ok());

        assert_eq!(parent_pid(), unsafe { libc::getppid() as i32 });

        unsafe { std::env::set_var(ATTACH_PID_ENV, "4321") };
        assert_eq!(attach_pid_from_env_or_parent(), 4321);
        unsafe { std::env::remove_var(ATTACH_PID_ENV) };
        assert_eq!(attach_pid_from_env_or_parent(), parent_pid());
    }
    #[test]
    fn runner_label_prefers_command_label_over_agent() {
        use std::collections::HashMap;

        // `runner_label` resolves the label the runner attaches: the
        // `COMMAND` label when present, else the `AGENT` fallback, else an
        // error. No base or branch test pins this resolution directly.
        fn with_labels(labels: HashMap<String, u64>) -> dsl::Compiled {
            dsl::Compiled {
                bytes: vec![],
                reasons: vec![],
                meta: vec![],
                labels,
                endpoint_resolutions: HashMap::new(),
            }
        }

        // `COMMAND` wins when both labels are present.
        let mut both = HashMap::new();
        both.insert("COMMAND".to_string(), 0b01u64);
        both.insert("AGENT".to_string(), 0b10u64);
        assert_eq!(runner_label(&with_labels(both)).unwrap(), 0b01u64);

        // With no `COMMAND`, the `AGENT` label is the fallback.
        let mut agent_only = HashMap::new();
        agent_only.insert("AGENT".to_string(), 0b10u64);
        assert_eq!(runner_label(&with_labels(agent_only)).unwrap(), 0b10u64);

        // Neither label: the runner label is unavailable.
        let err = runner_label(&with_labels(HashMap::new())).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("COMMAND"));
        assert!(msg.contains("AGENT"));
    }

    #[test]
    #[cfg(unix)]
    fn send_signal_reports_unknown_and_self_pids() {
        // A pid well past the kernel's pid ceiling is never live.
        let err = send_signal(99_999_999, libc::SIGCONT).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
        let err = send_process_group_signal(99_999_999, libc::SIGCONT).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));

        // A root test process can actually stop itself with SIGSTOP, so only
        // assert the error path when the sandbox forbids signalling our own pid
        // (non-root). skip the whole SIGSTOP probe under an absent /proc.
        if std::path::Path::new("/proc").exists() && unsafe { libc::geteuid() } != 0 {
            let self_pid = std::process::id();
            let err = send_signal(self_pid, libc::SIGSTOP).unwrap_err();
            assert!(
                matches!(
                    err.raw_os_error(),
                    Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::ESRCH)
                ),
                "unexpected error from self-signal: {err}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn proc_state_code_reads_own_process_state() {
        let state = proc_state_code(std::process::id()).expect("own state");
        assert!(
            matches!(state, 'R' | 'S' | 'D' | 'T' | 't'),
            "unexpected state {state:?}"
        );
        let err = proc_state_code(99_999_999).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    #[cfg(unix)]
    fn wait_for_stopped_process_times_out_on_own_pid() {
        let err =
            wait_for_stopped_process(std::process::id(), Duration::from_millis(1)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("last observed process state was"));
    }

    #[test]
    fn spawn_stopped_target_rejects_empty_command() {
        // `spawn_stopped_target` is the launch primitive every child domain
        // goes through; an empty command must fail before any process is
        // spawned. No base or branch test calls it.
        let dir = tempfile::tempdir().expect("tempdir");
        let feedback = FeedbackPaths {
            feedback: dir.path().join("feedback.json"),
            state: dir.path().join("state.json"),
            audit: dir.path().join("audit.ndjson"),
            events: dir.path().join("events.ndjson"),
        };
        let err = spawn_stopped_target(&[], &feedback, None, false, false).unwrap_err();
        assert!(err.to_string().contains("run requires a command"));
    }

    #[test]
    fn spawn_stopped_target_stops_child_before_returning() {
        // The helper must not return until the child has entered a stopped
        // state, so the caller can bind the domain before it runs.
        let dir = tempfile::tempdir().expect("tempdir");
        let feedback = FeedbackPaths {
            feedback: dir.path().join("feedback.json"),
            state: dir.path().join("state.json"),
            audit: dir.path().join("audit.ndjson"),
            events: dir.path().join("events.ndjson"),
        };
        let cmd = vec!["true".to_string()];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            match spawn_stopped_target(&cmd, &feedback, None, false, false) {
                Ok(mut child) => {
                    let pid = child.id().expect("child has a pid");
                    assert!(
                        matches!(proc_state_code(pid), Ok('T') | Ok('t')),
                        "child must be stopped on return"
                    );
                    // The CONT that resumes the child is denied to non-root in
                    // some sandboxes (EPERM); tolerate it and SIGKILL as `true`
                    // exits immediately anyway.
                    let _ = send_signal(pid, libc::SIGCONT);
                    let _ = send_signal(pid, libc::SIGKILL);
                    let _ = child.wait();
                }
                Err(e) => {
                    // With signals denied, the child can never be resumed; the
                    // helper must have observed the stop within its timeout
                    // rather than hang.
                    assert!(
                        e.to_string().contains("did not enter stopped state"),
                        "unexpected spawn error: {e}"
                    );
                }
            }
        });
    }
    #[test]
    fn string_missing_treats_none_empty_and_whitespace_as_missing() {
        // `string_missing` reports whether an optional string field is
        // effectively absent: `None`, an empty string, or a
        // whitespace-only string all read as missing; a non-empty value does
        // not. No base or branch test pins this helper directly.
        assert!(string_missing(None));
        assert!(string_missing(Some("")));
        assert!(string_missing(Some("   ")));
        assert!(string_missing(Some("\t\n")));
        assert!(!string_missing(Some("x")));
        assert!(!string_missing(Some("repo-supervisor")));
        // Leading/trailing whitespace does not make a value present.
        assert!(!string_missing(Some(" repo-supervisor ")));
    }

    #[test]
    fn watch_project_dir_prefers_policy_parent_else_root() {
        // `watch_project_dir` picks the policy file's directory, or the loaded
        // root when no explicit path is set; no base or branch test calls it.
        let with_path = crate::config::LoadedPolicy {
            config: Default::default(),
            root: PathBuf::from("/repo"),
            path: Some(PathBuf::from("/repo/.actplane/actplane.yaml")),
        };
        assert_eq!(
            watch_project_dir(&with_path),
            PathBuf::from("/repo/.actplane")
        );

        let without_path = crate::config::LoadedPolicy {
            config: Default::default(),
            root: PathBuf::from("/repo"),
            path: None,
        };
        assert_eq!(watch_project_dir(&without_path), PathBuf::from("/repo"));
    }

    #[test]
    fn watch_policy_rejects_parent_domain_before_loading_any_policy() {
        let cli = PolicyInput::default();
        let err = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(watch_policy_for_pid(&cli, true, std::process::id() as i32))
            .expect_err("parent-domain watch is rejected");
        assert!(err.to_string().contains("--parent-domain is not supported"));
    }

    #[test]
    fn watch_policy_rejects_an_invalid_attach_pid_without_sudo() {
        let cli = PolicyInput::default();
        // pid 0 and the init pid cannot host a watch attach.
        for attach_pid in [0, 1] {
            let err = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(watch_policy_for_pid(&cli, false, attach_pid))
                .expect_err("invalid attach pid is rejected");
            assert!(
                err.to_string().contains(&format!(
                    "invalid parent pid for watch attach: {attach_pid}"
                )),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn watch_policy_rejects_parent_domain_and_bad_attach_pid() {
        // `watch_policy` forwards to `watch_policy_for_pid`, whose argument
        // gates reject unsupported `--parent-domain` and an attach pid <= 1
        // before any engine or capability work. No base or branch test calls
        // either entry point.
        let cli = PolicyInput {
            rule: Some("sink exec \"x\"".to_string()),
            ..Default::default()
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let err = rt
            .block_on(watch_policy(&cli, true))
            .expect_err("parent-domain unsupported");
        assert!(
            err.to_string().contains("--parent-domain is not supported"),
            "{err}"
        );

        let err = rt
            .block_on(watch_policy_for_pid(&cli, false, 1))
            .expect_err("attach pid must exceed 1");
        assert!(err.to_string().contains("invalid parent pid"), "{err}");

        let err = rt
            .block_on(watch_policy_for_pid(&cli, false, 0))
            .expect_err("attach pid must exceed 1");
        assert!(err.to_string().contains("invalid parent pid"), "{err}");
    }
}
