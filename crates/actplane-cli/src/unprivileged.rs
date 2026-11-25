// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! `--backend unprivileged`: the static Landlock + seccomp tier from the
//! `actplane-sandbox` crate. Policies are parsed and validated exactly as for
//! the bpf-lsm backend; a policy with any clause the tier cannot enforce
//! exactly is refused with a per-clause explanation.

use std::path::Path;

use actplane_runtime::PolicyInput;
use actplane_sandbox::plan::LANDLOCK_ABI_WRITE;
use actplane_sandbox::{self as sandbox, Analysis, report};
use serde_json::{Value, json};

use crate::config::{load_policy, resolve_policy};
use crate::doctor::{domain_json, emit_check_report};
use crate::{Result, dsl};

/// Enforcement backend for `run` and `compile`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Backend {
    /// eBPF engine with BPF-LSM hooks (root or CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN, lsm=bpf).
    #[default]
    BpfLsm,
    /// Landlock + seccomp applied by the launcher; no privileges, static clauses only.
    Unprivileged,
}

struct Loaded {
    policy_ref: String,
    domain_lines: Vec<String>,
    domain: Value,
    analysis: Analysis,
}

fn load(cli: &PolicyInput) -> Result<Loaded> {
    let loaded = load_policy(cli)?;
    let resolved = resolve_policy(&loaded, cli.domain.as_deref())?;
    let policy_ref = loaded
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "--rule".into());
    let parsed =
        dsl::parse::parse(&resolved.source).map_err(|e| format!("policy does not compile: {e}"))?;
    // Same validation as the bpf-lsm backend, so both backends accept the
    // same policies before deciding what they can enforce.
    dsl::compile_str(&resolved.source).map_err(|e| format!("policy does not compile: {e}"))?;
    let mut domain_lines = Vec::new();
    match &resolved.domain {
        Some(domain) => {
            domain_lines.push(format!("domain: {}", domain.name));
            if let Some(parent) = &domain.parent {
                domain_lines.push(format!("parent: {parent}"));
            }
            let mut rules = domain.locked.clone();
            rules.extend(domain.defaults.clone());
            domain_lines.push(format!(
                "policy rules: {}",
                if rules.is_empty() {
                    "none".to_string()
                } else {
                    rules.join(", ")
                }
            ));
        }
        None => domain_lines.push("domain: none (flat policy)".into()),
    }
    Ok(Loaded {
        policy_ref,
        domain_lines,
        domain: domain_json(&resolved),
        analysis: sandbox::analyze(&parsed),
    })
}

/// `actplane compile --backend unprivileged [--json|--explain]`. Exits 1
/// when any clause is unsupported.
pub(crate) fn compile(
    cli: &PolicyInput,
    json_output: bool,
    explain_output: bool,
    out: Option<&Path>,
    report_out: Option<&Path>,
    force: bool,
) -> Result<i32> {
    if out.is_some() {
        return Err("--out writes the bpf-lsm kernel config blob; the unprivileged backend has no blob (use --json or --explain to review its sandbox plan)".into());
    }
    let host = sandbox::probe();
    let loaded = match load(cli) {
        Ok(loaded) => loaded,
        Err(e) if json_output => {
            let record = json!({
                "schema": "actplane.compile.unprivileged.v1",
                "backend": "unprivileged",
                "ok": false,
                "error": e.to_string(),
            });
            let text = serde_json::to_string_pretty(&record)? + "\n";
            emit_check_report(&text, report_out, force, "compile report")?;
            return Ok(1);
        }
        Err(e) => return Err(e),
    };
    let Loaded {
        policy_ref,
        domain_lines,
        domain,
        analysis,
    } = loaded;
    if json_output {
        let record = report::render_json(&policy_ref, domain, &analysis, &host);
        let text = serde_json::to_string_pretty(&record)? + "\n";
        emit_check_report(&text, report_out, force, "compile report")?;
    } else if explain_output {
        let text = report::render_explain(&policy_ref, &domain_lines, &analysis, &host);
        emit_check_report(&text, report_out, force, "policy review")?;
    } else {
        print!("{}", report::render_summary(&policy_ref, &analysis, &host));
    }
    Ok(if analysis.is_supported() { 0 } else { 1 })
}

/// `actplane run --backend unprivileged -- <cmd>`.
pub(crate) fn run(cli: &PolicyInput, cmd: &[String]) -> Result<i32> {
    if cmd.is_empty() {
        return Err("run requires a command after `--`".into());
    }
    let loaded = load(cli)?;
    let Some(spec) = loaded.analysis.spec() else {
        // Printed directly: main's error path would escape the newlines.
        eprintln!("actplane: {}", loaded.analysis.rejection_message());
        return Ok(1);
    };
    let sandbox =
        sandbox::prepare(spec).map_err(|e| format!("unprivileged backend cannot start: {e}"))?;
    eprintln!(
        "ActPlane: unprivileged backend: {} exact clause(s) from {}",
        loaded.analysis.exact_count(),
        loaded.policy_ref
    );
    for line in sandbox.summary() {
        eprintln!("ActPlane:   {line}");
    }
    let status = sandbox
        .run(cmd, target_user(cli.run_as_root))
        .map_err(|e| format!("cannot launch `{}` under the sandbox: {e}", cmd[0]))?;
    Ok(exit_code(status))
}

/// Lines for `actplane doctor`.
pub(crate) fn doctor_lines() -> Vec<String> {
    let host = sandbox::probe();
    let mark = |ok: bool| if ok { "✓" } else { "⚠" };
    vec![
        format!(
            "{} Landlock: {}",
            mark(host.landlock_abi >= LANDLOCK_ABI_WRITE),
            host.landlock_summary()
        ),
        format!(
            "{} seccomp: {}",
            mark(host.seccomp_filter && host.seccomp_arch_supported),
            host.seccomp_summary()
        ),
        format!("✓ no_new_privs: {}", host.no_new_privs_summary()),
    ]
}

/// sudo-launched ActPlane drops the target back to SUDO_UID/SUDO_GID, as the
/// bpf-lsm `run` does, unless `--run-as-root` is given.
fn target_user(run_as_root: bool) -> Option<(u32, u32)> {
    #[cfg(unix)]
    let is_root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let is_root = false;
    if run_as_root || !is_root {
        return None;
    }
    let uid = std::env::var("SUDO_UID").ok()?.parse::<u32>().ok()?;
    let gid = std::env::var("SUDO_GID").ok()?.parse::<u32>().ok()?;
    Some((uid, gid))
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}
