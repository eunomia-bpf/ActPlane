// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! `actplane compile --backend unprivileged` reports.

use crate::host::HostSupport;
use crate::plan::{
    Analysis, ClauseStatus, LANDLOCK_ABI_SCOPE, LANDLOCK_ABI_TCP, LANDLOCK_ABI_WRITE,
};
use crate::seccomp::{self, FilterOptions};
use serde_json::{Value, json};
use std::fmt::Write as _;

/// Hardening the backend applies to every launched process, given the host.
pub fn hardening_lines(analysis: &Analysis, host: &HostSupport) -> Vec<String> {
    let deny_network = analysis.spec().is_some_and(|s| s.deny_network);
    let opts = FilterOptions {
        deny_network,
        landlock_tcp: deny_network && host.landlock_abi >= LANDLOCK_ABI_TCP,
    };
    let mut out = vec![
        "no_new_privs is set before exec, so setuid/file-capability programs cannot regain privileges and the filters cannot be removed".to_string(),
    ];
    for line in seccomp::describe(opts) {
        out.push(format!("seccomp: {line}"));
    }
    if host.landlock_abi >= LANDLOCK_ABI_SCOPE {
        out.push("Landlock scoping: signals and abstract Unix sockets cannot reach processes outside the sandbox (ABI >= 6)".into());
    } else {
        out.push(format!(
            "Landlock scoping: not applied on this host (needs ABI {LANDLOCK_ABI_SCOPE}, Linux 6.12)"
        ));
    }
    out.push(
        "Landlock layers also stop sandboxed processes from ptracing processes outside the sandbox"
            .into(),
    );
    out.push(
        "an execute allow-list is accepted only when no allowed exec location is writable".into(),
    );
    out
}

fn host_lines(host: &HostSupport) -> Vec<String> {
    vec![
        format!("Landlock: {}", host.landlock_summary()),
        format!("seccomp: {}", host.seccomp_summary()),
        format!("no_new_privs: {}", host.no_new_privs_summary()),
    ]
}

fn requirement_line(analysis: &Analysis, host: &HostSupport) -> Option<String> {
    let spec = analysis.spec()?;
    let need = spec.landlock_min_abi();
    if need == 0 {
        return Some("needs no Landlock ABI (seccomp alone enforces the clauses)".into());
    }
    let ok = host.landlock_abi >= need;
    Some(format!(
        "needs Landlock ABI {need} or newer ({}); this host {}",
        if need >= LANDLOCK_ABI_WRITE {
            "Linux 6.2, for truncate control"
        } else {
            "Linux 5.13"
        },
        if ok {
            format!("has ABI {}", host.landlock_abi)
        } else if host.landlock_abi > 0 {
            format!(
                "has only ABI {}, so `run --backend unprivileged` will refuse",
                host.landlock_abi
            )
        } else {
            "has no Landlock, so `run --backend unprivileged` will refuse".to_string()
        }
    ))
}

/// Short per-clause listing for plain `actplane compile --backend unprivileged`.
pub fn render_summary(policy_ref: &str, analysis: &Analysis, host: &HostSupport) -> String {
    let mut out = String::new();
    let total = analysis.clauses.len();
    if analysis.is_supported() {
        let _ = writeln!(
            out,
            "✓ {policy_ref}: all {total} clause(s) map exactly to the unprivileged backend."
        );
    } else {
        let _ = writeln!(
            out,
            "✗ {policy_ref}: {} of {total} clause(s) are unsupported by the unprivileged backend; it refuses this policy.",
            total - analysis.exact_count()
        );
    }
    for c in &analysis.clauses {
        let _ = writeln!(
            out,
            "  - [{}] rule {} clause {}: {}",
            c.status.name(),
            c.rule,
            c.clause,
            c.text
        );
        let _ = writeln!(out, "      {}", c.detail);
    }
    if let Some(line) = requirement_line(analysis, host) {
        let _ = writeln!(out, "\nrequirements: {line}");
    }
    let _ = writeln!(
        out,
        "\n(review details with `actplane compile --backend unprivileged --explain`.)"
    );
    out
}

/// Human-readable review for `compile --backend unprivileged --explain`.
pub fn render_explain(
    policy_ref: &str,
    domain_lines: &[String],
    analysis: &Analysis,
    host: &HostSupport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "ActPlane policy review (backend: unprivileged)");
    let _ = writeln!(out, "policy: {policy_ref}");
    for line in domain_lines {
        let _ = writeln!(out, "{line}");
    }
    let _ = writeln!(
        out,
        "mode: static tier (Landlock + seccomp applied by the launcher before exec); see docs/design/unprivileged-backend.md"
    );
    match &analysis.runner_label {
        Some(label) => {
            let _ = writeln!(
                out,
                "runner label: {label} (`run` seeds it on the launched process, so `if {label}` covers the launched tree)"
            );
        }
        None => {
            let _ = writeln!(out, "runner label: none");
        }
    }

    let _ = writeln!(out, "\nhost:");
    for line in host_lines(host) {
        let _ = writeln!(out, "  - {line}");
    }

    let _ = writeln!(out, "\ndeclarations:");
    if analysis.declarations.is_empty() {
        let _ = writeln!(out, "  - none");
    }
    for d in &analysis.declarations {
        let _ = writeln!(out, "  - {}", d.text);
        let _ = writeln!(out, "    {}", d.detail);
    }

    let _ = writeln!(out, "\nclauses:");
    if analysis.clauses.is_empty() {
        let _ = writeln!(out, "  - none");
    }
    for c in &analysis.clauses {
        let _ = writeln!(out, "  - rule {} clause {}: {}", c.rule, c.clause, c.text);
        let _ = writeln!(out, "    status: {}", c.status.name());
        match c.status {
            ClauseStatus::Exact => {
                let _ = writeln!(out, "    enforcement: {}", c.detail);
            }
            ClauseStatus::Unsupported => {
                let _ = writeln!(out, "    reason: {}", c.detail);
            }
        }
        for n in &c.notes {
            let _ = writeln!(out, "    note: {n}");
        }
    }

    let _ = writeln!(out, "\nalways-applied hardening:");
    for line in hardening_lines(analysis, host) {
        let _ = writeln!(out, "  - {line}");
    }

    let _ = writeln!(out, "\nlimits of this backend:");
    for line in [
        "only processes launched by `actplane run --backend unprivileged` are covered; an already-running pid cannot be adopted",
        "denials return EACCES (Landlock) or EPERM (seccomp) without a per-event corrective-feedback record",
        "runtime policy deltas and child domains are not available in the static tier",
    ] {
        let _ = writeln!(out, "  - {line}");
    }

    let _ = writeln!(out, "\nresult:");
    if let Some(line) = requirement_line(analysis, host) {
        let _ = writeln!(out, "  - {line}");
    }
    if analysis.is_supported() {
        let _ = writeln!(
            out,
            "  - all {} clause(s) are exact; `actplane run --backend unprivileged -- <cmd>` enforces this policy without privileges",
            analysis.clauses.len()
        );
    } else {
        let _ = writeln!(
            out,
            "  - {} exact, {} unsupported; the unprivileged backend refuses this policy (no clause is weakened or dropped)",
            analysis.exact_count(),
            analysis.clauses.len() - analysis.exact_count()
        );
    }
    out
}

/// Machine-readable report for `compile --backend unprivileged --json`.
pub fn render_json(
    policy_ref: &str,
    domain: Value,
    analysis: &Analysis,
    host: &HostSupport,
) -> Value {
    let clauses: Vec<Value> = analysis
        .clauses
        .iter()
        .map(|c| {
            json!({
                "rule": c.rule,
                "clause": c.clause,
                "text": c.text,
                "status": c.status.name(),
                "detail": c.detail,
                "notes": c.notes,
            })
        })
        .collect();
    let declarations: Vec<Value> = analysis
        .declarations
        .iter()
        .map(|d| json!({ "text": d.text, "detail": d.detail }))
        .collect();
    let spec = analysis.spec();
    json!({
        "schema": "actplane.compile.unprivileged.v1",
        "backend": "unprivileged",
        "ok": analysis.is_supported(),
        "policy_ref": policy_ref,
        "domain": domain,
        "host": {
            "landlock_abi": host.landlock_abi,
            "landlock_error": host.landlock_error,
            "seccomp_filter": host.seccomp_filter,
            "seccomp_actions": host.seccomp_actions.as_deref().map(str::trim),
            "seccomp_arch_supported": host.seccomp_arch_supported,
            "no_new_privs": host.no_new_privs,
        },
        "runner_label": analysis.runner_label,
        "clause_count": analysis.clauses.len(),
        "exact_count": analysis.exact_count(),
        "clauses": clauses,
        "declarations": declarations,
        "requirements": {
            "landlock_min_abi": spec.map(|s| s.landlock_min_abi()),
            "landlock_tcp_abi": LANDLOCK_ABI_TCP,
            "landlock_scope_abi": LANDLOCK_ABI_SCOPE,
        },
        "hardening": hardening_lines(analysis, host),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::analyze;
    use actplane_ifc_compiler::parse;

    fn host(abi: i32) -> HostSupport {
        HostSupport {
            landlock_abi: abi,
            landlock_error: (abi == 0).then(|| "not enabled".to_string()),
            seccomp_filter: true,
            seccomp_actions: Some("kill_process errno user_notif allow\n".into()),
            no_new_privs: Some(false),
            seccomp_arch_supported: true,
        }
    }

    const CONFINE: &str = "source COMMAND = exec \"**\"\nrule confine:\n  block write file \"/**\" if COMMAND unless target \"/work/**\"\n  block connect endpoint \"*\"\n  because \"stay in /work\"\n";
    const LABELED: &str = "source SECRET = file \"**/.env\"\nrule no-exfil:\n  block connect endpoint \"*\" if SECRET\n  because \"x\"\n";

    #[test]
    fn explain_reports_exact_clauses_and_requirements() {
        let a = analyze(&parse::parse(CONFINE).unwrap());
        let text = render_explain(
            "--rule",
            &["domain: none (flat policy)".into()],
            &a,
            &host(8),
        );
        assert!(text.contains("backend: unprivileged"), "{text}");
        assert!(text.contains("status: exact"), "{text}");
        assert!(text.contains("beneath /work"), "{text}");
        assert!(text.contains("needs Landlock ABI 3 or newer"), "{text}");
        assert!(text.contains("io_uring_setup"), "{text}");
        assert!(text.contains("TCP fast-open"), "{text}");
        assert!(text.contains("signals and abstract Unix sockets"), "{text}");
        assert!(text.contains("all 2 clause(s) are exact"), "{text}");
    }

    #[test]
    fn explain_reports_unsupported_clauses_and_old_kernels() {
        let a = analyze(&parse::parse(LABELED).unwrap());
        let text = render_explain("--rule", &[], &a, &host(2));
        assert!(text.contains("status: unsupported"), "{text}");
        assert!(text.contains("reason: `if SECRET`"), "{text}");
        assert!(text.contains("refuses this policy"), "{text}");
        assert!(text.contains("scoping: not applied"), "{text}");

        let a = analyze(&parse::parse(CONFINE).unwrap());
        let text = render_explain("--rule", &[], &a, &host(2));
        assert!(text.contains("has only ABI 2"), "{text}");
        let text = render_summary("--rule", &a, &host(0));
        assert!(text.contains("has no Landlock"), "{text}");
    }

    #[test]
    fn json_report_has_per_clause_status() {
        let a = analyze(&parse::parse(LABELED).unwrap());
        let v = render_json("--rule", Value::Null, &a, &host(6));
        assert_eq!(v["schema"], "actplane.compile.unprivileged.v1");
        assert_eq!(v["ok"], false);
        assert_eq!(v["clauses"][0]["status"], "unsupported");
        assert_eq!(v["host"]["landlock_abi"], 6);
        assert_eq!(v["requirements"]["landlock_min_abi"], Value::Null);

        let a = analyze(&parse::parse(CONFINE).unwrap());
        let v = render_json("p.yaml", Value::Null, &a, &host(6));
        assert_eq!(v["ok"], true);
        assert_eq!(v["exact_count"], 2);
        assert_eq!(v["requirements"]["landlock_min_abi"], 3);
        assert_eq!(v["runner_label"], "COMMAND");
    }

    #[test]
    fn summary_lists_each_clause() {
        let a = analyze(&parse::parse(LABELED).unwrap());
        let text = render_summary("--rule", &a, &host(6));
        assert!(
            text.starts_with("✗ --rule: 1 of 1 clause(s) are unsupported"),
            "{text}"
        );
        assert!(
            text.contains("[unsupported] rule no-exfil clause 1"),
            "{text}"
        );
    }
}
