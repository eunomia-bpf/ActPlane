// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane — OS-enforced agent harness.
//!
//! Compiles a taint-DSL policy (docs/taint-dsl.md) to the kernel ABI, runs the
//! embedded eBPF enforcer, and reports the taint-rule violations it emits — each
//! with its policy reason (the corrective-feedback payload). The kernel does the
//! taint propagation, matching, and detection; this binary is the policy
//! compiler + reporting shim.

use clap::Parser;
use std::io::Write;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

mod binary_extractor;
mod dsl;
mod feedback;

use binary_extractor::BinaryExtractor;

#[derive(Parser)]
#[command(author, version, about = "ActPlane: OS-enforced agent harness", long_about = None)]
struct Cli {
    /// Taint-DSL policy file (see docs/taint-dsl.md).
    policy: String,
    /// Compile only: write the kernel config blob to this path and exit.
    #[arg(short, long)]
    out: Option<String>,
    /// When BPF LSM is inactive, send SIGKILL for block-effect violations.
    #[arg(long)]
    kill_on_violation: bool,
    /// Also append the formatted corrective-feedback payload for each violation
    /// to this file (the channel (a1) reason file agents read on EPERM).
    #[arg(long)]
    feedback_file: Option<String>,
}

#[derive(serde::Deserialize)]
struct Violation {
    pid: i32,
    ppid: i32,
    comm: String,
    target: String,
    rule_id: usize,
    #[allow(dead_code)]
    effect: Option<String>,
    blocked: Option<bool>,
    killed: Option<bool>,
    #[allow(dead_code)]
    taint_label: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    let cli = Cli::parse();

    let src = std::fs::read_to_string(&cli.policy)
        .map_err(|e| format!("reading {}: {}", cli.policy, e))?;
    let compiled = dsl::compile_str(&src)?;
    eprintln!(
        "ActPlane: compiled {} rule(s) ({} bytes of kernel config)",
        compiled.reasons.len(),
        compiled.bytes.len()
    );

    // compile-only mode
    if let Some(out) = &cli.out {
        std::fs::write(out, &compiled.bytes)?;
        eprintln!("wrote {}", out);
        return Ok(());
    }

    // write the config blob to a temp file for the loader
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(&compiled.bytes)?;
    let cfg_path = tmp.path().to_path_buf();

    let extractor = BinaryExtractor::new().await?;
    let mut cmd = Command::new(extractor.get_process_path());
    cmd.arg("--config").arg(&cfg_path);
    if cli.kill_on_violation {
        cmd.arg("--kill-on-violation");
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawning enforcer: {}", e))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();

    eprintln!("ActPlane: running (Ctrl-C to stop)...\n");
    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Violation>(&line) {
            report(&compiled.meta, &v, cli.feedback_file.as_deref());
        }
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(format!("enforcer exited with {}", status).into());
    }
    Ok(())
}

/// Report a violation: a human one-liner to stdout, plus the structured
/// corrective-feedback payload (docs/feedback-design.md §6) appended to the
/// feedback file if one was requested — channel (a1), the reason file an agent
/// reads when an operation fails with EPERM or the task is terminated.
fn report(meta: &[dsl::RuleMeta], v: &Violation, feedback_file: Option<&str>) {
    let verb = if v.killed.unwrap_or(false) {
        "KILLED"
    } else if v.blocked.unwrap_or(false) {
        "BLOCKED"
    } else {
        "VIOLATION"
    };
    let m = meta.get(v.rule_id);
    let reason = m.map(|m| m.reason.as_str()).unwrap_or("");
    let effect = v
        .effect
        .as_deref()
        .or_else(|| m.map(|m| effect_name(m.effect)))
        .unwrap_or("");
    println!(
        "🚫 {}: process '{}' (pid {}, ppid {}) — {}",
        verb, v.comm, v.pid, v.ppid, v.target
    );
    if !effect.is_empty() {
        println!("   effect: {}", effect);
    }
    if !reason.is_empty() {
        println!("   reason: {}", reason);
    }

    if let (Some(path), Some(m)) = (feedback_file, m) {
        let op = m.ops.first().map(|s| s.as_str()).unwrap_or("op");
        let payload = feedback::format_payload(
            &m.name,
            op,
            &v.target,
            &m.reason,
            m.remediation.as_deref(),
            m.effect,
        );
        if let Err(e) = append_feedback(path, &payload) {
            eprintln!("ActPlane: writing feedback file {}: {}", path, e);
        }
    }
}

/// Append a feedback payload (with a separator) to the reason file.
fn append_feedback(path: &str, payload: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}\n----", payload)
}

fn effect_name(effect: dsl::ast::Effect) -> &'static str {
    match effect {
        dsl::ast::Effect::Audit => "audit",
        dsl::ast::Effect::Block => "block",
        dsl::ast::Effect::Kill => "kill",
    }
}
