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

use binary_extractor::BinaryExtractor;

#[derive(Parser)]
#[command(author, version, about = "ActPlane: OS-enforced agent harness", long_about = None)]
struct Cli {
    /// Taint-DSL policy file (see docs/taint-dsl.md).
    policy: String,
    /// Compile only: write the kernel config blob to this path and exit.
    #[arg(short, long)]
    out: Option<String>,
}

#[derive(serde::Deserialize)]
struct Violation {
    pid: i32,
    ppid: i32,
    comm: String,
    target: String,
    rule_id: usize,
    blocked: Option<bool>,
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
            report(&compiled.reasons, &v);
        }
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(format!("enforcer exited with {}", status).into());
    }
    Ok(())
}

/// Report a violation with its policy reason — the corrective-feedback payload.
fn report(reasons: &[String], v: &Violation) {
    let reason = reasons.get(v.rule_id).map(|s| s.as_str()).unwrap_or("");
    let verb = if v.blocked.unwrap_or(false) {
        "BLOCKED"
    } else {
        "VIOLATION"
    };
    println!(
        "🚫 {}: process '{}' (pid {}, ppid {}) — {}",
        verb, v.comm, v.pid, v.ppid, v.target
    );
    if !reason.is_empty() {
        println!("   reason: {}", reason);
    }
}
