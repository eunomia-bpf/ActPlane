// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane — OS-enforced agent harness.
//!
//! Loads taint rules (YAML or inline), runs the embedded eBPF `process` tracer
//! with the compiled `source:sink` edges, and reports the taint-rule violations
//! it emits (a tainted process — a descendant of `source` — running a forbidden
//! `sink`). The kernel does the taint propagation and detection; this binary is
//! a thin policy + reporting shim, with no streaming/analyzer framework.

use clap::Parser;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

mod binary_extractor;
mod policy;

use binary_extractor::BinaryExtractor;
use policy::{Edge, Policy};

#[derive(Parser)]
#[command(author, version, about = "ActPlane: OS-enforced agent harness (taint-rule violations)", long_about = None)]
struct Cli {
    /// Path to a YAML taint policy (see policy.rs for the schema).
    #[arg(short, long)]
    config: Option<String>,

    /// Inline taint edge SOURCE:SINK (repeatable). Combined with --config.
    #[arg(short = 'r', long = "rule", value_name = "SOURCE:SINK")]
    rules: Vec<String>,
}

/// A violation event as emitted by the `process` tracer in taint mode.
#[derive(serde::Deserialize)]
struct Violation {
    pid: i32,
    ppid: i32,
    comm: String,
    filename: String,
    rule_id: usize,
    #[allow(dead_code)]
    taint_label: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    let cli = Cli::parse();

    // Compile the policy: config edges first, then inline --rule edges. Edge
    // order is the kernel's rule_id, so the reporting lookup stays consistent.
    let mut edges: Vec<Edge> = match &cli.config {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("reading {}: {}", path, e))?;
            Policy::from_yaml(&text)?.into_edges()
        }
        None => Vec::new(),
    };
    for r in &cli.rules {
        let (source, sink) = r
            .split_once(':')
            .filter(|(s, k)| !s.is_empty() && !k.is_empty())
            .ok_or_else(|| format!("invalid --rule '{}' (expected SOURCE:SINK)", r))?;
        edges.push(Edge {
            source: source.to_string(),
            sink: sink.to_string(),
            rule_name: "inline".to_string(),
            reason: String::new(),
        });
    }
    let policy = Policy::from_edges(edges);

    if policy.is_empty() {
        return Err("no taint rules: pass --config <yaml> or --rule SOURCE:SINK".into());
    }

    let edge_args = policy.edge_args();
    eprintln!("ActPlane: enforcing {} taint edge(s):", edge_args.len());
    for (i, e) in policy.edges().iter().enumerate() {
        eprintln!("  [{}] {} -> deny exec {}  ({})", i, e.source, e.sink, e.rule_name);
    }

    // Extract the embedded eBPF loader and run it in taint mode.
    let extractor = BinaryExtractor::new().await?;
    let mut cmd = Command::new(extractor.get_process_path());
    for edge in &edge_args {
        cmd.arg("-T").arg(edge);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());

    let mut child = cmd.spawn().map_err(|e| format!("spawning tracer: {}", e))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();

    eprintln!("ActPlane: watching for violations (Ctrl-C to stop)...\n");
    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Violation>(&line) {
            report(&policy, &v);
        }
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(format!("tracer exited with {}", status).into());
    }
    Ok(())
}

/// Print a human-readable violation with the policy's reason.
fn report(policy: &Policy, v: &Violation) {
    let (rule_name, reason) = match policy.edge(v.rule_id) {
        Some(e) => (e.rule_name.as_str(), e.reason.as_str()),
        None => ("?", ""),
    };
    println!(
        "🚫 BLOCKED [{}]: process '{}' (pid {}, ppid {}) tried to exec {}",
        rule_name, v.comm, v.pid, v.ppid, v.filename
    );
    if !reason.is_empty() {
        println!("   reason: {}", reason);
    }
}
