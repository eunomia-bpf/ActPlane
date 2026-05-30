// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//
// Drop-in replacement for the C `process` loader, built on the aya-based
// ebpf_ifc_engine crate. Same flags and same TAINT_VIOLATION JSON on stdout, so
// the collector can call this (or the library directly) instead of spawning the
// C binary. The C `process` loader is kept for now.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ebpf_ifc_engine::{bpf_lsm_active, Loader, Violation};

fn effect_name(e: u32) -> &'static str {
    match e {
        0 => "notify",
        1 => "block",
        2 => "kill",
        _ => "unknown",
    }
}

fn print_violation(v: &Violation) {
    let provenance = match &v.provenance {
        Some(p) => format!(
            "{{\"label\":{},\"timestamp\":{},\"pid\":{},\"op\":{},\"target\":\"{}\"}}",
            p.label, p.timestamp_ns, p.pid, p.op, p.target
        ),
        None => "null".to_string(),
    };
    println!(
        "{{\"timestamp\":{},\"event\":\"TAINT_VIOLATION\",\"effect\":\"{}\",\
\"blocked\":{},\"killed\":{},\"comm\":\"{}\",\"pid\":{},\"ppid\":{},\
\"target\":\"{}\",\"rule_id\":{},\"taint_label\":{},\"matched_label\":{},\
\"provenance\":{}}}",
        v.timestamp_ns,
        effect_name(v.effect),
        v.blocked,
        v.killed,
        v.comm,
        v.pid,
        v.ppid,
        v.target,
        v.rule_id,
        v.label,
        v.matched_label,
        provenance,
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn usage() -> ! {
    eprintln!("usage: actplane-loader --config policy.bin [--agent-pid PID --agent-label BIT]");
    std::process::exit(1);
}

fn main() {
    let mut config: Option<String> = None;
    let mut agent_pid: i32 = 0;
    let mut agent_label: u64 = 0;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => config = args.next(),
            "--agent-pid" => {
                agent_pid = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--agent-label" => {
                agent_label = args
                    .next()
                    .and_then(|s| parse_u64(&s))
                    .unwrap_or_else(|| usage())
            }
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    let config = config.unwrap_or_else(|| usage());

    let blob = match std::fs::read(&config) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read config '{config}': {e}");
            std::process::exit(1);
        }
    };

    let mut loader = match Loader::load(&blob) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("load failed: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "ActPlane: {} mode ({})",
        if loader.enforce_mode() {
            "enforce"
        } else {
            "tracepoint"
        },
        if bpf_lsm_active() {
            "BPF LSM is active"
        } else {
            "BPF LSM not active; block unsupported, notify reports, kill terminates"
        }
    );

    if agent_pid != 0 || agent_label != 0 {
        if let Err(e) = loader.seed_agent(agent_pid, agent_label) {
            eprintln!("seed agent failed: {e}");
            std::process::exit(1);
        }
        eprintln!("ActPlane: seeded AGENT pid {agent_pid} label {agent_label:#x}");
    }

    let stop = Arc::new(AtomicBool::new(false));
    install_signal_handler(stop.clone());
    eprintln!("ActPlane: ready");

    if let Err(e) = loader.run(&stop, |v| print_violation(&v)) {
        eprintln!("ring buffer error: {e}");
        std::process::exit(1);
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

// Minimal SIGINT/SIGTERM handler flipping the stop flag.
static STOP: AtomicBool = AtomicBool::new(false);
fn install_signal_handler(stop: Arc<AtomicBool>) {
    extern "C" fn handler(_sig: i32) {
        STOP.store(true, Ordering::SeqCst);
    }
    unsafe {
        libc::signal(libc::SIGINT, handler as usize);
        libc::signal(libc::SIGTERM, handler as usize);
    }
    // Bridge the static flag to the caller's flag on a tiny watcher thread.
    std::thread::spawn(move || {
        while !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        stop.store(true, Ordering::SeqCst);
    });
}
