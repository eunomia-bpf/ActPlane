// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! `--backend unprivileged` end to end through the `actplane` binary. None of
//! these tests needs privileges. Tests that launch a confined command skip
//! with a message when the kernel lacks Landlock, unless
//! `ACTPLANE_REQUIRE_LANDLOCK` is set (CI sets it).

use std::path::Path;
use std::process::{Command, Output};

fn actplane() -> &'static str {
    env!("CARGO_BIN_EXE_actplane")
}

fn run(args: &[&str]) -> Output {
    Command::new(actplane())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run actplane {args:?}: {e}"))
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

const LABELED: &str = r#"
source SECRET = file "**/.env"
rule no-exfil:
  block connect endpoint "*" if SECRET
  because "secret data must not leave the host"
"#;

const STATIC: &str = r#"
source COMMAND = exec "**"
rule confine:
  block write file "/**" if COMMAND unless target "/work/**"
  block connect endpoint "*" if COMMAND
  because "stay in /work and offline"
"#;

#[test]
fn run_and_compile_help_expose_backend_flag() {
    for sub in ["run", "compile"] {
        let out = run(&[sub, "--help"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let text = stdout(&out);
        assert!(text.contains("--backend"), "{sub} help:\n{text}");
        assert!(text.contains("unprivileged"), "{sub} help:\n{text}");
        assert!(text.contains("bpf-lsm"), "{sub} help:\n{text}");
    }
}

#[test]
fn compile_rejects_label_policy_per_clause() {
    let out = run(&["--rule", LABELED, "compile", "--backend", "unprivileged"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("[unsupported] rule no-exfil clause 1"),
        "{text}"
    );
    assert!(text.contains("`if SECRET`"), "{text}");

    let out = run(&[
        "--rule",
        LABELED,
        "compile",
        "--backend",
        "unprivileged",
        "--explain",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("backend: unprivileged"), "{text}");
    assert!(text.contains("status: unsupported"), "{text}");
    assert!(text.contains("refuses this policy"), "{text}");

    let out = run(&[
        "--rule",
        LABELED,
        "compile",
        "--backend",
        "unprivileged",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["schema"], "actplane.compile.unprivileged.v1");
    assert_eq!(v["ok"], false);
    assert_eq!(v["clauses"][0]["status"], "unsupported");
    assert_eq!(v["clauses"][0]["rule"], "no-exfil");
}

#[test]
fn compile_explain_reports_exact_static_clauses() {
    let out = run(&[
        "--rule",
        STATIC,
        "compile",
        "--backend",
        "unprivileged",
        "--explain",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("status: exact"), "{text}");
    assert!(!text.contains("status: unsupported"), "{text}");
    assert!(text.contains("beneath /work"), "{text}");
    assert!(text.contains("Landlock:"), "{text}");
    assert!(text.contains("io_uring_setup"), "{text}");

    let out = run(&[
        "--rule",
        STATIC,
        "compile",
        "--backend",
        "unprivileged",
        "--json",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["ok"], true);
    assert_eq!(v["exact_count"], 2);
    assert_eq!(v["runner_label"], "COMMAND");
}

#[test]
fn compile_default_backend_is_unchanged() {
    let out = run(&["--rule", STATIC, "compile", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["schema"], "actplane.compile.v1");
    let out = run(&[
        "--rule",
        STATIC,
        "compile",
        "--backend",
        "bpf-lsm",
        "--json",
    ]);
    let w: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v, w);
}

#[test]
fn compile_unprivileged_has_no_kernel_blob() {
    let dir = tempfile::tempdir().unwrap();
    let blob = dir.path().join("policy.bin");
    let out = run(&[
        "--rule",
        STATIC,
        "compile",
        "--backend",
        "unprivileged",
        "--out",
        blob.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no blob"), "{}", stderr(&out));
    assert!(!blob.exists());
}

#[test]
fn run_refuses_unsupported_policy_before_launch() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("launched");
    let out = run(&[
        "--rule",
        LABELED,
        "run",
        "--backend",
        "unprivileged",
        "--",
        "/bin/sh",
        "-c",
        "touch \"$1\"",
        "sh",
        marker.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("refuses to run it"), "{err}");
    assert!(err.contains("rule no-exfil clause 1"), "{err}");
    assert!(!marker.exists(), "the command must not start");
}

#[test]
fn run_rejects_runtime_domain_flags() {
    let out = run(&[
        "--rule",
        STATIC,
        "run",
        "--backend",
        "unprivileged",
        "--delta-text",
        "rule extra:\n  block write file \"*\"\n  because \"x\"\n",
        "--",
        "/bin/true",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no runtime domains"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn doctor_reports_unprivileged_backend_support() {
    let out = run(&["--rule", STATIC, "doctor"]);
    let text = stdout(&out);
    assert!(text.contains("unprivileged backend"), "{text}");
    assert!(text.contains("Landlock:"), "{text}");
    assert!(text.contains("seccomp:"), "{text}");
    assert!(text.contains("no_new_privs:"), "{text}");
}

fn landlock_or_skip(test: &str) -> bool {
    let host = actplane_sandbox::probe();
    if host.landlock_abi >= actplane_sandbox::plan::LANDLOCK_ABI_WRITE {
        eprintln!("{test}: running with Landlock ABI {}", host.landlock_abi);
        return true;
    }
    let msg = format!(
        "{test}: needs Landlock ABI {}, host has {} ({})",
        actplane_sandbox::plan::LANDLOCK_ABI_WRITE,
        host.landlock_abi,
        host.landlock_error.as_deref().unwrap_or("kernel too old")
    );
    if std::env::var_os("ACTPLANE_REQUIRE_LANDLOCK").is_some() {
        panic!("{msg}; ACTPLANE_REQUIRE_LANDLOCK is set, so this is a failure");
    }
    eprintln!("SKIP {msg}");
    false
}

#[cfg(target_os = "linux")]
#[test]
fn run_confines_writes_to_the_allowed_directory() {
    if !landlock_or_skip("run write confinement") {
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let a = allowed.path().to_str().unwrap();
    let b = outside.path().to_str().unwrap();
    let policy = format!(
        "source COMMAND = exec \"**\"\nrule confine:\n  block write file \"/**\" if COMMAND unless target \"{a}/**\"\n  because \"stay in the workspace\"\n"
    );

    let out = run(&[
        "--rule",
        &policy,
        "run",
        "--backend",
        "unprivileged",
        "--",
        "/bin/sh",
        "-c",
        "echo in > \"$1/in.txt\" && echo out > \"$2/out.txt\"",
        "sh",
        a,
        b,
    ]);
    let err = stderr(&out);
    assert!(err.contains("unprivileged backend"), "{err}");
    assert!(!out.status.success(), "write outside must fail: {err}");
    assert!(err.contains("Permission denied"), "{err}");
    assert_eq!(
        std::fs::read_to_string(Path::new(a).join("in.txt")).unwrap(),
        "in\n"
    );
    assert!(!Path::new(b).join("out.txt").exists());

    let out = run(&[
        "--rule",
        &policy,
        "run",
        "--backend",
        "unprivileged",
        "--",
        "/bin/sh",
        "-c",
        "echo again > \"$1/again.txt\"",
        "sh",
        a,
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(Path::new(a).join("again.txt").exists());
}
