use std::fs;
use std::path::Path;
use std::process::{Command, Output};

#[cfg(unix)]
use std::io::{BufRead, Write};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::time::Duration;

fn actplane() -> &'static str {
    env!("CARGO_BIN_EXE_actplane")
}

fn fixture(name: &str) -> String {
    format!(
        "{}/../../test/policies/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

fn run(args: &[&str]) -> Output {
    Command::new(actplane())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run actplane {args:?}: {e}"))
}

#[test]
fn top_level_help_is_engine_focused() {
    let output = run(&["--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    for command in [
        "run", "compile", "init", "doctor", "watch", "attach", "mcp", "control",
    ] {
        assert!(
            stdout.contains(command),
            "missing {command} in help:\n{stdout}"
        );
    }
    for removed in [
        "check",
        "templates",
        "setup",
        "domains",
        "rollout",
        "child-run",
    ] {
        assert!(
            !stdout.contains(&format!("  {removed}")),
            "removed command {removed} still appears in help:\n{stdout}"
        );
    }
}

#[test]
fn removed_top_level_commands_are_not_accepted() {
    for command in [
        "check",
        "templates",
        "setup",
        "domains",
        "rollout",
        "delta",
        "child-run",
    ] {
        let output = run(&[command, "--help"]);
        assert!(
            !output.status.success(),
            "removed command {command} unexpectedly succeeded"
        );
    }
}

#[test]
fn compile_default_prints_domain_summary() {
    let policy = fixture("15_domain_bindings.yaml");
    let output = run(&["--policy", &policy, "--domain", "review", "compile"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("domain: review"));
    assert!(stdout.contains("parent: session"));
    assert!(stdout.contains("policy: no-git-branch, readonly"));
    assert!(!stdout.contains("no-network —"));
}

#[test]
fn compile_json_reports_backend_support_and_static_warnings() {
    let policy = r#"
source NET = endpoint "localhost"
source WILD = endpoint "*.internal"

rule recv-soft:
  notify recv endpoint "*" if true
  because "recv notify"

rule host-connect:
  notify connect endpoint "localhost" if true
  because "hostname connect"
"#;
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");

    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["matrix_scope"], "static_policy_host_support");
    assert_eq!(value["rule_count"], 2);
    assert_eq!(value["backend_support"]["sources"][0]["label"], "NET");
    assert_eq!(value["backend_support"]["sources"][0]["supported"], true);
    assert!(
        value["backend_support"]["sources"][0]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("hostname resolved")
    );
    assert_eq!(value["backend_support"]["sources"][1]["label"], "WILD");
    assert_eq!(value["backend_support"]["sources"][1]["supported"], false);
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "endpoint_source_unsupported")
    );
}

#[test]
fn compile_json_reports_policy_load_errors_as_json() {
    let missing = "/tmp/actplane-definitely-missing-policy.yaml";
    let output = run(&["--policy", missing, "compile", "--json"]);
    assert!(!output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json error stdout");
    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["policy_ref"], missing);
    assert!(
        value["error"]
            .as_str()
            .unwrap_or("")
            .contains("reading /tmp/actplane-definitely-missing-policy.yaml")
    );
}

#[test]
fn compile_explain_writes_report_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("review.txt");
    let policy = r#"
source AGENT = exec "**"

rule no-network:
  notify connect endpoint "*" if AGENT unless target "127."
  because "network review"
"#;
    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--explain",
        "--report-out",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty when writing --report-out: {}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("wrote policy review"));
    let artifact = fs::read_to_string(&out).unwrap();
    assert!(artifact.contains("ActPlane policy review"));
    assert!(artifact.contains("rule no-network"));
    assert!(artifact.contains("review scope: selected policy"));
}

#[test]
fn compile_report_out_requires_report_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("review.txt");
    let policy = r#"
rule noop:
  notify exec "git" if true
  because "noop"
"#;
    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--report-out",
        out.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--report-out requires --json or --explain"));
}

#[test]
fn compile_domains_lists_effective_bindings() {
    let policy = fixture("15_domain_bindings.yaml");
    let output = run(&["--policy", &policy, "compile", "--domains"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("* review"));
    assert!(stdout.contains("  session"));
    assert!(stdout.contains("policy: no-git-branch, no-network"));
    assert!(stdout.contains("policy: no-git-branch, readonly"));
}

#[test]
fn compile_writes_kernel_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("policy.bin");
    let policy = fixture("15_domain_bindings.yaml");
    let output = run(&[
        "--policy",
        &policy,
        "--domain",
        "review",
        "compile",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(out.is_file());
    let stderr = stderr(&output);
    assert!(stderr.contains("domain `review`"));
    assert!(stderr.contains("policy: no-git-branch, readonly"));
    assert!(stderr.contains("compiled 2 rule(s)"));
}

#[test]
fn compile_out_respects_force() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("policy.bin");
    fs::write(&out, b"keep").unwrap();
    let policy = fixture("15_domain_bindings.yaml");

    let output = run(&[
        "--policy",
        &policy,
        "compile",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("already exists"));
    assert_eq!(fs::read(&out).unwrap(), b"keep");

    let output = run(&[
        "--policy",
        &policy,
        "compile",
        "--out",
        out.to_str().unwrap(),
        "--force",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_ne!(fs::read(&out).unwrap(), b"keep");
}

#[test]
fn compile_out_rejects_directory_and_symlink_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = r#"
rule noop:
  notify exec "git" if true
  because "noop"
"#;

    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--out",
        tmp.path().to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("is a directory, not an output file"));

    let target = tmp.path().join("target.bin");
    fs::write(&target, b"keep").unwrap();
    let link = tmp.path().join("link.bin");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let output = run(&["--rule", policy, "compile", "--out", link.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("is a symlink"));
    assert_eq!(fs::read(&target).unwrap(), b"keep");
}

#[test]
fn compile_report_out_rejects_existing_file_and_missing_parent() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = r#"
rule noop:
  notify exec "git" if true
  because "noop"
"#;

    let existing = tmp.path().join("review.txt");
    fs::write(&existing, "keep").unwrap();
    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--json",
        "--report-out",
        existing.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("already exists (use --force to overwrite)"));
    assert_eq!(fs::read_to_string(&existing).unwrap(), "keep");

    let missing = tmp.path().join("missing").join("review.txt");
    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--json",
        "--report-out",
        missing.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("No such file or directory"));
    assert!(!missing.exists());
}

#[test]
fn init_lists_and_writes_templates_without_templates_command() {
    let output = run(&["init", "--list-templates"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let list_stdout = stdout(&output);
    assert!(list_stdout.contains("ActPlane policy templates"));
    assert!(list_stdout.contains("no-secret-egress"));
    assert!(list_stdout.contains("test-before-commit"));

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("actplane.yaml");
    let output = run(&[
        "init",
        "--template",
        "workspace-confinement",
        "--set",
        "agent_exec=codex",
        "--set",
        "writable_path=/repo/**",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let written = fs::read_to_string(&out).unwrap();
    assert!(written.contains("# Parameter writable_path: /repo/**"));
    assert!(written.contains("source AGENT = exec \"codex\""));
    assert!(written.contains("unless target \"/repo/**\""));

    let compile = run(&["--policy", out.to_str().unwrap(), "compile", "--explain"]);
    assert!(compile.status.success(), "stderr: {}", stderr(&compile));
    assert!(stdout(&compile).contains("rule workspace-confinement"));
}

#[test]
fn init_generate_writes_candidate_policy() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("AGENTS.md"),
        "Do not run git branch or git worktree. Run pytest before committing. Keep secrets safe.",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::create_dir(tmp.path().join("tests")).unwrap();
    let policy = tmp.path().join("candidate.yaml");

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--generate", "--out", policy.to_str().unwrap()])
        .output()
        .expect("run init --generate");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("selected no-git-branch"));
    assert!(stderr(&output).contains("selected test-before-commit"));
    assert!(stderr(&output).contains("selected no-secret-egress"));

    let written = fs::read_to_string(&policy).unwrap();
    assert!(written.contains("ActPlane candidate policy generated"));
    assert!(written.contains("# template: no-git-branch"));
    assert!(written.contains("rule no-git-branch:"));
}

#[test]
fn run_help_exposes_child_domain_delta_flags() {
    let output = run(&["run", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--parent-domain"));
    assert!(stdout.contains("--child-id"));
    assert!(stdout.contains("--scope-id"));
    assert!(stdout.contains("--delta"));
    assert!(stdout.contains("--delta-text"));
    assert!(stdout.contains("--approved-by"));
    assert!(stdout.contains("--approval-ref"));
    assert!(stdout.contains("--generated-by"));
}

#[test]
fn run_accepts_global_domain_flag_after_subcommand() {
    let output = run(&["run", "--domain", "review", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--domain <DOMAIN>"));
    assert!(stdout.contains("--parent-domain"));
}

#[test]
fn watch_help_exposes_parent_domain_flag() {
    let output = run(&["watch", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--parent-domain"));
}

#[test]
fn attach_help_exposes_existing_process_domain_flags() {
    let output = run(&["attach", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--pid"));
    assert!(stdout.contains("--parent-domain"));
    assert!(stdout.contains("--child-domain"));
    assert!(stdout.contains("--domain-id"));
    assert!(stdout.contains("--child-id"));
    assert!(stdout.contains("--scope-id"));
    assert!(stdout.contains("--delta"));
    assert!(stdout.contains("--delta-text"));
    assert!(stdout.contains("--approved-by"));
    assert!(stdout.contains("--approval-ref"));
    assert!(stdout.contains("--generated-by"));
    assert!(stdout.contains("foreground engine"));
    assert!(stdout.contains("post-hoc"));
}

#[test]
fn run_parent_domain_rejects_runtime_delta_mode() {
    let output = run(&[
        "run",
        "--parent-domain",
        "--domain",
        "review",
        "--delta-text",
        "rule child:\n  notify exec \"git\" if true\n  because \"child\"",
        "/bin/true",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--parent-domain cannot be combined"));
}

#[test]
fn control_help_exposes_already_running_engine_commands() {
    let output = run(&["control", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    for command in [
        "status",
        "bind-child",
        "delta",
        "launch-child",
        "children",
        "logs",
        "stop",
        "restart",
    ] {
        assert!(
            stdout.contains(command),
            "missing {command} in help:\n{stdout}"
        );
    }
    for removed in [
        "append-delta",
        "list-children",
        "terminate-child",
        "restart-child",
    ] {
        assert!(
            !stdout.contains(removed),
            "old control command {removed} still appears in help:\n{stdout}"
        );
    }
}

#[test]
fn control_delta_add_help_exposes_delta_inputs() {
    let output = run(&["control", "delta", "add", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--target-id"));
    assert!(stdout.contains("--domain-id"));
    assert!(stdout.contains("--delta"));
    assert!(stdout.contains("--delta-text"));
    assert!(stdout.contains("--approved-by"));
    assert!(stdout.contains("--approval-ref"));
    assert!(stdout.contains("--generated-by"));
}

#[test]
fn renamed_control_commands_report_new_command_names_in_errors() {
    for (args, expected) in [
        (&["control", "logs"][..], "control logs requires"),
        (&["control", "stop"][..], "control stop requires"),
        (&["control", "restart"][..], "control restart requires"),
    ] {
        let output = run(args);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains(expected),
            "missing `{expected}` in stderr:\n{}",
            stderr(&output)
        );
    }
}

#[cfg(unix)]
#[test]
fn parent_domain_control_mutations_are_rejected_before_socket_connect() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": tmp.path().join("missing-control.sock"),
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": u32::MAX,
        }))
        .unwrap(),
    )
    .unwrap();

    for args in [
        vec!["attach", "--pid", "1234", "--child-domain"],
        vec!["control", "bind-child", "--pid", "1234"],
        vec![
            "control",
            "delta",
            "add",
            "--delta-text",
            "rule added:\n  notify exec \"git\" if true\n  because \"added\"",
        ],
        vec!["control", "launch-child", "/bin/true"],
    ] {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .args(args)
            .output()
            .expect("run parent-domain control mutation");
        assert!(!output.status.success());
        let stderr = stderr(&output);
        assert!(
            stderr.contains("unavailable in --parent-domain mode"),
            "stderr did not explain parent-domain mode:\n{stderr}"
        );
        assert!(
            !stderr.contains("missing-control.sock"),
            "command attempted to connect before rejecting parent-domain mode:\n{stderr}"
        );
    }
}

#[cfg(unix)]
#[test]
fn attach_sends_bind_then_child_delta_over_repo_control_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        r#"
version: 1
policy: |
  source COMMAND = exec "**"
  rule noop:
    notify exec "__actplane_never__" if COMMAND
    because "noop"
"#,
    )
    .unwrap();

    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        for response in ["attached", "delta accepted"] {
            let (mut stream, _) = listener.accept().expect("accept control client");
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read request");
            let request: serde_json::Value = serde_json::from_str(&line).expect("request JSON");
            tx.send(request).expect("send request");
            serde_json::to_writer(
                &mut stream,
                &serde_json::json!({ "ok": true, "text": response }),
            )
            .expect("write response");
            writeln!(stream).expect("write response newline");
        }
    });

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "--policy",
            policy.to_str().unwrap(),
            "attach",
            "--pid",
            "1234",
            "--child-domain",
            "--domain-id",
            "4242",
            "--scope-id",
            "7",
            "--delta-text",
            "rule added:\n  notify exec \"git\" if true\n  because \"added\"",
            "--approved-by",
            "reviewer",
            "--approval-ref",
            "ticket-7",
            "--generated-by",
            "cli-test",
        ])
        .output()
        .expect("run attach");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("attached"));
    assert!(stdout.contains("delta accepted"));

    let bind_request = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("bind control request");
    assert_eq!(bind_request["op"], "bind_child_domain");
    assert_eq!(bind_request["pid"], 1234);
    assert_eq!(bind_request["child_id"], 4242);
    assert_eq!(bind_request["scope_id"], 7);

    let delta_request = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("delta control request");
    assert_eq!(delta_request["op"], "append_policy_delta");
    assert_eq!(delta_request["target_id"], 4242);
    assert!(
        delta_request["policy"]
            .as_str()
            .unwrap()
            .contains("rule added")
    );
    assert_eq!(delta_request["policy_ref"], "--delta-text[0]");
    assert_eq!(delta_request["approved_by"], "reviewer");
    assert_eq!(delta_request["approval_ref"], "ticket-7");
    assert_eq!(delta_request["generated_by"], "cli-test");
    handle.join().expect("control server thread");
}

#[cfg(unix)]
#[test]
fn control_delta_add_sends_append_delta_over_repo_control_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        r#"
version: 1
policy: |
  source COMMAND = exec "**"
  rule noop:
    notify exec "__actplane_never__" if COMMAND
    because "noop"
"#,
    )
    .unwrap();

    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let mut line = String::new();
        std::io::BufReader::new(stream.try_clone().expect("clone stream"))
            .read_line(&mut line)
            .expect("read request");
        let request: serde_json::Value = serde_json::from_str(&line).expect("request JSON");
        tx.send(request).expect("send request");
        serde_json::to_writer(
            &mut stream,
            &serde_json::json!({ "ok": true, "text": "delta accepted" }),
        )
        .expect("write response");
        writeln!(stream).expect("write response newline");
    });

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "--policy",
            policy.to_str().unwrap(),
            "control",
            "delta",
            "add",
            "--target-id",
            "4242",
            "--delta-text",
            "rule added:\n  notify exec \"git\" if true\n  because \"added\"",
            "--approved-by",
            "reviewer",
            "--approval-ref",
            "ticket-7",
            "--generated-by",
            "cli-test",
        ])
        .output()
        .expect("run control delta add");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("delta accepted"));

    let request = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("control request");
    assert_eq!(request["op"], "append_policy_delta");
    assert_eq!(request["target_id"], 4242);
    assert!(request["policy"].as_str().unwrap().contains("rule added"));
    assert_eq!(request["policy_ref"], "--delta-text[0]");
    assert_eq!(request["approved_by"], "reviewer");
    assert_eq!(request["approval_ref"], "ticket-7");
    assert_eq!(request["generated_by"], "cli-test");
    handle.join().expect("control server thread");
}

// A zero `--domain-id` in child-domain attach mode is rejected before the
// control socket is contacted.
#[test]
fn attach_child_domain_rejects_zero_domain_id() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": 1,
            "proc_start_time": null,
            "socket_path": tmp.path().join("control.sock"),
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "attach",
            "--pid",
            "4242",
            "--child-domain",
            "--domain-id",
            "0",
        ])
        .output()
        .expect("run attach");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("--domain-id must be nonzero"),
        "stderr: {}",
        stderr(&output)
    );
}

// `attach --pid 1` targets the init process, which cannot be attached as a
// watched child, so the command rejects it before any policy discovery.
#[test]
fn attach_rejects_init_pid_before_policy_discovery() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["attach", "--pid", "1"])
        .output()
        .expect("run attach --pid 1");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(output.stdout.is_empty(), "stdout: {}", stdout(&output));
    assert_eq!(
        stderr(&output).trim(),
        "Error: \"invalid parent pid for watch attach: 1\""
    );
}

// `run`, `watch`, and `attach` share the auto-attach precondition that the
// policy must declare or reference a COMMAND (or legacy AGENT) label.
#[test]
fn autoattach_requires_command_label() {
    let tmp = tempfile::tempdir().unwrap();
    fs::copy(
        fixture("01_secret_no_exfil.yaml"),
        tmp.path().join("actplane.yaml"),
    )
    .unwrap();

    const EXPECTED: &str = "run/auto-attach mode requires the policy to declare or reference label COMMAND (or AGENT for backward compatibility)";
    for args in [
        vec!["run", "/bin/true"],
        vec!["watch"],
        vec!["attach", "--pid", "5"],
    ] {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .args(&args)
            .output()
            .expect("run auto-attach command");
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?} stderr: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(EXPECTED),
            "{args:?} stderr: {}",
            stderr(&output)
        );
    }
}

// `mcp --auto-attach-parent` enforces the same COMMAND-label precondition as
// the other auto-attach entry points, over stdio.
#[test]
fn mcp_auto_attach_requires_command_label() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    fs::copy(
        fixture("01_secret_no_exfil.yaml"),
        tmp.path().join("actplane.yaml"),
    )
    .unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["mcp", "--auto-attach-parent"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp --auto-attach-parent");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "run/auto-attach mode requires the policy to declare or reference label COMMAND (or AGENT for backward compatibility)"
        ),
        "stderr: {}",
        stderr(&output)
    );
}

// Without a discoverable policy, every engine-driving subcommand must fail
// with the same actionable message (exit 1) instead of proceeding with an
// empty policy. Discovery starts from cwd, so a fresh tempdir is isolated
// from any actplane.yaml in the repository.
#[test]
fn engine_commands_without_policy_report_discovery_error() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [&["compile"][..], &["watch"][..], &["run", "true"][..]] {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("run actplane {args:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?} exited {:?}: {}",
            output.status.code(),
            stderr(&output)
        );
        assert!(
            stderr(&output)
                .contains("no actplane.yaml found; pass --policy <file> or --rule <dsl>"),
            "{args:?} stderr: {}",
            stderr(&output)
        );
    }
}

// `run` rejects `--parent-domain` when any child runtime-delta option is set.
#[test]
fn run_parent_domain_rejects_child_runtime_options() {
    let output = run(&["run", "--parent-domain", "--child-id", "5", "true"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output)
            .contains("--parent-domain cannot be combined with child runtime delta options"),
        "stderr: {}",
        stderr(&output)
    );
}

// Argument combinations that `attach` and `init` reject should fail with a
// non-zero status and the specific conflict message, before any engine work
// (control socket, policy file, or integration writes) is attempted.
#[test]
fn cli_preflight_conflicts_fail_with_specific_errors() {
    let cases: &[(&[&str], &str)] = &[
        (&["attach", "--pid", "0"], "--pid must be positive"),
        (
            &["attach", "--pid", "5", "--parent-domain", "--child-domain"],
            "--parent-domain cannot be combined with child-domain attach options",
        ),
        (
            &["init", "--list-templates", "--force"],
            "--list-templates cannot be combined with write or integration flags",
        ),
        (&["init", "--set", "a=b"], "--set requires --template"),
        (
            &["init", "--print", "--with-mcp"],
            "--print cannot be combined with integration setup flags",
        ),
    ];
    for (args, expected) in cases {
        let output = run(args);
        assert!(
            !output.status.success(),
            "{args:?} unexpectedly succeeded: {}",
            stdout(&output)
        );
        assert!(
            stderr(&output).contains(expected),
            "{args:?} stderr missing {expected:?}: {}",
            stderr(&output)
        );
    }
}

// Without `--domain`, `compile` uses the policy's `default_domain`, and an
// explicit `--domain` selects a different domain with its own rule set.
#[test]
fn compile_resolves_default_domain_and_alternate_selection() {
    let policy = fixture("15_domain_bindings.yaml");

    let default = run(&["--policy", &policy, "compile"]);
    assert!(default.status.success(), "stderr: {}", stderr(&default));
    let out = stdout(&default);
    assert!(out.contains("domain: review"), "stdout: {out}");
    assert!(out.contains("parent: session"), "stdout: {out}");
    assert!(
        out.contains("policy: no-git-branch, readonly"),
        "stdout: {out}"
    );

    let session = run(&["--policy", &policy, "--domain", "session", "compile"]);
    assert!(session.status.success(), "stderr: {}", stderr(&session));
    let out = stdout(&session);
    assert!(out.contains("domain: session"), "stdout: {out}");
    assert!(
        out.contains("policy: no-git-branch, no-network"),
        "stdout: {out}"
    );
    assert!(
        !out.contains("readonly"),
        "the session domain must not include the review rule: {out}"
    );
}

// When a `domains:` policy omits `default_domain`, `compile` falls back to the
// root domain instead of erroring.
#[test]
fn compile_falls_back_to_root_domain_without_default() {
    let tmp = tempfile::tempdir().unwrap();
    let full = fs::read_to_string(fixture("15_domain_bindings.yaml")).unwrap();
    let stripped: String = full
        .lines()
        .filter(|line| !line.starts_with("default_domain:"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(tmp.path().join("actplane.yaml"), stripped).unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("compile")
        .output()
        .expect("run compile");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("domain: session"), "stdout: {out}");
    assert!(
        !out.contains("parent:"),
        "the root domain has no parent: {out}"
    );
    assert!(
        out.contains("policy: no-git-branch, no-network"),
        "stdout: {out}"
    );
}

// `compile --domains` on a legacy single-policy file succeeds and explains
// that no domains are defined.
#[test]
fn compile_domains_explains_legacy_policy() {
    let policy = fixture("01_secret_no_exfil.yaml");
    let output = run(&["--policy", &policy, "compile", "--domains"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains(&format!(
            "{policy} uses legacy `policy: |`; no domains are defined."
        )),
        "stdout: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("no domains are defined") && !stdout(&output).contains("domain:"),
        "a legacy policy must not list any domain: {}",
        stdout(&output)
    );
}

// A policy whose YAML parses but whose DSL body has a syntax error fails to
// compile, printing the parser diagnostic to stderr and exiting 1 in both the
// human and `--json` modes.
#[test]
fn compile_reports_dsl_parse_error_with_location() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("bad.yaml");
    fs::write(
        &policy,
        "version: 1\npolicy: |\n  rule broken\n    notify exec \"g\" if true\n",
    )
    .unwrap();

    let human = run(&["--policy", policy.to_str().unwrap(), "compile"]);
    assert_eq!(human.status.code(), Some(1), "stderr: {}", stderr(&human));
    assert!(human.stdout.is_empty(), "stdout: {}", stdout(&human));
    assert!(
        stderr(&human).contains("✗ policy does not compile: expected ':' after rule name"),
        "stderr: {}",
        stderr(&human)
    );

    let json = run(&["--policy", policy.to_str().unwrap(), "compile", "--json"]);
    assert_eq!(json.status.code(), Some(1), "stderr: {}", stderr(&json));
    let value: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("compile --json stdout");
    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["policy_ref"], policy.to_str().unwrap());
    assert!(
        value["error"]
            .as_str()
            .unwrap_or("")
            .contains("expected ':' after rule name"),
        "json error: {}",
        value["error"]
    );
}

// `compile --explain` renders the selected domain header with its rule list,
// and omits `parent:` for a self-contained auto-selected domain.
#[test]
fn compile_explain_renders_domain_binding_header() {
    let bound = run(&[
        "--policy",
        &fixture("15_domain_bindings.yaml"),
        "--domain",
        "review",
        "compile",
        "--explain",
    ]);
    assert!(bound.status.success(), "stderr: {}", stderr(&bound));
    let out = stdout(&bound);
    assert!(out.contains("domain: review"), "stdout: {out}");
    assert!(out.contains("parent: session"), "stdout: {out}");
    assert!(
        out.contains("policy rules: no-git-branch, readonly"),
        "stdout: {out}"
    );

    let auto = run(&[
        "--policy",
        &fixture("23_domain_single_auto_select.yaml"),
        "compile",
        "--explain",
    ]);
    assert!(auto.status.success(), "stderr: {}", stderr(&auto));
    let out = stdout(&auto);
    assert!(out.contains("domain: build"), "stdout: {out}");
    assert!(
        out.contains("policy rules: build-artifact-no-network"),
        "stdout: {out}"
    );
    assert!(
        !out.contains("parent:"),
        "auto-selected domain has no parent: {out}"
    );
}

// `compile --explain` prints the full policy review to stdout: labels, sources
// and flows, per-rule lowering with limitations, and the event/audit semantics.
#[test]
fn compile_explain_prints_policy_review_report() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source AGENT = exec \"**\"\n  rule no-network:\n    notify connect endpoint \"*\" if AGENT unless target \"127.\"\n    because \"network review\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["compile", "--explain"])
        .output()
        .expect("run compile --explain");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    for expected in [
        "ActPlane policy review",
        "domain: none (flat policy)",
        "rules: 1 DSL rule(s), 1 lowered kernel matcher(s)",
        "labels:\n  - AGENT = 0x1",
        "flow: matching exec adds the label to the process and fork descendants",
        "1. rule no-network",
        "reason: network review",
        "limitations: IPv4 only",
        "causal_chain is a reported single-hop origin",
        "warnings: none",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in:\n{out}");
    }
}

// The flat `compile --explain` report renders the host/backend profile, the
// file-source flow support line, and the empty-transform note for a policy
// with no transforms.
#[test]
fn compile_explain_renders_static_analysis_sections() {
    let output = run(&[
        "--policy",
        &fixture("01_secret_no_exfil.yaml"),
        "compile",
        "--explain",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("domain: none (flat policy)"), "stdout: {out}");
    assert!(
        out.contains("engine profile: policy-selected attach set"),
        "stdout: {out}"
    );
    assert!(
        out.contains("review scope: selected policy and current host support"),
        "stdout: {out}"
    );
    assert!(
        out.contains("file source labels are applied through file open/read flow"),
        "stdout: {out}"
    );
    assert!(
        out.contains("coverage note: ordinary flows use the loaded hook profile"),
        "stdout: {out}"
    );
    assert!(out.contains("transforms:\n  - none"), "stdout: {out}");
}

// `compile` report modes are mutually exclusive, and the global policy source
// is either a file or an inline rule, never both. clap enforces these before
// the handler runs, so the exit code is 2 and the message names both flags.
#[test]
fn compile_and_policy_source_flag_conflicts_are_rejected() {
    let cases: &[(&[&str], &str, &str)] = &[
        (
            &["compile", "--out", "/tmp/x.bin", "--json"],
            "--out <FILE>",
            "--json",
        ),
        (&["compile", "--json", "--explain"], "--json", "--explain"),
        (
            &["compile", "--out", "/tmp/x.bin", "--domains"],
            "--out <FILE>",
            "--domains",
        ),
        (
            &[
                "--policy",
                "test/policies/01_secret_no_exfil.yaml",
                "--rule",
                "rule r: notify exec \"x\" if true",
                "compile",
                "--json",
            ],
            "--policy <POLICY>",
            "--rule <RULE>",
        ),
    ];
    for (args, first, second) in cases {
        let output = run(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?} should be a clap usage error: {}",
            stderr(&output)
        );
        let err = stderr(&output);
        assert!(
            err.contains(first) && err.contains(second),
            "{args:?} stderr must name {first:?} and {second:?}: {err}"
        );
        assert!(
            err.contains("cannot be used with"),
            "{args:?} stderr: {err}"
        );
    }
}

// The human compile report maps each rule to its backend hook in a
// `backend support:` section, distinguishing exec and connect coverage.
#[test]
fn compile_renders_backend_support_lines_in_human_mode() {
    let policy = r#"
source COMMAND = exec "**"

rule run:
  notify exec "git" if COMMAND
  because "exec coverage"

rule call:
  notify connect endpoint "1.2.3.4" if COMMAND
  because "connect coverage"
"#;
    let output = run(&["--rule", policy, "compile"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("backend support:"), "stdout: {out}");
    assert!(
        out.contains("- run: notify exec -> post-exec tracepoint report"),
        "stdout: {out}"
    );
    assert!(
        out.contains("- call: notify connect -> connect tracepoint report, IPv4 only"),
        "stdout: {out}"
    );
}

// The human-mode `compile` report renders static backend-support warnings that
// `--json` exposes structurally, and a warning-free policy says so.
#[test]
fn compile_renders_support_warnings_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source WILD = endpoint \"*.internal\"\n  rule r:\n    notify connect endpoint \"*\" if WILD\n    because \"x\"\n",
    )
    .unwrap();

    let warned = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("compile")
        .output()
        .expect("run compile");
    assert!(warned.status.success(), "stderr: {}", stderr(&warned));
    let out = stdout(&warned);
    assert!(out.contains("⚠ 1 warning(s):"), "stdout: {out}");
    assert!(
        out.contains(
            "source WILD = endpoint \"*.internal\" is unsupported: endpoint source pattern is not numeric IPv4 or an exact resolvable hostname."
        ),
        "stdout: {out}"
    );

    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule r:\n    notify exec \"git\" if COMMAND\n    because \"x\"\n",
    )
    .unwrap();
    let clean = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("compile")
        .output()
        .expect("run compile");
    assert!(clean.status.success(), "stderr: {}", stderr(&clean));
    let out = stdout(&clean);
    assert!(out.contains("✓ no warnings."), "stdout: {out}");
    assert!(!out.contains("warning(s)"), "stdout: {out}");
}

// `compile --json` reports the resolved domain binding as a structured object
// with locked/disabled/default rule partitions.
#[test]
fn compile_json_reports_domain_binding_object() {
    let output = run(&[
        "--policy",
        &fixture("15_domain_bindings.yaml"),
        "--domain",
        "review",
        "compile",
        "--json",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("compile json");
    assert_eq!(report["domain"]["name"], "review");
    assert_eq!(report["domain"]["parent"], "session");
    assert_eq!(
        report["domain"]["locked"],
        serde_json::json!(["no-git-branch", "readonly"])
    );
    assert_eq!(
        report["domain"]["disabled"],
        serde_json::json!(["no-network"])
    );
    assert_eq!(report["domain"]["default"], serde_json::json!([]));
    assert_eq!(report["ok"], true);
}

// `compile --json` exposes per-rule lowering provenance: rule id, effect,
// kernel op, resolved target pattern and positional argument, mutability, and
// the source/clause hash references.
#[test]
fn compile_json_reports_per_rule_lowering_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule no-git-push:\n    kill exec \"git\" \"push\" if COMMAND\n    because \"no push\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["compile", "--json"])
        .output()
        .expect("run compile --json");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");

    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["rule_count"], 1);
    assert_eq!(
        value["policy_ref"],
        tmp.path().join("actplane.yaml").to_str().unwrap()
    );
    assert!(
        value["domain"].is_null(),
        "flat policy has no domain: {}",
        value["domain"]
    );

    let rule = &value["rules"][0];
    assert_eq!(rule["name"], "no-git-push");
    assert_eq!(rule["rule_id"], 0);
    assert_eq!(rule["effect"], "kill");
    assert_eq!(rule["kernel_op"], "exec");
    assert_eq!(rule["target_kind"], "exec");
    assert_eq!(rule["target_pattern"], "**/git");
    assert_eq!(rule["target_arg"], "push");
    assert_eq!(rule["immutable"], false);
    assert_eq!(rule["source_ref"], "rule:no-git-push");
    assert_eq!(rule["clause_op"], "exec");
    assert_eq!(
        rule["clause_text"],
        "  kill exec \"git\" \"push\" if COMMAND"
    );
}

// `compile --json` reports source and clause spans and content hashes for each
// rule, so provenance is addressable per rule and per clause.
#[test]
fn compile_json_reports_rule_provenance_spans() {
    let output = run(&[
        "--rule",
        "source COMMAND = exec \"**\"\n  rule first:\n    kill exec \"git\" \"push\" if COMMAND\n    because \"a\"\n  rule second:\n    notify connect endpoint \"*\" if COMMAND\n    because \"b\"\n",
        "compile",
        "--json",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("compile json");
    let rules = report["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 2);
    let first = &rules[0];
    assert_eq!(first["name"], "first");
    assert_eq!(first["rule_id"], 0);
    assert_eq!(first["source_start_line"], 2);
    assert_eq!(first["source_end_line"], 4);
    assert!(
        first["source_hash"]
            .as_str()
            .unwrap_or("")
            .starts_with("fnv1a64:"),
        "source hash: {first}"
    );
    assert_eq!(first["clause_start_line"], 3);
    assert_eq!(first["clause_end_line"], 3);
    assert_eq!(first["clause_source_index"], 0);
    assert_eq!(first["ops"], serde_json::json!(["exec"]));

    let second = &rules[1];
    assert_eq!(second["name"], "second");
    assert_eq!(second["rule_id"], 1);
    assert_eq!(second["source_start_line"], 5);
    assert_eq!(second["clause_start_line"], 6);
    assert_ne!(first["clause_hash"], second["clause_hash"]);
}

// An endpoint target that is neither numeric IPv4 nor an exact resolvable
// hostname is reported as an `endpoint_target_unsupported` warning, and the
// affected endpoint source is reported separately.
#[test]
fn compile_json_reports_unsupported_endpoint_target_warning() {
    let policy = r#"
source WILD = endpoint "*.internal"

rule r:
  notify connect endpoint "*.internal" if WILD
  because "x"
"#;
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("compile json");
    let warnings = report["warnings"].as_array().expect("warnings array");
    let codes: Vec<&str> = warnings
        .iter()
        .filter_map(|warning| warning["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"endpoint_source_unsupported"),
        "warnings: {warnings:?}"
    );
    assert!(
        codes.contains(&"endpoint_target_unsupported"),
        "warnings: {warnings:?}"
    );
}

// `compile --out` rejects a directory and a non-regular existing file before
// writing, then succeeds for a regular path.
#[cfg(unix)]
#[test]
fn compile_out_rejects_directory_and_non_regular_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = "rule r:\n  notify exec \"git\" if true\n  because \"x\"\n";

    let dir = tmp.path().join("outdir");
    fs::create_dir(&dir).unwrap();
    let output = run(&["--rule", policy, "compile", "--out", dir.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("is a directory, not an output file"),
        "stderr: {}",
        stderr(&output)
    );

    let fifo = tmp.path().join("out.fifo");
    let fifo_status = Command::new("mkfifo").arg(&fifo).status().expect("mkfifo");
    assert!(fifo_status.success(), "mkfifo failed");
    let output = run(&["--rule", policy, "compile", "--out", fifo.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("is not a regular output file"),
        "stderr: {}",
        stderr(&output)
    );

    let blob = tmp.path().join("ok.bin");
    let output = run(&["--rule", policy, "compile", "--out", blob.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("compiled 1 rule(s)"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(fs::metadata(&blob).unwrap().is_file());
}

// `compile --out <path>` requires the parent directory to exist and reports
// the rule count on success.
#[test]
fn compile_out_requires_parent_directory_and_reports_success() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = fixture("01_secret_no_exfil.yaml");

    let missing_parent = run(&[
        "--policy",
        &policy,
        "compile",
        "--out",
        tmp.path().join("nested/policy.bin").to_str().unwrap(),
    ]);
    assert_eq!(
        missing_parent.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&missing_parent)
    );
    assert!(
        stderr(&missing_parent).contains("parent directory for")
            && stderr(&missing_parent).contains("does not exist or is not a directory"),
        "stderr: {}",
        stderr(&missing_parent)
    );

    let out = tmp.path().join("policy.bin");
    let ok = run(&[
        "--policy",
        &policy,
        "compile",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok.status.success(), "stderr: {}", stderr(&ok));
    assert!(
        stderr(&ok).contains("compiled 2 rule(s) to"),
        "stderr: {}",
        stderr(&ok)
    );
    assert!(
        fs::metadata(&out).unwrap().len() > 0,
        "blob must be written"
    );
}

// `compile`'s output modes (`--json`, `--explain`, `--domains`) are mutually
// exclusive, and `--report-out` requires one of them.
#[test]
fn compile_output_modes_are_mutually_exclusive() {
    let policy = fixture("15_domain_bindings.yaml");
    for (a, b) in [
        ("--json", "--explain"),
        ("--domains", "--json"),
        ("--domains", "--explain"),
    ] {
        let output = run(&["--policy", &policy, "compile", a, b]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{a} {b} stderr: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(&format!("the argument '{a}' cannot be used with '{b}'")),
            "{a} {b} stderr: {}",
            stderr(&output)
        );
    }

    let report_out = run(&[
        "--policy",
        &policy,
        "compile",
        "--domains",
        "--report-out",
        "/tmp/actplane-unused-report.txt",
    ]);
    assert_eq!(
        report_out.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&report_out)
    );
    assert!(
        stderr(&report_out).contains("--report-out requires --json or --explain"),
        "stderr: {}",
        stderr(&report_out)
    );
}

// `compile --report-out` refuses to clobber an existing artifact (even an empty
// one) unless `--force` is given, and `--force` overwrites it.
#[test]
fn compile_report_out_rejects_existing_artifact_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("review.txt");
    fs::write(&out, "stale\n").unwrap();
    let policy = "rule noop:\n  notify exec \"git\" if true\n  because \"noop\"\n";

    let without = run(&[
        "--rule",
        policy,
        "compile",
        "--explain",
        "--report-out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(
        without.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&without)
    );
    assert!(
        stderr(&without).contains("already exists (use --force to overwrite)"),
        "stderr: {}",
        stderr(&without)
    );
    assert_eq!(fs::read_to_string(&out).unwrap(), "stale\n");

    let forced = run(&[
        "--rule",
        policy,
        "compile",
        "--explain",
        "--force",
        "--report-out",
        out.to_str().unwrap(),
    ]);
    assert!(forced.status.success(), "stderr: {}", stderr(&forced));
    let artifact = fs::read_to_string(&out).unwrap();
    assert!(
        artifact.contains("ActPlane policy review"),
        "artifact: {artifact}"
    );
}

// `compile --report-out` writes the JSON report and the explain review to the
// requested file, leaving stdout empty.
#[test]
fn compile_report_out_writes_json_and_explain_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        "version: 1\npolicy: |\n  rule r:\n    notify exec \"git\" if true\n    because \"x\"\n",
    )
    .unwrap();

    let json_path = tmp.path().join("report.json");
    let json = run(&[
        "--policy",
        policy.to_str().unwrap(),
        "compile",
        "--json",
        "--report-out",
        json_path.to_str().unwrap(),
    ]);
    assert!(json.status.success(), "stderr: {}", stderr(&json));
    assert_eq!(stdout(&json), "");
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).expect("json report");
    assert!(report.get("backend_support").is_some(), "report: {report}");

    let explain_path = tmp.path().join("report.txt");
    let explain = run(&[
        "--policy",
        policy.to_str().unwrap(),
        "compile",
        "--explain",
        "--report-out",
        explain_path.to_str().unwrap(),
    ]);
    assert!(explain.status.success(), "stderr: {}", stderr(&explain));
    assert_eq!(stdout(&explain), "");
    assert!(
        fs::read_to_string(&explain_path)
            .unwrap()
            .starts_with("ActPlane policy review"),
        "explain artifact missing review header"
    );
}

// `control bind-child` adopts an existing process into a child domain, and
// `control launch-child` asks the parent to spawn a new child domain. Each
// sends its own op over the repo control socket.
#[cfg(unix)]
#[test]
fn control_bind_and_launch_child_send_their_ops() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept control client");
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read request");
            tx.send(serde_json::from_str::<serde_json::Value>(&line).expect("request JSON"))
                .expect("send request");
            serde_json::to_writer(
                &mut stream,
                &serde_json::json!({ "ok": true, "text": "ok" }),
            )
            .expect("write response");
            writeln!(stream).expect("write response newline");
        }
    });

    let run_in_tmp = |args: &[&str]| {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .args(args)
            .output()
            .expect("run control command");
        assert!(
            output.status.success(),
            "{args:?} stderr: {}",
            stderr(&output)
        );
    };
    run_in_tmp(&[
        "control",
        "bind-child",
        "--pid",
        "1234",
        "--child-id",
        "9",
        "--scope-id",
        "5",
    ]);
    run_in_tmp(&[
        "control",
        "launch-child",
        "--child-id",
        "3",
        "--scope-id",
        "5",
        "/bin/echo",
        "hi",
    ]);
    handle.join().expect("control server thread");

    let bind = rx.recv().expect("bind request");
    assert_eq!(bind["op"], "bind_child_domain");
    assert_eq!(bind["pid"], 1234);
    assert_eq!(bind["child_id"], 9);
    assert_eq!(bind["scope_id"], 5);
    let launch = rx.recv().expect("launch request");
    assert_eq!(launch["op"], "launch_child_domain");
    assert_eq!(launch["child_id"], 3);
    assert_eq!(launch["scope_id"], 5);
    assert_eq!(launch["cmd"], serde_json::json!(["/bin/echo", "hi"]));
}

// `control logs`, `control stop`, and `control restart` require a child or
// domain id, which `--domain-id` aliases, and fail before reaching the socket.
#[test]
fn control_child_commands_require_a_child_id() {
    for (args, expected) in [
        (
            vec!["control", "logs"],
            "control logs requires --child-id or --domain-id",
        ),
        (
            vec!["control", "stop"],
            "control stop requires --child-id or --domain-id",
        ),
        (
            vec!["control", "restart"],
            "control restart requires --child-id or --domain-id",
        ),
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1), "args: {args:?}");
        assert!(
            stderr(&output).contains(expected),
            "args: {args:?} stderr: {}",
            stderr(&output)
        );
    }
}

// `control logs`, `control stop`, and `control restart` each send their own
// child-domain op over the repo control socket, carrying the flags through.
#[cfg(unix)]
#[test]
fn control_child_lifecycle_commands_send_their_ops() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept control client");
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read request");
            tx.send(serde_json::from_str::<serde_json::Value>(&line).expect("request JSON"))
                .expect("send request");
            serde_json::to_writer(
                &mut stream,
                &serde_json::json!({ "ok": true, "text": "ok" }),
            )
            .expect("write response");
            writeln!(stream).expect("write response newline");
        }
    });

    let run_in_tmp = |args: &[&str]| {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .args(args)
            .output()
            .expect("run control command");
        assert!(
            output.status.success(),
            "{args:?} stderr: {}",
            stderr(&output)
        );
    };
    run_in_tmp(&[
        "control",
        "logs",
        "--child-id",
        "7",
        "--stream",
        "stdout",
        "--max-bytes",
        "1024",
    ]);
    run_in_tmp(&["control", "stop", "--child-id", "7"]);
    run_in_tmp(&["control", "restart", "--child-id", "7"]);
    handle.join().expect("control server thread");

    let logs = rx.recv().expect("logs request");
    assert_eq!(logs["op"], "read_child_domain_logs");
    assert_eq!(logs["child_id"], 7);
    assert_eq!(logs["stream"], "stdout");
    assert_eq!(logs["max_bytes"], 1024);
    assert_eq!(
        rx.recv().expect("stop request")["op"],
        "terminate_child_domain"
    );
    let restart = rx.recv().expect("restart request");
    assert_eq!(restart["op"], "restart_child_domain");
    assert_eq!(restart["terminate_existing"], false);
}

// `control children` reaches the control server, and the argument shape of
// `bind-child` / `launch-child` is enforced by clap with a usage error.
#[test]
fn control_children_and_required_argument_errors() {
    let tmp = tempfile::tempdir().unwrap();

    let children = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["control", "children"])
        .output()
        .expect("run control children");
    assert!(!children.status.success());
    assert!(
        stderr(&children).contains(".actplane/control.json"),
        "stderr: {}",
        stderr(&children)
    );

    let bind = run(&["control", "bind-child"]);
    assert_eq!(bind.status.code(), Some(2), "stderr: {}", stderr(&bind));
    let bind_err = stderr(&bind);
    assert!(
        bind_err.contains("required arguments") && bind_err.contains("--pid <PID>"),
        "stderr: {bind_err}"
    );

    let launch = run(&["control", "launch-child"]);
    assert_eq!(launch.status.code(), Some(2), "stderr: {}", stderr(&launch));
    let launch_err = stderr(&launch);
    assert!(
        launch_err.contains("required arguments") && launch_err.contains("<CMD>..."),
        "stderr: {launch_err}"
    );
}

// `control children` reads the repo control socket and sends the
// `list_child_domains` request, printing the server's text reply.
#[cfg(unix)]
#[test]
fn control_children_queries_local_server() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let mut line = String::new();
        std::io::BufReader::new(stream.try_clone().expect("clone stream"))
            .read_line(&mut line)
            .expect("read request");
        tx.send(serde_json::from_str::<serde_json::Value>(&line).expect("request JSON"))
            .expect("send request");
        serde_json::to_writer(
            &mut stream,
            &serde_json::json!({ "ok": true, "text": "2 child domain(s)" }),
        )
        .expect("write response");
        writeln!(stream).expect("write response newline");
    });

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["control", "children"])
        .output()
        .expect("run control children");
    handle.join().expect("control server thread");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "2 child domain(s)");
    let request = rx.recv().expect("captured request");
    assert_eq!(request["op"], "list_child_domains");
}

// `control delta add` resolves the `--domain-id` alias into `target_id` and
// sends an on-disk `--delta` file with its path as the policy ref.
#[cfg(unix)]
#[test]
fn control_delta_add_resolves_alias_and_file_source() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();
    let delta_file = tmp.path().join("delta.dsl");
    fs::write(
        &delta_file,
        "rule d:\n  notify exec \"git\" if true\n  because \"y\"\n",
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept control client");
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read request");
            tx.send(serde_json::from_str::<serde_json::Value>(&line).expect("request JSON"))
                .expect("send request");
            serde_json::to_writer(
                &mut stream,
                &serde_json::json!({ "ok": true, "text": "ok" }),
            )
            .expect("write response");
            writeln!(stream).expect("write response newline");
        }
    });

    let alias = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "control",
            "delta",
            "add",
            "--domain-id",
            "8",
            "--delta-text",
            "rule d:\n  notify exec \"git\" if true\n  because \"y\"",
        ])
        .output()
        .expect("run delta add alias");
    assert!(alias.status.success(), "stderr: {}", stderr(&alias));
    let file = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "control",
            "delta",
            "add",
            "--delta",
            delta_file.to_str().unwrap(),
        ])
        .output()
        .expect("run delta add file");
    assert!(file.status.success(), "stderr: {}", stderr(&file));
    handle.join().expect("control server thread");

    let alias_request = rx.recv().expect("alias request");
    assert_eq!(alias_request["op"], "append_policy_delta");
    assert_eq!(alias_request["target_id"], 8);
    assert_eq!(alias_request["policy_ref"], "--delta-text[0]");
    let file_request = rx.recv().expect("file request");
    assert_eq!(file_request["op"], "append_policy_delta");
    assert_eq!(file_request["policy_ref"], delta_file.to_str().unwrap());
    assert_eq!(
        file_request["policy"],
        "rule d:\n  notify exec \"git\" if true\n  because \"y\"\n"
    );
}

// `control delta add --delta <FILE>` reads the fragment from disk, and a
// missing file is reported before any control-server connection.
#[test]
fn control_delta_add_reports_unreadable_delta_file() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "control",
            "delta",
            "add",
            "--target-id",
            "1",
            "--delta",
            "NOPE.dsl",
        ])
        .output()
        .expect("run control delta add --delta");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let err = stderr(&output);
    assert!(
        err.contains("cannot read policy delta NOPE.dsl: No such file or directory"),
        "stderr: {err}"
    );
    assert!(
        !err.contains("control.json"),
        "the delta must be read before the control server is contacted: {err}"
    );
}

// `control launch-child --delta-text` embeds the inline fragment in the
// request's `policy` field (with a provenance comment) and sends the documented
// restart defaults.
#[cfg(unix)]
#[test]
fn control_launch_child_sends_inline_delta_policy() {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixListener;
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        tx.send(serde_json::from_str::<serde_json::Value>(&line).unwrap())
            .unwrap();
        stream
            .write_all(b"{\"ok\":true,\"text\":\"launched\"}\n")
            .unwrap();
    });

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "control",
            "launch-child",
            "--child-id",
            "3",
            "--delta-text",
            "rule x:\n  notify exec \"g\" if true\n  because \"y\"\n",
            "/bin/echo",
            "hi",
        ])
        .output()
        .expect("run control command");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let request = rx.recv().expect("launch request");
    handle.join().expect("control server thread");

    assert_eq!(request["op"], "launch_child_domain");
    assert_eq!(request["child_id"], 3);
    assert_eq!(request["cmd"], serde_json::json!(["/bin/echo", "hi"]));
    assert_eq!(request["scope_id"], 0);
    assert_eq!(request["restart_policy"], "never");
    assert_eq!(request["restart_limit"], 3);
    assert_eq!(request["restart_backoff_ms"], 1000);
    let policy = request["policy"].as_str().expect("policy");
    assert!(
        policy.contains("# delta --delta-text[0]"),
        "policy: {policy}"
    );
    assert!(policy.contains("rule x:"), "policy: {policy}");
}

// Non-default restart supervision and approval metadata are forwarded verbatim,
// and `--delta <file>` is embedded with its path as the provenance comment.
#[cfg(unix)]
#[test]
fn control_launch_child_forwards_restart_and_approval_options() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        tmp.path().join("delta.dsl"),
        "rule d:\n  notify exec \"git\" if true\n  because \"y\"\n",
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let mut line = String::new();
        std::io::BufReader::new(stream.try_clone().expect("clone stream"))
            .read_line(&mut line)
            .expect("read request");
        tx.send(serde_json::from_str::<serde_json::Value>(&line).expect("request JSON"))
            .expect("send request");
        std::io::Write::write_all(&mut stream, b"{\"ok\":true,\"text\":\"launched\"}\n")
            .expect("write response");
    });

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "control",
            "launch-child",
            "--child-id",
            "7",
            "--scope-id",
            "9",
            "--restart-policy",
            "on_exit",
            "--restart-limit",
            "5",
            "--restart-backoff-ms",
            "250",
            "--approved-by",
            "reviewer",
            "--approval-ref",
            "ticket-1",
            "--generated-by",
            "cli-test",
            "--delta",
            tmp.path().join("delta.dsl").to_str().unwrap(),
            "/bin/true",
        ])
        .output()
        .expect("run control launch-child");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let request = rx.recv().expect("launch request");
    handle.join().expect("control server thread");

    assert_eq!(request["restart_policy"], "on_exit");
    assert_eq!(request["restart_limit"], 5);
    assert_eq!(request["restart_backoff_ms"], 250);
    assert_eq!(request["scope_id"], 9);
    assert_eq!(request["approved_by"], "reviewer");
    assert_eq!(request["approval_ref"], "ticket-1");
    assert_eq!(request["generated_by"], "cli-test");
    let policy = request["policy"].as_str().expect("policy");
    assert!(policy.contains("# delta "), "policy: {policy}");
    assert!(policy.contains("rule d:"), "policy: {policy}");
}

// `control restart` forwards the fresh-domain id and terminate flag, and the
// `logs`/`restart` `--domain-id` alias resolves into the `child_id` field.
#[cfg(unix)]
#[test]
fn control_restart_forwards_fresh_domain_and_alias_resolves() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept control client");
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read request");
            tx.send(serde_json::from_str::<serde_json::Value>(&line).expect("request JSON"))
                .expect("send request");
            serde_json::to_writer(
                &mut stream,
                &serde_json::json!({ "ok": true, "text": "ok" }),
            )
            .expect("write response");
            writeln!(stream).expect("write response newline");
        }
    });

    let run_in_tmp = |args: &[&str]| {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .args(args)
            .output()
            .expect("run control command");
        assert!(
            output.status.success(),
            "{args:?} stderr: {}",
            stderr(&output)
        );
    };
    run_in_tmp(&[
        "control",
        "restart",
        "--child-id",
        "3",
        "--new-child-id",
        "55",
        "--terminate-existing",
    ]);
    run_in_tmp(&["control", "logs", "--domain-id", "9"]);
    handle.join().expect("control server thread");

    let restart = rx.recv().expect("restart request");
    assert_eq!(restart["op"], "restart_child_domain");
    assert_eq!(restart["child_id"], 3);
    assert_eq!(restart["new_child_id"], 55);
    assert_eq!(restart["terminate_existing"], true);
    let logs = rx.recv().expect("logs request");
    assert_eq!(logs["op"], "read_child_domain_logs");
    assert_eq!(logs["child_id"], 9);
}

// `control status` reports each way the control endpoint can be unavailable:
// missing state file, malformed state, and a state file pointing at an absent
// socket.
#[test]
fn control_status_reports_unavailable_endpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let run_in = |dir: &Path| {
        Command::new(actplane())
            .current_dir(dir)
            .args(["control", "status"])
            .output()
            .expect("run control status")
    };

    let missing = run_in(tmp.path());
    assert_eq!(
        missing.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&missing)
    );
    assert!(
        stderr(&missing).contains("control.json: No such file or directory"),
        "stderr: {}",
        stderr(&missing)
    );

    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        "{\"socket\":\"/tmp/x.sock\"}",
    )
    .unwrap();
    let malformed = run_in(tmp.path());
    assert_eq!(
        malformed.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&malformed)
    );
    assert!(
        stderr(&malformed).contains("parse")
            && stderr(&malformed).contains("missing field `schema`"),
        "stderr: {}",
        stderr(&malformed)
    );

    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": 1,
            "proc_start_time": null,
            "socket_path": tmp.path().join("absent.sock"),
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": u32::MAX,
        }))
        .unwrap(),
    )
    .unwrap();
    let absent_socket = run_in(tmp.path());
    assert_eq!(
        absent_socket.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&absent_socket)
    );
    assert!(
        stderr(&absent_socket).contains("connect")
            && stderr(&absent_socket).contains("absent.sock: No such file or directory"),
        "stderr: {}",
        stderr(&absent_socket)
    );
}

// `control status` reports the unreachable control server when no state file
// exists, and `control delta add` requires an inline or file delta.
#[test]
fn control_status_and_delta_input_guards() {
    let tmp = tempfile::tempdir().unwrap();

    let status = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["control", "status"])
        .output()
        .expect("run control status");
    assert!(!status.status.success());
    assert!(
        stderr(&status).contains(".actplane/control.json"),
        "stderr: {}",
        stderr(&status)
    );
    assert!(
        stderr(&status).contains("No such file or directory"),
        "stderr: {}",
        stderr(&status)
    );

    let delta = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["control", "delta", "add", "--target-id", "1"])
        .output()
        .expect("run control delta add");
    assert!(!delta.status.success());
    assert!(
        stderr(&delta).contains("control delta add requires --delta or --delta-text"),
        "stderr: {}",
        stderr(&delta)
    );
}

// A reachable `control status` server receives the `status` op and the client
// prints the reply text verbatim. The unusable-endpoint paths are covered
// elsewhere.
#[cfg(unix)]
#[test]
fn control_status_queries_live_server_and_prints_text() {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixListener;
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        tx.send(serde_json::from_str::<serde_json::Value>(&line).unwrap())
            .unwrap();
        stream
            .write_all(b"{\"ok\":true,\"text\":\"engine root 7, 2 rules\"}\n")
            .unwrap();
    });

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["control", "status"])
        .output()
        .expect("run control status");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "engine root 7, 2 rules\n");
    let request = rx.recv().expect("status request");
    handle.join().expect("control server thread");
    assert_eq!(request["op"], "status");
}

// `doctor` prints a human-readable setup report and exits non-zero when any
// check is a problem. Exact counts are host-dependent (BTF, privileges,
// installed hooks), so assert the policy resolution lines and the missing-file
// failure, which are deterministic.
#[test]
fn doctor_reports_policy_state_and_missing_policy_error() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("p.yaml");
    fs::copy(fixture("01_secret_no_exfil.yaml"), &policy).unwrap();

    let output = run(&["doctor", "--policy", policy.to_str().unwrap()]);
    let out = stdout(&output);
    assert!(out.contains("ActPlane doctor"), "stdout: {out}");
    assert!(
        out.contains(&format!("✓ policy: {} (2 rule(s))", policy.display())),
        "stdout: {out}"
    );
    assert!(out.contains("kernel BTF:"), "stdout: {out}");
    assert!(out.contains("eBPF privilege:"), "stdout: {out}");
    assert!(out.contains("setup has"), "stdout: {out}");

    // A policy path that does not exist is reported as a problem.
    let missing = run(&[
        "doctor",
        "--policy",
        tmp.path().join("absent.yaml").to_str().unwrap(),
    ]);
    assert!(!missing.status.success());
    assert!(
        stdout(&missing).contains(&format!(
            "✗ policy: reading {}",
            tmp.path().join("absent.yaml").display()
        )),
        "stdout: {}",
        stdout(&missing)
    );
}

// For a policy with `domains:`, `doctor` annotates the policy line with the
// resolved domain, honours an explicit `--domain`, and rejects an unknown one.
#[test]
fn doctor_annotates_domain_policy_resolution() {
    let policy = fixture("15_domain_bindings.yaml");

    let default = run(&["doctor", "--policy", &policy]);
    let out = stdout(&default);
    assert!(
        out.contains(&format!("✓ policy: {policy} domain `review` (2 rule(s))")),
        "stdout: {out}"
    );

    let session = run(&["doctor", "--policy", &policy, "--domain", "session"]);
    assert!(
        stdout(&session).contains(&format!("✓ policy: {policy} domain `session` (2 rule(s))")),
        "stdout: {}",
        stdout(&session)
    );

    let unknown = run(&["doctor", "--policy", &policy, "--domain", "bogus"]);
    assert!(
        stdout(&unknown).contains("✗ policy: unknown domain `bogus` (available: review, session)"),
        "stdout: {}",
        stdout(&unknown)
    );
}

// `doctor --rule` diagnoses inline DSL instead of a discovered policy file,
// reporting the rule count on success and the parse error on failure.
#[test]
fn doctor_diagnoses_inline_rule_policy() {
    let good = run(&[
        "doctor",
        "--rule",
        "rule r1:\n  notify exec \"git\" if true\n  because \"x\"",
    ]);
    let out = stdout(&good);
    assert!(
        out.contains("✓ policy: --rule (1 rule(s))"),
        "stdout: {out}"
    );

    let bad = run(&["doctor", "--rule", "garbage dsl"]);
    assert_eq!(bad.status.code(), Some(1), "stderr: {}", stderr(&bad));
    assert!(
        stdout(&bad).contains("✗ policy: --rule does not compile: unknown declaration 'garbage'"),
        "stdout: {}",
        stdout(&bad)
    );
}

// `doctor` flags present-but-unwired Codex/MCP configs, and `init --with-codex
// --with-mcp --force` repairs them so doctor stops complaining.
#[test]
fn doctor_flags_unwired_integrations_and_init_repairs_them() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join(".codex")).unwrap();
    fs::write(
        tmp.path().join(".codex/hooks.json"),
        r#"{"hooks":{"PostToolUse":[{"hooks":[{"command":"echo hi"}]}]}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join(".mcp.json"),
        r#"{"mcpServers":{"other":{"command":"other"}}}"#,
    )
    .unwrap();

    let before = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    assert_eq!(before.status.code(), Some(1), "stderr: {}", stderr(&before));
    let out = stdout(&before);
    assert!(
        out.contains("exists but is not wired to `actplane feedback-hook`")
            && out.contains("init --with-codex --force"),
        "stdout: {out}"
    );
    assert!(
        out.contains("does not auto-attach with PATH `actplane`")
            && out.contains("init --with-mcp"),
        "stdout: {out}"
    );

    let init = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--with-codex", "--with-mcp", "--force"])
        .output()
        .expect("run init --with-codex --with-mcp --force");
    assert!(init.status.success(), "stderr: {}", stderr(&init));

    let after = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    let out = stdout(&after);
    assert!(
        out.contains("✓ Codex hook:") && out.contains("✓ project MCP config:"),
        "doctor must see the repaired integrations:\n{out}"
    );
    assert!(
        !out.contains("not wired to `actplane feedback-hook`")
            && !out.contains("does not auto-attach"),
        "stdout: {out}"
    );
}

// `doctor` reports a discovered policy that does not compile, distinct from a
// missing policy, and exits non-zero.
#[test]
fn doctor_reports_noncompiling_discovered_policy() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  rule bad:\n    prevent exec \"git\"\n    because \"unknown declaration\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains(&format!(
            "✗ policy: {} does not compile: unknown declaration 'prevent'",
            tmp.path().join("actplane.yaml").display()
        )),
        "stdout: {out}"
    );
    assert!(
        !out.contains("no actplane.yaml found"),
        "the policy exists, so it must not be reported as missing:\n{out}"
    );
}

// With no `--policy`, `doctor` discovers `actplane.yaml` upward from cwd. In a
// fresh directory it reports the missing policy and the missing integrations,
// and exits non-zero.
#[test]
fn doctor_reports_missing_discovered_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("ActPlane doctor"), "stdout: {out}");
    assert!(
        out.contains("no actplane.yaml found; pass --policy <file> or --rule <dsl>"),
        "stdout: {out}"
    );
    assert!(
        out.contains("Codex hook: missing") && out.contains(".codex/hooks.json"),
        "stdout: {out}"
    );
    assert!(
        out.contains("project MCP config: .mcp.json missing"),
        "stdout: {out}"
    );
    assert!(
        out.contains("setup has") && out.contains("problem(s)"),
        "stdout: {out}"
    );
}

// Every `actplane <subcommand...> --flag` spelling cited in the top-level docs
// must resolve to a real flag, so a renamed or removed CLI option fails CI
// instead of silently rotting the documentation.
#[test]
fn documented_actplane_flags_exist() {
    let docs_dir = format!("{}/../../docs", env!("CARGO_MANIFEST_DIR"));
    const DOCS: &[&str] = &[
        "agent-integrations.md",
        "cookbook.md",
        "rule-language.md",
        "security_model.md",
        "support-matrix.md",
        "compare.md",
    ];
    let commands = discover_subcommands(&[]);
    let mut checked = 0usize;
    for doc in DOCS {
        let text = match fs::read_to_string(format!("{docs_dir}/{doc}")) {
            Ok(text) => text,
            Err(_) => continue,
        };
        for (path, flags) in documented_invocations(&text, &commands) {
            let mut help_args: Vec<&str> = path.split_whitespace().collect();
            help_args.push("--help");
            let help = stdout(&run(&help_args));
            for flag in flags {
                assert!(
                    help.contains(&format!("--{flag}")),
                    "docs/{doc} cites `actplane {path} --{flag}` but that flag is absent:\n{help}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 10,
        "expected to verify documented flags, only checked {checked}"
    );
}

/// Names of the subcommands listed under `Commands:` in `actplane <path> --help`.
fn discover_subcommands(path: &[&str]) -> Vec<String> {
    let mut args: Vec<&str> = path.to_vec();
    args.push("--help");
    let help = stdout(&run(&args));
    let mut names = Vec::new();
    let mut in_commands = false;
    for line in help.lines() {
        if line == "Commands:" {
            in_commands = true;
            continue;
        }
        if !in_commands {
            continue;
        }
        if line.trim().is_empty() {
            break;
        }
        if let Some(token) = line.split_whitespace().next() {
            names.push(token.to_string());
        }
    }
    names
}

/// Collect `actplane <subcommand...> --flag...` invocations from a doc string.
/// The subcommand path is the leading lowercase words that resolve to real
/// command names, so prose like `--json/--explain reports` does not invent a
/// command.
fn documented_invocations(text: &str, commands: &[String]) -> Vec<(String, Vec<String>)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find("actplane ") {
        let start = cursor + offset + "actplane ".len();
        let mut end = start;
        while end < bytes.len() {
            let c = bytes[end] as char;
            if c.is_ascii_alphanumeric() || c == '-' || c == ' ' {
                end += 1;
            } else {
                break;
            }
        }
        let words: Vec<&str> = text[start..end].split_whitespace().collect();
        if let Some(first) = words.first() {
            if first.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
                let mut path: Vec<String> = Vec::new();
                let mut flags: Vec<String> = Vec::new();
                let mut valid = true;
                for word in &words {
                    if let Some(flag) = word.strip_prefix("--") {
                        flags.push(flag.to_string());
                    } else if flags.is_empty() {
                        let resolved = if path.is_empty() {
                            commands.iter().any(|c| c == word)
                        } else {
                            let parent: Vec<&str> = path.iter().map(String::as_str).collect();
                            discover_subcommands(&parent).iter().any(|c| c == word)
                        };
                        if resolved {
                            path.push(word.to_string());
                        } else {
                            valid = false;
                            break;
                        }
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && !path.is_empty() && !flags.is_empty() {
                    found.push((path.join(" "), flags));
                }
            }
        }
        cursor = end;
    }
    found
}

// `--domain` selects a named runtime domain from a policy file. An unknown
// name lists the available domains, and a policy without a `domains:` section
// rejects `--domain` outright. cli_ux.rs covered only the success path.
#[test]
fn domain_selection_reports_unknown_and_domainless_policies() {
    let unknown = run(&[
        "--policy",
        &fixture("15_domain_bindings.yaml"),
        "--domain",
        "nope",
        "compile",
    ]);
    assert!(!unknown.status.success());
    assert!(
        stderr(&unknown).contains("unknown domain `nope` (available: review, session)"),
        "stderr: {}",
        stderr(&unknown)
    );

    let domainless = run(&[
        "--policy",
        &fixture("01_secret_no_exfil.yaml"),
        "--domain",
        "review",
        "compile",
    ]);
    assert!(!domainless.status.success());
    assert!(
        stderr(&domainless)
            .contains("`--domain` requires a policy file with `rules:` and `domains:`"),
        "stderr: {}",
        stderr(&domainless)
    );
}

// A policy with a `declassify` clause renders that transform in the `--explain`
// transforms section, alongside the runtime-append authority note.
#[test]
fn compile_explain_renders_declassify_transform() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source SECRET = file \"**/.env\"\n  rule r:\n    kill connect endpoint \"*\" if SECRET\n    because \"x\"\n  declassify SECRET by exec \"**/redact\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["compile", "--explain"])
        .output()
        .expect("run compile --explain");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("labels:\n  - SECRET = 0x1"), "stdout: {out}");
    assert!(
        out.contains(
            "  - declassify SECRET by exec \"**/redact\" -> removes the label when the gate exec matches"
        ),
        "stdout: {out}"
    );
    assert!(
        out.contains(
            "  - runtime appended declassification still requires AUTH_DECLASSIFY and authority over the cleared local label bits"
        ),
        "stdout: {out}"
    );
}

// A policy declaring `runtime.approval.append_delta` renders its admission
// model in the `--explain` runtime-delta section.
#[test]
fn compile_explain_renders_append_delta_approval_config() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\nruntime:\n  approval:\n    append_delta:\n      required: true\n      require_approval_ref: true\n      require_generated_by: true\n      allowed_approvers: [alice, bob]\npolicy: |\n  source COMMAND = exec \"**\"\n  rule r:\n    notify exec \"git\" if COMMAND\n    because \"x\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["compile", "--explain"])
        .output()
        .expect("run compile --explain");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    for expected in [
        "runtime delta admission:\n  - append policy delta approval: required",
        "required metadata: approved_by, approval_ref, generated_by",
        "allowed approvers: alice, bob",
        "admission model: static_metadata_allowlist",
        "external_verified=false, signature=null",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in:\n{out}");
    }
}

// An `endorse` clause renders as the label-adding counterpart of `declassify`
// in the `--explain` transforms section.
#[test]
fn compile_explain_renders_endorse_transform() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source TRUST = exec \"**/gate\"\n  rule r:\n    notify connect endpoint \"*\" if true\n    because \"x\"\n  endorse TRUST by exec \"**/approve\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["compile", "--explain"])
        .output()
        .expect("run compile --explain");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("labels:\n  - TRUST = 0x1"), "stdout: {out}");
    assert!(
        out.contains(
            "  - endorse TRUST by exec \"**/approve\" -> adds the label when the gate exec matches"
        ),
        "stdout: {out}"
    );
}

// The `--explain` sources section renders an endpoint source's flow direction
// and the in-kernel IPv6 limitation.
#[test]
fn compile_explain_renders_endpoint_source_flow() {
    let policy = fixture("18_untrusted_tool_network.yaml");
    let output = run(&["--policy", &policy, "compile", "--explain"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("labels:\n  - TOOL = 0x1\n  - UNTRUST = 0x2"),
        "stdout: {out}"
    );
    assert!(
        out.contains("source UNTRUST = endpoint \"*\"")
            && out.contains(
                "flow: matching IPv4 endpoint carries the label; recv copies it into the process, connect records egress labels"
            ),
        "stdout: {out}"
    );
    assert!(
        out.contains("limitations: IPv6 is not enforced in-kernel"),
        "stdout: {out}"
    );
}

// `compile --explain` prints an `after ... since ...` staleness gate verbatim
// in the clause line and reports the argv-based enforcement limitation.
#[test]
fn compile_explain_renders_stale_gate_clause() {
    let policy = fixture("06_test_before_commit_since.yaml");
    let output = run(&["--policy", &policy, "compile", "--explain"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains(
            "clause 1: block exec \"**/git\" \"commit\" if AGENT unless after exec \"**/pytest\" since write \"src/**\" or write \"tests/**\""
        ),
        "stdout: {out}"
    );
    assert!(
        out.contains("enforcement: unsupported; argv is only available after exec"),
        "stdout: {out}"
    );
    assert!(
        out.contains("limitations: use kill exec for post-exec termination"),
        "stdout: {out}"
    );
}

// `feedback-hook` is the adapter that turns new bytes in the corrective
// feedback file into an agent `additionalContext` payload. It reads the hook
// event from stdin, locates the feedback file for the given cwd (honoring
// `ACTPLANE_FEEDBACK_FILE` and the recorded hook state), emits the new bytes
// once, advances the stored offset, and stays silent when nothing changed.
#[test]
fn feedback_hook_emits_new_feedback_once_and_advances_state() {
    let tmp = tempfile::tempdir().unwrap();
    let actplane_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&actplane_dir).unwrap();
    let feedback_path = actplane_dir.join("last-violation.txt");
    fs::write(&feedback_path, "TAINT_VIOLATION rule=first\n").unwrap();

    // State records the current file length as the consumed offset, so the
    // first invocation must emit the whole file.
    let state_path = actplane_dir.join("feedback-hook.state.json");
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "feedback_file": feedback_path,
            "offset": 0,
        }))
        .unwrap(),
    )
    .unwrap();

    let stdin = serde_json::to_string(&serde_json::json!({
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
    }))
    .unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["feedback-hook"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(stdin.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run feedback-hook");
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("feedback-hook stdout JSON");
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext string");
    assert!(
        context.contains("TAINT_VIOLATION rule=first"),
        "context missing feedback payload: {context}"
    );
    assert!(
        context.contains("authoritative feedback"),
        "context missing kernel-feedback framing: {context}"
    );

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(
        state["offset"].as_u64(),
        Some("TAINT_VIOLATION rule=first\n".len() as u64),
        "hook state must advance the consumed offset"
    );

    // A second run with no appended bytes must stay silent.
    let repeat = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["feedback-hook"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(stdin.as_bytes())?;
            child.wait_with_output()
        })
        .expect("rerun feedback-hook");
    assert!(repeat.status.success(), "stderr: {}", stderr(&repeat));
    assert!(
        stdout(&repeat).trim().is_empty(),
        "unchanged feedback must not re-emit: {}",
        stdout(&repeat)
    );
}

// `feedback-hook` honors `ACTPLANE_FEEDBACK_FILE` / `ACTPLANE_HOOK_STATE`
// overrides, and after the state's offset it emits only the appended tail,
// not the whole file.
#[test]
fn feedback_hook_honors_env_override_and_emits_only_new_tail() {
    let tmp = tempfile::tempdir().unwrap();
    let feedback = tmp.path().join("alt-feedback.txt");
    fs::write(&feedback, "HEAD\nTAIL-NEW\n").unwrap();
    let state = tmp.path().join("hook-state.json");
    fs::write(
        &state,
        serde_json::to_string_pretty(&serde_json::json!({
            "feedback_file": feedback,
            "offset": 5,
        }))
        .unwrap(),
    )
    .unwrap();

    let stdin = serde_json::to_string(&serde_json::json!({ "cwd": tmp.path() })).unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .env("ACTPLANE_FEEDBACK_FILE", &feedback)
        .env("ACTPLANE_HOOK_STATE", &state)
        .args(["feedback-hook"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(stdin.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run feedback-hook");
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("feedback-hook stdout JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext string");
    assert!(
        context.contains("TAIL-NEW"),
        "context must include the appended tail: {context}"
    );
    assert!(
        !context.contains("HEAD"),
        "context must not repeat consumed bytes: {context}"
    );
}

// The `feedback-hook` adapter is a silent no-op when there is nothing new to
// report: it exits 0 with empty stdout both when the offset is already at EOF
// and when the feedback file does not exist.
#[test]
fn feedback_hook_is_silent_when_no_new_feedback() {
    let tmp = tempfile::tempdir().unwrap();
    let feedback = tmp.path().join("feedback.txt");
    fs::write(&feedback, "ONE TWO\n").unwrap();
    let at_eof = tmp.path().join("at-eof.json");
    fs::write(
        &at_eof,
        serde_json::to_string(&serde_json::json!({ "feedback_file": feedback, "offset": 8 }))
            .unwrap(),
    )
    .unwrap();

    let missing = tmp.path().join("missing.txt");
    let missing_state = tmp.path().join("missing.json");
    fs::write(
        &missing_state,
        serde_json::to_string(&serde_json::json!({ "feedback_file": missing, "offset": 0 }))
            .unwrap(),
    )
    .unwrap();

    let stdin = serde_json::to_string(&serde_json::json!({ "cwd": tmp.path() })).unwrap();
    for state in [&at_eof, &missing_state] {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .env("ACTPLANE_HOOK_STATE", state)
            .args(["feedback-hook"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().unwrap().write_all(stdin.as_bytes())?;
                child.wait_with_output()
            })
            .expect("run feedback-hook");
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(
            output.stdout.is_empty(),
            "expected silent no-op, got stdout: {}",
            stdout(&output)
        );
    }
}

// `--generate` is exclusive with `--template` and `--list-templates`, and an
// unreadable `--instructions` file fails before any policy is written.
#[test]
fn generate_flag_conflicts_and_instruction_errors() {
    let generate_template = run(&["init", "--generate", "--template", "no-git-branch"]);
    assert_eq!(
        generate_template.status.code(),
        Some(2),
        "stderr: {}",
        stderr(&generate_template)
    );
    assert!(
        stderr(&generate_template)
            .contains("the argument '--generate' cannot be used with '--template <TEMPLATE>'"),
        "stderr: {}",
        stderr(&generate_template)
    );

    let list_generate = run(&["init", "--list-templates", "--generate"]);
    assert_eq!(
        list_generate.status.code(),
        Some(2),
        "stderr: {}",
        stderr(&list_generate)
    );
    assert!(
        stderr(&list_generate)
            .contains("the argument '--list-templates' cannot be used with '--generate'"),
        "stderr: {}",
        stderr(&list_generate)
    );

    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    let instructions = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--generate", "--instructions", "NOPE.md"])
        .output()
        .expect("run init --generate --instructions");
    assert_eq!(
        instructions.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&instructions)
    );
    assert!(
        stderr(&instructions).contains("reading instructions NOPE.md: No such file or directory"),
        "stderr: {}",
        stderr(&instructions)
    );
    assert!(
        !tmp.path().join("actplane.yaml").exists(),
        "no policy may be written when instructions are unreadable"
    );
}

// `--generate` reads project instructions and picks templates from their
// content: an instruction forbidding `git push` selects `no-git-push`.
#[test]
fn generate_selects_template_from_instruction_content() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    fs::write(
        tmp.path().join("AGENTS.md"),
        "# AGENTS\n\nAlways run tests before committing. Never push to main.\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--generate", "--print"])
        .output()
        .expect("run init --generate --print");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains(&format!(
            "# Instructions considered:\n# - {}",
            tmp.path().join("AGENTS.md").display()
        )),
        "instructions source must be listed:\n{out}"
    );
    assert!(
        stderr(&output).contains("selected no-git-push")
            && stderr(&output).contains("project instructions forbid agent-run git push"),
        "the git-push instruction must select no-git-push:\n{}",
        stderr(&output)
    );
    assert!(
        out.contains("# template: no-git-push")
            && out.contains("kill exec \"git\" \"push\" if COMMAND"),
        "the candidate policy must embed the selected rule:\n{out}"
    );

    let write = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--generate"])
        .output()
        .expect("run init --generate");
    assert!(write.status.success(), "stderr: {}", stderr(&write));
    let compiled = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("compile")
        .output()
        .expect("run compile");
    assert!(
        compiled.status.success(),
        "generated candidate must compile: {}",
        stderr(&compiled)
    );
}

// `--with-codex` writes the AGENTS.md guidance without clobbering an existing
// file: it keeps an existing AGENTS.md, links to CLAUDE.md when present, and
// writes a stub otherwise.
#[test]
fn init_with_codex_preserves_agents_guidance() {
    // An existing AGENTS.md is kept verbatim.
    let kept = tempfile::tempdir().unwrap();
    fs::write(kept.path().join("AGENTS.md"), "# Mine\n").unwrap();
    let output = Command::new(actplane())
        .current_dir(kept.path())
        .args(["init", "--with-codex"])
        .output()
        .expect("run init --with-codex");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("keeping") && stderr(&output).contains("AGENTS.md"),
        "stderr: {}",
        stderr(&output)
    );
    assert_eq!(
        fs::read_to_string(kept.path().join("AGENTS.md")).unwrap(),
        "# Mine\n"
    );

    // With CLAUDE.md present and no AGENTS.md, AGENTS.md is a symlink.
    let linked = tempfile::tempdir().unwrap();
    fs::write(linked.path().join("CLAUDE.md"), "# Claude guide\n").unwrap();
    let output = Command::new(actplane())
        .current_dir(linked.path())
        .args(["init", "--with-codex"])
        .output()
        .expect("run init --with-codex");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let agents = linked.path().join("AGENTS.md");
    assert!(
        fs::symlink_metadata(&agents)
            .unwrap()
            .file_type()
            .is_symlink(),
        "AGENTS.md should be a symlink to CLAUDE.md"
    );
    assert_eq!(fs::read_to_string(&agents).unwrap(), "# Claude guide\n");

    // With neither present, a stub is written.
    let stub = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(stub.path())
        .args(["init", "--with-codex"])
        .output()
        .expect("run init --with-codex");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let written = fs::read_to_string(stub.path().join("AGENTS.md")).unwrap();
    assert!(
        written.starts_with("# AGENTS.md"),
        "stub should start with the AGENTS.md heading: {written}"
    );
}

// `init --all` writes the starter policy plus every project integration in one
// pass: the Codex feedback hook, the MCP auto-attach config, and the AGENTS.md
// guidance. Each artifact must contain the command/args the runtime expects.
#[test]
fn init_all_writes_policy_and_integration_files() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--all"])
        .output()
        .expect("run init --all");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("project integration ready"),
        "stderr: {}",
        stderr(&output)
    );

    // Starter policy: a valid, compilable actplane.yaml.
    let policy = tmp.path().join("actplane.yaml");
    let policy_text = fs::read_to_string(&policy).expect("actplane.yaml written");
    assert!(policy_text.contains("version: 1"));
    let compile = run(&["--policy", policy.to_str().unwrap(), "compile", "--explain"]);
    assert!(compile.status.success(), "stderr: {}", stderr(&compile));

    // Codex feedback hook wires the `feedback-hook` adapter.
    let hooks: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(tmp.path().join(".codex/hooks.json")).unwrap())
            .expect("hooks.json JSON");
    let hook_command = hooks["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .expect("hook command string");
    assert!(
        hook_command.contains("actplane") && hook_command.contains("feedback-hook"),
        "hook command: {hook_command}"
    );

    // MCP config points at the stdio server with auto-attach.
    let mcp: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(tmp.path().join(".mcp.json")).unwrap())
            .expect("mcp.json JSON");
    assert_eq!(mcp["mcpServers"]["actplane"]["command"], "actplane");
    let mcp_args = mcp["mcpServers"]["actplane"]["args"]
        .as_array()
        .expect("mcp args array");
    assert!(mcp_args.iter().any(|a| a == "mcp"));
    assert!(mcp_args.iter().any(|a| a == "--auto-attach-parent"));

    // AGENTS.md guidance tells the agent to treat kernel feedback as authority.
    let agents = fs::read_to_string(tmp.path().join("AGENTS.md")).expect("AGENTS.md written");
    assert!(agents.contains("ActPlane"));
    assert!(agents.contains(".actplane/last-violation.txt"));
}

// `init --all` composes with the policy-selection flags: `--generate` still
// emits a generated rule set and writes every integration, while `--template`
// restricts the policy to the named template.
#[test]
fn init_all_composes_with_policy_selection_flags() {
    let generated = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(generated.path())
        .args(["init", "--all", "--generate"])
        .output()
        .expect("run init --all --generate");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let err = stderr(&output);
    assert!(
        err.contains("actplane: wrote 2 generated template-backed rule set(s) to actplane.yaml"),
        "stderr: {err}"
    );
    assert!(
        err.contains("actplane: project integration ready"),
        "stderr: {err}"
    );
    for path in [
        ".codex/hooks.json",
        ".mcp.json",
        "AGENTS.md",
        "actplane.yaml",
    ] {
        assert!(generated.path().join(path).is_file(), "missing {path}");
    }

    let templated = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(templated.path())
        .args(["init", "--all", "--template", "no-git-branch"])
        .output()
        .expect("run init --all --template");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let policy = fs::read_to_string(templated.path().join("actplane.yaml")).unwrap();
    assert!(
        policy.contains("# ActPlane policy generated from template `no-git-branch`."),
        "policy: {policy}"
    );
    assert!(
        !policy.contains("rule no-secret-exfil:"),
        "template selection leaked the starter rules: {policy}"
    );
}

// `init`'s clap argument groups are enforced before any file is touched: the
// listing/printing modes and the template/generate selectors are mutually
// exclusive.
#[test]
fn init_arguments_are_mutually_exclusive() {
    let tmp = tempfile::tempdir().unwrap();
    let run_in = |args: &[&str]| {
        Command::new(actplane())
            .current_dir(tmp.path())
            .args(args)
            .output()
            .expect("run init")
    };

    for (args, first, second) in [
        (
            vec!["init", "--list-templates", "--template", "no-git-branch"],
            "'--list-templates'",
            "'--template <TEMPLATE>'",
        ),
        (
            vec!["init", "--list-templates", "--out", "x.yaml"],
            "'--list-templates'",
            "'--out <FILE>'",
        ),
        (
            vec!["init", "--list-templates", "--print"],
            "'--list-templates'",
            "'--print'",
        ),
        (
            vec!["init", "--print", "--out", "x.yaml"],
            "'--print'",
            "'--out <FILE>'",
        ),
    ] {
        let output = run_in(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let err = stderr(&output);
        assert!(
            err.contains("cannot be used with") && err.contains(first) && err.contains(second),
            "{args:?} stderr: {err}"
        );
    }
    assert!(
        !tmp.path().join("x.yaml").exists(),
        "a conflicting invocation must not write a file"
    );
}

// `--with-codex` reconciles `.codex/hooks.json`: it leaves an already-wired
// hook untouched, refreshes an absolute-path hook to the PATH command, and
// keeps an unrelated hook unless `--force`.
#[test]
fn init_with_codex_reconciles_hook_config() {
    let run_codex = |dir: &Path| {
        Command::new(actplane())
            .current_dir(dir)
            .args(["init", "--with-codex"])
            .output()
            .expect("run init --with-codex")
    };

    let wired = tempfile::tempdir().unwrap();
    fs::create_dir_all(wired.path().join(".codex")).unwrap();
    let wired_hook =
        r#"{"hooks":{"PostToolUse":[{"hooks":[{"command":"actplane feedback-hook"}]}],"x":1}}"#;
    fs::write(wired.path().join(".codex/hooks.json"), wired_hook).unwrap();
    let output = run_codex(wired.path());
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("already wired"),
        "stderr: {}",
        stderr(&output)
    );
    assert_eq!(
        fs::read_to_string(wired.path().join(".codex/hooks.json")).unwrap(),
        wired_hook,
        "an already-wired hook must not be rewritten"
    );

    let refresh = tempfile::tempdir().unwrap();
    fs::create_dir_all(refresh.path().join(".codex")).unwrap();
    fs::write(
        refresh.path().join(".codex/hooks.json"),
        r#"{"hooks":{"PostToolUse":[{"hooks":[{"command":"/opt/bin/actplane feedback-hook"}]}]}}"#,
    )
    .unwrap();
    let output = run_codex(refresh.path());
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("refreshing Codex hook"),
        "stderr: {}",
        stderr(&output)
    );
    let hooks: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(refresh.path().join(".codex/hooks.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        hooks["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        "actplane feedback-hook"
    );

    let unrelated = tempfile::tempdir().unwrap();
    fs::create_dir_all(unrelated.path().join(".codex")).unwrap();
    let unrelated_hook = r#"{"hooks":{"PostToolUse":[{"hooks":[{"command":"echo hi"}]}]}}"#;
    fs::write(unrelated.path().join(".codex/hooks.json"), unrelated_hook).unwrap();
    let output = run_codex(unrelated.path());
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("keeping existing") && stderr(&output).contains("--force"),
        "stderr: {}",
        stderr(&output)
    );
    assert_eq!(
        fs::read_to_string(unrelated.path().join(".codex/hooks.json")).unwrap(),
        unrelated_hook,
        "an unrelated hook must be kept"
    );
}

// `init --generate` infers a candidate policy from project manifests and
// instructions. On a Cargo project it writes a deterministic, reviewable
// starter with the conservative source-repository templates.
#[test]
fn init_generate_writes_candidate_policy_from_project() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--generate"])
        .output()
        .expect("run init --generate");
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let err = stderr(&output);
    assert!(err.contains("selected no-git-branch"), "stderr: {err}");
    assert!(err.contains("selected test-before-commit"), "stderr: {err}");
    assert!(
        err.contains("wrote 2 generated template-backed rule set(s) to actplane.yaml"),
        "stderr: {err}"
    );

    let policy = fs::read_to_string(tmp.path().join("actplane.yaml")).unwrap();
    assert!(
        policy.contains("candidate policy generated by `actplane init --generate`"),
        "policy: {policy}"
    );
}

// `--with-codex` and `--with-mcp` each wire only their own integration, and
// neither overwrites an existing policy without `--force`.
#[test]
fn init_integration_flags_scope_their_writes() {
    let codex = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(codex.path())
        .args(["init", "--with-codex"])
        .output()
        .expect("run init --with-codex");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(codex.path().join("actplane.yaml").is_file());
    assert!(codex.path().join(".codex/hooks.json").is_file());
    assert!(codex.path().join("AGENTS.md").is_file());
    assert!(
        !codex.path().join(".mcp.json").exists(),
        "--with-codex must not write MCP config"
    );

    let mcp = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(mcp.path())
        .args(["init", "--with-mcp"])
        .output()
        .expect("run init --with-mcp");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(mcp.path().join("actplane.yaml").is_file());
    assert!(mcp.path().join(".mcp.json").is_file());
    assert!(
        !mcp.path().join(".codex/hooks.json").exists(),
        "--with-mcp must not write the Codex hook"
    );

    // Re-running without --force refuses to clobber the policy.
    let repeat = Command::new(actplane())
        .current_dir(codex.path())
        .args(["init", "--with-codex"])
        .output()
        .expect("rerun init");
    assert!(!repeat.status.success());
    assert!(
        stderr(&repeat).contains("actplane.yaml already exists (use --force to overwrite)"),
        "stderr: {}",
        stderr(&repeat)
    );
}

// `--with-mcp` merges into an existing `.mcp.json` without dropping other
// servers, keeps an invalid file unless `--force`, and replaces it with
// `--force`.
#[test]
fn init_with_mcp_merges_existing_config() {
    let merge = tempfile::tempdir().unwrap();
    fs::write(
        merge.path().join(".mcp.json"),
        r#"{"mcpServers":{"other":{"command":"other","args":["x"]}},"note":"keep"}"#,
    )
    .unwrap();
    let output = Command::new(actplane())
        .current_dir(merge.path())
        .args(["init", "--with-mcp"])
        .output()
        .expect("run init --with-mcp");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(merge.path().join(".mcp.json")).unwrap()).unwrap();
    assert_eq!(doc["note"], "keep");
    assert_eq!(doc["mcpServers"]["other"]["command"], "other");
    assert_eq!(doc["mcpServers"]["actplane"]["command"], "actplane");
    assert_eq!(doc["mcpServers"]["actplane"]["args"][0], "mcp");

    // Invalid JSON is kept unless --force.
    let invalid = tempfile::tempdir().unwrap();
    fs::write(invalid.path().join(".mcp.json"), "{not json").unwrap();
    let output = Command::new(actplane())
        .current_dir(invalid.path())
        .args(["init", "--with-mcp"])
        .output()
        .expect("run init --with-mcp");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("keeping invalid") && stderr(&output).contains("--force"),
        "stderr: {}",
        stderr(&output)
    );
    assert_eq!(
        fs::read_to_string(invalid.path().join(".mcp.json")).unwrap(),
        "{not json"
    );

    // --force replaces invalid JSON with a valid config.
    let forced = tempfile::tempdir().unwrap();
    fs::write(forced.path().join(".mcp.json"), "{not json").unwrap();
    let output = Command::new(actplane())
        .current_dir(forced.path())
        .args(["init", "--with-mcp", "--force"])
        .output()
        .expect("run init --with-mcp --force");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("replacing invalid"),
        "stderr: {}",
        stderr(&output)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(forced.path().join(".mcp.json")).unwrap())
            .expect("forced config must be valid JSON");
    assert_eq!(doc["mcpServers"]["actplane"]["command"], "actplane");
}

// `--with-mcp` keeps a `.mcp.json` whose `mcpServers` is not an object unless
// `--force`, which replaces it and preserves the rest of the document.
#[test]
fn init_with_mcp_keeps_non_object_servers() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join(".mcp.json"),
        r#"{"mcpServers":5,"note":"keep"}"#,
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--with-mcp"])
        .output()
        .expect("run init --with-mcp");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("because `mcpServers` is not an object"),
        "stderr: {}",
        stderr(&output)
    );
    assert_eq!(
        fs::read_to_string(tmp.path().join(".mcp.json")).unwrap(),
        r#"{"mcpServers":5,"note":"keep"}"#
    );

    let forced = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--with-mcp", "--force"])
        .output()
        .expect("run init --with-mcp --force");
    assert!(forced.status.success(), "stderr: {}", stderr(&forced));
    assert!(
        stderr(&forced).contains("wired MCP config"),
        "stderr: {}",
        stderr(&forced)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(tmp.path().join(".mcp.json")).unwrap()).unwrap();
    assert_eq!(doc["note"], "keep");
    assert_eq!(doc["mcpServers"]["actplane"]["command"], "actplane");
    assert_eq!(
        doc["mcpServers"]["actplane"]["args"],
        serde_json::json!(["mcp", "--auto-attach-parent"])
    );
}

// `init --out` rejects a directory and a non-regular existing target, sharing
// the output-path guard with `compile --out`.
#[cfg(unix)]
#[test]
fn init_out_rejects_directory_and_non_regular_targets() {
    let tmp = tempfile::tempdir().unwrap();

    let dir = tmp.path().join("outdir");
    fs::create_dir(&dir).unwrap();
    let output = run(&[
        "init",
        "--template",
        "no-git-branch",
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("is a directory, not an output file"),
        "stderr: {}",
        stderr(&output)
    );

    let fifo = tmp.path().join("out.fifo");
    let fifo_status = Command::new("mkfifo").arg(&fifo).status().expect("mkfifo");
    assert!(fifo_status.success(), "mkfifo failed");
    let output = run(&[
        "init",
        "--template",
        "no-git-branch",
        "--out",
        fifo.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("is not a regular output file"),
        "stderr: {}",
        stderr(&output)
    );
}

// `init --out <path>` writes to the requested path, requires the parent
// directory to exist, and reports the concrete file when refusing to clobber.
#[test]
fn init_out_writes_requested_path_and_guards_existing_file() {
    let tmp = tempfile::tempdir().unwrap();

    let missing_parent = run(&[
        "init",
        "--out",
        tmp.path().join("nested/policy.yaml").to_str().unwrap(),
    ]);
    assert_eq!(
        missing_parent.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&missing_parent)
    );
    assert!(
        stderr(&missing_parent).contains("parent directory for")
            && stderr(&missing_parent).contains("does not exist or is not a directory"),
        "stderr: {}",
        stderr(&missing_parent)
    );

    let out = tmp.path().join("policy.yaml");
    let first = run(&[
        "init",
        "--template",
        "no-git-branch",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(first.status.success(), "stderr: {}", stderr(&first));
    let policy = fs::read_to_string(&out).unwrap();
    assert!(
        policy.contains("ActPlane policy generated from template `no-git-branch`"),
        "policy: {policy}"
    );

    let again = run(&[
        "init",
        "--template",
        "no-git-branch",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(again.status.code(), Some(1), "stderr: {}", stderr(&again));
    assert!(
        stderr(&again).contains(&format!(
            "{} already exists (use --force to overwrite)",
            out.display()
        )),
        "stderr: {}",
        stderr(&again)
    );
}

// `init --print` emits the policy (starter or template-based) on stdout and
// writes no files, unlike the default `init` write path.
#[test]
fn init_print_emits_policy_without_writing_files() {
    let tmp = tempfile::tempdir().unwrap();

    let starter = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--print"])
        .output()
        .expect("run init --print");
    assert!(starter.status.success(), "stderr: {}", stderr(&starter));
    let printed = stdout(&starter);
    assert!(printed.contains("version: 1"), "stdout: {printed}");
    assert!(
        printed.contains("ActPlane project policy"),
        "stdout: {printed}"
    );
    assert!(
        fs::read_dir(tmp.path()).unwrap().next().is_none(),
        "--print must not write files into cwd"
    );

    let templated = run(&["init", "--template", "test-before-commit", "--print"]);
    assert!(templated.status.success(), "stderr: {}", stderr(&templated));
    assert!(
        stdout(&templated).contains("ActPlane policy generated from template `test-before-commit`"),
        "stdout: {}",
        stdout(&templated)
    );
}

// Re-running bare `init` in a directory that already has the starter policy
// refuses to overwrite it until `--force` is passed.
#[test]
fn init_refuses_to_clobber_existing_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let first = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("init")
        .output()
        .expect("run init");
    assert!(first.status.success(), "stderr: {}", stderr(&first));
    let policy = tmp.path().join("actplane.yaml");
    assert!(policy.exists(), "stdout: {}", stdout(&first));

    let again = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("init")
        .output()
        .expect("run init again");
    assert_eq!(again.status.code(), Some(1), "stdout: {}", stdout(&again));
    assert!(
        stderr(&again).contains("actplane.yaml already exists (use --force to overwrite)"),
        "stderr: {}",
        stderr(&again)
    );

    let forced = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--force"])
        .output()
        .expect("run init --force");
    assert!(forced.status.success(), "stderr: {}", stderr(&forced));
    assert!(
        stderr(&forced).contains("wrote starter policy"),
        "stderr: {}",
        stderr(&forced)
    );
}

// `init --template <id>` without `--out` writes `actplane.yaml` in the current
// directory, and an unknown template id fails before writing anything.
#[test]
fn init_template_writes_default_path_and_reports_unknown_id() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--template", "test-before-commit"])
        .output()
        .expect("run init --template");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("wrote template `test-before-commit` to actplane.yaml"),
        "stderr: {}",
        stderr(&output)
    );
    let written = fs::read_to_string(tmp.path().join("actplane.yaml")).expect("actplane.yaml");
    assert!(written.contains("ActPlane policy generated from template `test-before-commit`"));

    let unknown = run(&[
        "init",
        "--template",
        "__nope__",
        "--out",
        tmp.path().join("x.yaml").to_str().unwrap(),
    ]);
    assert!(!unknown.status.success());
    let err = stderr(&unknown);
    assert!(err.contains("unknown template `__nope__`"), "stderr: {err}");
    assert!(
        err.contains("no-git-branch"),
        "stderr should list available: {err}"
    );
    assert!(!tmp.path().join("x.yaml").exists());
}

// `init --set` rejects malformed assignments: a missing `=`, an empty key, and
// a value containing `=` (which yields an unknown key) all fail before writing.
#[test]
fn init_template_set_rejects_malformed_assignments() {
    let tmp = tempfile::tempdir().unwrap();
    let run_in_tmp = |value: &str| {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .args([
                "init",
                "--template",
                "no-network",
                "--set",
                value,
                "--print",
            ])
            .output()
            .expect("run init --set");
        assert!(!output.status.success(), "expected failure for {value:?}");
        stderr(&output)
    };

    assert!(
        run_in_tmp("agent_exec").contains("template parameter `agent_exec` must use key=value")
    );
    assert!(run_in_tmp("=x").contains("invalid template parameter key ``"));
    assert!(run_in_tmp("a=b=c").contains("unknown parameter `a` for template `no-network`"));
}

// `init --template --set NAME=VALUE` substitutes template parameters into the
// generated policy and rejects unknown names by listing the valid ones.
#[test]
fn init_template_set_substitutes_parameters_and_rejects_unknown() {
    let output = run(&[
        "init",
        "--template",
        "workspace-confinement",
        "--set",
        "agent_exec=my-agent",
        "--set",
        "writable_path=/srv/work",
        "--print",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let policy = stdout(&output);
    assert!(
        policy.contains("# Parameter agent_exec: my-agent")
            && policy.contains("# Parameter writable_path: /srv/work"),
        "policy must echo the substituted parameters:\n{policy}"
    );
    assert!(
        policy.contains("exec \"my-agent\"") && policy.contains("unless target \"/srv/work\""),
        "policy must substitute values into the rule body:\n{policy}"
    );
    assert!(
        !policy.contains("{{"),
        "no unsubstituted placeholders may remain:\n{policy}"
    );

    let unknown = run(&[
        "init",
        "--template",
        "workspace-confinement",
        "--set",
        "nope=1",
        "--print",
    ]);
    assert_eq!(
        unknown.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&unknown)
    );
    let err = stderr(&unknown);
    assert!(
        err.contains("unknown parameter `nope` for template `workspace-confinement`")
            && err.contains("available: agent_exec, writable_path"),
        "stderr: {err}"
    );
}

// The `mcp` stdio server validates the opening `initialize` request before it
// needs any kernel access, so these failures are deterministic without root.
#[test]
fn mcp_reports_initialize_handshake_errors() {
    use std::io::Write as _;
    let run_mcp = |stdin: &str| {
        let mut child = Command::new(actplane())
            .arg("mcp")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn mcp");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().expect("mcp output")
    };

    let empty = run_mcp("");
    assert_eq!(empty.status.code(), Some(1), "stderr: {}", stderr(&empty));
    assert!(
        stderr(&empty).contains("ConnectionClosed(\"initialize request\")"),
        "stderr: {}",
        stderr(&empty)
    );
    assert!(empty.stdout.is_empty(), "stdout: {}", stdout(&empty));

    let malformed =
        run_mcp("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n");
    assert_eq!(
        malformed.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&malformed)
    );
    let response: serde_json::Value =
        serde_json::from_slice(&malformed.stdout).expect("mcp error response");
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(response["error"]["code"], -32602);
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("clientCapabilities"),
        "response: {response}"
    );
    assert!(
        stderr(&malformed).contains("ExpectedInitializeRequest"),
        "stderr: {}",
        stderr(&malformed)
    );
}

// The policy MCP resource reports a DSL compile error as its text rather than
// failing the request.
#[test]
fn mcp_policy_resource_reports_compile_error() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  rule broken\n    notify exec \"git\" if true\n    because \"x\"\n",
    )
    .unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":{\"uri\":\"actplane:///policy\"}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let response = stdout(&output)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("mcp json line"))
        .find(|message| message["id"] == 2)
        .expect("policy resource response");
    let text = response["result"]["contents"][0]["text"]
        .as_str()
        .expect("policy text");
    assert!(text.starts_with("Policy compile error: "), "text: {text}");
    assert!(
        text.contains("expected ':' after rule name"),
        "text: {text}"
    );
}

// With no discoverable policy, the policy MCP resource reports the missing
// file instead of failing the request.
#[test]
fn mcp_policy_resource_reports_missing_policy() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":{\"uri\":\"actplane:///policy\"}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let response = stdout(&output)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("mcp json line"))
        .find(|message| message["id"] == 2)
        .expect("policy resource response");
    assert_eq!(
        response["result"]["contents"][0]["text"],
        "No actplane.yaml found."
    );
}

// `resources/read` renders the policy validation summary and the latest
// corrective feedback, and rejects an unknown URI with -32602.
#[test]
fn mcp_reads_policy_and_feedback_resources() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  rule r:\n    notify exec \"git\" if true\n    because \"x\"\n",
    )
    .unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":{\"uri\":\"actplane:///policy\"}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/read\",\"params\":{\"uri\":\"actplane:///feedback\"}}\n{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"resources/read\",\"params\":{\"uri\":\"actplane:///missing\"}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let mut by_id = std::collections::BTreeMap::new();
    for line in stdout(&output).lines() {
        let message: serde_json::Value = serde_json::from_str(line).expect("mcp json line");
        if let Some(id) = message["id"].as_u64() {
            by_id.insert(id, message);
        }
    }
    let policy_text = by_id[&2]["result"]["contents"][0]["text"]
        .as_str()
        .expect("policy text");
    assert!(
        policy_text.contains("Policy valid") && policy_text.contains("1 rules"),
        "policy text: {policy_text}"
    );
    let feedback_text = by_id[&3]["result"]["contents"][0]["text"]
        .as_str()
        .expect("feedback text");
    assert!(
        feedback_text.contains("No ActPlane feedback file yet"),
        "feedback text: {feedback_text}"
    );
    assert_eq!(by_id[&4]["error"]["code"], -32602);
    assert_eq!(
        by_id[&4]["error"]["message"],
        "Unknown resource: actplane:///missing"
    );
}

// `resources/list` advertises the policy and feedback resources, while
// `prompts/list` is empty. Unknown tools and calls made without an attached
// engine surface as distinct errors.
#[test]
fn mcp_lists_resources_and_prompts() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/list\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"prompts/list\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"no_such_tool\",\"arguments\":{}}}\n{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"bind_child_domain\",\"arguments\":{}}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let mut by_id = std::collections::BTreeMap::new();
    for line in stdout(&output).lines() {
        let message: serde_json::Value = serde_json::from_str(line).expect("mcp json line");
        if let Some(id) = message["id"].as_u64() {
            by_id.insert(id, message);
        }
    }
    let resources = by_id[&2]["result"]["resources"]
        .as_array()
        .expect("resources array");
    let uris: Vec<&str> = resources
        .iter()
        .filter_map(|resource| resource["uri"].as_str())
        .collect();
    assert!(
        uris.contains(&"actplane:///policy") && uris.contains(&"actplane:///feedback"),
        "unexpected resource set: {uris:?}"
    );
    assert_eq!(by_id[&3]["result"]["prompts"], serde_json::json!([]));
    assert_eq!(by_id[&4]["error"]["code"], -32601);
    assert_eq!(by_id[&4]["error"]["message"], "Unknown tool: no_such_tool");
    assert_eq!(by_id[&5]["error"]["code"], -32603);
    assert_eq!(
        by_id[&5]["error"]["message"],
        "No eBPF engine attached (MCP not started with --auto-attach-parent)"
    );
}

// The MCP server answers `ping` and `resources/templates/list`, and rejects an
// unknown resource URI with an invalid-params error.
#[test]
fn mcp_answers_ping_and_templates_and_unknown_resource() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/templates/list\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"resources/read\",\"params\":{\"uri\":\"actplane:///logs\"}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let mut by_id = std::collections::BTreeMap::new();
    for line in stdout(&output).lines() {
        let message: serde_json::Value = serde_json::from_str(line).expect("mcp json line");
        if let Some(id) = message["id"].as_u64() {
            by_id.insert(id, message);
        }
    }
    assert_eq!(
        by_id[&2]["result"]["resourceTemplates"],
        serde_json::json!([])
    );
    assert_eq!(by_id[&3]["result"], serde_json::json!({}));
    assert_eq!(by_id[&4]["error"]["code"], -32602);
    assert_eq!(
        by_id[&4]["error"]["message"],
        "Unknown resource: actplane:///logs"
    );
}

// MCP tool calls reject missing required arguments with -32602, and the
// child-domain listing tools answer without an attached engine.
#[test]
fn mcp_tools_reject_missing_arguments() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  rule r:\n    notify exec \"git\" if true\n    because \"x\"\n",
    )
    .unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_child_domain_logs\",\"arguments\":{}}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"launch_child_domain\",\"arguments\":{}}}\n{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"list_child_domains\",\"arguments\":{}}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let mut by_id = std::collections::BTreeMap::new();
    for line in stdout(&output).lines() {
        let message: serde_json::Value = serde_json::from_str(line).expect("mcp json line");
        if let Some(id) = message["id"].as_u64() {
            by_id.insert(id, message);
        }
    }
    assert_eq!(by_id[&2]["error"]["code"], -32602);
    assert_eq!(by_id[&2]["error"]["message"], "missing `child_id`");
    assert_eq!(by_id[&3]["error"]["code"], -32602);
    assert_eq!(by_id[&3]["error"]["message"], "missing `cmd`");
    assert_eq!(by_id[&4]["result"]["content"][0]["text"], "[]");
    assert_eq!(by_id[&4]["result"]["isError"], false);
}

// `tools/list` enumerates the child-domain control tools the MCP server
// exposes, with `pid`, `policy`, and `cmd` the only required inputs.
#[test]
fn mcp_tools_list_enumerates_child_domain_tools() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let mut listed = None;
    for line in stdout(&output).lines() {
        let message: serde_json::Value = serde_json::from_str(line).expect("mcp json line");
        if message["id"] == 2 {
            listed = Some(message);
        }
    }
    let listed = listed.expect("tools/list response");
    let tools = listed["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 8, "unexpected tool set: {listed}");
    for name in [
        "bind_child_domain",
        "append_policy_delta",
        "launch_child_domain",
        "list_child_domains",
        "read_child_domain_logs",
        "terminate_child_domain",
        "restart_child_domain",
        "reconcile_child_domains",
    ] {
        assert!(
            tools.iter().any(|tool| tool["name"] == name),
            "missing tool {name} in {listed}"
        );
    }
    let required = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .and_then(|tool| tool["inputSchema"]["required"].as_array().cloned())
            .unwrap_or_default()
    };
    assert_eq!(
        required("bind_child_domain"),
        vec![serde_json::json!("pid")]
    );
    assert_eq!(
        required("append_policy_delta"),
        vec![serde_json::json!("policy")]
    );
    assert_eq!(
        required("launch_child_domain"),
        vec![serde_json::json!("cmd")]
    );
    assert!(required("list_child_domains").is_empty());
}

// A log request for a child domain the engine does not know is rejected with
// invalid-params, and the armless reconcile totals are still reported.
#[test]
fn mcp_unknown_child_domain_is_rejected() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  rule r:\n    notify exec \"git\" if true\n    because \"x\"\n",
    )
    .unwrap();
    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_child_domain_logs\",\"arguments\":{\"child_id\":1}}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"reconcile_child_domains\",\"arguments\":{}}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let mut by_id = std::collections::BTreeMap::new();
    for line in stdout(&output).lines() {
        let message: serde_json::Value = serde_json::from_str(line).expect("mcp json line");
        if let Some(id) = message["id"].as_u64() {
            by_id.insert(id, message);
        }
    }
    assert_eq!(by_id[&2]["error"]["code"], -32602);
    assert_eq!(by_id[&2]["error"]["message"], "unknown child domain 1");
    let totals: serde_json::Value = serde_json::from_str(
        by_id[&3]["result"]["content"][0]["text"]
            .as_str()
            .expect("reconcile text"),
    )
    .expect("reconcile totals JSON");
    assert_eq!(totals["total"], 0);
    assert_eq!(totals["children"], serde_json::json!([]));
}

// The MCP server forwards an `initialize` carrying well-formed `_meta` as an
// unknown request (the CLI does not implement the initialize method), replying
// -32601 method not found while the session stays alive and exits cleanly.
#[test]
fn mcp_reports_method_not_found_for_valid_initialize() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule r:\n    notify exec \"git\" if COMMAND\n    because \"x\"\n",
    )
    .unwrap();

    let mut child = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2025-06-18\",\"io.modelcontextprotocol/clientCapabilities\":{\"roots\":{}}}}}\n",
        )
        .unwrap();
    let output = child.wait_with_output().expect("mcp output");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("mcp initialize response");
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(response["error"]["code"], -32601);
    assert_eq!(response["error"]["message"], "initialize");
}

// Runtime-id flags (`--pid`, `--child-id`/`--domain-id`, `--scope-id`) are
// unsigned integers parsed by clap, so non-numeric input exits 2 before any
// policy work, and the `--domain-id`/`--child-id` aliases are exclusive.
#[test]
fn numeric_id_flags_reject_non_numeric_and_alias_conflicts() {
    for (args, flag, value) in [
        (
            vec!["attach", "--pid", "1", "--domain-id", "abc"],
            "--domain-id <DOMAIN_ID>",
            "abc",
        ),
        (
            vec![
                "attach",
                "--pid",
                "1",
                "--domain-id",
                "1",
                "--scope-id",
                "abc",
            ],
            "--scope-id <SCOPE_ID>",
            "abc",
        ),
        (
            vec!["attach", "--pid", "1", "--child-id", "abc"],
            "--child-id <CHILD_ID>",
            "abc",
        ),
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let err = stderr(&output);
        assert!(
            err.contains(&format!(
                "invalid value '{value}' for '{flag}': invalid digit found in string"
            )),
            "{args:?} stderr: {err}"
        );
    }

    let alias = run(&[
        "attach",
        "--pid",
        "1",
        "--domain-id",
        "1",
        "--child-id",
        "2",
    ]);
    assert_eq!(alias.status.code(), Some(2));
    let err = stderr(&alias);
    assert!(
        err.contains(
            "the argument '--domain-id <DOMAIN_ID>' cannot be used with '--child-id <CHILD_ID>'"
        ),
        "stderr: {err}"
    );
}

// The root policy-source flags are mutually exclusive, and `--domain` without
// a policy file fails at runtime.
#[test]
fn policy_source_flags_are_mutually_exclusive() {
    let rule = "rule noop:\n  notify exec \"git\" if true\n  because \"noop\"\n";

    let rule_vs_policy = run(&[
        "--rule",
        rule,
        "--policy",
        &fixture("01_secret_no_exfil.yaml"),
        "compile",
    ]);
    assert_eq!(
        rule_vs_policy.status.code(),
        Some(2),
        "stderr: {}",
        stderr(&rule_vs_policy)
    );
    assert!(
        stderr(&rule_vs_policy)
            .contains("the argument '--rule <RULE>' cannot be used with '--policy <POLICY>'"),
        "stderr: {}",
        stderr(&rule_vs_policy)
    );

    let rule_vs_domain = run(&["--rule", rule, "--domain", "review", "compile"]);
    assert_eq!(
        rule_vs_domain.status.code(),
        Some(2),
        "stderr: {}",
        stderr(&rule_vs_domain)
    );
    assert!(
        stderr(&rule_vs_domain)
            .contains("the argument '--rule <RULE>' cannot be used with '--domain <DOMAIN>'"),
        "stderr: {}",
        stderr(&rule_vs_domain)
    );

    let domain_without_policy = run(&["--domain", "review", "compile"]);
    assert_eq!(
        domain_without_policy.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&domain_without_policy)
    );
    assert!(
        stderr(&domain_without_policy)
            .contains("`--domain` requires a policy file with `rules:` and `domains:`"),
        "stderr: {}",
        stderr(&domain_without_policy)
    );
}

// Outside `--json`, policy-source load failures surface as plain `Error:`
// messages, whether the path is a directory, missing, or the inline DSL is
// invalid.
#[test]
fn policy_source_load_errors_are_reported_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();

    let dir = run(&["--policy", tmp.path().to_str().unwrap(), "compile"]);
    assert_eq!(dir.status.code(), Some(1), "stderr: {}", stderr(&dir));
    assert!(
        stderr(&dir).contains("reading") && stderr(&dir).contains("Is a directory"),
        "stderr: {}",
        stderr(&dir)
    );

    let missing = run(&["--policy", "no-such-policy.yaml", "compile"]);
    assert_eq!(
        missing.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&missing)
    );
    assert!(
        stderr(&missing).contains("reading")
            && stderr(&missing).contains("no-such-policy.yaml")
            && stderr(&missing).contains("No such file or directory"),
        "stderr: {}",
        stderr(&missing)
    );

    let invalid = run(&["--rule", "this is not a rule", "compile"]);
    assert_eq!(
        invalid.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&invalid)
    );
    assert!(
        stderr(&invalid).contains("✗ policy does not compile: unknown declaration 'this'"),
        "stderr: {}",
        stderr(&invalid)
    );
}

// A policy YAML that parses but has the wrong shape, or has empty `rules`,
// fails validation with a message pointing at the offending section, and
// `--json` reports the same failure structurally.
#[test]
fn compile_reports_policy_structure_validation_errors() {
    let tmp = tempfile::tempdir().unwrap();

    let malformed = tmp.path().join("malformed.yaml");
    fs::write(&malformed, "version: 1\nrules:\n  - name: x\n").unwrap();
    let output = run(&["--policy", malformed.to_str().unwrap(), "compile"]);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("rules: invalid type: sequence, expected a map"),
        "stderr: {}",
        stderr(&output)
    );

    let empty = tmp.path().join("empty.yaml");
    fs::write(&empty, "version: 1\nrules:\n").unwrap();
    let output = run(&["--policy", empty.to_str().unwrap(), "compile"]);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "must contain either a non-empty `policy: |` block or both `rules:` and `domains:`"
        ),
        "stderr: {}",
        stderr(&output)
    );

    let json = run(&["--policy", malformed.to_str().unwrap(), "compile", "--json"]);
    assert_eq!(json.status.code(), Some(1), "stderr: {}", stderr(&json));
    let value: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("compile --json stdout");
    assert_eq!(value["ok"], false);
    assert!(
        value["error"]
            .as_str()
            .unwrap()
            .contains("rules: invalid type: sequence, expected a map"),
        "json error: {}",
        value["error"]
    );
}

// `actplane.yaml` is discovered upward from cwd, so compiling from a nested
// subdirectory uses the project-root policy and reports that path.
#[test]
fn policy_is_discovered_upward_from_nested_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::copy(fixture("01_secret_no_exfil.yaml"), &policy).unwrap();
    let nested = tmp.path().join("crates/inner/src");
    fs::create_dir_all(&nested).unwrap();

    let output = Command::new(actplane())
        .current_dir(&nested)
        .arg("compile")
        .output()
        .expect("run compile from nested dir");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains(&format!("✓ {}: 2 rule(s) compile.", policy.display())),
        "compile must report the discovered root policy:\n{out}"
    );
}

// A policy YAML with an unknown top-level field fails to deserialize; both
// `compile` and `run` report the file and the allowed field set.
#[test]
fn policy_yaml_unknown_field_reports_expected_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let broken = tmp.path().join("broken.yaml");
    fs::write(&broken, "not: [valid\n").unwrap();

    for args in [
        vec!["compile", "--policy", broken.to_str().unwrap()],
        vec!["run", "--policy", broken.to_str().unwrap(), "/bin/true"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let err = stderr(&output);
        assert!(
            err.contains(&format!(
                "Error: \"parsing {}: unknown field `not`",
                broken.display()
            )),
            "{args:?} stderr: {err}"
        );
        assert!(
            err.contains(
                "expected one of `version`, `policy`, `rules`, `domains`, `default_domain`, `runtime`, `feedback`"
            ),
            "{args:?} stderr: {err}"
        );
    }
}

// `run --delta <FILE>` reads a child-domain delta and reports a missing file
// before launching the command.
#[test]
fn run_reports_unreadable_child_delta_file() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source AGENT = exec \"**\"\n  rule noop:\n    notify exec \"git\" if AGENT\n    because \"noop\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["run", "--delta", "NOPE.dsl", "/bin/true"])
        .output()
        .expect("run run --delta");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output)
            .contains("cannot read child policy delta NOPE.dsl: No such file or directory"),
        "stderr: {}",
        stderr(&output)
    );
}

// The `runtime.approval` schema rejects a scalar `append_delta` and an unknown
// `runtime` field with serde-derived messages.
#[test]
fn runtime_approval_schema_errors_are_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");

    fs::write(
        &policy,
        "version: 1\nruntime:\n  approval:\n    append_delta: true\npolicy: |\n  rule r:\n    notify exec \"git\" if true\n    because \"x\"\n",
    )
    .unwrap();
    let scalar = run(&["--policy", policy.to_str().unwrap(), "compile"]);
    assert_eq!(scalar.status.code(), Some(1), "stderr: {}", stderr(&scalar));
    assert!(
        stderr(&scalar).contains("runtime.approval.append_delta")
            && stderr(&scalar).contains("expected struct AppendDeltaApprovalConfig"),
        "stderr: {}",
        stderr(&scalar)
    );

    fs::write(
        &policy,
        "version: 1\nruntime:\n  profile: x\npolicy: |\n  rule r:\n    notify exec \"git\" if true\n    because \"x\"\n",
    )
    .unwrap();
    let unknown = run(&["--policy", policy.to_str().unwrap(), "compile"]);
    assert_eq!(
        unknown.status.code(),
        Some(1),
        "stderr: {}",
        stderr(&unknown)
    );
    assert!(
        stderr(&unknown).contains("runtime: unknown field `profile`, expected `approval`"),
        "stderr: {}",
        stderr(&unknown)
    );
}

// Every built-in template must produce a policy that compiles, so a template
// cannot ship broken DSL.
#[test]
fn every_template_generates_a_compilable_policy() {
    let listing = run(&["init", "--list-templates"]);
    assert!(listing.status.success(), "stderr: {}", stderr(&listing));
    let ids: Vec<String> = stdout(&listing)
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect();
    assert_eq!(ids.len(), 10, "expected the 10 built-in templates: {ids:?}");

    let tmp = tempfile::tempdir().unwrap();
    for id in &ids {
        let printed = run(&["init", "--template", id, "--print"]);
        assert!(
            printed.status.success(),
            "template {id} failed to render: {}",
            stderr(&printed)
        );
        assert!(
            !stdout(&printed).contains("{{"),
            "template {id} left placeholders: {}",
            stdout(&printed)
        );

        let policy = tmp.path().join(format!("{id}.yaml"));
        fs::write(&policy, printed.stdout).unwrap();
        let compiled = run(&["--policy", policy.to_str().unwrap(), "compile"]);
        assert!(
            compiled.status.success(),
            "template {id} did not compile:\n{}",
            stderr(&compiled)
        );
    }
}

// `--version` reports the crate version, and `help <subcommand>` routes to the
// same text as `<subcommand> --help`.
#[test]
fn version_and_help_subcommand_route_correctly() {
    let version = run(&["--version"]);
    assert!(version.status.success(), "stderr: {}", stderr(&version));
    assert_eq!(
        stdout(&version).trim(),
        format!("actplane {}", env!("CARGO_PKG_VERSION"))
    );

    let short = run(&["-V"]);
    assert_eq!(stdout(&short), stdout(&version));

    for command in ["compile", "control", "init"] {
        let via_subcommand = run(&["help", command]);
        let via_flag = run(&[command, "--help"]);
        assert!(
            via_subcommand.status.success(),
            "help {command} stderr: {}",
            stderr(&via_subcommand)
        );
        assert_eq!(
            stdout(&via_subcommand),
            stdout(&via_flag),
            "`help {command}` must match `{command} --help`"
        );
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn compile_json_reports_policy_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule noop:\n    notify exec \"__never__\" if COMMAND\n    because \"b\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .args(["--policy", policy.to_str().unwrap(), "compile", "--json"])
        .output()
        .expect("compile json");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("compile json");
    assert_eq!(report["schema"], "actplane.compile.v1");
    assert_eq!(report["ok"], true);
    assert_eq!(report["policy_ref"], policy.to_str().unwrap());
    assert_eq!(report["domain"], serde_json::Value::Null);
    assert_eq!(report["rule_count"], 1);
    assert_eq!(report["warnings"], serde_json::json!([]));
    let rule = &report["rules"][0];
    assert_eq!(rule["name"], "noop");
    assert_eq!(rule["reason"], "b");
    assert_eq!(rule["effect"], "notify");
    assert_eq!(rule["kernel_op"], "exec");
    assert_eq!(rule["immutable"], false);
    let clause = &report["backend_support"]["clauses"][0];
    assert_eq!(clause["status"], "supported");
    assert_eq!(clause["mode"], "tracepoint");
}

#[test]
fn compile_explain_lists_lowered_matchers_and_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule noop:\n    notify exec \"__never__\" if COMMAND\n    because \"b\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .args(["--policy", policy.to_str().unwrap(), "compile", "--explain"])
        .output()
        .expect("compile explain");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("ActPlane policy review"), "{text}");
    assert!(
        text.contains(&format!("policy: {}", policy.display())),
        "{text}"
    );
    assert!(text.contains("domain: none (flat policy)"), "{text}");
    assert!(
        text.contains("rules: 1 DSL rule(s), 1 lowered kernel matcher(s)"),
        "{text}"
    );
    assert!(text.contains("  - COMMAND = 0x1"), "{text}");
    assert!(text.contains("  - source COMMAND = exec \"**\""), "{text}");
    assert!(text.contains("rules:\n  1. rule noop"), "{text}");
    assert!(
        text.contains("clause 1: notify exec \"**/__never__\" if COMMAND"),
        "{text}"
    );
    assert!(text.contains("backend: tracepoint; pre_op=false"), "{text}");
    assert!(text.contains("warnings: none"), "{text}");
}

#[test]
fn run_with_missing_child_delta_reports_the_path() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("absent.dsl");
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule noop:\n    notify exec \"__never__\" if COMMAND\n    because \"b\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .args([
            "--policy",
            policy.to_str().unwrap(),
            "run",
            "--delta",
            missing.to_str().unwrap(),
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run with missing delta");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains(&format!(
            "cannot read child policy delta {}: No such file or directory",
            missing.display()
        )),
        "stderr did not report the missing delta:\n{}",
        stderr(&output)
    );
}

#[test]
fn attach_child_domain_with_delta_requires_control_state() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("absent.dsl");
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "attach",
            "--pid",
            "1",
            "--child-domain",
            "--delta",
            missing.to_str().unwrap(),
        ])
        .output()
        .expect("attach with missing delta");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains(&format!(
            "read {}: No such file or directory",
            state_dir.join("control.json").display()
        )),
        "stderr did not report the missing control state:\n{}",
        stderr(&output)
    );
}

fn run_with_path(args: &[&str], bin_dir: &std::path::Path, cwd: &std::path::Path) -> Output {
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(actplane())
        .args(args)
        .current_dir(cwd)
        .env("PATH", path)
        .output()
        .unwrap_or_else(|e| panic!("run actplane {args:?}: {e}"))
}

#[test]
fn doctor_reports_policy_readiness_and_problem_count() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  \
         rule noop:\n    notify exec \"__actplane_never__\" if COMMAND\n    because \"noop\"\n",
    )
    .expect("policy");
    let hooks = tmp.path().join(".codex");
    fs::create_dir_all(&hooks).expect("codex dir");
    fs::write(
        hooks.join("hooks.json"),
        "{\"hooks\":{\"PostToolUse\":[{\"hooks\":[{\"command\":\"actplane feedback-hook\"}]}]}}",
    )
    .expect("hooks");

    let bin_dir = std::path::Path::new(actplane()).parent().expect("bin dir");
    let output = run_with_path(
        &["--policy", policy.to_str().unwrap(), "doctor"],
        bin_dir,
        tmp.path(),
    );
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        stdout(&output),
        stderr(&output)
    );
    let text = stdout(&output);
    assert!(text.starts_with("ActPlane doctor"), "{text}");
    assert!(text.contains("✓ policy: "), "{text}");
    assert!(text.contains("(1 rule(s))"), "{text}");
    assert!(
        text.contains(&format!(
            "✓ feedback file: {}",
            tmp.path().join(".actplane/last-violation.txt").display()
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "✓ audit log: {}",
            tmp.path().join(".actplane/audit.jsonl").display()
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "✓ event log: {}",
            tmp.path().join(".actplane/events.jsonl").display()
        )),
        "{text}"
    );
    assert!(text.contains("✓ Codex hook: "), "{text}");
    assert!(
        text.contains("⚠ project MCP config: .mcp.json missing"),
        "{text}"
    );
    assert!(text.contains("✓ setup looks usable."), "{text}");

    fs::write(
        tmp.path().join("broken.yaml"),
        "version: 1\npolicy: |\n  rule x\n",
    )
    .expect("broken");
    let broken = run_with_path(
        &[
            "--policy",
            tmp.path().join("broken.yaml").to_str().unwrap(),
            "doctor",
        ],
        bin_dir,
        tmp.path(),
    );
    assert!(!broken.status.success());
    assert!(
        stdout(&broken).contains("does not compile"),
        "{}",
        stdout(&broken)
    );
    assert!(
        stdout(&broken).contains("✗ setup has 1 problem(s)."),
        "{}",
        stdout(&broken)
    );
}

#[test]
fn doctor_reports_missing_policy_without_an_engine() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join("absent.yaml");
    let output = run(&["--policy", missing.to_str().unwrap(), "doctor"]);
    assert!(!output.status.success());
    let text = stdout(&output);
    assert!(text.contains("✗ policy: "), "{text}");
    assert!(text.contains("✗ setup has"), "{text}");
}

#[test]
fn doctor_reports_a_ready_project_policy() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("actplane.yaml"),
        "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule noop:\n    notify exec \"__never__\" if COMMAND\n    because \"b\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    assert!(!output.status.success(), "doctor should report problems");
    let stdout = stdout(&output);
    assert!(stdout.contains("ActPlane doctor"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "✓ policy: {} (1 rule(s))",
            tmp.path().join("actplane.yaml").display()
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "✓ feedback file: {}",
            tmp.path().join(".actplane/last-violation.txt").display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("✓ kernel BTF:"), "{stdout}");
    assert!(stdout.contains("✓ eBPF privilege:"), "{stdout}");
    assert!(stdout.contains("Next commands:"), "{stdout}");
    assert!(stdout.contains("actplane compile"), "{stdout}");
    assert!(
        stdout.contains("sudo -E actplane run -- <agent-or-command>"),
        "{stdout}"
    );
    assert!(stdout.contains("✗ setup has 2 problem(s)."), "{stdout}");
}

#[test]
fn doctor_reports_a_project_without_a_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    assert!(!output.status.success());
    let stdout = stdout(&output);
    assert!(
        stdout.contains("✗ policy: no actplane.yaml found; pass --policy <file> or --rule <dsl>"),
        "{stdout}"
    );
    assert!(
        stdout.contains("⚠ Codex instructions: AGENTS.md missing"),
        "{stdout}"
    );
    assert!(
        stdout.contains("⚠ project MCP config: .mcp.json missing"),
        "{stdout}"
    );
    assert!(stdout.contains("✗ setup has 3 problem(s)."), "{stdout}");
    assert!(!stdout.contains("✓ feedback file:"), "{stdout}");
    assert!(!stdout.contains("✓ audit log:"), "{stdout}");
    assert!(!stdout.contains("✓ event log:"), "{stdout}");
}

#[test]
fn compile_json_reports_parse_errors_as_json() {
    let output = run(&["--rule", "rule broken", "compile", "--json"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).is_empty(),
        "report goes to stdout: {}",
        stderr(&output)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json error stdout");
    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["policy_ref"], "--rule");
    assert_eq!(value["domain"], serde_json::Value::Null);
    assert!(
        value["error"]
            .as_str()
            .unwrap_or("")
            .contains("expected ':' after rule name"),
        "error: {value}"
    );
}

#[test]
fn compile_json_reports_domain_resolution_errors_as_json() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    let base = fs::read_to_string(fixture("15_domain_bindings.yaml")).unwrap();
    fs::write(
        &policy,
        base.replace("parent: session", "parent: nonexistent"),
    )
    .unwrap();

    let output = run(&[
        "--policy",
        policy.to_str().unwrap(),
        "--domain",
        "review",
        "compile",
        "--json",
    ]);
    assert!(!output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json error stdout");
    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["policy_ref"], policy.to_str().unwrap());
    assert_eq!(value["domain"], serde_json::Value::Null);
    assert_eq!(value["error"], "unknown domain `nonexistent`");

    fs::write(
        &policy,
        base.replace("default_domain: review", "default_domain: ghost"),
    )
    .unwrap();
    let output = run(&["--policy", policy.to_str().unwrap(), "compile", "--json"]);
    assert!(!output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json error stdout");
    assert_eq!(value["ok"], false);
    assert_eq!(
        value["error"],
        "default_domain `ghost` is not defined (available: review, session)"
    );
}

#[test]
fn compile_explain_reports_parse_failure_on_stderr() {
    let output = run(&["--rule", "rule broken", "compile", "--explain"]);
    assert!(!output.status.success());
    assert!(stdout(&output).is_empty(), "stdout: {}", stdout(&output));
    assert!(
        stderr(&output).contains("policy does not compile"),
        "stderr: {}",
        stderr(&output)
    );
}

fn run_in_dir(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(actplane())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run actplane {args:?}: {e}"))
}

#[test]
fn init_all_wires_every_project_integration() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run_in_dir(tmp.path(), &["init", "--all"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    for rel in [
        "actplane.yaml",
        "AGENTS.md",
        ".mcp.json",
        ".codex/hooks.json",
    ] {
        assert!(tmp.path().join(rel).is_file(), "{rel} should be written");
    }
    let err = stderr(&output);
    assert!(err.contains("project integration ready in"));
    assert!(err.contains("actplane compile"));
}

#[test]
fn init_with_codex_leaves_mcp_config_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run_in_dir(tmp.path(), &["init", "--with-codex"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(tmp.path().join("AGENTS.md").is_file());
    assert!(tmp.path().join(".codex/hooks.json").is_file());
    assert!(
        !tmp.path().join(".mcp.json").exists(),
        "codex-only init must not write MCP config"
    );
}

#[test]
fn init_with_mcp_leaves_codex_hooks_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run_in_dir(tmp.path(), &["init", "--with-mcp"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(tmp.path().join(".mcp.json").is_file());
    assert!(
        !tmp.path().join(".codex/hooks.json").exists(),
        "mcp-only init must not write codex hooks"
    );
}

#[test]
fn init_writes_a_compilable_starter_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("init")
        .output()
        .expect("run init");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("actplane: wrote starter policy to actplane.yaml"),
        "{}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("actplane compile"));
    assert!(stderr(&output).contains("actplane doctor"));

    let policy = tmp.path().join("actplane.yaml");
    assert!(policy.is_file());
    let compile = run(&["--policy", policy.to_str().unwrap(), "compile"]);
    assert!(compile.status.success(), "stderr: {}", stderr(&compile));
    assert!(
        stdout(&compile).contains("compile."),
        "{}",
        stdout(&compile)
    );
}

#[test]
fn init_refuses_to_overwrite_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(&policy, "keep me").unwrap();

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("init")
        .output()
        .expect("run init");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("actplane.yaml already exists (use --force to overwrite)"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fs::read_to_string(&policy).unwrap(), "keep me");

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--force"])
        .output()
        .expect("run init --force");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_ne!(fs::read_to_string(&policy).unwrap(), "keep me");
}

#[test]
fn init_print_rejects_integration_flags() {
    let output = run(&["init", "--print", "--with-codex"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("--print cannot be combined with integration setup flags"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn compile_report_out_respects_force() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("review.txt");
    let policy = r#"
rule noop:
  notify exec "git" if true
  because "noop"
"#;
    let args = [
        "--rule",
        policy,
        "compile",
        "--explain",
        "--report-out",
        out.to_str().unwrap(),
    ];

    let output = run(&args);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let first = fs::read_to_string(&out).unwrap();
    assert!(first.contains("ActPlane policy review"));

    let output = run(&args);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("already exists (use --force to overwrite)"));
    assert_eq!(fs::read_to_string(&out).unwrap(), first);

    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--explain",
        "--report-out",
        out.to_str().unwrap(),
        "--force",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("wrote policy review"));
    assert!(
        fs::read_to_string(&out)
            .unwrap()
            .contains("ActPlane policy review")
    );
}

#[test]
fn compile_json_report_out_respects_force() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("report.json");
    fs::write(&out, "stale").unwrap();
    let policy = r#"
rule noop:
  notify exec "git" if true
  because "noop"
"#;

    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--json",
        "--report-out",
        out.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("already exists (use --force to overwrite)"));
    assert_eq!(fs::read_to_string(&out).unwrap(), "stale");

    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--json",
        "--report-out",
        out.to_str().unwrap(),
        "--force",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("wrote compile report"));
    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(written["schema"], "actplane.compile.v1");
    assert_eq!(written["ok"], true);
}

#[cfg(unix)]
#[test]
fn compile_out_rejects_symlink_target() {
    const POLICY: &str = r#"
  source COMMAND = exec "**"
  rule noop:
    notify exec "__actplane_never__" if COMMAND
    because "noop"
"#;
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real.bin");
    let link = tmp.path().join("link.bin");
    fs::write(&real, b"x").unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let output = run(&["--rule", POLICY, "compile", "--out", link.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("is a symlink; use the resolved target path instead"),
        "stderr: {}",
        stderr(&output)
    );
    assert_eq!(fs::read(&real).unwrap(), b"x");
}

#[test]
fn watch_requires_a_policy_declaring_command_label() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        "version: 1\npolicy: |\n  rule r:\n    notify exec \"git\" if true\n    because \"b\"\n",
    )
    .unwrap();

    let output = Command::new(actplane())
        .args(["--policy", policy.to_str().unwrap(), "watch"])
        .output()
        .expect("run watch");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains(
            "Error: \"run/auto-attach mode requires the policy to declare or reference label COMMAND (or AGENT for backward compatibility)\""
        ),
        "stderr did not explain the missing COMMAND label:\n{}",
        stderr(&output)
    );
}

#[test]
fn run_and_attach_require_their_targets() {
    let run_output = run(&["run"]);
    assert!(!run_output.status.success());
    assert!(
        stderr(&run_output).contains("<CMD>"),
        "run without a command should report the missing target:\n{}",
        stderr(&run_output)
    );

    let attach_output = run(&["attach"]);
    assert!(!attach_output.status.success());
    assert!(
        stderr(&attach_output).contains("--pid <PID>"),
        "attach without a pid should report the missing flag:\n{}",
        stderr(&attach_output)
    );
}
