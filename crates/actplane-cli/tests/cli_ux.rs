use std::fs;
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
        "run", "compile", "init", "doctor", "watch", "mcp", "control",
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
    assert!(stdout.contains("locked: no-git-branch, readonly"));
    assert!(stdout.contains("default: none"));
    assert!(!stdout.contains("no-network —"));
}

#[test]
fn compile_json_reports_backend_support_and_static_warnings() {
    let policy = r#"
source NET = endpoint "source.example.com"

rule recv-soft:
  notify recv endpoint "*" if true
  because "recv notify"

rule host-connect:
  notify connect endpoint "api.example.com" if true
  because "hostname connect"
"#;
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");

    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["matrix_scope"], "static_initial_policy_host_support");
    assert_eq!(value["rule_count"], 2);
    assert_eq!(value["backend_support"]["sources"][0]["label"], "NET");
    assert_eq!(value["backend_support"]["sources"][0]["supported"], false);
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
    assert!(artifact.contains("review scope: selected initial policy"));
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
    assert!(stdout.contains("disables: no-network"));
    assert!(stdout.contains("locked: no-git-branch, readonly"));
    assert!(stdout.contains("default: no-network"));
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
    assert!(stderr.contains("locked: no-git-branch, readonly"));
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
        "reload",
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

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}
