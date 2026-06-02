use std::fs;
use std::process::{Command, Output};

fn actplane() -> &'static str {
    env!("CARGO_BIN_EXE_actplane")
}

fn fixture(name: &str) -> String {
    format!("{}/test/policies/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn run(args: &[&str]) -> Output {
    Command::new(actplane())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run actplane {args:?}: {e}"))
}

#[test]
fn check_prints_domain_summary() {
    let policy = fixture("15_domain_bindings.yaml");
    let output = run(&["--policy", &policy, "--domain", "review", "check"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("domain: review"));
    assert!(stdout.contains("parent: session"));
    assert!(stdout.contains("locked: no-git-branch, readonly"));
    assert!(stdout.contains("default: none"));
    assert!(!stdout.contains("no-network —"));
}

#[test]
fn domains_lists_effective_bindings_and_default_selection() {
    let policy = fixture("15_domain_bindings.yaml");
    let output = run(&["--policy", &policy, "domains"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("* review"));
    assert!(stdout.contains("  session"));
    assert!(stdout.contains("disables: no-network"));
    assert!(stdout.contains("locked: no-git-branch, readonly"));
    assert!(stdout.contains("default: no-network"));
}

#[test]
fn compile_prints_selected_domain_before_output_path() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("review.bin");
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
fn ambiguous_domains_error_tells_user_how_to_select() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("actplane.yaml");
    fs::write(
        &path,
        r#"
version: 1
rules:
  r:
    ifc: |
      rule r:
        kill exec "git"
        because "r"
domains:
  alpha:
    bind:
      - rule: r
        mode: default
  beta:
    bind:
      - rule: r
        mode: default
"#,
    )
    .unwrap();
    let output = run(&["--policy", path.to_str().unwrap(), "check"]);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("policy defines multiple domains"));
    assert!(stderr.contains("alpha, beta"));
    assert!(stderr.contains("--domain"));
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}
