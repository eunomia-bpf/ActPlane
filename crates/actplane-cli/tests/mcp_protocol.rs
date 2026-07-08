use std::io::{BufRead, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use serde_json::{Value, json};

fn actplane() -> &'static str {
    env!("CARGO_BIN_EXE_actplane")
}

struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: mpsc::Receiver<Value>,
    stderr_rx: mpsc::Receiver<String>,
}

impl McpProcess {
    fn start(policy: &std::path::Path, cwd: &std::path::Path) -> Self {
        let mut command = Command::new(actplane());
        command.args(["--policy", policy.to_str().expect("policy path"), "mcp"]);
        Self::spawn(command, cwd)
    }

    fn start_auto_attach(policy: &std::path::Path, cwd: &std::path::Path) -> Option<Self> {
        Self::start_auto_attach_with_pid(policy, cwd, std::process::id() as i32)
    }

    fn start_auto_attach_with_pid(
        policy: &std::path::Path,
        cwd: &std::path::Path,
        attach_pid: i32,
    ) -> Option<Self> {
        let attach_pid = attach_pid.to_string();
        let pin_root = bpf_pin_root();
        let mut command = if unsafe { libc::geteuid() } == 0 {
            let mut command = Command::new(actplane());
            command.env("ACTPLANE_ATTACH_PID", &attach_pid);
            command.env("ACTPLANE_BPF_PIN_ROOT", &pin_root);
            command
        } else if passwordless_sudo_available() {
            let mut command = Command::new("sudo");
            command.arg("-E").arg("env");
            command.arg(format!("ACTPLANE_ATTACH_PID={attach_pid}"));
            command.arg(format!("ACTPLANE_BPF_PIN_ROOT={pin_root}"));
            command.arg(actplane());
            command
        } else {
            return None;
        };
        command.args([
            "--policy",
            policy.to_str().expect("policy path"),
            "mcp",
            "--auto-attach-parent",
        ]);
        Some(Self::spawn(command, cwd))
    }

    fn spawn(mut command: Command, cwd: &std::path::Path) -> Self {
        command
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("spawn actplane mcp");
        let stdin = child.stdin.take().expect("mcp stdin");
        let stdout = child.stdout.take().expect("mcp stdout");
        let stderr = child.stderr.take().expect("mcp stderr");
        let (tx, rx) = mpsc::channel();
        let (stderr_tx, stderr_rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(&line) {
                    Ok(value) => {
                        let _ = tx.send(value);
                    }
                    Err(e) => {
                        let _ = tx.send(json!({
                            "jsonrpc": "2.0",
                            "parse_error": e.to_string(),
                            "raw": line,
                        }));
                    }
                }
            }
        });
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr).lines() {
                let Ok(line) = line else {
                    break;
                };
                let _ = stderr_tx.send(line);
            }
        });
        Self {
            child,
            stdin: Some(stdin),
            rx,
            stderr_rx,
        }
    }

    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().expect("mcp stdin open");
        serde_json::to_writer(&mut *stdin, &value).expect("write request");
        writeln!(stdin).expect("write newline");
        stdin.flush().expect("flush request");
    }

    fn response(&self, id: i64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut stderr = Vec::new();
        let mut seen = Vec::new();
        loop {
            let now = Instant::now();
            while let Ok(line) = self.stderr_rx.try_recv() {
                stderr.push(line);
            }
            assert!(
                now < deadline,
                "timed out waiting for MCP response id {id}; seen: {seen:?}; stderr: {stderr:?}"
            );
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(value) => {
                    if value.get("id").and_then(Value::as_i64) == Some(id) {
                        return value;
                    }
                    seen.push(value);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("MCP stdout closed waiting for response id {id}; stderr: {stderr:?}");
                }
            }
        }
    }
}

impl Drop for McpProcess {
    fn drop(&mut self) {
        drop(self.stdin.take());
        #[cfg(unix)]
        {
            let _ = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn passwordless_sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn bpf_pin_root() -> String {
    let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_string());
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_string());
    format!(
        "/sys/fs/bpf/actplane/test-mcp-{run_id}-{attempt}-{}",
        std::process::id()
    )
}

fn reset_bpf_pin_root() {
    let root = bpf_pin_root();
    let mut command = if unsafe { libc::geteuid() } == 0 {
        Command::new("rm")
    } else if passwordless_sudo_available() {
        let mut command = Command::new("sudo");
        command.arg("-n");
        command
    } else {
        return;
    };
    let _ = command
        .args(["-rf", &root])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn test_child_id(offset: u32) -> u32 {
    0x4000_0000 | ((std::process::id() & 0xffff) << 12) | (offset & 0x0fff)
}

#[test]
fn mcp_stdio_jsonrpc_lists_resources_and_domain_tools() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = tmp.path().join("actplane.yaml");
    std::fs::write(
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
    .expect("write policy");

    let mut mcp = McpProcess::start(&policy, tmp.path());
    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "actplane-test", "version": "0" }
        }
    }));
    let init = mcp.response(1);
    assert_eq!(
        init["result"]["capabilities"]["tools"],
        json!({}),
        "initialize response: {init}"
    );
    assert_eq!(init["result"]["capabilities"]["resources"], json!({}));

    mcp.send(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    std::thread::sleep(Duration::from_millis(50));

    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    let tools = mcp.response(2);
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect();
    for expected in [
        "launch_child_domain",
        "list_child_domains",
        "read_child_domain_logs",
        "terminate_child_domain",
        "append_policy_delta",
        "restart_child_domain",
        "reconcile_child_domains",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool {expected}: {names:?}"
        );
    }

    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/list",
        "params": {}
    }));
    let resources = mcp.response(3);
    let uris: Vec<&str> = resources["result"]["resources"]
        .as_array()
        .expect("resources array")
        .iter()
        .filter_map(|resource| resource.get("uri").and_then(Value::as_str))
        .collect();
    assert!(uris.contains(&"actplane:///policy"), "resources: {uris:?}");
    assert!(
        uris.contains(&"actplane:///feedback"),
        "resources: {uris:?}"
    );

    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/read",
        "params": { "uri": "actplane:///policy" }
    }));
    let policy_resource = mcp.response(4);
    let text = policy_resource["result"]["contents"][0]["text"]
        .as_str()
        .expect("policy resource text");
    assert!(text.contains("Policy valid"), "{text}");
    assert!(text.contains("noop"), "{text}");

    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": { "name": "list_child_domains", "arguments": {} }
    }));
    let list_children = mcp.response(5);
    assert_eq!(list_children["result"]["isError"], false);
    assert_eq!(list_children["result"]["content"][0]["text"], "[]");

    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "launch_child_domain",
            "arguments": { "cmd": ["/bin/true"] }
        }
    }));
    let launch_without_engine = mcp.response(6);
    let error = launch_without_engine["error"].to_string();
    assert!(
        error.contains("No eBPF engine attached"),
        "unexpected launch error: {launch_without_engine}"
    );
}

#[test]
fn mcp_stdio_jsonrpc_handles_repeated_requests() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = write_base_policy(tmp.path());
    let mut mcp = McpProcess::start(&policy, tmp.path());
    initialize_mcp(&mut mcp, 1, "actplane-repeated-request-stress");

    for i in 0..96 {
        let id = 100 + i as i64;
        let kind = match i % 3 {
            0 => {
                mcp.send(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/list",
                    "params": {}
                }));
                "tools/list"
            }
            1 => {
                mcp.send(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "resources/list",
                    "params": {}
                }));
                "resources/list"
            }
            _ => {
                mcp.send(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": "list_child_domains", "arguments": {} }
                }));
                "tools/call"
            }
        };

        let response = mcp.response(id);
        assert!(
            response.get("error").is_none(),
            "{kind} id {id} returned error: {response}"
        );
        match kind {
            "tools/list" => assert!(
                response["result"]["tools"].as_array().is_some(),
                "tools/list response: {response}"
            ),
            "resources/list" => assert!(
                response["result"]["resources"].as_array().is_some(),
                "resources/list response: {response}"
            ),
            "tools/call" => {
                assert_eq!(response["result"]["isError"], false, "{response}");
                assert_eq!(response["result"]["content"][0]["text"], "[]");
            }
            _ => unreachable!("unexpected request kind"),
        }
    }
}

#[test]
#[ignore = "requires root/CAP_BPF or passwordless sudo and loads live eBPF programs"]
fn mcp_stdio_jsonrpc_launches_child_domain_with_delta_privileged() {
    reset_bpf_pin_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = tmp.path().join("actplane.yaml");
    std::fs::write(
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
    .expect("write policy");
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, "classified\n").expect("write secret");
    let hit = tmp.path().join("apmcphit");
    std::fs::copy("/bin/true", &hit).expect("copy /bin/true");
    let delta = format!(
        "source SECRET = file \"{}\"\nrule mcp-secret:\n  notify exec \"apmcphit\" if SECRET\n  because \"mcp delta fired\"\n",
        secret.display()
    );

    let Some(mut mcp) = McpProcess::start_auto_attach(&policy, tmp.path()) else {
        eprintln!("skipping privileged MCP e2e: no root/CAP_BPF or passwordless sudo");
        return;
    };
    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "actplane-priv-test", "version": "0" }
        }
    }));
    let init = mcp.response(1);
    assert!(init.get("result").is_some(), "initialize failed: {init}");
    mcp.send(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    std::thread::sleep(Duration::from_millis(50));

    let child_id = test_child_id(1);
    let log_child_id = test_child_id(10);
    let restart_child_id = test_child_id(20);
    let replacement_child_id = test_child_id(21);
    let command = format!("read _ < '{}'; exec '{}'", secret.display(), hit.display());
    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "launch_child_domain",
            "arguments": {
                "child_id": child_id,
                "cmd": ["/bin/sh", "-c", command],
                "policy": delta
            }
        }
    }));
    let launch = mcp.response(2);
    assert!(
        launch["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains(&format!("child domain {child_id}")),
        "launch response: {launch}"
    );

    let feedback = poll_feedback(tmp.path(), "mcp delta fired");
    assert!(
        feedback.contains("mcp-secret"),
        "feedback did not include appended rule: {feedback}"
    );
    assert!(
        feedback.contains("Provenance"),
        "feedback did not include provenance: {feedback}"
    );
    let audit = poll_audit_append_delta(tmp.path(), child_id);
    let provenance = audit["rule_provenance"]
        .as_array()
        .expect("rule provenance");
    assert_eq!(provenance[0]["name"], "mcp-secret");
    assert_eq!(provenance[0]["source_ref"], "rule:mcp-secret");
    assert!(
        provenance[0]["source_text"]
            .as_str()
            .unwrap_or("")
            .contains("rule mcp-secret")
    );

    let mut next_id = 3;
    let append_audit_delta = call_tool(
        &mut mcp,
        &mut next_id,
        "append_policy_delta",
        json!({
            "policy": "rule mcp-audit:\n  notify exec \"__actplane_never__\"\n  because \"audit metadata\"\n",
            "policy_ref": "inline://mcp-audit",
            "approved_by": "test-reviewer",
            "approval_ref": "test-approval-1",
            "generated_by": "mcp-protocol-test"
        }),
    );
    assert!(
        tool_text(&append_audit_delta).contains("Appended policy delta"),
        "append audit delta response: {append_audit_delta}"
    );
    let audit = poll_audit_append_delta_ref(tmp.path(), "inline://mcp-audit");
    assert_eq!(audit["approved_by"], "test-reviewer");
    assert_eq!(audit["approval_ref"], "test-approval-1");
    assert_eq!(audit["generated_by"], "mcp-protocol-test");
    assert_eq!(audit["approval_chain"]["approved_by"], "test-reviewer");
    assert_eq!(audit["approval_chain"]["approval_ref"], "test-approval-1");
    assert_eq!(audit["approval_chain"]["generated_by"], "mcp-protocol-test");
    assert_eq!(audit["approval_chain"]["enforced"], false);
    assert_eq!(audit["approval_chain"]["workflow"], "declarative_metadata");
    assert!(
        audit["actor_identity"]["stable_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("pid:")
    );
    assert!(
        audit["caller_identity"]["stable_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("pid:")
    );
    assert_ne!(
        audit["caller_identity"]["proc_start_time"],
        serde_json::Value::Null
    );
    assert!(
        audit["submitter_identity"]["stable_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("pid:")
    );

    let launch_log_child = call_tool(
        &mut mcp,
        &mut next_id,
        "launch_child_domain",
        json!({
            "child_id": log_child_id,
            "cmd": ["/bin/sh", "-c", "echo mcp-log-line; sleep 30"]
        }),
    );
    assert!(
        tool_text(&launch_log_child).contains(&format!("child domain {log_child_id}")),
        "launch log child response: {launch_log_child}"
    );
    let logs = poll_child_stdout(&mut mcp, &mut next_id, log_child_id, "mcp-log-line");
    assert_eq!(logs["child_id"], log_child_id);
    assert!(
        logs["stdout"]["content"]
            .as_str()
            .unwrap_or("")
            .contains("mcp-log-line"),
        "child logs: {logs}"
    );

    let terminate = call_tool(
        &mut mcp,
        &mut next_id,
        "terminate_child_domain",
        json!({ "child_id": log_child_id }),
    );
    let terminate_text = tool_text(&terminate);
    assert!(
        terminate_text.contains(&format!("Terminated child domain {log_child_id}"))
            || terminate_text.contains("already exited"),
        "terminate response: {terminate}"
    );

    let launch_restart_child = call_tool(
        &mut mcp,
        &mut next_id,
        "launch_child_domain",
        json!({
            "child_id": restart_child_id,
            "cmd": ["/bin/sh", "-c", "echo mcp-restart-line; sleep 30"]
        }),
    );
    assert!(
        tool_text(&launch_restart_child).contains(&format!("child domain {restart_child_id}")),
        "launch restart child response: {launch_restart_child}"
    );

    let restart = call_tool(
        &mut mcp,
        &mut next_id,
        "restart_child_domain",
        json!({
            "child_id": restart_child_id,
            "new_child_id": replacement_child_id,
            "terminate_existing": true
        }),
    );
    assert!(
        tool_text(&restart).contains(&format!("child domain {replacement_child_id}")),
        "restart response: {restart}"
    );
    let restarted_logs = poll_child_stdout(
        &mut mcp,
        &mut next_id,
        replacement_child_id,
        "mcp-restart-line",
    );
    assert!(
        restarted_logs["stdout"]["content"]
            .as_str()
            .unwrap_or("")
            .contains("mcp-restart-line"),
        "restarted child logs: {restarted_logs}"
    );

    let reconcile = call_tool(&mut mcp, &mut next_id, "reconcile_child_domains", json!({}));
    let reconciled = tool_json(&reconcile);
    let children = reconciled["children"].as_array().expect("children array");
    let original = find_child(children, restart_child_id);
    assert_ne!(
        original["status"]["state"], "running",
        "original child still running after restart: {reconciled}"
    );
    let replacement = find_child(children, replacement_child_id);
    assert_eq!(replacement["restarted_from"], restart_child_id);
    assert_eq!(replacement["status"]["state"], "running");

    let terminate_replacement = call_tool(
        &mut mcp,
        &mut next_id,
        "terminate_child_domain",
        json!({ "child_id": replacement_child_id }),
    );
    assert!(
        tool_text(&terminate_replacement).contains(&format!("child domain {replacement_child_id}"))
            || tool_text(&terminate_replacement).contains("already exited"),
        "terminate replacement response: {terminate_replacement}"
    );
}

#[test]
#[ignore = "requires root/CAP_BPF or passwordless sudo and loads live eBPF programs"]
fn mcp_append_delta_requires_configured_approval_privileged() {
    reset_bpf_pin_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = tmp.path().join("actplane.yaml");
    std::fs::write(
        &policy,
        r#"
version: 1
runtime:
  approval:
    append_delta:
      required: true
      require_approval_ref: true
      require_generated_by: true
      allowed_approvers:
        - repo-supervisor
policy: |
  source COMMAND = exec "**"
  rule noop:
    notify exec "__actplane_never__" if COMMAND
    because "noop"
"#,
    )
    .expect("write policy");

    let Some(mut mcp) = McpProcess::start_auto_attach(&policy, tmp.path()) else {
        eprintln!("skipping privileged MCP approval e2e: no root/CAP_BPF or passwordless sudo");
        return;
    };
    initialize_mcp(&mut mcp, 1, "actplane-approval-test");

    let mut next_id = 2;
    let rejected = call_tool_raw(
        &mut mcp,
        &mut next_id,
        "append_policy_delta",
        json!({
            "policy": "rule missing-approval:\n  notify exec \"__actplane_never__\"\n  because \"missing approval\"",
            "policy_ref": "inline://missing-approval"
        }),
    );
    assert!(
        rejected.to_string().contains("requires approval metadata"),
        "missing approval response: {rejected}"
    );
    let rejected_audit =
        poll_audit_append_delta_ref_status(tmp.path(), "inline://missing-approval", "rejected");
    assert_eq!(rejected_audit["approval_chain"]["enforced"], true);
    assert_eq!(rejected_audit["approval_chain"]["decision"], "rejected");
    assert_eq!(
        rejected_audit["approval_chain"]["missing_fields"],
        json!(["approved_by", "approval_ref", "generated_by"])
    );

    let accepted = call_tool(
        &mut mcp,
        &mut next_id,
        "append_policy_delta",
        json!({
            "policy": "rule approved:\n  notify exec \"__actplane_never__\"\n  because \"approved\"",
            "policy_ref": "inline://approved",
            "approved_by": "repo-supervisor",
            "approval_ref": "ticket-42",
            "generated_by": "mcp-approval-test"
        }),
    );
    assert!(
        tool_text(&accepted).contains("Appended policy delta"),
        "accepted response: {accepted}"
    );
    let accepted_audit =
        poll_audit_append_delta_ref_status(tmp.path(), "inline://approved", "accepted");
    assert_eq!(accepted_audit["approval_chain"]["enforced"], true);
    assert_eq!(accepted_audit["approval_chain"]["decision"], "accepted");
    assert_eq!(
        accepted_audit["approval_chain"]["admission_model"],
        "static_metadata_allowlist"
    );
    assert_eq!(accepted_audit["approval_chain"]["external_verified"], false);
    assert_eq!(
        accepted_audit["approval_chain"]["signature"],
        serde_json::Value::Null
    );
}

#[test]
#[ignore = "requires root/CAP_BPF or passwordless sudo and loads live eBPF programs"]
fn mcp_background_supervisor_relaunches_on_exit_child_privileged() {
    reset_bpf_pin_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = write_base_policy(tmp.path());
    let Some(mut mcp) = McpProcess::start_auto_attach(&policy, tmp.path()) else {
        eprintln!("skipping privileged MCP supervisor e2e: no root/CAP_BPF or passwordless sudo");
        return;
    };
    initialize_mcp(&mut mcp, 1, "actplane-supervisor-test");

    let mut next_id = 2;
    let child_id = test_child_id(100);
    let launch = call_tool(
        &mut mcp,
        &mut next_id,
        "launch_child_domain",
        json!({
            "child_id": child_id,
            "cmd": ["/bin/sh", "-c", "echo mcp-supervisor-line; sleep 30"],
            "restart_policy": "on_exit",
            "restart_limit": 1,
            "restart_backoff_ms": 100
        }),
    );
    assert!(
        tool_text(&launch).contains(&format!("child domain {child_id}")),
        "launch response: {launch}"
    );

    let listed = call_tool(&mut mcp, &mut next_id, "list_child_domains", json!({}));
    let rows = tool_json(&listed);
    let children = rows.as_array().expect("children array");
    let original = find_child(children, child_id);
    assert_eq!(original["restart_policy"], "on_exit");
    assert_eq!(original["restart_limit"].as_u64(), Some(1));
    assert_eq!(original["restart_backoff_ms"].as_u64(), Some(100));
    let original_pid = original["pid"].as_i64().expect("original pid") as i32;

    kill_process_group(original_pid);
    let reconciled = poll_supervised_replacement(&mut mcp, &mut next_id, child_id);
    let children = reconciled.as_array().expect("children array");
    let old = find_child(children, child_id);
    let replacement_id = old["replacement_child_id"]
        .as_u64()
        .expect("replacement child id") as u32;
    assert_ne!(replacement_id, child_id);

    assert_ne!(
        old["status"]["state"], "running",
        "old child should no longer be running: {reconciled}"
    );
    let replacement = find_child(children, replacement_id);
    assert_eq!(replacement["restarted_from"], child_id);
    assert_eq!(replacement["restart_policy"], "on_exit");
    assert_eq!(replacement["restart_count"].as_u64(), Some(1));
    assert_eq!(replacement["restart_limit"].as_u64(), Some(1));
    assert_eq!(replacement["status"]["state"], "running");
    let replacement_pid = replacement["pid"].as_i64().expect("replacement pid") as i32;

    let logs = poll_child_stdout(
        &mut mcp,
        &mut next_id,
        replacement_id,
        "mcp-supervisor-line",
    );
    assert!(
        logs["stdout"]["content"]
            .as_str()
            .unwrap_or("")
            .contains("mcp-supervisor-line"),
        "replacement child logs: {logs}"
    );

    kill_process_group(replacement_pid);
    let blocked = poll_restart_blocked(&mut mcp, &mut next_id, replacement_id);
    let blocked_children = blocked.as_array().expect("blocked children array");
    let replacement = find_child(blocked_children, replacement_id);
    assert_eq!(
        replacement["restart_blocked_reason"],
        "restart limit reached"
    );
    assert_eq!(
        replacement["replacement_child_id"],
        Value::Null,
        "supervisor should not relaunch past restart_limit: {blocked}"
    );
    let audit = poll_audit_restart_status(tmp.path(), replacement_id, "blocked");
    assert_eq!(audit["error"], "restart limit reached");
    assert!(audit["submitter_pid"].as_i64().is_some());
    assert!(audit["engine_parent_domain_id"].as_u64().is_some());
}

#[test]
#[ignore = "requires root/CAP_BPF or passwordless sudo and loads live eBPF programs"]
fn mcp_restart_adopts_existing_child_and_relaunches_after_exit_privileged() {
    reset_bpf_pin_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = write_base_policy(tmp.path());
    let Some(mut first_mcp) = McpProcess::start_auto_attach(&policy, tmp.path()) else {
        eprintln!("skipping privileged MCP adoption e2e: no root/CAP_BPF or passwordless sudo");
        return;
    };
    initialize_mcp(&mut first_mcp, 1, "actplane-adopt-first");

    let mut next_id = 2;
    let child_id = test_child_id(200);
    let launch = call_tool(
        &mut first_mcp,
        &mut next_id,
        "launch_child_domain",
        json!({
            "child_id": child_id,
            "cmd": ["/bin/sh", "-c", "echo mcp-adopt-line; sleep 30"],
            "restart_policy": "on_exit",
            "restart_limit": 1,
            "restart_backoff_ms": 100
        }),
    );
    assert!(
        tool_text(&launch).contains(&format!("child domain {child_id}")),
        "launch response: {launch}"
    );
    let listed = call_tool(
        &mut first_mcp,
        &mut next_id,
        "list_child_domains",
        json!({}),
    );
    let rows = tool_json(&listed);
    let children = rows.as_array().expect("children array");
    let original = find_child(children, child_id);
    assert_eq!(original["supervision"]["mode"], "wait_handle");
    let original_pid = original["pid"].as_i64().expect("original pid") as i32;

    drop(first_mcp);
    assert!(
        process_exists(original_pid),
        "child process should survive MCP server restart"
    );

    let Some(mut second_mcp) = McpProcess::start_auto_attach(&policy, tmp.path()) else {
        eprintln!("skipping privileged MCP adoption e2e: no root/CAP_BPF or passwordless sudo");
        kill_process_group(original_pid);
        return;
    };
    initialize_mcp(&mut second_mcp, 100, "actplane-adopt-second");
    let mut next_id = 101;

    let adopted_rows = poll_child_adopted(&mut second_mcp, &mut next_id, child_id);
    let adopted_children = adopted_rows.as_array().expect("adopted children array");
    let adopted = find_child(adopted_children, child_id);
    assert_eq!(adopted["pid"].as_i64(), Some(original_pid as i64));
    let audit = poll_audit_child_event(
        tmp.path(),
        "adopt_child_domain",
        "child_domain_id",
        child_id,
        "accepted",
    );
    assert_eq!(audit["supervision_mode"], "adopted_polling");
    assert!(audit["submitter_pid"].as_i64().is_some());
    assert!(audit["engine_parent_pid"].as_i64().is_some());
    assert!(audit["engine_parent_domain_id"].as_u64().is_some());
    assert!(
        audit["audit_context_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("mcp-")
    );

    kill_process_group(original_pid);
    let reconciled = poll_supervised_replacement(&mut second_mcp, &mut next_id, child_id);
    let children = reconciled.as_array().expect("children array");
    let old = find_child(children, child_id);
    let replacement_id = old["replacement_child_id"]
        .as_u64()
        .expect("replacement child id") as u32;
    assert_ne!(old["status"]["state"], "running");
    let replacement = find_child(children, replacement_id);
    assert_eq!(replacement["restarted_from"], child_id);
    assert_eq!(replacement["restart_count"].as_u64(), Some(1));
    assert_eq!(replacement["supervision"]["mode"], "wait_handle");

    let terminate = call_tool(
        &mut second_mcp,
        &mut next_id,
        "terminate_child_domain",
        json!({ "child_id": replacement_id }),
    );
    assert!(
        tool_text(&terminate).contains("child domain")
            || tool_text(&terminate).contains("already exited"),
        "terminate response: {terminate}"
    );
}

#[test]
#[ignore = "requires root/CAP_BPF or passwordless sudo and loads live eBPF programs"]
fn mcp_local_control_handles_concurrent_status_privileged() {
    reset_bpf_pin_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = write_base_policy(tmp.path());
    let Some(mut mcp) = McpProcess::start_auto_attach(&policy, tmp.path()) else {
        eprintln!(
            "skipping privileged MCP control stress e2e: no root/CAP_BPF or passwordless sudo"
        );
        return;
    };
    initialize_mcp(&mut mcp, 1, "actplane-control-stress");
    wait_for_control_state(&mut mcp, &tmp.path().join(".actplane").join("control.json"));

    let mut threads = Vec::new();
    for _ in 0..16 {
        let policy = policy.clone();
        let cwd = tmp.path().to_path_buf();
        threads.push(std::thread::spawn(move || {
            for _ in 0..8 {
                let status = actplane_control_output(&policy, &cwd, &["control", "status"]);
                assert!(status.contains("\"attached\": true"), "{status}");
            }
        }));
    }
    for thread in threads {
        thread.join().expect("concurrent MCP control status thread");
    }
}

fn initialize_mcp(mcp: &mut McpProcess, id: i64, client_name: &str) {
    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": client_name, "version": "0" }
        }
    }));
    let init = mcp.response(id);
    assert!(init.get("result").is_some(), "initialize failed: {init}");
    mcp.send(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    std::thread::sleep(Duration::from_millis(50));
}

fn wait_for_control_state(mcp: &mut McpProcess, path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut stderr = Vec::new();
    loop {
        while let Ok(line) = mcp.stderr_rx.try_recv() {
            stderr.push(line);
        }
        if path.is_file() {
            return;
        }
        if let Some(status) = mcp.child.try_wait().expect("poll mcp") {
            panic!("MCP exited early with {status}; stderr: {stderr:?}");
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}; stderr: {stderr:?}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn actplane_control_output(
    policy: &std::path::Path,
    cwd: &std::path::Path,
    args: &[&str],
) -> String {
    let output = Command::new(actplane())
        .current_dir(cwd)
        .arg("--policy")
        .arg(policy)
        .args(args)
        .output()
        .expect("run actplane control");
    assert!(
        output.status.success(),
        "actplane {:?} failed: {}\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn call_tool(mcp: &mut McpProcess, next_id: &mut i64, name: &str, arguments: Value) -> Value {
    let response = call_tool_raw(mcp, next_id, name, arguments);
    assert!(
        response.get("error").is_none(),
        "tool {name} returned top-level error: {response}"
    );
    assert_eq!(
        response["result"]["isError"], false,
        "tool {name} returned tool error: {response}"
    );
    response
}

fn call_tool_raw(mcp: &mut McpProcess, next_id: &mut i64, name: &str, arguments: Value) -> Value {
    let id = *next_id;
    *next_id += 1;
    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        }
    }));
    mcp.response(id)
}

fn tool_text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text content")
}

fn tool_json(response: &Value) -> Value {
    serde_json::from_str(tool_text(response)).expect("tool JSON content")
}

fn poll_child_stdout(
    mcp: &mut McpProcess,
    next_id: &mut i64,
    child_id: u32,
    needle: &str,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = call_tool(
            mcp,
            next_id,
            "read_child_domain_logs",
            json!({
                "child_id": child_id,
                "stream": "stdout",
                "max_bytes": 4096,
            }),
        );
        let logs = tool_json(&response);
        let stdout = logs["stdout"]["content"].as_str().unwrap_or("");
        if stdout.contains(needle) {
            return logs;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for child {child_id} stdout containing {needle}; saw {logs}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn find_child<'a>(children: &'a [Value], child_id: u32) -> &'a Value {
    children
        .iter()
        .find(|child| child["child_id"].as_u64() == Some(child_id as u64))
        .unwrap_or_else(|| panic!("missing child {child_id}: {children:?}"))
}

fn poll_supervised_replacement(
    mcp: &mut McpProcess,
    next_id: &mut i64,
    old_child_id: u32,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = call_tool(mcp, next_id, "list_child_domains", json!({}));
        let rows = tool_json(&response);
        if rows
            .as_array()
            .map(|children| {
                children.iter().any(|child| {
                    child["child_id"].as_u64() == Some(old_child_id as u64)
                        && child["replacement_child_id"].as_u64().is_some()
                })
            })
            .unwrap_or(false)
        {
            return rows;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for background supervisor to replace child {old_child_id}; saw {rows}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn poll_restart_blocked(mcp: &mut McpProcess, next_id: &mut i64, child_id: u32) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = call_tool(mcp, next_id, "list_child_domains", json!({}));
        let rows = tool_json(&response);
        if rows
            .as_array()
            .map(|children| {
                children.iter().any(|child| {
                    child["child_id"].as_u64() == Some(child_id as u64)
                        && child["restart_blocked_reason"].as_str() == Some("restart limit reached")
                        && child["restart_alerted_unix_ms"].as_u64().is_some()
                        && child["replacement_child_id"].as_u64().is_none()
                })
            })
            .unwrap_or(false)
        {
            return rows;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for restart limit alert on child {child_id}; saw {rows}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn poll_child_adopted(mcp: &mut McpProcess, next_id: &mut i64, child_id: u32) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = call_tool(mcp, next_id, "list_child_domains", json!({}));
        let rows = tool_json(&response);
        if rows
            .as_array()
            .map(|children| {
                children.iter().any(|child| {
                    child["child_id"].as_u64() == Some(child_id as u64)
                        && child["status"]["state"].as_str() == Some("running")
                        && child["supervision"]["mode"].as_str() == Some("adopted_polling")
                        && child["adopted_unix_ms"].as_u64().is_some()
                })
            })
            .unwrap_or(false)
        {
            return rows;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for child {child_id} adoption; saw {rows}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn kill_process_group(pid: i32) {
    let rc = unsafe { libc::kill(-pid, libc::SIGTERM) };
    assert!(
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
        "kill process group {pid} failed: {}",
        std::io::Error::last_os_error()
    );
}

fn process_exists(pid: i32) -> bool {
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

fn poll_audit_restart_status(root: &std::path::Path, child_id: u32, status: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = read_audit_files(root);
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line).expect("audit JSONL record");
            if value["event"] == "restart_child_domain"
                && value["old_child_domain_id"].as_u64() == Some(child_id as u64)
                && value["status"].as_str() == Some(status)
            {
                return value;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for audit restart status {status} on child {child_id}; saw {text}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn poll_audit_append_delta(root: &std::path::Path, target_id: u32) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = read_audit_files(root);
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line).expect("audit JSONL record");
            if value["event"] == "append_policy_delta"
                && value["status"].as_str() == Some("accepted")
                && value["target_id"].as_u64() == Some(target_id as u64)
            {
                return value;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for append-delta audit on target {target_id}; saw {text}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn poll_audit_append_delta_ref(root: &std::path::Path, policy_ref: &str) -> Value {
    poll_audit_append_delta_ref_status(root, policy_ref, "accepted")
}

fn poll_audit_append_delta_ref_status(
    root: &std::path::Path,
    policy_ref: &str,
    status: &str,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = read_audit_files(root);
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line).expect("audit JSONL record");
            if value["event"] == "append_policy_delta"
                && value["status"].as_str() == Some(status)
                && value["policy_ref"].as_str() == Some(policy_ref)
            {
                return value;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for append-delta audit with policy_ref {policy_ref}; saw {text}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn poll_audit_child_event(
    root: &std::path::Path,
    event: &str,
    child_field: &str,
    child_id: u32,
    status: &str,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = read_audit_files(root);
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line).expect("audit JSONL record");
            if value["event"] == event
                && value[child_field].as_u64() == Some(child_id as u64)
                && value["status"].as_str() == Some(status)
            {
                return value;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for audit event {event}/{status} on child {child_id}; saw {text}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_audit_files(root: &std::path::Path) -> String {
    let mut out = String::new();
    let root_audit = root.join(".actplane").join("audit.jsonl");
    if let Ok(text) = std::fs::read_to_string(root_audit) {
        out.push_str(&text);
    }
    let runs = root.join(".actplane").join("runs");
    let Ok(entries) = std::fs::read_dir(runs) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("audit.jsonl");
        if let Ok(text) = std::fs::read_to_string(path) {
            out.push_str(&text);
        }
    }
    out
}

fn poll_feedback(root: &std::path::Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = read_feedback_files(root);
        if text.contains(needle) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for feedback containing {needle}; saw {text}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_feedback_files(root: &std::path::Path) -> String {
    let mut out = String::new();
    let runs = root.join(".actplane").join("runs");
    let Ok(entries) = std::fs::read_dir(runs) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("feedback.txt");
        if let Ok(text) = std::fs::read_to_string(path) {
            out.push_str(&text);
        }
    }
    out
}

fn write_base_policy(cwd: &std::path::Path) -> std::path::PathBuf {
    let policy = cwd.join("actplane.yaml");
    std::fs::write(
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
    .expect("write policy");
    policy
}
