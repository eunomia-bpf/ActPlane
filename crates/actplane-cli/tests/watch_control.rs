use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

fn actplane() -> &'static str {
    env!("CARGO_BIN_EXE_actplane")
}

struct WatchProcess {
    child: Child,
    stderr_path: std::path::PathBuf,
}

impl WatchProcess {
    fn start_with_attach_pid(
        policy: &std::path::Path,
        cwd: &std::path::Path,
        attach_pid: i32,
    ) -> Option<Self> {
        let attach_pid = attach_pid.to_string();
        let mut command = if unsafe { libc::geteuid() } == 0 {
            let mut command = Command::new(actplane());
            command.env("ACTPLANE_ATTACH_PID", &attach_pid);
            command
        } else if passwordless_sudo_available() {
            let mut command = Command::new("sudo");
            command.arg("-E").arg("env");
            command.arg(format!("ACTPLANE_ATTACH_PID={attach_pid}"));
            command.arg(actplane());
            command
        } else {
            return None;
        };
        command.args(["--policy", policy.to_str().expect("policy path"), "watch"]);
        let stdout_path = cwd.join("watch.out");
        let stderr_path = cwd.join("watch.err");
        let stdout = std::fs::File::create(&stdout_path).expect("watch stdout");
        let stderr = std::fs::File::create(&stderr_path).expect("watch stderr");
        command
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn actplane watch");
        Some(Self { child, stderr_path })
    }

    fn stop(&mut self) {
        #[cfg(unix)]
        {
            let _ = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGINT) };
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        #[cfg(unix)]
        {
            let _ = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGTERM) };
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

impl Drop for WatchProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

struct FakeAgent {
    child: Child,
}

impl FakeAgent {
    fn start(name: &str) -> Self {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("trap 'exit 0' INT TERM; while :; do sleep 1; done")
            .arg(name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn fake agent root");
        Self { child }
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for FakeAgent {
    fn drop(&mut self) {
        self.stop();
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

#[test]
#[ignore = "requires root/CAP_BPF or passwordless sudo and loads live eBPF programs"]
fn watch_exposes_repo_local_control_socket_privileged() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut agent = FakeAgent::start("actplane-watch-control-agent");
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

    let Some(mut watch) = WatchProcess::start_with_attach_pid(&policy, tmp.path(), agent.pid())
    else {
        eprintln!("skipping privileged watch control e2e: no root/CAP_BPF or passwordless sudo");
        agent.stop();
        return;
    };
    let control_state = tmp.path().join(".actplane").join("control.json");
    wait_for_control_state(&mut watch, &control_state);

    let status = actplane_output(&policy, tmp.path(), &["control", "status"]);
    assert!(status.contains("\"attached\": true"), "{status}");

    let mut status_threads = Vec::new();
    for _ in 0..8 {
        let policy = policy.clone();
        let cwd = tmp.path().to_path_buf();
        status_threads.push(std::thread::spawn(move || {
            for _ in 0..4 {
                let status = actplane_output(&policy, &cwd, &["control", "status"]);
                assert!(status.contains("\"attached\": true"), "{status}");
            }
        }));
    }
    for thread in status_threads {
        thread.join().expect("concurrent status thread");
    }

    let launch = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "--policy",
            policy.to_str().expect("policy path"),
            "control",
            "launch-child",
            "--child-id",
            "550010",
            "--",
            "/bin/sh",
            "-c",
            "echo watch-control-line; sleep 30",
        ])
        .output()
        .expect("control launch-child");
    assert!(
        launch.status.success(),
        "launch-child failed: {}\n{}",
        String::from_utf8_lossy(&launch.stdout),
        String::from_utf8_lossy(&launch.stderr)
    );

    let logs = poll_child_logs(&policy, tmp.path(), 550010, "watch-control-line");
    assert!(logs.contains("watch-control-line"), "{logs}");

    let terminate = actplane_output(
        &policy,
        tmp.path(),
        &["control", "stop", "--child-id", "550010"],
    );
    assert!(
        terminate.contains("child domain 550010") || terminate.contains("already exited"),
        "{terminate}"
    );

    let nested_script = format!(
        r#"
set +e
output=$({actplane} --policy {policy} control launch-child --child-id 550012 -- /bin/true 2>&1)
rc=$?
echo nested-control-rc=$rc
printf '%s\n' "$output"
test "$rc" -ne 0
"#,
        actplane = actplane(),
        policy = policy.display(),
    );
    launch_child(&policy, tmp.path(), 550011, &nested_script);
    let nested_logs = poll_child_logs(&policy, tmp.path(), 550011, "nested-control-rc=");
    assert!(
        !nested_logs.contains("nested-control-rc=0")
            && nested_logs.contains("not trusted parent domain"),
        "bound child-domain peer was not rejected as expected: {nested_logs}"
    );
    let children = actplane_output(&policy, tmp.path(), &["control", "children"]);
    let children_json: serde_json::Value = serde_json::from_str(&children).expect("children JSON");
    let created_nested_child = children_json
        .as_array()
        .expect("children array")
        .iter()
        .any(|child| child["child_id"].as_u64() == Some(550012));
    assert!(
        !created_nested_child,
        "rejected nested launch still created child domain 550012: {children}"
    );

    watch.stop();
    agent.stop();
    assert!(
        !control_state.exists(),
        "control state remained after graceful watch shutdown"
    );

    let marker = tmp.path().join("cleanup-marker");
    std::fs::File::create(&marker)
        .and_then(|mut f| writeln!(f, "ok"))
        .expect("tempdir remains writable by the test user");
}

#[test]
#[ignore = "requires root/CAP_BPF or passwordless sudo and loads concurrent live eBPF programs"]
fn two_watch_engines_keep_child_domain_deltas_isolated_privileged() {
    let tmp_a = tempfile::tempdir().expect("tempdir A");
    let tmp_b = tempfile::tempdir().expect("tempdir B");
    let mut agent_a = FakeAgent::start("actplane-agent-a");
    let mut agent_b = FakeAgent::start("actplane-agent-b");

    let policy_a = write_base_policy(tmp_a.path());
    let policy_b = write_base_policy(tmp_b.path());
    let secret_a = tmp_a.path().join("secret-a.txt");
    let secret_b = tmp_b.path().join("secret-b.txt");
    let hit_a = tmp_a.path().join("apagentahit");
    let hit_b = tmp_b.path().join("apagentbhit");
    std::fs::write(&secret_a, "agent A secret\n").expect("write secret A");
    std::fs::write(&secret_b, "agent B secret\n").expect("write secret B");
    std::fs::copy("/bin/true", &hit_a).expect("copy hit A");
    std::fs::copy("/bin/true", &hit_b).expect("copy hit B");

    let Some(mut watch_a) =
        WatchProcess::start_with_attach_pid(&policy_a, tmp_a.path(), agent_a.pid())
    else {
        eprintln!("skipping two-watch isolation e2e: no root/CAP_BPF or passwordless sudo");
        return;
    };
    let Some(mut watch_b) =
        WatchProcess::start_with_attach_pid(&policy_b, tmp_b.path(), agent_b.pid())
    else {
        eprintln!("skipping two-watch isolation e2e: no root/CAP_BPF or passwordless sudo");
        return;
    };

    wait_for_control_state(
        &mut watch_a,
        &tmp_a.path().join(".actplane").join("control.json"),
    );
    wait_for_control_state(
        &mut watch_b,
        &tmp_b.path().join(".actplane").join("control.json"),
    );

    let delta_a = format!(
        "source SECRET_A = file \"{}\"\nrule only-agent-a:\n  notify exec \"apagentahit\" if SECRET_A\n  because \"agent A delta fired\"\n",
        secret_a.display()
    );
    let delta_b = format!(
        "source SECRET_B = file \"{}\"\nrule only-agent-b:\n  notify exec \"apagentbhit\" if SECRET_B\n  because \"agent B delta fired\"\n",
        secret_b.display()
    );

    launch_child_with_delta(
        &policy_a,
        tmp_a.path(),
        560010,
        &delta_a,
        &format!("read _ < {}; exec {}", secret_a.display(), hit_a.display()),
    );
    launch_child_with_delta(
        &policy_b,
        tmp_b.path(),
        560020,
        &delta_b,
        &format!("read _ < {}; exec {}", secret_b.display(), hit_b.display()),
    );

    let feedback_a = poll_feedback(tmp_a.path(), "agent A delta fired");
    let feedback_b = poll_feedback(tmp_b.path(), "agent B delta fired");
    assert!(feedback_a.contains("only-agent-a"), "{feedback_a}");
    assert!(
        !feedback_a.contains("agent B delta fired") && !feedback_a.contains("only-agent-b"),
        "engine A feedback included engine B policy: {feedback_a}"
    );
    assert!(feedback_b.contains("only-agent-b"), "{feedback_b}");
    assert!(
        !feedback_b.contains("agent A delta fired") && !feedback_b.contains("only-agent-a"),
        "engine B feedback included engine A policy: {feedback_b}"
    );

    watch_a.stop();
    watch_b.stop();
    agent_a.stop();
    agent_b.stop();
}

fn wait_for_control_state(watch: &mut WatchProcess, path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if path.is_file() {
            return;
        }
        if let Some(status) = watch.child.try_wait().expect("poll watch") {
            panic!(
                "watch exited early with {status}; stderr: {}",
                watch.stderr()
            );
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}; stderr: {}",
            path.display(),
            watch.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn actplane_output(policy: &std::path::Path, cwd: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new(actplane())
        .current_dir(cwd)
        .arg("--policy")
        .arg(policy)
        .args(args)
        .output()
        .expect("run actplane");
    assert!(
        output.status.success(),
        "actplane {:?} failed: {}\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
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
    .expect("write base policy");
    policy
}

fn launch_child_with_delta(
    policy: &std::path::Path,
    cwd: &std::path::Path,
    child_id: u32,
    delta: &str,
    script: &str,
) {
    let output = Command::new(actplane())
        .current_dir(cwd)
        .arg("--policy")
        .arg(policy)
        .args([
            "control",
            "launch-child",
            "--child-id",
            &child_id.to_string(),
            "--delta-text",
            delta,
            "--",
            "/bin/sh",
            "-c",
            script,
        ])
        .output()
        .expect("control launch-child with delta");
    assert!(
        output.status.success(),
        "launch-child {child_id} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn launch_child(policy: &std::path::Path, cwd: &std::path::Path, child_id: u32, script: &str) {
    let output = Command::new(actplane())
        .current_dir(cwd)
        .arg("--policy")
        .arg(policy)
        .args([
            "control",
            "launch-child",
            "--child-id",
            &child_id.to_string(),
            "--",
            "/bin/sh",
            "-c",
            script,
        ])
        .output()
        .expect("control launch-child");
    assert!(
        output.status.success(),
        "launch-child {child_id} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn poll_feedback(cwd: &std::path::Path, needle: &str) -> String {
    let path = cwd.join(".actplane").join("last-violation.txt");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
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

fn poll_child_logs(
    policy: &std::path::Path,
    cwd: &std::path::Path,
    child_id: u32,
    needle: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let logs = actplane_output(
            policy,
            cwd,
            &[
                "control",
                "logs",
                "--child-id",
                &child_id.to_string(),
                "--stream",
                "both",
            ],
        );
        if logs.contains(needle) {
            return logs;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for child {child_id} logs containing {needle}; saw {logs}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
