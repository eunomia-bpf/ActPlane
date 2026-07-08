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

fn bpf_pin_root() -> String {
    let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_string());
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_string());
    format!(
        "/sys/fs/bpf/actplane/test-watch-{run_id}-{attempt}-{}",
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
    0x5000_0000 | ((std::process::id() & 0xffff) << 12) | (offset & 0x0fff)
}

#[test]
#[ignore = "requires root/CAP_BPF or passwordless sudo and loads live eBPF programs"]
fn watch_exposes_repo_local_control_socket_privileged() {
    reset_bpf_pin_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut agent = FakeAgent::start("actplane-watch-control-agent");
    let child_id = test_child_id(1);
    let nested_parent_id = test_child_id(2);
    let nested_rejected_id = test_child_id(3);
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

    let child_id_arg = child_id.to_string();
    let launch = Command::new(actplane())
        .current_dir(tmp.path())
        .arg("--policy")
        .arg(policy.to_str().expect("policy path"))
        .args([
            "control",
            "launch-child",
            "--child-id",
            &child_id_arg,
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

    let logs = poll_child_logs(&policy, tmp.path(), child_id, "watch-control-line");
    assert!(logs.contains("watch-control-line"), "{logs}");

    let terminate = actplane_output(
        &policy,
        tmp.path(),
        &["control", "stop", "--child-id", &child_id_arg],
    );
    assert!(
        terminate.contains(&format!("child domain {child_id}"))
            || terminate.contains("already exited"),
        "{terminate}"
    );

    let nested_script = format!(
        r#"
set +e
output=$({actplane} --policy {policy} control launch-child --child-id {nested_rejected_id} -- /bin/true 2>&1)
rc=$?
echo nested-control-rc=$rc
printf '%s\n' "$output"
test "$rc" -ne 0
"#,
        actplane = actplane(),
        policy = policy.display(),
        nested_rejected_id = nested_rejected_id,
    );
    launch_child(&policy, tmp.path(), nested_parent_id, &nested_script);
    let nested_logs = poll_child_logs(&policy, tmp.path(), nested_parent_id, "nested-control-rc=");
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
        .any(|child| child["child_id"].as_u64() == Some(nested_rejected_id.into()));
    assert!(
        !created_nested_child,
        "rejected nested launch still created child domain {nested_rejected_id}: {children}"
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
