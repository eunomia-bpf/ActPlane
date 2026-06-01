use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ebpf_ifc_engine::Loader;
use tokio::process::{Child, Command};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};

use crate::config::{FeedbackPaths, feedback_paths, load_policy, policy_source};
use crate::report::{append_violation_feedback, report, to_violation};
use crate::{Cli, Result, dsl};

const ATTACH_PID_ENV: &str = "ACTPLANE_ATTACH_PID";

pub(crate) async fn watch_policy(cli: &Cli) -> Result<i32> {
    require_bpf_caps_or_elevate(cli.internal_elevated)?;
    let loaded = load_policy(cli)?;
    let policy = policy_source(&loaded, cli.domain.as_deref())?;
    let compiled = dsl::compile_str(&policy)?;
    let feedback = feedback_paths(&loaded);
    prepare_feedback_files(&feedback, target_user(cli.run_as_root))?;

    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::result::Result<(), String>>();
    let blob = compiled.bytes;
    let meta = compiled.meta;
    let labels = compiled.labels;
    let fb = feedback.feedback.clone();
    let stop_thread = stop.clone();
    let poller = std::thread::spawn(move || {
        let mut loader = match Loader::load(&blob) {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("load engine: {e}")));
                return;
            }
        };
        let _ = ready_tx.send(Ok(()));
        let _ = loader.run(&stop_thread, |v| {
            report(&meta, &labels, &to_violation(&v), Some(&fb))
        });
    });

    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = poller.join();
            return Err(e.into());
        }
        Err(_) => return Err("engine thread exited before readiness".into()),
    }
    eprintln!(
        "ActPlane: watching with feedback file {}\n",
        feedback.feedback.display()
    );

    let _ = tokio::signal::ctrl_c().await;
    stop.store(true, Ordering::SeqCst);
    let _ = poller.join();
    Ok(0)
}

pub(crate) struct AttachGuard {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn start_mcp_auto_attach(cli: &Cli) -> Result<AttachGuard> {
    let attach_pid = std::env::var(ATTACH_PID_ENV)
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or_else(parent_pid);
    if attach_pid <= 1 {
        return Err(format!("invalid parent pid for auto-attach: {attach_pid}").into());
    }

    require_bpf_caps_or_elevate_with_env(
        cli.internal_elevated,
        &[(ATTACH_PID_ENV, attach_pid.to_string())],
    )?;

    let loaded = load_policy(cli)?;
    let policy = policy_source(&loaded, cli.domain.as_deref())?;
    let compiled = dsl::compile_str(&policy)?;
    let agent_label = runner_label(&compiled)?;
    let feedback = feedback_paths(&loaded);
    prepare_feedback_files(&feedback, target_user(cli.run_as_root))?;

    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::result::Result<(), String>>();
    let blob = compiled.bytes;
    let meta = compiled.meta;
    let labels = compiled.labels;
    let fb = feedback.feedback.clone();
    let stop_thread = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut loader = match Loader::load(&blob) {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("load engine: {e}")));
                return;
            }
        };
        if let Err(e) = loader.seed_label(attach_pid, agent_label) {
            let _ = ready_tx.send(Err(format!("seed parent pid {attach_pid}: {e}")));
            return;
        }
        let _ = ready_tx.send(Ok(()));
        let _ = loader.run(&stop_thread, |v| {
            append_violation_feedback(&meta, &labels, &to_violation(&v), &fb)
        });
    });

    match ready_rx.recv() {
        Ok(Ok(())) => {
            eprintln!(
                "ActPlane: MCP auto-attached pid {} under COMMAND label 0x{:x}; feedback {}",
                attach_pid,
                agent_label,
                feedback.feedback.display()
            );
            Ok(AttachGuard {
                stop,
                thread: Some(thread),
            })
        }
        Ok(Err(e)) => {
            stop.store(true, Ordering::SeqCst);
            let _ = thread.join();
            Err(e.into())
        }
        Err(_) => {
            stop.store(true, Ordering::SeqCst);
            let _ = thread.join();
            Err("engine thread exited before readiness".into())
        }
    }
}

fn parent_pid() -> i32 {
    unsafe { libc::getppid() as i32 }
}

/// Check whether we have BPF capabilities (root or CAP_BPF + CAP_SYS_ADMIN).
pub(crate) fn have_bpf_caps() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    let eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|h| u64::from_str_radix(h.trim(), 16).ok())
        })
        .unwrap_or(0);
    let has = |bit: u32| eff & (1u64 << bit) != 0;
    has(39) && has(21)
}

pub(crate) fn passwordless_sudo_available() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// If we lack BPF caps, try passwordless sudo to re-exec ourselves elevated.
/// Returns Ok(()) if we already have caps; otherwise re-execs or exits with an error.
fn require_bpf_caps_or_elevate(already_elevated: bool) -> Result<()> {
    require_bpf_caps_or_elevate_with_env(already_elevated, &[])
}

fn require_bpf_caps_or_elevate_with_env(
    already_elevated: bool,
    extra_env: &[(&str, String)],
) -> Result<()> {
    if have_bpf_caps() {
        return Ok(());
    }
    if already_elevated {
        eprintln!("actplane: still lacks BPF caps after elevation attempt");
        std::process::exit(1);
    }
    if passwordless_sudo_available() {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("actplane"));
        let args: Vec<String> = std::env::args().collect();
        let mut cmd = std::process::Command::new("sudo");
        cmd.arg("-E").arg(&exe).arg("--internal-elevated");
        for (name, value) in extra_env {
            cmd.env(name, value);
        }
        for arg in &args[1..] {
            cmd.arg(arg);
        }
        eprintln!("actplane: auto-elevating via passwordless sudo ...");
        #[cfg(unix)]
        {
            let e = cmd.exec();
            Err(format!("sudo exec: {e}").into())
        }
        #[cfg(not(unix))]
        {
            let status = cmd.status().map_err(|e| format!("sudo re-exec: {e}"))?;
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        eprintln!(
            "actplane: this command loads an eBPF engine, which needs root \
                 (or CAP_BPF + CAP_SYS_ADMIN).\n\
                 \n  Re-run with sudo, e.g.:   sudo -E actplane <same args>\n\
                 \n  (sudo-launched ActPlane drops the target command back to your user automatically.)"
        );
        std::process::exit(1);
    }
}

pub(crate) async fn run_command(cli: &Cli, cmd: &[String]) -> Result<i32> {
    require_bpf_caps_or_elevate(cli.internal_elevated)?;
    let loaded = load_policy(cli)?;
    let policy = policy_source(&loaded, cli.domain.as_deref())?;
    let compiled = dsl::compile_str(&policy)?;
    let agent_label = runner_label(&compiled)?;
    let feedback = feedback_paths(&loaded);
    let target_owner = target_user(cli.run_as_root);
    prepare_feedback_files(&feedback, target_owner)?;

    let mut target = spawn_stopped_target(cmd, &feedback, loaded.path.as_deref(), cli.run_as_root)?;
    let target_pid = target.id().ok_or("target process has no pid")?;

    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::result::Result<(), String>>();
    let blob = compiled.bytes;
    let meta = compiled.meta;
    let labels = compiled.labels;
    let fb = feedback.feedback.clone();
    let stop_thread = stop.clone();
    let poller = std::thread::spawn(move || {
        let mut loader = match Loader::load(&blob) {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("load engine: {e}")));
                return;
            }
        };
        if let Err(e) = loader.seed_label(target_pid as i32, agent_label) {
            let _ = ready_tx.send(Err(format!("seed pid: {e}")));
            return;
        }
        let _ = ready_tx.send(Ok(()));
        let _ = loader.run(&stop_thread, |v| {
            report(&meta, &labels, &to_violation(&v), Some(&fb))
        });
    });

    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = send_signal(target_pid, libc::SIGKILL);
            let _ = target.wait().await;
            let _ = poller.join();
            return Err(e.into());
        }
        Err(_) => {
            let _ = send_signal(target_pid, libc::SIGKILL);
            let _ = target.wait().await;
            return Err("engine thread exited before readiness".into());
        }
    }

    eprintln!(
        "ActPlane: running pid {} under COMMAND label 0x{:x}; feedback {}\n",
        target_pid,
        agent_label,
        feedback.feedback.display()
    );
    send_signal(target_pid, libc::SIGCONT)?;

    let status = target.wait().await?;
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::SeqCst);
    let _ = poller.join();
    Ok(exit_code(status))
}

fn runner_label(compiled: &dsl::Compiled) -> Result<u64> {
    compiled
        .labels
        .get("COMMAND")
        .or_else(|| compiled.labels.get("AGENT"))
        .copied()
        .ok_or_else(|| {
            "run/auto-attach mode requires the policy to declare or reference label COMMAND \
             (or AGENT for backward compatibility)"
                .into()
        })
}

fn prepare_feedback_files(
    paths: &FeedbackPaths,
    owner: Option<(libc::uid_t, libc::gid_t)>,
) -> Result<()> {
    if let Some(parent) = paths.feedback.parent() {
        std::fs::create_dir_all(parent)?;
        if let Some((uid, gid)) = owner {
            chown_path(parent, uid, gid)?;
        }
    }
    std::fs::write(&paths.feedback, "")?;
    if let Some((uid, gid)) = owner {
        chown_path(&paths.feedback, uid, gid)?;
    }
    match std::fs::remove_file(&paths.state) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn chown_path(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn spawn_stopped_target(
    cmd: &[String],
    feedback: &FeedbackPaths,
    policy_path: Option<&Path>,
    run_as_root: bool,
) -> Result<Child> {
    if cmd.is_empty() {
        return Err("run requires a command after `--`".into());
    }
    let drop_to = target_user(run_as_root);
    let mut target = Command::new("/bin/sh");
    target.arg("-c");
    target.arg("kill -STOP $$; exec \"$@\"");
    target.arg("actplane-target");
    target.args(cmd);
    target.stdin(Stdio::inherit());
    target.stdout(Stdio::inherit());
    target.stderr(Stdio::inherit());
    target.env("ACTPLANE_FEEDBACK_FILE", &feedback.feedback);
    target.env("ACTPLANE_HOOK_STATE", &feedback.state);
    if let Some(policy_path) = policy_path {
        target.env("ACTPLANE_POLICY_FILE", policy_path);
    }

    unsafe {
        target.pre_exec(move || {
            if let Some((uid, gid)) = drop_to {
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(target.spawn()?)
}

fn target_user(run_as_root: bool) -> Option<(libc::uid_t, libc::gid_t)> {
    if run_as_root || unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let uid = std::env::var("SUDO_UID")
        .ok()?
        .parse::<libc::uid_t>()
        .ok()?;
    let gid = std::env::var("SUDO_GID")
        .ok()?
        .parse::<libc::gid_t>()
        .ok()?;
    Some((uid, gid))
}

fn send_signal(pid: u32, sig: i32) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    if let Some(sig) = status.signal() {
        return 128 + sig;
    }
    1
}
