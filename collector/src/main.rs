// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane — OS-enforced agent harness.
//!
//! Loads an `actplane.yaml` project policy, lowers its embedded taint DSL to the
//! kernel ABI, runs the embedded eBPF enforcer, and reports every kernel-detected
//! violation with the rule's corrective-feedback payload.

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::process::{Child, Command};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

mod dsl;
mod feedback;
mod mcp;

use ebpf_ifc_engine::Loader;

type AnyError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, AnyError>;

const DEFAULT_POLICY_FILES: &[&str] = &["actplane.yaml", ".actplane/policy.yaml"];
const DEFAULT_FEEDBACK_FILE: &str = ".actplane/last-violation.txt";
const DEFAULT_HOOK_STATE_FILE: &str = ".actplane/feedback-hook.state.json";
const HOOK_MAX_CHARS: usize = 8000;

#[derive(Parser)]
#[command(author, version, about = "ActPlane: OS-enforced agent harness", long_about = None,
    after_help = "EXAMPLES:\n  \
      # get started: write a starter policy, then validate it (no sudo needed)\n  \
      actplane init  &&  actplane check\n\n  \
      # enforce a one-line policy around a command (needs sudo for the eBPF load)\n  \
      sudo -E actplane --rule 'source COMMAND = exec \"**\"\n                       rule no-git-branch:\n                         kill exec \"git\" \"branch\" if COMMAND\n                         because \"create a branch via the host, not the agent\"' run claude -p '...'\n\n  \
      # use a project policy file (auto-discovered as ./actplane.yaml upward)\n  \
      sudo -E actplane run <your agent command>\n\n  \
      # just compile/validate a policy (no privileges needed)\n  \
      actplane --policy actplane.yaml compile --out /tmp/policy.bin\n\n  \
      # watch & report violations system-wide without launching a child\n  \
      sudo -E actplane --policy actplane.yaml watch\n\n\
    See docs/rule-language.md for the policy language.")]
struct Cli {
    /// Project policy YAML. Defaults to discovering actplane.yaml upward from cwd.
    #[arg(long, global = true, conflicts_with = "rule")]
    policy: Option<PathBuf>,
    /// Inline policy DSL used instead of a YAML file.
    #[arg(long, global = true, conflicts_with = "policy")]
    rule: Option<String>,
    /// Run the target command as root. By default sudo-launched ActPlane drops
    /// the target back to SUDO_UID/SUDO_GID.
    #[arg(long, global = true)]
    run_as_root: bool,
    /// Internal flag: set by auto-elevation to prevent recursive sudo.
    #[arg(long, global = true, hide = true)]
    internal_elevated: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command under the policy harness.
    Run {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Compile the policy to the kernel config blob.
    Compile {
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Write a starter actplane.yaml (commented guardrail template) in the cwd.
    Init {
        /// Overwrite an existing actplane.yaml.
        #[arg(short, long)]
        force: bool,
    },
    /// Validate the policy (no privileges): compile it, summarize each rule in
    /// plain language, and warn about anything that won't enforce as written.
    Check,
    /// Load the policy and report violations without starting a child command.
    Watch,
    /// Hook adapter: forward new feedback-file bytes as agent additionalContext.
    FeedbackHook,
    /// Run as an MCP (Model Context Protocol) server over stdio.
    Mcp,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default, rename = "version")]
    _version: Option<u32>,
    policy: String,
    #[serde(default)]
    feedback: FeedbackConfig,
}

#[derive(Debug, Default, serde::Deserialize)]
struct FeedbackConfig {
    path: Option<PathBuf>,
}

struct LoadedPolicy {
    config: FileConfig,
    root: PathBuf,
    path: Option<PathBuf>,
}

#[derive(Clone)]
struct FeedbackPaths {
    feedback: PathBuf,
    state: PathBuf,
}

#[derive(serde::Deserialize)]
struct Violation {
    pid: i32,
    ppid: i32,
    comm: String,
    target: String,
    rule_id: usize,
    #[allow(dead_code)]
    effect: Option<String>,
    blocked: Option<bool>,
    killed: Option<bool>,
    #[allow(dead_code)]
    taint_label: u64,
    #[allow(dead_code)]
    matched_label: u64,
    provenance: Option<ViolationProvenance>,
}

#[derive(Clone, serde::Deserialize)]
struct ViolationProvenance {
    label: u64,
    timestamp_ns: u64,
    pid: i32,
    op: u32,
    target: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let code = match &cli.command {
        Commands::Run { cmd } => run_command(&cli, cmd).await?,
        Commands::Compile { out } => compile_policy(&cli, out).await?,
        Commands::Init { force } => init_policy(*force)?,
        Commands::Check => check_policy(&cli)?,
        Commands::Watch => watch_policy(&cli).await?,
        Commands::FeedbackHook => {
            feedback_hook().await?;
            0
        }
        Commands::Mcp => {
            mcp::run_mcp_server().await?;
            0
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

async fn compile_policy(cli: &Cli, out: &Path) -> Result<i32> {
    let loaded = load_policy(cli)?;
    let compiled = dsl::compile_str(&loaded.config.policy)?;
    std::fs::write(out, &compiled.bytes)?;
    eprintln!(
        "ActPlane: compiled {} rule(s) to {}",
        compiled.reasons.len(),
        out.display()
    );
    Ok(0)
}

const STARTER_POLICY: &str = r#"# ActPlane project policy. Constraints are enforced in the kernel (eBPF), below
# the tool layer, so they hold across any tool / subprocess / direct syscall.
# Validate any time with:  actplane check
# Enforce around an agent:  sudo -E actplane run <your agent command>
# DSL reference: docs/rule-language.md
policy: |
  # `source COMMAND` marks the process tree launched by `actplane run`.
  source COMMAND = exec "**"

  # 1) The command must not create git branches/worktrees (do it yourself on the host).
  rule no-git-branch:
    kill exec "git" "branch"   if COMMAND
    kill exec "git" "worktree" if COMMAND
    because "create branches/worktrees on the host, not via the agent"

  # 2) Secrets must not leave the host. Reading a secret file taints the process;
  #    a tainted process may not open an outbound connection (redact to clear it).
  source SECRET = file "**/.env"
  source SECRET = file "**/secrets/**"
  rule no-secret-exfil:
    kill connect endpoint "*" if SECRET
    because "data derived from local secrets must not leave the host; redact first"
  declassify SECRET by exec "**/redact"

  # 3) No commit before the tests have run in this session.
  rule test-before-commit:
    kill exec "git" "commit" if COMMAND unless after exec "**/pytest"
    because "run the tests before committing"
"#;

fn init_policy(force: bool) -> Result<i32> {
    let path = std::env::current_dir()?.join("actplane.yaml");
    if path.exists() && !force {
        eprintln!(
            "actplane: {} already exists (use --force to overwrite).",
            path.display()
        );
        return Ok(1);
    }
    std::fs::write(&path, STARTER_POLICY)?;
    eprintln!(
        "actplane: wrote {}\n  Next:  actplane check        # validate it (no sudo)\n         \
         sudo -E actplane run <your agent command>",
        path.display()
    );
    Ok(0)
}

fn check_policy(cli: &Cli) -> Result<i32> {
    let loaded = load_policy(cli)?;
    let compiled = match dsl::compile_str(&loaded.config.policy) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ policy does not compile: {}", e);
            return Ok(1);
        }
    };
    let where_ = loaded
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "--rule".into());
    println!("✓ {}: {} rule(s) compile.\n", where_, compiled.meta.len());
    for (i, m) in compiled.meta.iter().enumerate() {
        let eff = format!("{:?}", m.effect).to_lowercase();
        let ops = if m.ops.is_empty() {
            "—".into()
        } else {
            m.ops.join("/")
        };
        println!(
            "  {}. {} — {} {} ({})",
            i + 1,
            m.name,
            eff,
            ops,
            m.reason
        );
    }
    // Warnings: things that compile but won't enforce as the author likely expects.
    let lsm_bpf = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.contains("bpf"))
        .unwrap_or(false);
    let mut warns: Vec<String> = Vec::new();
    if !lsm_bpf
        && compiled
            .meta
            .iter()
            .any(|m| format!("{:?}", m.effect).eq_ignore_ascii_case("block"))
    {
        warns.push(
            "`block` rules need BPF-LSM (not active here: /sys/kernel/security/lsm has no `bpf`); \
             those rules will report (notify) but not deny. Use `kill` instead to terminate."
                .into(),
        );
    }
    // hostname (non-IP) connect targets are not enforced numerically in-kernel.
    for line in loaded.config.policy.lines() {
        let t = line.trim();
        // Match any action verb (notify/block/kill) before "connect endpoint"
        let rest_opt = t.strip_prefix("notify connect endpoint")
            .or_else(|| t.strip_prefix("block connect endpoint"))
            .or_else(|| t.strip_prefix("kill connect endpoint"));
        if let Some(rest) = rest_opt {
            if let Some(pat) = rest.split('"').nth(1) {
                let ipish = pat == "*"
                    || pat
                        .trim_end_matches('.')
                        .split('.')
                        .all(|o| !o.is_empty() && o.chars().all(|c| c.is_ascii_digit()));
                if !ipish {
                    warns.push(format!(
                        "connect endpoint \"{}\" looks like a hostname; the kernel matches \
                         numeric IPv4 only, so this rule will not fire (use an IP/CIDR prefix).",
                        pat
                    ));
                }
            }
        }
    }
    if warns.is_empty() {
        println!("\n✓ no warnings.");
    } else {
        println!("\n⚠ {} warning(s):", warns.len());
        for w in &warns {
            println!("  - {}", w);
        }
    }
    if unsafe { libc::geteuid() } != 0 {
        println!(
            "\n(note: `check` needs no privileges; enforcing needs `sudo -E actplane run/watch`.)"
        );
    }
    Ok(0)
}

async fn watch_policy(cli: &Cli) -> Result<i32> {
    require_bpf_caps_or_elevate(cli.internal_elevated)?;
    let loaded = load_policy(cli)?;
    let compiled = dsl::compile_str(&loaded.config.policy)?;
    let feedback = feedback_paths(&loaded);
    prepare_feedback_files(&feedback, target_user(cli.run_as_root))?;

    // Load + attach the in-process eBPF enforcer on a dedicated thread (aya
    // state stays single-threaded); report violations until Ctrl-C.
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
                let _ = ready_tx.send(Err(format!("load enforcer: {e}")));
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
        Err(_) => return Err("enforcer thread exited before readiness".into()),
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

/// Check whether we have BPF capabilities (root or CAP_BPF + CAP_SYS_ADMIN).
fn have_bpf_caps() -> bool {
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

/// If we lack BPF caps, try passwordless sudo to re-exec ourselves elevated.
/// Returns Ok(()) if we already have caps; otherwise re-execs or exits with an error.
fn require_bpf_caps_or_elevate(already_elevated: bool) -> Result<()> {
    if have_bpf_caps() {
        return Ok(());
    }
    if already_elevated {
        eprintln!("actplane: still lacks BPF caps after elevation attempt");
        std::process::exit(1);
    }
    // Try passwordless sudo
    let probe = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match probe {
        Ok(s) if s.success() => {
            // Re-exec under sudo with --internal-elevated to prevent recursion
            let exe = std::env::current_exe()
                .unwrap_or_else(|_| PathBuf::from("actplane"));
            let args: Vec<String> = std::env::args().collect();
            // Build: sudo -E <exe> --internal-elevated <original args[1..]>
            let mut cmd = std::process::Command::new("sudo");
            cmd.arg("-E").arg(&exe).arg("--internal-elevated");
            for arg in &args[1..] {
                cmd.arg(arg);
            }
            eprintln!("actplane: auto-elevating via passwordless sudo ...");
            let status = cmd.status().map_err(|e| format!("sudo re-exec: {e}"))?;
            std::process::exit(status.code().unwrap_or(1));
        }
        _ => {
            eprintln!(
                "actplane: this command loads an eBPF enforcer, which needs root \
                 (or CAP_BPF + CAP_SYS_ADMIN).\n\
                 \n  Re-run with sudo, e.g.:   sudo -E actplane <same args>\n\
                 \n  (sudo-launched ActPlane drops the target command back to your user automatically.)"
            );
            std::process::exit(1);
        }
    }
}

async fn run_command(cli: &Cli, cmd: &[String]) -> Result<i32> {
    require_bpf_caps_or_elevate(cli.internal_elevated)?;
    let loaded = load_policy(cli)?;
    let compiled = dsl::compile_str(&loaded.config.policy)?;
    let agent_label = compiled
        .labels
        .get("COMMAND")
        .or_else(|| compiled.labels.get("AGENT"))
        .copied()
        .ok_or("run mode requires the policy to declare or reference label COMMAND (or AGENT for backward compatibility)")?;
    let feedback = feedback_paths(&loaded);
    let target_owner = target_user(cli.run_as_root);
    prepare_feedback_files(&feedback, target_owner)?;

    let mut target = spawn_stopped_target(cmd, &feedback, loaded.path.as_deref(), cli.run_as_root)?;
    let target_pid = target.id().ok_or("target process has no pid")?;

    // Load + attach the in-process eBPF enforcer and seed the AGENT lineage on a
    // dedicated thread (aya state stays single-threaded), signalling readiness
    // before we resume the stopped target.
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
                let _ = ready_tx.send(Err(format!("load enforcer: {e}")));
                return;
            }
        };
        if let Err(e) = loader.seed_agent(target_pid as i32, agent_label) {
            let _ = ready_tx.send(Err(format!("seed agent: {e}")));
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
            return Err("enforcer thread exited before readiness".into());
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
    // Let the poller drain any final in-flight violation, then stop it.
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::SeqCst);
    let _ = poller.join();
    Ok(exit_code(status))
}

/// Map the eBPF crate's violation into the collector's reporting struct.
fn to_violation(v: &ebpf_ifc_engine::Violation) -> Violation {
    Violation {
        pid: v.pid,
        ppid: v.ppid,
        comm: v.comm.clone(),
        target: v.target.clone(),
        rule_id: v.rule_id as usize,
        effect: Some(
            match v.effect {
                0 => "notify",
                1 => "block",
                2 => "kill",
                _ => "unknown",
            }
            .to_string(),
        ),
        blocked: Some(v.blocked),
        killed: Some(v.killed),
        taint_label: v.label,
        matched_label: v.matched_label,
        provenance: v.provenance.as_ref().map(|p| ViolationProvenance {
            label: p.label,
            timestamp_ns: p.timestamp_ns,
            pid: p.pid,
            op: p.op,
            target: p.target.clone(),
        }),
    }
}

fn load_policy(cli: &Cli) -> Result<LoadedPolicy> {
    if let Some(rule) = &cli.rule {
        return Ok(LoadedPolicy {
            config: FileConfig {
                policy: rule.clone(),
                ..FileConfig::default()
            },
            root: std::env::current_dir()?,
            path: None,
        });
    }

    let cwd = std::env::current_dir()?;
    let explicit_policy = cli.policy.is_some();
    let path = match &cli.policy {
        Some(path) => absolutize(path, &cwd),
        None => discover_policy(&cwd)
            .ok_or("no actplane.yaml found; pass --policy <file> or --rule <dsl>")?,
    };
    let src =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {}", path.display(), e))?;
    let config: FileConfig =
        serde_yaml::from_str(&src).map_err(|e| format!("parsing {}: {}", path.display(), e))?;
    if config.policy.trim().is_empty() {
        return Err(format!(
            "{} must contain a non-empty `policy: |` block",
            path.display()
        )
        .into());
    }
    let root = if explicit_policy {
        cwd
    } else {
        path.parent().map(Path::to_path_buf).unwrap_or(cwd)
    };
    Ok(LoadedPolicy {
        config,
        root,
        path: Some(path),
    })
}

fn discover_policy(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        for name in DEFAULT_POLICY_FILES {
            let candidate = d.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        dir = d.parent();
    }
    None
}

fn feedback_paths(loaded: &LoadedPolicy) -> FeedbackPaths {
    let feedback = loaded
        .config
        .feedback
        .path
        .as_ref()
        .map(|p| absolutize(p, &loaded.root))
        .unwrap_or_else(|| loaded.root.join(DEFAULT_FEEDBACK_FILE));
    let state = feedback
        .parent()
        .map(|p| p.join("feedback-hook.state.json"))
        .unwrap_or_else(|| loaded.root.join(DEFAULT_HOOK_STATE_FILE));
    FeedbackPaths { feedback, state }
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

fn absolutize(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Report a violation: a human one-liner to stdout, plus the structured
/// corrective-feedback payload appended to the reason file.
fn report(
    meta: &[dsl::RuleMeta],
    labels: &HashMap<String, u64>,
    v: &Violation,
    feedback_file: Option<&Path>,
) {
    let verb = if v.killed.unwrap_or(false) {
        "KILLED"
    } else if v.blocked.unwrap_or(false) {
        "BLOCKED"
    } else {
        "VIOLATION"
    };
    let m = meta.get(v.rule_id);
    let reason = m.map(|m| m.reason.as_str()).unwrap_or("");
    let effect = v
        .effect
        .as_deref()
        .or_else(|| m.map(|m| effect_name(m.effect)))
        .unwrap_or("");
    println!(
        "🚫 {}: process '{}' (pid {}, ppid {}) — {}",
        verb, v.comm, v.pid, v.ppid, v.target
    );
    if !effect.is_empty() {
        println!("   effect: {}", effect);
    }
    if !reason.is_empty() {
        println!("   reason: {}", reason);
    }
    if let Some(p) = &v.provenance {
        println!(
            "   provenance: pid {} {} {} -> label {}",
            p.pid,
            kernel_op_name(p.op),
            p.target,
            label_name(labels, p.label)
        );
    }

    if let (Some(path), Some(m)) = (feedback_file, m) {
        let op = m.ops.first().map(|s| s.as_str()).unwrap_or("op");
        let provenance = v.provenance.as_ref().map(|p| feedback::Provenance {
            label: label_name(labels, p.label),
            origin_pid: p.pid,
            origin_op: kernel_op_name(p.op).to_string(),
            origin_target: if p.target.is_empty() {
                "<unknown>".to_string()
            } else {
                p.target.clone()
            },
            origin_timestamp_ns: p.timestamp_ns,
        });
        let payload = feedback::format_payload(
            &m.name,
            op,
            &v.target,
            &m.reason,
            m.effect,
            v.blocked.unwrap_or(false),
            v.killed.unwrap_or(false),
            provenance.as_ref(),
        );
        if let Err(e) = append_feedback(path, &payload) {
            eprintln!("ActPlane: writing feedback file {}: {}", path.display(), e);
        }
    }
}

fn label_name(labels: &HashMap<String, u64>, label: u64) -> String {
    labels
        .iter()
        .find_map(|(name, bit)| (*bit == label).then(|| name.clone()))
        .unwrap_or_else(|| format!("0x{label:x}"))
}

fn kernel_op_name(op: u32) -> &'static str {
    match op {
        0 => "exec",
        1 => "read",
        2 => "write",
        3 => "connect",
        _ => "op",
    }
}

fn append_feedback(path: &Path, payload: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}\n----", payload)
}

fn effect_name(effect: dsl::ast::Effect) -> &'static str {
    match effect {
        dsl::ast::Effect::Notify => "notify",
        dsl::ast::Effect::Block => "block",
        dsl::ast::Effect::Kill => "kill",
    }
}

async fn feedback_hook() -> Result<()> {
    let data: serde_json::Value = match serde_json::from_str(&read_stdin()?) {
        Ok(v) => v,
        Err(_) => serde_json::Value::Object(Default::default()),
    };
    let cwd = data
        .get("cwd")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?);
    let event = data
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("PostToolUse");
    let feedback = env_path_or("ACTPLANE_FEEDBACK_FILE", &cwd, DEFAULT_FEEDBACK_FILE);
    let state = env_path_or(
        "ACTPLANE_HOOK_STATE",
        &cwd,
        feedback
            .parent()
            .map(|p| p.join("feedback-hook.state.json"))
            .unwrap_or_else(|| cwd.join(DEFAULT_HOOK_STATE_FILE))
            .to_string_lossy()
            .as_ref(),
    );
    let feedback_text = new_feedback(&feedback, &state)?;
    if feedback_text.trim().is_empty() {
        return Ok(());
    }
    let context = hook_context(&feedback_text);
    let output = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": context,
        }
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn read_stdin() -> std::io::Result<String> {
    let mut raw = String::new();
    let mut stdin = std::io::stdin();
    std::io::Read::read_to_string(&mut stdin, &mut raw)?;
    Ok(raw)
}

fn env_path_or(name: &str, cwd: &Path, default: &str) -> PathBuf {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default));
    absolutize(&path, cwd)
}

fn new_feedback(feedback: &Path, state: &Path) -> Result<String> {
    let size = match std::fs::metadata(feedback) {
        Ok(m) => m.len(),
        Err(_) => return Ok(String::new()),
    };
    let (previous, mut offset) = load_hook_state(state).unwrap_or_default();
    let feedback_name = feedback.to_string_lossy().to_string();
    if previous.as_deref() != Some(feedback_name.as_str()) || offset > size {
        offset = 0;
    }
    if offset == size {
        return Ok(String::new());
    }
    let mut f = std::fs::File::open(feedback)?;
    std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(offset))?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut buf)?;
    save_hook_state(state, feedback, size)?;
    Ok(String::from_utf8_lossy(&buf).trim().to_string())
}

fn load_hook_state(path: &Path) -> Option<(Option<String>, u64)> {
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    Some((
        value
            .get("feedback_file")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        value.get("offset").and_then(|v| v.as_u64()).unwrap_or(0),
    ))
}

fn save_hook_state(state: &Path, feedback: &Path, offset: u64) -> Result<()> {
    if let Some(parent) = state.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = state.with_extension("tmp");
    let value = serde_json::json!({
        "feedback_file": feedback.to_string_lossy(),
        "offset": offset,
    });
    std::fs::write(&tmp, serde_json::to_string(&value)? + "\n")?;
    std::fs::rename(tmp, state)?;
    Ok(())
}

fn hook_context(feedback: &str) -> String {
    let text = if feedback.chars().count() > HOOK_MAX_CHARS {
        let tail: String = feedback
            .chars()
            .rev()
            .take(HOOK_MAX_CHARS)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("... truncated ...\n{tail}")
    } else {
        feedback.to_string()
    };
    format!(
        "ActPlane detected an OS-level harness violation during the previous \
         tool action. Treat this as authoritative feedback from the kernel \
         enforcer; do not retry the same operation unchanged. Follow the \
         suggested alternative or satisfy the listed precondition.\n\n{text}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_yaml_rejects_removed_fallback_config() {
        let err = serde_yaml::from_str::<FileConfig>(
            r#"
policy: |
  source AGENT = exec "**/claude"
fallback:
  kill_on_violation: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `fallback`"));
    }
}
