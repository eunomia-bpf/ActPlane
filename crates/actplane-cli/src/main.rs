// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane — OS-level agent harness.
//!
//! Loads an `actplane.yaml` project policy, lowers its embedded taint DSL to the
//! kernel ABI, runs the embedded eBPF engine, and reports every kernel-detected
//! rule match with the corrective-feedback payload.

use clap::{Args, Parser, Subcommand};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

mod doctor;
mod setup;
mod template_generate;
mod templates;

pub use actplane_ifc_compiler as dsl;
pub use actplane_runtime::{audit, config, control, hook, mcp, runtime};

type AnyError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, AnyError>;

#[derive(Parser)]
#[command(author, version, about = "ActPlane: OS-level policy engine for agent processes", long_about = None,
    after_help = "EXAMPLES:\n  \
      # get started: write a starter policy, then diagnose host support\n  \
      actplane init  &&  actplane doctor\n\n  \
      # write a starter policy from a built-in template\n  \
      actplane init --template no-git-branch --out actplane.yaml\n\n  \
      # infer a candidate policy from project instructions and manifests\n  \
      actplane init --generate --out actplane.yaml\n\n  \
      # compile/validate a policy and emit a review artifact (no privileges needed)\n  \
      actplane compile --explain --report-out docs/actplane-review.txt\n\n  \
      # apply a one-line policy around a command (needs sudo for the eBPF load)\n  \
      sudo -E actplane --rule 'source COMMAND = exec \"**\"\n                       rule no-git-branch:\n                         kill exec \"git\" \"branch\" if COMMAND\n                         because \"create a branch via the host, not the agent\"' run claude -p '...'\n\n  \
      # use a project policy file (auto-discovered as ./actplane.yaml upward)\n  \
      sudo -E actplane run <your agent command>\n\n  \
      # serve MCP resources and auto-attach to the parent agent when Codex starts it\n  \
      actplane mcp --auto-attach-parent\n\n  \
      # compile a policy blob for the low-level loader\n  \
      actplane --policy actplane.yaml compile --out /tmp/policy.bin\n\n  \
      # attach to the parent agent/shell and report violations without launching a child\n  \
      actplane --policy actplane.yaml watch\n\n  \
      # append a scoped runtime delta to an already-running watch/MCP engine\n  \
      actplane control delta add --target-id <domain-id> --delta policy-delta.dsl\n\n\
    See docs/rule-language.md for the policy language.")]
pub(crate) struct Cli {
    /// Project policy YAML. Defaults to discovering actplane.yaml upward from cwd.
    #[arg(long, global = true, conflicts_with = "rule")]
    pub(crate) policy: Option<PathBuf>,
    /// Inline policy DSL used instead of a YAML file.
    #[arg(long, global = true, conflicts_with = "policy")]
    pub(crate) rule: Option<String>,
    /// Domain to compile/run from a policy file with `domains:`.
    #[arg(long, global = true, conflicts_with = "rule")]
    pub(crate) domain: Option<String>,
    /// Run the target command as root. By default sudo-launched ActPlane drops
    /// the target back to SUDO_UID/SUDO_GID.
    #[arg(long, global = true)]
    pub(crate) run_as_root: bool,
    /// Internal flag: set by auto-elevation to prevent recursive sudo.
    #[arg(long, global = true, hide = true)]
    pub(crate) internal_elevated: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command under the policy harness.
    Run(RunArgs),
    /// Compile, validate, review, or emit a kernel config blob.
    Compile(CompileArgs),
    /// Initialize a project policy and optional agent integrations.
    Init(InitArgs),
    /// Diagnose policy discovery, kernel support, feedback hooks, and MCP setup.
    Doctor,
    /// Load the policy and report violations without starting a child command.
    Watch(WatchArgs),
    /// Hook adapter: forward new feedback-file bytes as agent additionalContext.
    #[command(hide = true)]
    FeedbackHook,
    /// Run as an MCP (Model Context Protocol) server over stdio.
    Mcp {
        /// On startup, load the eBPF engine and seed the parent process.
        #[arg(long)]
        auto_attach_parent: bool,
    },
    /// Control an already-running auto-attached ActPlane engine.
    Control {
        #[command(subcommand)]
        command: ControlCommands,
    },
}

#[derive(Args)]
struct RunArgs {
    /// Run directly in the selected parent/global policy domain.
    #[arg(long)]
    parent_domain: bool,
    /// Optional runtime domain id when launching with runtime deltas. Defaults to the launched pid.
    #[arg(long)]
    child_id: Option<u32>,
    /// Optional narrower scope id when launching with runtime deltas.
    #[arg(long, default_value_t = 0)]
    scope_id: u32,
    /// Append-only ActPlane DSL fragment file installed before resume.
    #[arg(long = "delta", value_name = "FILE")]
    deltas: Vec<PathBuf>,
    /// Inline append-only ActPlane DSL fragment installed before resume.
    #[arg(long = "delta-text", value_name = "DSL")]
    delta_text: Vec<String>,
    /// Optional approval metadata for runtime policy deltas.
    #[arg(long)]
    approved_by: Option<String>,
    /// Optional ticket, review, or decision id for runtime policy deltas.
    #[arg(long)]
    approval_ref: Option<String>,
    /// Optional tool or agent identity that generated runtime policy deltas.
    #[arg(long)]
    generated_by: Option<String>,
    /// Command argv.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    cmd: Vec<String>,
}

#[derive(Args)]
struct CompileArgs {
    /// Write the kernel config blob to a file.
    #[arg(short, long, value_name = "FILE", conflicts_with_all = ["json", "explain", "domains"])]
    out: Option<PathBuf>,
    /// Emit a stable machine-readable compile/support report.
    #[arg(long)]
    json: bool,
    /// Emit a human-readable policy review explaining enforcement timing and limits.
    #[arg(long, conflicts_with = "json")]
    explain: bool,
    /// Emit policy domains and their effective locked/default rules.
    #[arg(long, conflicts_with_all = ["out", "json", "explain"])]
    domains: bool,
    /// Write the compile report artifact to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    report_out: Option<PathBuf>,
    /// Overwrite an existing output file.
    #[arg(short, long)]
    force: bool,
}

#[derive(Args)]
struct InitArgs {
    /// Output policy path. Defaults to actplane.yaml unless --print or --list-templates is used.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Write a policy from a built-in template id.
    #[arg(long, conflicts_with_all = ["generate", "list_templates"])]
    template: Option<String>,
    /// Override a declared template parameter, as key=value. Repeat for multiple parameters.
    #[arg(long = "set", value_name = "KEY=VALUE")]
    params: Vec<String>,
    /// Infer a candidate policy from project instructions and manifests.
    #[arg(long, conflicts_with_all = ["template", "list_templates"])]
    generate: bool,
    /// Instruction file to inspect for --generate. Defaults to project AGENTS.md/CLAUDE.md.
    #[arg(long = "instructions", value_name = "FILE")]
    instructions: Vec<PathBuf>,
    /// Optional task hint to include in --generate template selection.
    #[arg(long)]
    task: Option<String>,
    /// List built-in templates and exit.
    #[arg(long, conflicts_with_all = ["template", "generate", "out", "print"])]
    list_templates: bool,
    /// Print the generated policy/template instead of writing a file.
    #[arg(long, conflicts_with = "out")]
    print: bool,
    /// Wire project-local Codex feedback hook and AGENTS.md guidance.
    #[arg(long)]
    with_codex: bool,
    /// Wire project-local MCP auto-attach config.
    #[arg(long)]
    with_mcp: bool,
    /// Write the policy and all project integrations.
    #[arg(long)]
    all: bool,
    /// Overwrite ActPlane-managed output files.
    #[arg(short, long)]
    force: bool,
}

#[derive(Args)]
struct WatchArgs {
    /// Attach directly in the selected parent/global policy domain.
    #[arg(long)]
    parent_domain: bool,
}

#[derive(Subcommand)]
enum ControlCommands {
    /// Show the currently reachable local control server.
    Status,
    /// Hot-reload actplane.yaml into the already-running engine.
    #[command(name = "reload")]
    ReloadPolicy,
    /// Bind an already-started subagent root pid to a child runtime domain.
    BindChild {
        /// Linux pid of the subagent root process.
        #[arg(long)]
        pid: i32,
        /// Optional runtime domain id. Defaults to pid.
        #[arg(long)]
        child_id: Option<u32>,
        /// Optional narrower scope id.
        #[arg(long, default_value_t = 0)]
        scope_id: u32,
    },
    /// Append an ActPlane DSL delta to an existing runtime domain.
    Delta {
        #[command(subcommand)]
        command: DeltaCommands,
    },
    /// Launch a stopped child process in the running engine, attach policy, then resume.
    LaunchChild {
        /// Optional runtime domain id. Defaults to the launched pid.
        #[arg(long)]
        child_id: Option<u32>,
        /// Optional narrower scope id.
        #[arg(long, default_value_t = 0)]
        scope_id: u32,
        /// ActPlane DSL fragment file installed before resume.
        #[arg(long = "delta", value_name = "FILE")]
        deltas: Vec<PathBuf>,
        /// Inline ActPlane DSL fragment installed before resume.
        #[arg(long = "delta-text", value_name = "DSL")]
        delta_text: Vec<String>,
        /// Relaunch policy for reconciliation: never or on_exit.
        #[arg(long, default_value = "never")]
        restart_policy: String,
        /// Maximum automatic relaunches for this child lineage.
        #[arg(long, default_value_t = 3)]
        restart_limit: u32,
        /// Delay before automatic relaunch after exit, in milliseconds.
        #[arg(long, default_value_t = 1000)]
        restart_backoff_ms: u64,
        /// Optional approval metadata for child policy deltas.
        #[arg(long)]
        approved_by: Option<String>,
        /// Optional ticket, review, or decision id for child policy deltas.
        #[arg(long)]
        approval_ref: Option<String>,
        /// Optional tool or agent identity that generated child policy deltas.
        #[arg(long)]
        generated_by: Option<String>,
        /// Child command argv.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// List child domains known to the running control server.
    #[command(name = "children")]
    ListChildren,
    /// Read detached stdout/stderr logs for a launched child domain.
    #[command(name = "logs")]
    ReadLogs {
        /// Child runtime domain id.
        #[arg(long, conflicts_with = "domain_id")]
        child_id: Option<u32>,
        /// Alias for --child-id.
        #[arg(long, conflicts_with = "child_id")]
        domain_id: Option<u32>,
        /// stdout, stderr, or both.
        #[arg(long, default_value = "both")]
        stream: String,
        /// Maximum bytes to return per stream.
        #[arg(long, default_value_t = 8192)]
        max_bytes: usize,
    },
    /// Terminate the process group for a launched child domain.
    #[command(name = "stop")]
    TerminateChild {
        /// Child runtime domain id.
        #[arg(long, conflicts_with = "domain_id")]
        child_id: Option<u32>,
        /// Alias for --child-id.
        #[arg(long, conflicts_with = "child_id")]
        domain_id: Option<u32>,
    },
    /// Restart a launched child domain in a fresh runtime domain.
    #[command(name = "restart")]
    RestartChild {
        /// Existing child runtime domain id.
        #[arg(long, conflicts_with = "domain_id")]
        child_id: Option<u32>,
        /// Alias for --child-id.
        #[arg(long, conflicts_with = "child_id")]
        domain_id: Option<u32>,
        /// Optional fresh runtime domain id. Defaults to the new pid.
        #[arg(long)]
        new_child_id: Option<u32>,
        /// Terminate the existing process group first if it is still running.
        #[arg(long)]
        terminate_existing: bool,
    },
    /// Reconcile child registry state against live Linux processes.
    #[command(hide = true)]
    ReconcileChildren,
}

#[derive(Subcommand)]
enum DeltaCommands {
    /// Append an ActPlane DSL delta to an existing runtime domain.
    Add(DeltaAddArgs),
}

#[derive(Args)]
struct DeltaAddArgs {
    /// Runtime domain id to receive the delta. Defaults to the attached parent domain.
    #[arg(long, conflicts_with = "domain_id")]
    target_id: Option<u32>,
    /// Alias for --target-id.
    #[arg(long, conflicts_with = "target_id")]
    domain_id: Option<u32>,
    /// ActPlane DSL fragment file.
    #[arg(long = "delta", value_name = "FILE")]
    deltas: Vec<PathBuf>,
    /// Inline ActPlane DSL fragment.
    #[arg(long = "delta-text", value_name = "DSL")]
    delta_text: Vec<String>,
    /// Optional approval metadata for this delta.
    #[arg(long)]
    approved_by: Option<String>,
    /// Optional ticket, review, or decision id for this delta.
    #[arg(long)]
    approval_ref: Option<String>,
    /// Optional tool or agent identity that generated this delta.
    #[arg(long)]
    generated_by: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let code = match &cli.command {
        Commands::Run(args) => run_command(&cli, args).await?,
        Commands::Compile(args) => compile_policy(&cli, args).await?,
        Commands::Init(args) => init_command(args)?,
        Commands::Doctor => doctor::doctor(&policy_input(&cli))?,
        Commands::Watch(args) => {
            runtime::watch_policy(&policy_input(&cli), args.parent_domain).await?
        }
        Commands::FeedbackHook => {
            hook::feedback_hook().await?;
            0
        }
        Commands::Mcp { auto_attach_parent } => {
            let attach = if *auto_attach_parent {
                Some(runtime::start_mcp_auto_attach(&policy_input(&cli))?)
            } else {
                None
            };
            let control = attach.as_ref().and_then(|a| a.engine_control());
            mcp::run_mcp_server_with_control(control, Some(control_project_dir(&cli)?)).await?;
            drop(attach);
            0
        }
        Commands::Control { command } => control_command(&cli, command).await?,
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

async fn run_command(cli: &Cli, args: &RunArgs) -> Result<i32> {
    let policy = policy_input(cli);
    let child_mode = args.child_id.is_some()
        || args.scope_id != 0
        || !args.deltas.is_empty()
        || !args.delta_text.is_empty()
        || args.approved_by.is_some()
        || args.approval_ref.is_some()
        || args.generated_by.is_some();
    if args.parent_domain && child_mode {
        return Err("--parent-domain cannot be combined with child runtime delta options".into());
    }
    if child_mode {
        let audit_meta = policy_audit_meta_from_fields(
            None,
            &args.approved_by,
            &args.approval_ref,
            &args.generated_by,
        );
        return runtime::run_child_command(
            &policy,
            args.child_id,
            args.scope_id,
            &args.deltas,
            &args.delta_text,
            &audit_meta,
            &args.cmd,
        )
        .await;
    }
    runtime::run_command(&policy, &args.cmd, args.parent_domain).await
}

fn policy_input(cli: &Cli) -> actplane_runtime::PolicyInput {
    actplane_runtime::PolicyInput {
        policy: cli.policy.clone(),
        rule: cli.rule.clone(),
        domain: cli.domain.clone(),
        run_as_root: cli.run_as_root,
        internal_elevated: cli.internal_elevated,
    }
}

fn init_command(args: &InitArgs) -> Result<i32> {
    if !args.generate && (!args.instructions.is_empty() || args.task.is_some()) {
        return Err("--instructions and --task require --generate".into());
    }
    if args.list_templates {
        if !args.params.is_empty() || args.with_codex || args.with_mcp || args.all || args.force {
            return Err(
                "--list-templates cannot be combined with write or integration flags".into(),
            );
        }
        println!("ActPlane policy templates");
        for template in templates::all() {
            println!(
                "  {:<24} {:<12} {:<6} {}",
                template.id, template.category, template.effect, template.title
            );
        }
        return Ok(0);
    }
    if args.print && (args.with_codex || args.with_mcp || args.all) {
        return Err("--print cannot be combined with integration setup flags".into());
    }

    let (policy_yaml, source_label) = if let Some(name) = &args.template {
        let template = templates::get(name)?;
        (
            templates::render_yaml(template, &args.params)?,
            format!("template `{}`", template.id),
        )
    } else if args.generate {
        let root = template_project_root()?;
        let generated =
            template_generate::generate(&root, &args.instructions, args.task.as_deref())?;
        for line in template_generate::summary(&generated) {
            eprintln!("actplane: selected {line}");
        }
        (
            template_generate::render_yaml(&generated)?,
            format!(
                "{} generated template-backed rule set(s)",
                generated.templates.len()
            ),
        )
    } else {
        if !args.params.is_empty() {
            return Err("--set requires --template".into());
        }
        (setup::starter_policy().to_string(), "starter policy".into())
    };

    if args.print {
        print!("{policy_yaml}");
    } else {
        let out = args
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from("actplane.yaml"));
        write_output_file(&out, &policy_yaml, args.force)?;
        eprintln!("actplane: wrote {source_label} to {}", out.display());
    }

    let with_codex = args.all || args.with_codex;
    let with_mcp = args.all || args.with_mcp;
    if with_codex || with_mcp {
        setup::setup_project_integrations(args.force, with_codex, with_mcp, with_codex)?;
    }
    eprintln!("Next:\n  actplane compile\n  actplane doctor");
    Ok(0)
}

fn write_output_file(path: &Path, contents: &str, force: bool) -> Result<()> {
    preflight_output_file(path, force)?;
    std::fs::write(path, contents)?;
    Ok(())
}

fn write_binary_output_file(path: &Path, contents: &[u8], force: bool) -> Result<()> {
    preflight_output_file(path, force)?;
    std::fs::write(path, contents)?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum OutputPathKey {
    #[cfg(unix)]
    ExistingFile {
        dev: u64,
        ino: u64,
    },
    Path(PathBuf),
}

fn preflight_output_file(path: &Path, force: bool) -> Result<OutputPathKey> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "{} is a symlink; use the resolved target path instead",
                    path.display()
                )
                .into());
            }
            if meta.is_dir() {
                return Err(
                    format!("{} is a directory, not an output file", path.display()).into(),
                );
            }
            if !meta.is_file() {
                return Err(format!("{} is not a regular output file", path.display()).into());
            }
            if !force {
                return Err(format!(
                    "{} already exists (use --force to overwrite)",
                    path.display()
                )
                .into());
            }
            #[cfg(unix)]
            {
                return Ok(OutputPathKey::ExistingFile {
                    dev: meta.dev(),
                    ino: meta.ino(),
                });
            }
            #[cfg(not(unix))]
            {
                return Ok(OutputPathKey::Path(std::fs::canonicalize(path)?));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("reading metadata for {}: {}", path.display(), e).into());
        }
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(format!(
            "parent directory for {} does not exist or is not a directory",
            path.display()
        )
        .into());
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("{} is not a valid output file path", path.display()))?;
    Ok(OutputPathKey::Path(
        std::fs::canonicalize(parent)?.join(file_name),
    ))
}

fn template_project_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    if let Some(policy) = config::discover_policy(&cwd) {
        return Ok(policy
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| cwd.clone()));
    }
    if has_local_instruction_file(&cwd) {
        return Ok(cwd);
    }
    let mut dir = Some(cwd.as_path());
    while let Some(candidate) = dir {
        if candidate.join(".git").exists() {
            return Ok(candidate.to_path_buf());
        }
        dir = candidate.parent();
    }
    Ok(cwd)
}

fn has_local_instruction_file(root: &Path) -> bool {
    [
        "AGENTS.md",
        "CLAUDE.md",
        ".agents/AGENTS.md",
        ".agents/instructions.md",
        ".codex/AGENTS.md",
    ]
    .iter()
    .any(|rel| root.join(rel).is_file())
}

async fn control_command(cli: &Cli, command: &ControlCommands) -> Result<i32> {
    let project_dir = control_project_dir(cli)?;
    reject_parent_domain_control_mutation(&project_dir, command)?;
    let responses = match command {
        ControlCommands::Status => {
            vec![control::send_request(
                &project_dir,
                serde_json::json!({ "op": "status" }),
            )?]
        }
        ControlCommands::ReloadPolicy => vec![control::send_request(
            &project_dir,
            serde_json::json!({ "op": "reload_policy" }),
        )?],
        ControlCommands::BindChild {
            pid,
            child_id,
            scope_id,
        } => {
            let mut request = serde_json::json!({
                "op": "bind_child_domain",
                "pid": pid,
                "scope_id": scope_id,
            });
            if let Some(child_id) = child_id {
                request["child_id"] = serde_json::json!(child_id);
            }
            vec![control::send_request(&project_dir, request)?]
        }
        ControlCommands::Delta { command } => match command {
            DeltaCommands::Add(args) => {
                append_delta_control_requests(&project_dir, args, "control delta add")?
            }
        },
        ControlCommands::LaunchChild {
            child_id,
            scope_id,
            deltas,
            delta_text,
            restart_policy,
            restart_limit,
            restart_backoff_ms,
            approved_by,
            approval_ref,
            generated_by,
            cmd,
        } => {
            let policy =
                join_policy_delta_fragments(load_policy_delta_fragments(deltas, delta_text)?);
            let mut request = serde_json::json!({
                "op": "launch_child_domain",
                "cmd": cmd,
                "scope_id": scope_id,
                "restart_policy": restart_policy,
                "restart_limit": restart_limit,
                "restart_backoff_ms": restart_backoff_ms,
            });
            if let Some(child_id) = child_id {
                request["child_id"] = serde_json::json!(child_id);
            }
            add_policy_audit_meta_fields(
                &mut request,
                &policy_audit_meta_from_fields(None, approved_by, approval_ref, generated_by),
            );
            if let Some(policy) = policy {
                request["policy"] = serde_json::json!(policy);
            }
            vec![control::send_request(&project_dir, request)?]
        }
        ControlCommands::ListChildren => vec![control::send_request(
            &project_dir,
            serde_json::json!({ "op": "list_child_domains" }),
        )?],
        ControlCommands::ReadLogs {
            child_id,
            domain_id,
            stream,
            max_bytes,
        } => {
            let child_id = child_id
                .or(*domain_id)
                .ok_or("control logs requires --child-id or --domain-id")?;
            vec![control::send_request(
                &project_dir,
                serde_json::json!({
                    "op": "read_child_domain_logs",
                    "child_id": child_id,
                    "stream": stream,
                    "max_bytes": max_bytes,
                }),
            )?]
        }
        ControlCommands::TerminateChild {
            child_id,
            domain_id,
        } => {
            let child_id = child_id
                .or(*domain_id)
                .ok_or("control stop requires --child-id or --domain-id")?;
            vec![control::send_request(
                &project_dir,
                serde_json::json!({
                    "op": "terminate_child_domain",
                    "child_id": child_id,
                }),
            )?]
        }
        ControlCommands::RestartChild {
            child_id,
            domain_id,
            new_child_id,
            terminate_existing,
        } => {
            let child_id = child_id
                .or(*domain_id)
                .ok_or("control restart requires --child-id or --domain-id")?;
            let mut request = serde_json::json!({
                "op": "restart_child_domain",
                "child_id": child_id,
                "terminate_existing": terminate_existing,
            });
            if let Some(new_child_id) = new_child_id {
                request["new_child_id"] = serde_json::json!(new_child_id);
            }
            vec![control::send_request(&project_dir, request)?]
        }
        ControlCommands::ReconcileChildren => vec![control::send_request(
            &project_dir,
            serde_json::json!({ "op": "reconcile_child_domains" }),
        )?],
    };
    for response in responses {
        print_control_response(response)?;
    }
    Ok(0)
}

fn reject_parent_domain_control_mutation(
    project_dir: &Path,
    command: &ControlCommands,
) -> Result<()> {
    let unsupported_operation = match command {
        ControlCommands::BindChild { .. } => Some("bind child domain"),
        ControlCommands::LaunchChild { .. } => Some("launch child domain"),
        ControlCommands::Delta {
            command: DeltaCommands::Add(args),
        } if args
            .target_id
            .or(args.domain_id)
            .is_none_or(|target_id| target_id == ebpf_ifc_engine::GLOBAL_ACTIVE_DOMAIN_ID) =>
        {
            Some("append policy delta")
        }
        _ => None,
    };
    let Some(operation) = unsupported_operation else {
        return Ok(());
    };
    let state = control::read_state(project_dir)?;
    if state.parent_domain_id == ebpf_ifc_engine::GLOBAL_ACTIVE_DOMAIN_ID {
        return Err(parent_domain_control_mutation_error(operation).into());
    }
    Ok(())
}

fn parent_domain_control_mutation_error(operation: &str) -> String {
    format!(
        "{operation} is unavailable in --parent-domain mode; start watch without \
         --parent-domain, or use mcp --auto-attach-parent, to create an authority-bearing \
         runtime parent domain"
    )
}

fn append_delta_control_requests(
    project_dir: &Path,
    args: &DeltaAddArgs,
    command_name: &str,
) -> Result<Vec<serde_json::Value>> {
    let target_id = args.target_id.or(args.domain_id);
    let policies = load_policy_delta_fragments(&args.deltas, &args.delta_text)?;
    if policies.is_empty() {
        return Err(format!("{command_name} requires --delta or --delta-text").into());
    }
    let mut responses = Vec::new();
    for (policy_ref, policy) in policies {
        let mut request = serde_json::json!({
            "op": "append_policy_delta",
            "policy": policy,
            "policy_ref": policy_ref,
        });
        add_policy_audit_meta_fields(&mut request, &policy_audit_meta_from_delta_args(args));
        if let Some(target_id) = target_id {
            request["target_id"] = serde_json::json!(target_id);
        }
        responses.push(control::send_request(project_dir, request)?);
    }
    Ok(responses)
}

fn policy_audit_meta_from_delta_args(args: &DeltaAddArgs) -> runtime::PolicyAuditMeta {
    policy_audit_meta_from_fields(
        None,
        &args.approved_by,
        &args.approval_ref,
        &args.generated_by,
    )
}

fn policy_audit_meta_from_fields(
    policy_ref: Option<String>,
    approved_by: &Option<String>,
    approval_ref: &Option<String>,
    generated_by: &Option<String>,
) -> runtime::PolicyAuditMeta {
    runtime::PolicyAuditMeta {
        policy_ref,
        approved_by: approved_by.clone(),
        approval_ref: approval_ref.clone(),
        generated_by: generated_by.clone(),
    }
}

fn add_policy_audit_meta_fields(request: &mut serde_json::Value, meta: &runtime::PolicyAuditMeta) {
    if let Some(policy_ref) = &meta.policy_ref {
        request["policy_ref"] = serde_json::json!(policy_ref);
    }
    if let Some(approved_by) = &meta.approved_by {
        request["approved_by"] = serde_json::json!(approved_by);
    }
    if let Some(approval_ref) = &meta.approval_ref {
        request["approval_ref"] = serde_json::json!(approval_ref);
    }
    if let Some(generated_by) = &meta.generated_by {
        request["generated_by"] = serde_json::json!(generated_by);
    }
}

fn control_project_dir(cli: &Cli) -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    if let Some(policy) = &cli.policy {
        let path = config::absolutize(policy, &cwd);
        return Ok(path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| cwd.clone()));
    }
    if let Some(policy) = config::discover_policy(&cwd) {
        return Ok(policy
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| cwd.clone()));
    }
    Ok(cwd)
}

fn load_policy_delta_fragments(
    paths: &[PathBuf],
    inline: &[String],
) -> Result<Vec<(String, String)>> {
    let mut deltas = Vec::new();
    for path in paths {
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read policy delta {}: {e}", path.display()))?;
        deltas.push((path.display().to_string(), src));
    }
    for (idx, src) in inline.iter().enumerate() {
        deltas.push((format!("--delta-text[{idx}]"), src.clone()));
    }
    Ok(deltas)
}

fn join_policy_delta_fragments(deltas: Vec<(String, String)>) -> Option<String> {
    if deltas.is_empty() {
        return None;
    }
    let mut out = String::new();
    for (policy_ref, src) in deltas {
        out.push_str("\n# delta ");
        out.push_str(&policy_ref);
        out.push('\n');
        out.push_str(src.trim());
        out.push('\n');
    }
    Some(out)
}

fn print_control_response(response: serde_json::Value) -> Result<()> {
    if !response
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(response
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("ActPlane control request failed")
            .to_string()
            .into());
    }
    if let Some(text) = response.get("text").and_then(|v| v.as_str()) {
        println!("{text}");
        return Ok(());
    }
    if let Some(result) = response.get("result") {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn compile_policy(cli: &Cli, args: &CompileArgs) -> Result<i32> {
    if args.report_out.is_some() && !(args.json || args.explain) {
        return Err("--report-out requires --json or --explain".into());
    }
    if args.domains {
        return doctor::list_domains(&policy_input(cli));
    }
    if args.json || args.explain {
        return doctor::check_policy(
            &policy_input(cli),
            args.json,
            args.explain,
            args.report_out.as_deref(),
            args.force,
        );
    }
    let Some(out) = &args.out else {
        return doctor::check_policy(&policy_input(cli), false, false, None, false);
    };
    let policy = policy_input(cli);
    let loaded = config::load_policy(&policy)?;
    let resolved = config::resolve_policy(&loaded, policy.domain.as_deref())?;
    let compiled = dsl::compile_str(&resolved.source)?;
    write_binary_output_file(out, &compiled.bytes, args.force)?;
    if let Some(domain) = &resolved.domain {
        eprintln!(
            "ActPlane: domain `{}` (locked: {}; default: {})",
            domain.name,
            format_rule_list(&domain.locked),
            format_rule_list(&domain.defaults)
        );
    }
    eprintln!(
        "ActPlane: compiled {} rule(s) to {}",
        compiled.reasons.len(),
        out.display()
    );
    Ok(0)
}

fn format_rule_list(rules: &[String]) -> String {
    if rules.is_empty() {
        "none".into()
    } else {
        rules.join(", ")
    }
}
