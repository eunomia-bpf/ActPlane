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
      # attach an already-started agent pid with a foreground engine\n  \
      actplane attach --pid <pid>\n\n  \
      # bind an already-started subagent pid to a child domain in a running engine\n  \
      actplane attach --pid <pid> --child-domain --delta child-policy.dsl\n\n  \
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
    /// Attach an already-started process to ActPlane.
    Attach(AttachArgs),
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
    /// Emit policy domains and their effective policy rules.
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

#[derive(Args)]
#[command(after_help = "NOTES:\n  \
    By default, `attach` starts a foreground engine, seeds the target pid as \
    the runtime root domain, reports violations, and exposes the repo-local \
    control socket until Ctrl-C. Supplying --child-domain, --domain-id, \
    --child-id, --scope-id, or delta flags instead binds the target pid into \
    an already-running MCP/watch engine as a child runtime domain.\n\n  \
    `attach` is post-hoc. It binds future events from the target process tree \
    to ActPlane, but it does not reconstruct file, network, or label history \
    from before the attach. For strict launch-time enforcement, prefer \
    `actplane run --delta ... -- <cmd>` or \
    `actplane control launch-child ... -- <cmd>`.")]
struct AttachArgs {
    /// Linux pid of the already-started process to attach.
    #[arg(long)]
    pid: i32,
    /// Attach directly in the selected parent/global policy domain when starting a foreground engine.
    #[arg(long)]
    parent_domain: bool,
    /// Bind the pid as a child domain in an already-running MCP/watch engine.
    #[arg(long)]
    child_domain: bool,
    /// Runtime domain id for the attached process. Defaults to pid.
    #[arg(long, conflicts_with = "child_id")]
    domain_id: Option<u32>,
    /// Alias for --domain-id.
    #[arg(long, conflicts_with = "domain_id")]
    child_id: Option<u32>,
    /// Optional narrower scope id.
    #[arg(long, default_value_t = 0)]
    scope_id: u32,
    /// Append-only ActPlane DSL fragment file installed into the attached domain.
    #[arg(long = "delta", value_name = "FILE")]
    deltas: Vec<PathBuf>,
    /// Inline append-only ActPlane DSL fragment installed into the attached domain.
    #[arg(long = "delta-text", value_name = "DSL")]
    delta_text: Vec<String>,
    /// Optional approval metadata for attached-domain policy deltas.
    #[arg(long)]
    approved_by: Option<String>,
    /// Optional ticket, review, or decision id for attached-domain policy deltas.
    #[arg(long)]
    approval_ref: Option<String>,
    /// Optional tool or agent identity that generated attached-domain policy deltas.
    #[arg(long)]
    generated_by: Option<String>,
}

#[derive(Subcommand)]
enum ControlCommands {
    /// Show the currently reachable local control server.
    Status,
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
        Commands::Attach(args) => attach_command(&cli, args).await?,
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

async fn attach_command(cli: &Cli, args: &AttachArgs) -> Result<i32> {
    if args.pid <= 0 {
        return Err("--pid must be positive".into());
    }
    let child_mode = args.child_domain
        || args.domain_id.is_some()
        || args.child_id.is_some()
        || args.scope_id != 0
        || !args.deltas.is_empty()
        || !args.delta_text.is_empty()
        || args.approved_by.is_some()
        || args.approval_ref.is_some()
        || args.generated_by.is_some();
    if args.parent_domain && child_mode {
        return Err("--parent-domain cannot be combined with child-domain attach options".into());
    }
    if !child_mode {
        return runtime::watch_policy_for_pid(&policy_input(cli), args.parent_domain, args.pid)
            .await;
    }

    let project_dir = control_project_dir(cli)?;
    reject_parent_domain_runtime_mutation(&project_dir, "attach process")?;

    let domain_id = args.domain_id.or(args.child_id).unwrap_or(args.pid as u32);
    if domain_id == 0 {
        return Err("--domain-id must be nonzero".into());
    }

    let bind_request = serde_json::json!({
        "op": "bind_child_domain",
        "pid": args.pid,
        "child_id": domain_id,
        "scope_id": args.scope_id,
    });
    print_control_response(control::send_request(&project_dir, bind_request)?)?;

    let delta_args = DeltaAddArgs {
        target_id: Some(domain_id),
        domain_id: None,
        deltas: args.deltas.clone(),
        delta_text: args.delta_text.clone(),
        approved_by: args.approved_by.clone(),
        approval_ref: args.approval_ref.clone(),
        generated_by: args.generated_by.clone(),
    };
    if !delta_args.deltas.is_empty() || !delta_args.delta_text.is_empty() {
        for response in append_delta_control_requests(&project_dir, &delta_args, "attach")? {
            print_control_response(response)?;
        }
    }
    Ok(0)
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
    reject_parent_domain_runtime_mutation(project_dir, operation)
}

fn reject_parent_domain_runtime_mutation(project_dir: &Path, operation: &str) -> Result<()> {
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
            "ActPlane: domain `{}` policy: {}",
            domain.name,
            format_domain_policy_rules(domain)
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

fn format_domain_policy_rules(domain: &config::DomainSummary) -> String {
    let mut rules = domain.locked.clone();
    rules.extend(domain.defaults.clone());
    format_rule_list(&rules)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn init_args() -> InitArgs {
        InitArgs {
            out: None,
            template: None,
            params: Vec::new(),
            generate: false,
            instructions: Vec::new(),
            task: None,
            list_templates: false,
            print: false,
            with_codex: false,
            with_mcp: false,
            all: false,
            force: false,
        }
    }

    #[test]
    fn init_command_rejects_conflicting_flag_combinations() {
        let mut args = init_args();
        args.instructions = vec![PathBuf::from("AGENTS.md")];
        assert_eq!(
            init_command(&args).err().map(|e| e.to_string()),
            Some("--instructions and --task require --generate".into())
        );

        let mut args = init_args();
        args.list_templates = true;
        args.with_codex = true;
        assert_eq!(
            init_command(&args).err().map(|e| e.to_string()),
            Some("--list-templates cannot be combined with write or integration flags".into())
        );

        let mut args = init_args();
        args.list_templates = true;
        args.params = vec!["k=v".into()];
        assert_eq!(
            init_command(&args).err().map(|e| e.to_string()),
            Some("--list-templates cannot be combined with write or integration flags".into())
        );

        let mut args = init_args();
        args.print = true;
        args.all = true;
        assert_eq!(
            init_command(&args).err().map(|e| e.to_string()),
            Some("--print cannot be combined with integration setup flags".into())
        );
    }

    #[test]
    fn add_policy_audit_meta_fields_writes_only_present_optional_fields() {
        // `add_policy_audit_meta_fields` copies each audit field that is
        // `Some` onto a control request, leaving unset fields absent rather
        // than writing JSON `null`, and preserving existing keys. No base or
        // branch test pins this helper directly.
        let mut request = serde_json::json!({ "op": "append_policy_delta" });
        add_policy_audit_meta_fields(
            &mut request,
            &runtime::PolicyAuditMeta {
                policy_ref: Some("policy.dsl".to_string()),
                approved_by: Some("alice".to_string()),
                approval_ref: None,
                generated_by: Some("tool".to_string()),
            },
        );
        assert_eq!(request["policy_ref"], "policy.dsl");
        assert_eq!(request["approved_by"], "alice");
        assert_eq!(request["generated_by"], "tool");
        assert!(request.get("approval_ref").is_none());
        assert_eq!(request["op"], "append_policy_delta");
    }
    use tempfile::tempdir;

    #[test]
    fn parent_domain_control_mutation_error_names_the_operation() {
        let message = parent_domain_control_mutation_error("append policy delta");
        assert!(message.starts_with("append policy delta is unavailable in --parent-domain mode"));
        assert!(message.contains("mcp --auto-attach-parent"));
        assert!(message.ends_with("runtime parent domain"));
    }

    #[test]
    fn reject_parent_domain_control_mutation_classifies_commands() {
        let dir = tempdir().expect("tempdir");
        let state_dir = dir.path().join(".actplane");
        std::fs::create_dir_all(&state_dir).expect("mkdir");
        let write_state = |parent_domain_id: u32| {
            std::fs::write(
                state_dir.join("control.json"),
                serde_json::to_string(&serde_json::json!({
                    "schema": "actplane.control.v1",
                    "pid": std::process::id() as i32,
                    "proc_start_time": null,
                    "socket_path": dir.path().join("missing.sock"),
                    "project_dir": dir.path(),
                    "parent_pid": 1111,
                    "parent_domain_id": parent_domain_id,
                }))
                .expect("serialize"),
            )
            .expect("write state");
        };
        let delta_add = |target: Option<u32>| ControlCommands::Delta {
            command: DeltaCommands::Add(DeltaAddArgs {
                target_id: target,
                domain_id: None,
                deltas: Vec::new(),
                delta_text: Vec::new(),
                approved_by: None,
                approval_ref: None,
                generated_by: None,
            }),
        };

        write_state(ebpf_ifc_engine::GLOBAL_ACTIVE_DOMAIN_ID);
        for command in [
            ControlCommands::BindChild {
                pid: 1234,
                child_id: None,
                scope_id: 0,
            },
            ControlCommands::LaunchChild {
                child_id: None,
                scope_id: 0,
                deltas: Vec::new(),
                delta_text: Vec::new(),
                restart_policy: "never".to_string(),
                restart_limit: 3,
                restart_backoff_ms: 1000,
                approved_by: None,
                approval_ref: None,
                generated_by: None,
                cmd: vec!["/bin/true".to_string()],
            },
            delta_add(None),
            delta_add(Some(ebpf_ifc_engine::GLOBAL_ACTIVE_DOMAIN_ID)),
        ] {
            let err = reject_parent_domain_control_mutation(dir.path(), &command)
                .err()
                .expect("parent-domain mutation rejected")
                .to_string();
            assert!(err.contains("unavailable in --parent-domain mode"), "{err}");
        }

        // A delta aimed at a child domain is allowed to proceed.
        reject_parent_domain_control_mutation(dir.path(), &delta_add(Some(7)))
            .expect("child-domain delta allowed");
        reject_parent_domain_control_mutation(dir.path(), &ControlCommands::Status)
            .expect("status allowed");

        // A non-parent-domain engine allows every mutation.
        write_state(0);
        reject_parent_domain_control_mutation(dir.path(), &delta_add(None))
            .expect("non-parent engine allows delta");
    }

    #[test]
    fn print_control_response_reports_ok_text_and_errors() {
        assert!(print_control_response(serde_json::json!({"ok": true, "text": "bound"})).is_ok());
        assert!(
            print_control_response(serde_json::json!({"ok": true, "result": {"bound": 1}})).is_ok()
        );
        assert!(print_control_response(serde_json::json!({"ok": true})).is_ok());
        assert!(print_control_response(serde_json::json!({"ok": false})).is_err());
        // A non-boolean `ok` is treated as failure and uses the default message.
        let err = print_control_response(serde_json::json!({"ok": "yes", "text": "x"}))
            .err()
            .expect("non-bool ok")
            .to_string();
        assert_eq!(err, "ActPlane control request failed");

        let err = print_control_response(serde_json::json!({"ok": false, "error": "boom"}))
            .err()
            .expect("error response")
            .to_string();
        assert_eq!(err, "boom");
    }

    #[test]
    fn join_policy_delta_fragments_joins_with_delta_headers() {
        // `join_policy_delta_fragments` renders a policy delta as one block per
        // source: `\n# delta <policy_ref>\n<src.trimmed>\n`. No base or branch
        // test pins this joiner directly.
        assert_eq!(join_policy_delta_fragments(Vec::new()), None);
        assert_eq!(
            join_policy_delta_fragments(vec![(
                "main.dsl".to_string(),
                "source main\n".to_string(),
            )])
            .expect("a delta list is Some"),
            "\n# delta main.dsl\nsource main\n"
        );
        // Two fragments join in order, each with its own delta header.
        assert_eq!(
            join_policy_delta_fragments(vec![
                ("a.dsl".to_string(), "  source a  ".to_string()),
                ("b.dsl".to_string(), "source b\n".to_string()),
            ])
            .expect("a delta list is Some"),
            "\n# delta a.dsl\nsource a\n\n# delta b.dsl\nsource b\n"
        );
    }

    #[test]
    fn load_policy_delta_fragments_reads_files_then_inline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = dir.path().join("a.dsl");
        let second = dir.path().join("b.dsl");
        std::fs::write(&first, "  rule a:\n    notify exec \"a\"\n  ").expect("write a");
        std::fs::write(&second, "rule b:\n  notify exec \"b\"\n").expect("write b");

        let deltas = load_policy_delta_fragments(
            &[first.clone(), second],
            &["rule c:\n  notify exec \"c\"".to_string()],
        )
        .expect("load deltas");
        assert_eq!(deltas.len(), 3);
        assert_eq!(deltas[0].0, first.display().to_string());
        assert_eq!(deltas[0].1, "  rule a:\n    notify exec \"a\"\n  ");
        assert_eq!(deltas[2].0, "--delta-text[0]");

        let inline_only = load_policy_delta_fragments(&[], &["x".to_string(), "y".to_string()])
            .expect("inline deltas");
        assert_eq!(inline_only.len(), 2);
        assert_eq!(inline_only[0].0, "--delta-text[0]");
        assert_eq!(inline_only[1].0, "--delta-text[1]");
        assert_eq!(inline_only[1].1, "y");

        let empty = load_policy_delta_fragments(&[], &[]).expect("empty deltas");
        assert!(empty.is_empty());
    }

    #[test]
    fn load_policy_delta_fragments_reports_unreadable_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("absent.dsl");
        let err = load_policy_delta_fragments(&[missing.clone()], &[])
            .err()
            .expect("missing delta errors");
        let err = err.to_string();
        assert!(err.starts_with(&format!("cannot read policy delta {}", missing.display())));
        assert!(err.contains("No such file or directory"), "{err}");
    }

    #[test]
    fn join_policy_delta_fragments_trims_and_headers_each_source() {
        let joined = join_policy_delta_fragments(vec![
            ("a.dsl".to_string(), "  rule a:\n  ".to_string()),
            ("--delta-text[0]".to_string(), "rule b:".to_string()),
        ])
        .expect("joined");
        assert_eq!(
            joined,
            "\n# delta a.dsl\nrule a:\n\n# delta --delta-text[0]\nrule b:\n"
        );
        assert!(join_policy_delta_fragments(Vec::new()).is_none());
    }

    #[test]
    fn preflight_output_file_classifies_rejections() {
        let dir = tempdir().expect("tempdir");

        // Missing file with a missing parent directory.
        let orphan = dir.path().join("absent").join("out.bin");
        let err = preflight_output_file(&orphan, false)
            .err()
            .expect("missing parent rejected")
            .to_string();
        assert_eq!(
            err,
            format!(
                "parent directory for {} does not exist or is not a directory",
                orphan.display()
            )
        );

        // A directory is not an output file.
        let sub = dir.path().join("adir");
        std::fs::create_dir(&sub).expect("mkdir");
        let err = preflight_output_file(&sub, true)
            .err()
            .expect("dir rejected")
            .to_string();
        assert_eq!(
            err,
            format!("{} is a directory, not an output file", sub.display())
        );

        // An existing file is rejected unless forced.
        let existing = dir.path().join("out.bin");
        std::fs::write(&existing, "old").expect("write");
        let err = preflight_output_file(&existing, false)
            .err()
            .expect("existing file rejected")
            .to_string();
        assert_eq!(
            err,
            format!(
                "{} already exists (use --force to overwrite)",
                existing.display()
            )
        );
        assert!(preflight_output_file(&existing, true).is_ok());

        // A fresh path is keyed by canonical path.
        let fresh = dir.path().join("fresh.bin");
        assert!(preflight_output_file(&fresh, false).is_ok());

        // A symlink is rejected even when the target is a regular file.
        #[cfg(unix)]
        {
            let link = dir.path().join("link.bin");
            std::os::unix::fs::symlink(&existing, &link).expect("symlink");
            let err = preflight_output_file(&link, true)
                .err()
                .expect("symlink rejected")
                .to_string();
            assert_eq!(
                err,
                format!(
                    "{} is a symlink; use the resolved target path instead",
                    link.display()
                )
            );
        }
    }

    #[test]
    fn write_output_helpers_refuse_to_clobber_without_force() {
        let dir = tempdir().expect("tempdir");
        let text = dir.path().join("policy.bin");
        write_output_file(&text, "hello", false).expect("first write");
        assert_eq!(std::fs::read_to_string(&text).expect("read"), "hello");
        assert!(write_output_file(&text, "other", false).is_err());
        write_output_file(&text, "other", true).expect("forced overwrite");
        assert_eq!(std::fs::read_to_string(&text).expect("read"), "other");

        let binary = dir.path().join("engine.bin");
        write_binary_output_file(&binary, &[0, 1, 2], false).expect("binary write");
        assert_eq!(std::fs::read(&binary).expect("read"), vec![0, 1, 2]);
        assert!(write_binary_output_file(&binary, &[3], false).is_err());
        write_binary_output_file(&binary, &[3], true).expect("forced binary overwrite");
        assert_eq!(std::fs::read(&binary).expect("read"), vec![3]);
    }

    #[test]
    fn append_delta_control_requests_reports_missing_socket() {
        let dir = tempdir().expect("tempdir");
        let args = DeltaAddArgs {
            target_id: None,
            domain_id: None,
            deltas: Vec::new(),
            delta_text: vec!["rule r:\n".to_string()],
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        };
        let err = append_delta_control_requests(dir.path(), &args, "control delta add")
            .err()
            .expect("missing control socket")
            .to_string();
        assert!(err.contains("control.json"), "{err}");
    }

    #[test]
    fn preflight_output_file_rejects_non_regular_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        {
            let fifo = tmp.path().join("pipe");
            let c_path =
                std::ffi::CString::new(fifo.to_str().expect("fifo path")).expect("cstring");
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0, "mkfifo");
            let err = preflight_output_file(&fifo, true).expect_err("fifo rejected");
            assert_eq!(
                err.to_string(),
                format!("{} is not a regular output file", fifo.display())
            );
        }
        let missing_parent = tmp.path().join("nope").join("out.bin");
        let err = preflight_output_file(&missing_parent, true).expect_err("missing parent");
        assert_eq!(
            err.to_string(),
            format!(
                "parent directory for {} does not exist or is not a directory",
                missing_parent.display()
            )
        );
    }

    #[test]
    fn template_project_root_prefers_policy_then_git() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let policy = tmp.path().join("actplane.yaml");
        std::fs::write(&policy, "version: 1\n").expect("policy");
        assert_eq!(
            template_project_root_from(tmp.path()).expect("policy root"),
            tmp.path()
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(tmp.path().join(".git")).expect("git dir");
        let nested = tmp.path().join("nested").join("deeper");
        std::fs::create_dir_all(&nested).expect("nested");
        assert_eq!(
            template_project_root_from(&nested).expect("git root"),
            tmp.path()
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            template_project_root_from(tmp.path()).expect("fallback root"),
            tmp.path()
        );
    }

    #[test]
    fn format_rule_list_renders_domain_bindings() {
        assert_eq!(format_rule_list(&[]), "none");
        assert_eq!(format_rule_list(&["a".into(), "b".into()]), "a, b");
        let domain = config::DomainSummary {
            name: "review".into(),
            parent: None,
            disabled: vec!["x".into()],
            locked: vec!["a".into()],
            defaults: vec!["b".into(), "c".into()],
        };
        assert_eq!(format_domain_policy_rules(&domain), "a, b, c");
    }

    fn template_project_root_from(start: &Path) -> Result<PathBuf> {
        let previous = std::env::current_dir()?;
        std::env::set_current_dir(start)?;
        let root = template_project_root();
        std::env::set_current_dir(previous)?;
        root
    }

    #[test]
    fn parent_domain_control_mutation_error_names_the_operation_and_recovery_path() {
        // `parent_domain_control_mutation_error` renders the single-line error
        // message for a control mutation attempted in `--parent-domain` mode,
        // naming the offending operation and the two recovery paths. No base
        // or branch test pins this formatter directly.
        assert_eq!(
            parent_domain_control_mutation_error("pause"),
            "pause is unavailable in --parent-domain mode; start watch without \
             --parent-domain, or use mcp --auto-attach-parent, to create an \
             authority-bearing runtime parent domain"
        );
        // A different operation name is substituted in the leading position.
        assert!(
            parent_domain_control_mutation_error("stop")
                .starts_with("stop is unavailable in --parent-domain mode")
        );
    }

    fn write_state_c2(project_dir: &Path, parent_domain_id: u32) {
        let dir = project_dir.join(".actplane");
        std::fs::create_dir_all(&dir).unwrap();
        let state = control::ControlState {
            schema: "actplane.control.v1".to_string(),
            pid: 4321,
            proc_start_time: None,
            socket_path: dir.join("control.sock"),
            project_dir: project_dir.to_path_buf(),
            parent_pid: 4320,
            parent_domain_id,
        };
        std::fs::write(
            dir.join("control.json"),
            serde_json::to_string(&state).unwrap(),
        )
        .unwrap();
    }

    fn delta_add_c3(target_id: Option<u32>) -> DeltaAddArgs {
        DeltaAddArgs {
            target_id,
            domain_id: None,
            deltas: Vec::new(),
            delta_text: Vec::new(),
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        }
    }

    #[test]
    fn reject_parent_domain_runtime_mutation_errors_only_for_global_parent() {
        let dir = tempfile::tempdir().unwrap();
        write_state_c2(dir.path(), ebpf_ifc_engine::GLOBAL_ACTIVE_DOMAIN_ID);
        let err =
            reject_parent_domain_runtime_mutation(dir.path(), "bind child domain").unwrap_err();
        assert!(
            err.to_string()
                .contains("bind child domain is unavailable in --parent-domain mode")
        );
        write_state_c2(dir.path(), 7);
        assert!(reject_parent_domain_runtime_mutation(dir.path(), "bind child domain").is_ok());
    }

    #[test]
    fn reject_parent_domain_control_mutation_selects_unsupported_operations() {
        let dir = tempfile::tempdir().unwrap();
        write_state_c2(dir.path(), ebpf_ifc_engine::GLOBAL_ACTIVE_DOMAIN_ID);
        let bind = ControlCommands::BindChild {
            pid: 1,
            child_id: None,
            scope_id: 0,
        };
        assert!(reject_parent_domain_control_mutation(dir.path(), &bind).is_err());
        let status = ControlCommands::Status;
        assert!(reject_parent_domain_control_mutation(dir.path(), &status).is_ok());
        let add = ControlCommands::Delta {
            command: DeltaCommands::Add(delta_add_c3(None)),
        };
        assert!(reject_parent_domain_control_mutation(dir.path(), &add).is_err());
        let add_child = ControlCommands::Delta {
            command: DeltaCommands::Add(delta_add_c3(Some(7))),
        };
        assert!(reject_parent_domain_control_mutation(dir.path(), &add_child).is_ok());
    }

    #[test]
    fn policy_audit_meta_from_delta_args_leaves_policy_ref_unset() {
        // The delta control path has no single policy file, so
        // `policy_audit_meta_from_delta_args` builds a `PolicyAuditMeta` with
        // `policy_ref == None` and passes the three optional audit fields
        // through unchanged. No base or branch test pins it directly.
        let args = DeltaAddArgs {
            target_id: None,
            domain_id: None,
            deltas: Vec::new(),
            delta_text: Vec::new(),
            approved_by: Some("alice".to_string()),
            approval_ref: Some("PR-7".to_string()),
            generated_by: Some("tool".to_string()),
        };
        assert_eq!(
            policy_audit_meta_from_delta_args(&args),
            runtime::PolicyAuditMeta {
                policy_ref: None,
                approved_by: Some("alice".to_string()),
                approval_ref: Some("PR-7".to_string()),
                generated_by: Some("tool".to_string()),
            }
        );
        let unset = DeltaAddArgs {
            target_id: Some(3),
            domain_id: None,
            deltas: Vec::new(),
            delta_text: Vec::new(),
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        };
        assert_eq!(
            policy_audit_meta_from_delta_args(&unset),
            runtime::PolicyAuditMeta {
                policy_ref: None,
                approved_by: None,
                approval_ref: None,
                generated_by: None,
            }
        );
    }

    #[test]
    fn policy_audit_meta_from_fields_passes_through_all_option_fields() {
        // `policy_audit_meta_from_fields` builds a `runtime::PolicyAuditMeta`
        // from the control-path audit fields, passing `policy_ref` by value
        // and cloning the three `&Option<String>` fields. No base or branch
        // test pins this constructor directly.
        let approved_by = Some("alice".to_string());
        let approval_ref = Some("PR-42".to_string());
        let generated_by = Some("tool".to_string());
        assert_eq!(
            policy_audit_meta_from_fields(
                Some("policy.dsl".to_string()),
                &approved_by,
                &approval_ref,
                &generated_by
            ),
            runtime::PolicyAuditMeta {
                policy_ref: Some("policy.dsl".to_string()),
                approved_by: Some("alice".to_string()),
                approval_ref: Some("PR-42".to_string()),
                generated_by: Some("tool".to_string()),
            }
        );
        // Unset fields stay `None`.
        assert_eq!(
            policy_audit_meta_from_fields(None, &None, &None, &None),
            runtime::PolicyAuditMeta {
                policy_ref: None,
                approved_by: None,
                approval_ref: None,
                generated_by: None,
            }
        );
    }

    #[test]
    fn policy_input_copies_cli_fields_verbatim() {
        // `policy_input` projects the global CLI arguments onto the runtime's
        // `PolicyInput`, cloning policy/rule/domain and copying the two
        // elevation booleans. No base or branch test pins it directly.
        let cli = Cli {
            policy: Some(PathBuf::from("/tmp/actplane.yaml")),
            rule: Some("source COMMAND = exec \"**\"".to_string()),
            domain: Some("team".to_string()),
            run_as_root: true,
            internal_elevated: false,
            command: Commands::Doctor,
        };
        let input = policy_input(&cli);
        assert_eq!(input.policy, Some(PathBuf::from("/tmp/actplane.yaml")));
        assert_eq!(input.rule.as_deref(), Some("source COMMAND = exec \"**\""));
        assert_eq!(input.domain.as_deref(), Some("team"));
        assert!(input.run_as_root);
        assert!(!input.internal_elevated);

        let empty = Cli {
            policy: None,
            rule: None,
            domain: None,
            run_as_root: false,
            internal_elevated: true,
            command: Commands::Doctor,
        };
        let input = policy_input(&empty);
        assert!(input.policy.is_none());
        assert!(input.rule.is_none());
        assert!(input.domain.is_none());
        assert!(!input.run_as_root);
        assert!(input.internal_elevated);
    }

    fn test_cli(policy: Option<PathBuf>) -> Cli {
        Cli::try_parse_from(match policy {
            Some(path) => vec![
                "actplane".to_string(),
                "--policy".to_string(),
                path.display().to_string(),
                "control".to_string(),
                "status".to_string(),
            ],
            None => vec![
                "actplane".to_string(),
                "control".to_string(),
                "status".to_string(),
            ],
        })
        .expect("parse cli")
    }

    #[test]
    fn has_local_instruction_file_matches_known_locations() {
        let dir = tempdir().expect("tempdir");
        assert!(!has_local_instruction_file(dir.path()));
        for rel in [
            "AGENTS.md",
            "CLAUDE.md",
            ".agents/AGENTS.md",
            ".agents/instructions.md",
            ".codex/AGENTS.md",
        ] {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, "instructions").expect("write");
            assert!(has_local_instruction_file(dir.path()), "{rel} should count");
            std::fs::remove_file(&path).expect("remove");
        }
        std::fs::write(dir.path().join("docs.md"), "x").expect("write");
        assert!(!has_local_instruction_file(dir.path()));
    }

    #[test]
    fn control_project_dir_prefers_explicit_policy_parent() {
        let dir = tempdir().expect("tempdir");
        let policy_path = dir.path().join("elsewhere").join("actplane.yaml");
        std::fs::create_dir_all(policy_path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&policy_path, "version: 1\npolicy: |\n  rule r:\n").expect("write");
        let cli = test_cli(Some(policy_path.clone()));
        assert_eq!(
            control_project_dir(&cli).expect("project dir"),
            policy_path.parent().expect("parent").to_path_buf()
        );

        let relative = test_cli(Some(PathBuf::from("actplane.yaml")));
        let cwd = std::env::current_dir().expect("cwd");
        assert_eq!(control_project_dir(&relative).expect("project dir"), cwd);
    }

    #[test]
    fn append_delta_control_requests_requires_a_fragment() {
        let dir = tempdir().expect("tempdir");
        let args = DeltaAddArgs {
            target_id: None,
            domain_id: None,
            deltas: Vec::new(),
            delta_text: Vec::new(),
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        };
        let err = append_delta_control_requests(dir.path(), &args, "control delta add")
            .err()
            .expect("empty delta errors")
            .to_string();
        assert_eq!(err, "control delta add requires --delta or --delta-text");

        let missing = dir.path().join("absent.dsl");
        let args = DeltaAddArgs {
            target_id: None,
            domain_id: None,
            deltas: vec![missing.clone()],
            delta_text: Vec::new(),
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        };
        let err = append_delta_control_requests(dir.path(), &args, "control delta add")
            .err()
            .expect("missing delta errors")
            .to_string();
        assert!(
            err.starts_with(&format!("cannot read policy delta {}", missing.display())),
            "{err}"
        );
    }

    #[test]
    fn format_rule_list_joins_or_reports_none() {
        assert_eq!(format_rule_list(&[]), "none");
        assert_eq!(format_rule_list(&["a".into(), "b".into()]), "a, b");
    }

    #[test]
    fn format_domain_policy_rules_concatenates_locked_then_defaults() {
        let domain = config::DomainSummary {
            name: "root".into(),
            parent: None,
            disabled: vec![],
            locked: vec!["locked-one".into()],
            defaults: vec!["default-two".into()],
        };
        assert_eq!(
            format_domain_policy_rules(&domain),
            "locked-one, default-two"
        );
    }

    #[test]
    fn join_policy_delta_fragments_frames_each_fragment() {
        assert_eq!(join_policy_delta_fragments(vec![]), None);
        let joined = join_policy_delta_fragments(vec![
            ("a.dsl".into(), "  rule x: allow\n".into()),
            ("b.dsl".into(), "rule y: deny".into()),
        ])
        .unwrap();
        assert!(joined.contains("# delta a.dsl"));
        assert!(joined.contains("rule x: allow"));
        assert!(joined.contains("# delta b.dsl"));
        assert!(joined.contains("rule y: deny"));
        // Fragments are trimmed when embedded, not the header.
        assert!(joined.contains("\nrule y: deny\n"));
    }

    #[test]
    fn policy_audit_meta_from_fields_copies_each_option() {
        let meta = policy_audit_meta_from_fields(
            Some("p.yaml".into()),
            &Some("alice".into()),
            &None,
            &Some("cli".into()),
        );
        assert_eq!(meta.policy_ref.as_deref(), Some("p.yaml"));
        assert_eq!(meta.approved_by.as_deref(), Some("alice"));
        assert_eq!(meta.approval_ref, None);
        assert_eq!(meta.generated_by.as_deref(), Some("cli"));
    }

    #[test]
    fn add_policy_audit_meta_fields_only_sets_present_options() {
        let mut request = serde_json::json!({ "keep": 1 });
        add_policy_audit_meta_fields(
            &mut request,
            &runtime::PolicyAuditMeta {
                policy_ref: Some("p.yaml".into()),
                approved_by: None,
                approval_ref: Some("ticket-7".into()),
                generated_by: None,
            },
        );
        assert_eq!(request["keep"], 1);
        assert_eq!(request["policy_ref"], "p.yaml");
        assert_eq!(request["approval_ref"], "ticket-7");
        assert!(request.get("approved_by").is_none());
        assert!(request.get("generated_by").is_none());
    }

    #[test]
    fn has_local_instruction_file_recognizes_known_names() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!has_local_instruction_file(tmp.path()));
        std::fs::write(tmp.path().join("AGENTS.md"), "").unwrap();
        assert!(has_local_instruction_file(tmp.path()));
    }

    #[test]
    fn write_output_file_writes_and_refuses_reuse_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("out.txt");
        write_output_file(&path, "one", false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one");
        assert!(write_output_file(&path, "two", false).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one");
        write_output_file(&path, "two", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
    }

    #[test]
    fn write_binary_output_file_writes_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("blob.bin");
        write_binary_output_file(&path, &[0, 1, 2, 255], false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![0, 1, 2, 255]);
    }

    #[test]
    fn preflight_rejects_directory_and_missing_parent() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(preflight_output_file(tmp.path(), true).is_err());
        let missing = tmp.path().join("nope").join("out.txt");
        assert!(preflight_output_file(&missing, false).is_err());
    }
}

#[cfg(test)]
mod main_guard_tests {
    use super::*;

    fn cli(policy: Option<PathBuf>, rule: Option<&str>) -> Cli {
        Cli {
            policy,
            rule: rule.map(str::to_string),
            domain: None,
            run_as_root: false,
            internal_elevated: false,
            command: Commands::Compile(CompileArgs {
                out: None,
                json: false,
                explain: false,
                domains: false,
                report_out: None,
                force: false,
            }),
        }
    }

    fn attach(pid: i32) -> AttachArgs {
        AttachArgs {
            pid,
            parent_domain: false,
            child_domain: false,
            domain_id: None,
            child_id: None,
            scope_id: 0,
            deltas: Vec::new(),
            delta_text: Vec::new(),
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    #[test]
    fn attach_command_requires_a_positive_pid_before_any_policy_load() {
        let cli = cli(None, None);
        for pid in [0, -1] {
            let err = rt()
                .block_on(attach_command(&cli, &attach(pid)))
                .expect_err("non-positive pid is rejected");
            assert_eq!(err.to_string(), "--pid must be positive");
        }
    }

    #[test]
    fn attach_command_rejects_parent_domain_with_child_options() {
        let cli = cli(None, None);
        let mut args = attach(42);
        args.parent_domain = true;
        args.deltas.push(PathBuf::from("child.dsl"));
        let err = rt()
            .block_on(attach_command(&cli, &args))
            .expect_err("parent-domain plus child options is rejected");
        assert_eq!(
            err.to_string(),
            "--parent-domain cannot be combined with child-domain attach options"
        );
    }

    #[test]
    fn compile_policy_requires_json_or_explain_for_report_out() {
        let cli = cli(None, None);
        let args = CompileArgs {
            out: None,
            json: false,
            explain: false,
            domains: false,
            report_out: Some(PathBuf::from("review.txt")),
            force: false,
        };
        let err = rt()
            .block_on(compile_policy(&cli, &args))
            .expect_err("report-out without a mode is rejected");
        assert_eq!(err.to_string(), "--report-out requires --json or --explain");
    }

    #[test]
    fn compile_policy_reports_a_policy_load_error_for_an_unparseable_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = dir.path().join("actplane.yaml");
        std::fs::write(
            &policy,
            "fallback:\n  kill_on_violation: true\npolicy: \"rule r:\\n  block exec \\\"git\\\"\\n  because \\\"x\\\"\"\n",
        )
        .expect("write policy");
        let cli = cli(Some(policy), None);
        let args = CompileArgs {
            out: Some(dir.path().join("policy.bin")),
            json: false,
            explain: false,
            domains: false,
            report_out: None,
            force: false,
        };
        let err = rt()
            .block_on(compile_policy(&cli, &args))
            .expect_err("unparseable policy is rejected");
        assert!(
            err.to_string().contains("policy"),
            "unexpected error: {err}"
        );
    }
}

#[cfg(test)]
mod main_control_guard_tests {
    use super::*;

    fn write_state(project_dir: &Path, parent_domain_id: u32) {
        let state = control::ControlState {
            schema: "actplane.control.v1".to_string(),
            pid: 1234,
            proc_start_time: None,
            socket_path: project_dir.join("sock"),
            project_dir: project_dir.to_path_buf(),
            parent_pid: 1234,
            parent_domain_id,
        };
        let dir = project_dir.join(".actplane");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(
            dir.join("control.json"),
            serde_json::to_string(&state).expect("state json"),
        )
        .expect("write state");
    }

    fn delta_add(target_id: Option<u32>) -> ControlCommands {
        ControlCommands::Delta {
            command: DeltaCommands::Add(DeltaAddArgs {
                target_id,
                domain_id: None,
                deltas: Vec::new(),
                delta_text: Vec::new(),
                approved_by: None,
                approval_ref: None,
                generated_by: None,
            }),
        }
    }

    #[test]
    fn control_mutation_guards_gate_on_the_running_engine_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_state(dir.path(), ebpf_ifc_engine::GLOBAL_ACTIVE_DOMAIN_ID);
        let target = Some(ebpf_ifc_engine::GLOBAL_ACTIVE_DOMAIN_ID);

        // Only the global-active engine rejects authority-bearing mutations.
        let err = reject_parent_domain_control_mutation(dir.path(), &delta_add(target))
            .expect_err("global-active engine rejects delta add");
        assert!(
            err.to_string()
                .contains("append policy delta is unavailable in --parent-domain mode"),
            "unexpected error: {err}"
        );

        // Status and a non-global target are both allowed to proceed.
        reject_parent_domain_control_mutation(dir.path(), &ControlCommands::Status)
            .expect("status is not a mutation");
        reject_parent_domain_control_mutation(dir.path(), &delta_add(Some(7)))
            .expect("a bound child target is a mutation");

        // A parent-domain engine never reaches the socket send path.
        write_state(dir.path(), 5);
        reject_parent_domain_control_mutation(dir.path(), &delta_add(target))
            .expect("authority-bearing engine allows delta add");
    }
}

#[cfg(test)]
mod main_control_status_tests {
    use super::*;

    fn cli_with_policy(policy: PathBuf) -> Cli {
        Cli {
            policy: Some(policy),
            rule: None,
            domain: None,
            run_as_root: false,
            internal_elevated: false,
            command: Commands::Doctor,
        }
    }

    fn rt_c2() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    #[test]
    fn control_status_reports_a_stale_state_before_connecting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = dir.path().join("actplane.yaml");
        std::fs::write(&policy, "policy: \"x\"\n").expect("write policy");

        // A dead pid is stale: the command is refused before any socket connect.
        let state = control::ControlState {
            schema: "actplane.control.v1".to_string(),
            pid: 99_999_999,
            proc_start_time: None,
            socket_path: dir.path().join(".actplane").join("sock"),
            project_dir: dir.path().to_path_buf(),
            parent_pid: 1,
            parent_domain_id: 1,
        };
        let control_dir = dir.path().join(".actplane");
        std::fs::create_dir_all(&control_dir).expect("mkdir");
        std::fs::write(
            control_dir.join("control.json"),
            serde_json::to_string(&state).expect("state json"),
        )
        .expect("write state");

        let cli = cli_with_policy(policy);
        let err = rt_c2()
            .block_on(control_command(&cli, &ControlCommands::Status))
            .expect_err("stale state is rejected");
        assert!(
            err.to_string().contains("stale ActPlane control state"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn control_status_forwards_the_engine_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = dir.path().join("actplane.yaml");
        std::fs::write(&policy, "policy: \"x\"\n").expect("write policy");

        // A live local control server backed by a trivial handler.
        let guard = control::start_server(
            dir.path(),
            std::process::id() as i32,
            1,
            |request, _peer| serde_json::json!({ "ok": true, "result": request }),
        )
        .expect("start control server");

        let cli = cli_with_policy(policy);
        let code = rt_c2()
            .block_on(control_command(&cli, &ControlCommands::Status))
            .expect("status succeeds");
        assert_eq!(code, 0);
        drop(guard);

        // After the guard drops the state file is gone, so the request is stale.
        let err = rt_c2()
            .block_on(control_command(&cli, &ControlCommands::Status))
            .expect_err("state is removed with the guard");
        assert!(err.to_string().contains("read"), "unexpected error: {err}");
    }
}

#[cfg(test)]
mod main_delta_guard_tests {
    use super::*;

    fn delta_add_c2(deltas: Vec<PathBuf>, delta_text: Vec<String>) -> DeltaAddArgs {
        DeltaAddArgs {
            target_id: Some(7),
            domain_id: None,
            deltas,
            delta_text,
            approved_by: None,
            approval_ref: None,
            generated_by: None,
        }
    }

    #[test]
    fn delta_control_requests_require_a_fragment_before_any_socket_send() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = append_delta_control_requests(
            dir.path(),
            &delta_add_c2(Vec::new(), Vec::new()),
            "control delta add",
        )
        .expect_err("no fragment is rejected");
        assert_eq!(
            err.to_string(),
            "control delta add requires --delta or --delta-text"
        );
    }

    #[test]
    fn load_policy_delta_fragments_refs_files_and_inline_text() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("delta.dsl");
        std::fs::write(&file, "rule r:\n  block exec \"git\"\n  because \"x\"\n").expect("write");

        let fragments =
            load_policy_delta_fragments(std::slice::from_ref(&file), &["inline body".to_string()])
                .expect("fragments load");
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0].0, file.display().to_string());
        assert!(fragments[0].1.contains("block exec \"git\""));
        assert_eq!(fragments[1].0, "--delta-text[0]");
        assert_eq!(fragments[1].1, "inline body");

        let joined = join_policy_delta_fragments(fragments).expect("joined");
        assert!(joined.contains("# delta --delta-text[0]"));
        assert!(join_policy_delta_fragments(Vec::new()).is_none());
    }

    #[test]
    fn load_policy_delta_fragments_reports_a_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("absent.dsl");
        let err = load_policy_delta_fragments(&[missing.clone()], &[])
            .expect_err("missing delta file is rejected");
        assert!(
            err.to_string()
                .starts_with(&format!("cannot read policy delta {}", missing.display())),
            "unexpected error: {err}"
        );
    }
}

#[cfg(test)]
mod main_run_guard_tests {
    use super::*;

    fn run(pid: Option<u32>, deltas: Vec<PathBuf>) -> RunArgs {
        RunArgs {
            parent_domain: true,
            child_id: pid,
            scope_id: 0,
            deltas,
            delta_text: Vec::new(),
            approved_by: None,
            approval_ref: None,
            generated_by: None,
            cmd: vec!["true".to_string()],
        }
    }

    #[test]
    fn run_command_rejects_parent_domain_with_any_child_mode_signal() {
        let cli = Cli {
            policy: None,
            rule: None,
            domain: None,
            run_as_root: false,
            internal_elevated: false,
            command: Commands::Compile(CompileArgs {
                out: None,
                json: false,
                explain: false,
                domains: false,
                report_out: None,
                force: false,
            }),
        };
        let rt = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
        };
        // child_id alone, and a delta alone, each count as child mode.
        for args in [
            run(Some(7), Vec::new()),
            run(None, vec![PathBuf::from("d.dsl")]),
        ] {
            let err = rt()
                .block_on(run_command(&cli, &args))
                .expect_err("parent-domain plus child mode is rejected");
            assert_eq!(
                err.to_string(),
                "--parent-domain cannot be combined with child runtime delta options"
            );
        }
    }
}
