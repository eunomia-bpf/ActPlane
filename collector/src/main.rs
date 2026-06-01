// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane — OS-level agent harness.
//!
//! Loads an `actplane.yaml` project policy, lowers its embedded taint DSL to the
//! kernel ABI, runs the embedded eBPF engine, and reports every kernel-detected
//! rule match with the corrective-feedback payload.

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

mod config;
mod doctor;
mod dsl;
mod feedback;
mod hook;
mod mcp;
mod report;
mod runtime;
mod setup;

type AnyError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, AnyError>;

#[derive(Parser)]
#[command(author, version, about = "ActPlane: OS-level agent harness", long_about = None,
    after_help = "EXAMPLES:\n  \
      # get started: write a starter policy, wire agent hooks/MCP, then diagnose\n  \
      actplane init  &&  actplane doctor\n\n  \
      # apply a one-line policy around a command (needs sudo for the eBPF load)\n  \
      sudo -E actplane --rule 'source COMMAND = exec \"**\"\n                       rule no-git-branch:\n                         kill exec \"git\" \"branch\" if COMMAND\n                         because \"create a branch via the host, not the agent\"' run claude -p '...'\n\n  \
      # use a project policy file (auto-discovered as ./actplane.yaml upward)\n  \
      sudo -E actplane run <your agent command>\n\n  \
      # serve MCP resources and auto-attach to the parent agent when Codex starts it\n  \
      actplane mcp --auto-attach-parent\n\n  \
      # just compile/validate a policy (no privileges needed)\n  \
      actplane --policy actplane.yaml compile --out /tmp/policy.bin\n\n  \
      # watch & report violations system-wide without launching a child\n  \
      sudo -E actplane --policy actplane.yaml watch\n\n\
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
    /// Wire project-local Codex hooks, MCP config, and AGENTS.md.
    Setup {
        /// Overwrite ActPlane-managed project integration files.
        #[arg(short, long)]
        force: bool,
    },
    /// Validate the policy (no privileges): compile it, summarize each rule in
    /// plain language, and warn about anything that won't apply as written.
    Check,
    /// Diagnose policy discovery, kernel support, feedback hooks, and MCP setup.
    Doctor,
    /// Load the policy and report violations without starting a child command.
    Watch,
    /// Hook adapter: forward new feedback-file bytes as agent additionalContext.
    FeedbackHook,
    /// Run as an MCP (Model Context Protocol) server over stdio.
    Mcp {
        /// On startup, load the eBPF engine and seed the parent process.
        #[arg(long)]
        auto_attach_parent: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let code = match &cli.command {
        Commands::Run { cmd } => runtime::run_command(&cli, cmd).await?,
        Commands::Compile { out } => compile_policy(&cli, out).await?,
        Commands::Init { force } => setup::init_policy(*force)?,
        Commands::Setup { force } => setup::setup_project(*force)?,
        Commands::Check => doctor::check_policy(&cli)?,
        Commands::Doctor => doctor::doctor(&cli)?,
        Commands::Watch => runtime::watch_policy(&cli).await?,
        Commands::FeedbackHook => {
            hook::feedback_hook().await?;
            0
        }
        Commands::Mcp { auto_attach_parent } => {
            let _attach = if *auto_attach_parent {
                Some(runtime::start_mcp_auto_attach(&cli)?)
            } else {
                None
            };
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
    let loaded = config::load_policy(cli)?;
    let policy = config::policy_source(&loaded, cli.domain.as_deref())?;
    let compiled = dsl::compile_str(&policy)?;
    std::fs::write(out, &compiled.bytes)?;
    eprintln!(
        "ActPlane: compiled {} rule(s) to {}",
        compiled.reasons.len(),
        out.display()
    );
    Ok(0)
}
