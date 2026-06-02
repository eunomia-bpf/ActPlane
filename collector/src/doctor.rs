use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::config::{domain_summaries, feedback_paths, load_policy, resolve_policy};
use crate::runtime::{have_bpf_caps, passwordless_sudo_available};
use crate::setup::{codex_hook_has_actplane_command, project_mcp_auto_attach_ok};
use crate::{Cli, Result, dsl};

pub(crate) fn check_policy(cli: &Cli) -> Result<i32> {
    let loaded = load_policy(cli)?;
    let resolved = resolve_policy(&loaded, cli.domain.as_deref())?;
    let compiled = match dsl::compile_str(&resolved.source) {
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
    if let Some(domain) = &resolved.domain {
        println!("domain: {}", domain.name);
        if let Some(parent) = &domain.parent {
            println!("parent: {}", parent);
        }
        println!("locked: {}", format_rule_list(&domain.locked));
        println!("default: {}\n", format_rule_list(&domain.defaults));
    }
    for (i, m) in compiled.meta.iter().enumerate() {
        let eff = format!("{:?}", m.effect).to_lowercase();
        let ops = if m.ops.is_empty() {
            "—".into()
        } else {
            m.ops.join("/")
        };
        println!("  {}. {} — {} {} ({})", i + 1, m.name, eff, ops, m.reason);
    }
    let lsm_bpf = active_lsms().is_some_and(|s| lsm_list_has_bpf(&s));
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
    for line in resolved.source.lines() {
        let t = line.trim();
        let rest_opt = t
            .strip_prefix("notify connect endpoint")
            .or_else(|| t.strip_prefix("block connect endpoint"))
            .or_else(|| t.strip_prefix("kill connect endpoint"));
        if let Some(rest) = rest_opt
            && let Some(pat) = rest.split('"').nth(1)
        {
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
            "\n(note: `check` needs no privileges; applying policies needs `sudo -E actplane run/watch`.)"
        );
    }
    Ok(0)
}

pub(crate) fn doctor(cli: &Cli) -> Result<i32> {
    println!("ActPlane doctor\n");
    let mut problems = 0;

    doctor_path_actplane(&mut problems);

    match load_policy(cli) {
        Ok(loaded) => {
            let where_ = loaded
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "--rule".into());
            let resolved = resolve_policy(&loaded, cli.domain.as_deref())?;
            match dsl::compile_str(&resolved.source) {
                Ok(compiled) => {
                    if let Some(domain) = &resolved.domain {
                        println!(
                            "✓ policy: {} domain `{}` ({} rule(s))",
                            where_,
                            domain.name,
                            compiled.meta.len()
                        );
                    } else {
                        println!("✓ policy: {} ({} rule(s))", where_, compiled.meta.len());
                    }
                    let feedback = feedback_paths(&loaded);
                    println!("✓ feedback file: {}", feedback.feedback.display());
                }
                Err(e) => {
                    problems += 1;
                    println!("✗ policy: {} does not compile: {}", where_, e);
                }
            }
            doctor_agent_files(&loaded.root, &mut problems);
        }
        Err(e) => {
            problems += 1;
            println!("✗ policy: {}", e);
            let cwd = std::env::current_dir()?;
            doctor_agent_files(&cwd, &mut problems);
        }
    }

    if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        println!("✓ kernel BTF: /sys/kernel/btf/vmlinux");
    } else {
        problems += 1;
        println!("✗ kernel BTF: missing /sys/kernel/btf/vmlinux");
    }

    if have_bpf_caps() {
        println!("✓ eBPF privilege: current process has root/CAP_BPF+CAP_SYS_ADMIN");
    } else if passwordless_sudo_available() {
        println!("✓ eBPF privilege: passwordless sudo is available");
    } else {
        problems += 1;
        println!("✗ eBPF privilege: run/watch needs sudo or CAP_BPF+CAP_SYS_ADMIN");
    }

    let lsm = active_lsms().unwrap_or_default();
    if lsm_list_has_bpf(&lsm) {
        println!("✓ BPF-LSM: active ({})", lsm.trim());
    } else if let Some(source) = bpf_lsm_configured_for_next_boot() {
        println!(
            "⚠ BPF-LSM: configured for next boot in {}; reboot pending ({})",
            source.display(),
            lsm.trim()
        );
    } else {
        println!(
            "⚠ BPF-LSM: not active; `block` rules will report but not deny ({})",
            lsm.trim()
        );
    }

    println!("\nNext commands:");
    println!("  actplane check");
    println!("  codex");
    println!("  sudo -E actplane run -- <agent-or-command>");

    if problems == 0 {
        println!("\n✓ setup looks usable.");
        Ok(0)
    } else {
        println!("\n✗ setup has {} problem(s).", problems);
        Ok(1)
    }
}

pub(crate) fn list_domains(cli: &Cli) -> Result<i32> {
    let loaded = load_policy(cli)?;
    let where_ = loaded
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "--rule".into());
    if loaded.config.policy.is_some() {
        println!(
            "{} uses legacy `policy: |`; no domains are defined.",
            where_
        );
        return Ok(0);
    }

    let selected = resolve_policy(&loaded, cli.domain.as_deref())?
        .domain
        .map(|d| d.name);
    println!("Domains in {}", where_);
    for domain in domain_summaries(&loaded.config)? {
        let mark = if Some(domain.name.as_str()) == selected.as_deref() {
            "*"
        } else {
            " "
        };
        println!("{} {}", mark, domain.name);
        if let Some(parent) = &domain.parent {
            println!("    parent: {}", parent);
        }
        if !domain.disabled.is_empty() {
            println!("    disables: {}", format_rule_list(&domain.disabled));
        }
        println!("    locked: {}", format_rule_list(&domain.locked));
        println!("    default: {}", format_rule_list(&domain.defaults));
    }
    Ok(0)
}

fn format_rule_list(rules: &[String]) -> String {
    if rules.is_empty() {
        "none".into()
    } else {
        rules.join(", ")
    }
}

fn doctor_path_actplane(problems: &mut usize) {
    match find_executable_on_path("actplane") {
        Some(path) => {
            let version = command_version(&path).unwrap_or_else(|| "version unknown".into());
            println!("✓ PATH actplane: {} ({})", path.display(), version);
        }
        None => {
            *problems += 1;
            println!("✗ PATH actplane: not found; install or add the release binary to PATH");
        }
    }
}

fn doctor_agent_files(root: &Path, problems: &mut usize) {
    let codex_hooks = root.join(".codex/hooks.json");
    if codex_hooks.is_file() {
        let hooks = std::fs::read_to_string(&codex_hooks).unwrap_or_default();
        if codex_hook_has_actplane_command(&hooks) {
            println!("✓ Codex hook: {}", codex_hooks.display());
        } else {
            *problems += 1;
            println!(
                "✗ Codex hook: {} exists but is not wired to `actplane feedback-hook`; run `actplane setup --force`",
                codex_hooks.display()
            );
        }
    } else {
        *problems += 1;
        println!(
            "✗ Codex hook: missing {}; add `actplane feedback-hook` as PostToolUse",
            codex_hooks.display()
        );
    }

    let agents = root.join("AGENTS.md");
    if agents.is_symlink() {
        println!(
            "✓ Codex instructions: {} -> {:?}",
            agents.display(),
            std::fs::read_link(&agents).ok()
        );
    } else if agents.is_file() {
        println!("✓ Codex instructions: {}", agents.display());
    } else {
        println!("⚠ Codex instructions: AGENTS.md missing");
    }

    let mcp = root.join(".mcp.json");
    let mut project_mcp_ok = false;
    if mcp.is_file() {
        let text = std::fs::read_to_string(&mcp).unwrap_or_default();
        if project_mcp_auto_attach_ok(&text) {
            project_mcp_ok = true;
            println!("✓ project MCP config: {}", mcp.display());
        } else {
            *problems += 1;
            println!(
                "✗ project MCP config: {} does not auto-attach with PATH `actplane`; run `actplane setup`",
                mcp.display()
            );
        }
    } else {
        println!("⚠ project MCP config: .mcp.json missing");
    }
    if project_mcp_ok && let Some(global) = codex_global_mcp_actplane_config() {
        println!(
            "⚠ Codex global MCP also defines actplane ({}); keep either global or project config, not both",
            global.display()
        );
    }
}

fn codex_global_mcp_actplane_config() -> Option<PathBuf> {
    let path = std::env::var_os("HOME")
        .map(PathBuf::from)?
        .join(".codex/config.toml");
    let text = std::fs::read_to_string(&path).ok()?;
    text.lines()
        .any(|line| line.trim() == "[mcp_servers.actplane]")
        .then_some(path)
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn command_version(path: &Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!version.is_empty()).then_some(version)
}

fn active_lsms() -> Option<String> {
    std::fs::read_to_string("/sys/kernel/security/lsm").ok()
}

fn lsm_list_has_bpf(lsms: &str) -> bool {
    lsms.split(',').any(|name| name.trim() == "bpf")
}

fn bpf_lsm_configured_for_next_boot() -> Option<PathBuf> {
    [
        "/proc/cmdline",
        "/etc/default/grub.d/99-actplane-bpf-lsm.cfg",
        "/boot/grub/grub.cfg",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| {
        std::fs::read_to_string(path)
            .map(|text| text_has_bpf_lsm_arg(&text))
            .unwrap_or(false)
    })
}

fn text_has_bpf_lsm_arg(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .filter_map(|token| token.strip_prefix("lsm="))
        .any(lsm_list_has_bpf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsm_parser_requires_exact_bpf_token() {
        assert!(lsm_list_has_bpf("lockdown,capability,bpf"));
        assert!(text_has_bpf_lsm_arg(
            r#"GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} lsm=landlock,lockdown,yama,bpf""#
        ));
        assert!(!lsm_list_has_bpf("lockdown,capability,bpfish"));
        assert!(!text_has_bpf_lsm_arg(
            "BOOT_IMAGE=/vmlinuz lsm=landlock,lockdown,yama,bpfish"
        ));
    }
}
