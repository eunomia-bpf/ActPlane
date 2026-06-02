use std::path::Path;

use crate::Result;

pub(crate) const ACTPLANE_HOOK_COMMAND: &str = "actplane feedback-hook";
pub(crate) const ACTPLANE_MCP_COMMAND: &str = "actplane";
pub(crate) const ACTPLANE_MCP_ARGS: &[&str] = &["mcp", "--auto-attach-parent"];

const CODEX_HOOKS_JSON: &str = r#"{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "actplane feedback-hook",
            "statusMessage": "Checking ActPlane feedback"
          }
        ]
      }
    ]
  }
}
"#;

const PROJECT_MCP_JSON: &str = r#"{
  "mcpServers": {
    "actplane": {
      "type": "stdio",
      "command": "actplane",
      "args": ["mcp", "--auto-attach-parent"]
    }
  }
}
"#;

const AGENTS_STUB: &str = r#"# AGENTS.md

This workspace is protected by ActPlane, an OS-level eBPF harness. When an
operation fails with `EPERM` / `Operation not permitted`, or a hook injects an
`[ActPlane]` message, treat it as authoritative kernel feedback. Read
`.actplane/last-violation.txt` if you need the full reason, then follow the
suggested path instead of retrying the same operation unchanged.
"#;

const STARTER_POLICY: &str = r#"# ActPlane project policy. Constraints are applied in the kernel (eBPF), below
# the tool layer, so they hold across any tool / subprocess / direct syscall.
# Validate any time with:  actplane check
# Apply around an agent:  sudo -E actplane run <your agent command>
# DSL reference: docs/rule-language.md
version: 1
default_domain: session

rules:
  no-git-branch:
    ifc: |
      source COMMAND = exec "**"
      rule no-git-branch:
        kill exec "git" "branch"   if COMMAND
        kill exec "git" "worktree" if COMMAND
        because "create branches/worktrees on the host, not via the agent"

  no-secret-exfil:
    ifc: |
      source SECRET = file "**/.env"
      source SECRET = file "**/secrets/**"
      rule no-secret-exfil:
        kill connect endpoint "*" if SECRET
        because "data derived from local secrets must not leave the host; redact first"
      declassify SECRET by exec "**/redact"

  test-before-commit:
    ifc: |
      source COMMAND = exec "**"
      rule test-before-commit:
        kill exec "git" "commit" if COMMAND unless after exec "**/pytest"
        because "run the tests before committing"

  readonly-review:
    ifc: |
      source COMMAND = exec "**"
      rule readonly-review:
        kill write file "/**" if COMMAND
        because "review domains are read-only"

domains:
  session:
    bind:
      - rule: no-git-branch
        mode: locked
      - rule: no-secret-exfil
        mode: locked
      - rule: test-before-commit
        mode: default

  review:
    parent: session
    disable:
      - test-before-commit
    bind:
      - rule: readonly-review
        mode: locked
"#;

pub(crate) fn init_policy(force: bool) -> Result<i32> {
    let path = std::env::current_dir()?.join("actplane.yaml");
    if path.exists() && !force {
        eprintln!(
            "actplane: keeping existing {} (use --force to overwrite).",
            path.display()
        );
    } else {
        std::fs::write(&path, STARTER_POLICY)?;
        eprintln!("actplane: wrote {}", path.display());
    }
    setup_project(force)?;
    eprintln!(
        "Next:\n  actplane check\n  actplane doctor\n  codex   # MCP auto-attach will try passwordless sudo"
    );
    Ok(0)
}

pub(crate) fn setup_project(force: bool) -> Result<i32> {
    let root = std::env::current_dir()?;
    setup_codex_hook(&root, force)?;
    setup_project_mcp(&root, force)?;
    setup_agents_doc(&root, force)?;
    eprintln!("actplane: project integration ready in {}", root.display());
    Ok(0)
}

fn setup_codex_hook(root: &Path, force: bool) -> Result<()> {
    let dir = root.join(".codex");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("hooks.json");
    if path.exists() && !force {
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if codex_hook_has_actplane_command(&existing) {
            eprintln!("actplane: Codex hook already wired: {}", path.display());
            return Ok(());
        }
        if existing.contains(ACTPLANE_HOOK_COMMAND) {
            eprintln!(
                "actplane: refreshing Codex hook to use PATH command `actplane`: {}",
                path.display()
            );
        } else {
            eprintln!(
                "actplane: keeping existing {} (run `actplane setup --force` to replace it)",
                path.display()
            );
            return Ok(());
        }
    }
    std::fs::write(&path, CODEX_HOOKS_JSON)?;
    eprintln!("actplane: wrote Codex hook {}", path.display());
    Ok(())
}

fn setup_project_mcp(root: &Path, force: bool) -> Result<()> {
    let path = root.join(".mcp.json");
    if !path.exists() {
        std::fs::write(&path, PROJECT_MCP_JSON)?;
        eprintln!("actplane: wrote MCP config {}", path.display());
        return Ok(());
    }

    let src = std::fs::read_to_string(&path)?;
    let mut doc: serde_json::Value = match serde_json::from_str(&src) {
        Ok(v) => v,
        Err(e) if force => {
            eprintln!("actplane: replacing invalid {} ({})", path.display(), e);
            std::fs::write(&path, PROJECT_MCP_JSON)?;
            return Ok(());
        }
        Err(e) => {
            eprintln!(
                "actplane: keeping invalid {} ({}, run `actplane setup --force` to replace it)",
                path.display(),
                e
            );
            return Ok(());
        }
    };
    let Some(obj) = doc.as_object_mut() else {
        if force {
            std::fs::write(&path, PROJECT_MCP_JSON)?;
        } else {
            eprintln!(
                "actplane: keeping non-object {} (run `actplane setup --force` to replace it)",
                path.display()
            );
        }
        return Ok(());
    };
    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if !servers.is_object() {
        if force {
            *servers = serde_json::json!({});
        } else {
            eprintln!(
                "actplane: keeping {} because `mcpServers` is not an object",
                path.display()
            );
            return Ok(());
        }
    }
    servers.as_object_mut().unwrap().insert(
        "actplane".to_string(),
        serde_json::json!({
            "type": "stdio",
            "command": "actplane",
            "args": ["mcp", "--auto-attach-parent"],
        }),
    );
    std::fs::write(&path, serde_json::to_string_pretty(&doc)? + "\n")?;
    eprintln!("actplane: wired MCP config {}", path.display());
    Ok(())
}

#[cfg(unix)]
fn setup_agents_doc(root: &Path, force: bool) -> Result<()> {
    use std::os::unix::fs::symlink;

    let agents = root.join("AGENTS.md");
    if agents.exists() || agents.is_symlink() {
        if !force {
            eprintln!("actplane: keeping {}", agents.display());
            return Ok(());
        }
        std::fs::remove_file(&agents)?;
    }
    let claude = root.join("CLAUDE.md");
    if claude.is_file() {
        symlink("CLAUDE.md", &agents)?;
        eprintln!("actplane: linked AGENTS.md -> CLAUDE.md");
    } else {
        std::fs::write(&agents, AGENTS_STUB)?;
        eprintln!("actplane: wrote {}", agents.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn setup_agents_doc(root: &Path, force: bool) -> Result<()> {
    let agents = root.join("AGENTS.md");
    if agents.exists() && !force {
        eprintln!("actplane: keeping {}", agents.display());
        return Ok(());
    }
    std::fs::write(&agents, AGENTS_STUB)?;
    eprintln!("actplane: wrote {}", agents.display());
    Ok(())
}

pub(crate) fn codex_hook_has_actplane_command(src: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(src)
        .map(|value| json_has_command(&value, ACTPLANE_HOOK_COMMAND))
        .unwrap_or(false)
}

fn json_has_command(value: &serde_json::Value, command: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.get("command").and_then(|v| v.as_str()) == Some(command)
                || map.values().any(|v| json_has_command(v, command))
        }
        serde_json::Value::Array(items) => items.iter().any(|v| json_has_command(v, command)),
        _ => false,
    }
}

pub(crate) fn project_mcp_auto_attach_ok(src: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(src) else {
        return false;
    };
    let Some(server) = value
        .get("mcpServers")
        .and_then(|v| v.get("actplane"))
        .and_then(|v| v.as_object())
    else {
        return false;
    };
    let command_ok = server.get("command").and_then(|v| v.as_str()) == Some(ACTPLANE_MCP_COMMAND);
    let args = server
        .get("args")
        .and_then(|v| v.as_array())
        .map(|items| items.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    command_ok && args.as_slice() == ACTPLANE_MCP_ARGS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileConfig, LoadedPolicy, policy_source};
    use crate::dsl;
    use std::path::PathBuf;

    #[test]
    fn codex_hook_detection_parses_nested_json() {
        let hook = r#"{
          "hooks": {
            "PostToolUse": [
              {
                "matcher": ".*",
                "hooks": [
                  { "type": "command", "command": "actplane feedback-hook" }
                ]
              }
            ]
          }
        }"#;
        assert!(codex_hook_has_actplane_command(hook));
        assert!(!codex_hook_has_actplane_command(
            r#"{"hooks":{"PostToolUse":[{"hooks":[{"command":"/tmp/actplane feedback-hook"}]}]}}"#
        ));
        assert!(!codex_hook_has_actplane_command("{not json"));
    }

    #[test]
    fn project_mcp_detection_requires_path_command_and_auto_attach_arg() {
        let good = r#"{
          "mcpServers": {
            "actplane": {
              "type": "stdio",
              "command": "actplane",
              "args": ["mcp", "--auto-attach-parent"]
            }
          }
        }"#;
        assert!(project_mcp_auto_attach_ok(good));
        assert!(!project_mcp_auto_attach_ok(
            r#"{"mcpServers":{"actplane":{"command":"/tmp/actplane","args":["mcp","--auto-attach-parent"]}}}"#
        ));
        assert!(!project_mcp_auto_attach_ok(
            r#"{"mcpServers":{"actplane":{"command":"actplane","args":["mcp"]}}}"#
        ));
        assert!(!project_mcp_auto_attach_ok(
            r#"{"mcpServers":{"actplane":{"command":"actplane","args":["--auto-attach-parent","mcp"]}}}"#
        ));
    }

    #[test]
    fn starter_policy_uses_domain_schema_and_compiles() {
        let config: FileConfig = serde_yaml::from_str(STARTER_POLICY).unwrap();
        assert!(config.policy.is_none());
        assert!(config.domains.contains_key("session"));
        assert!(config.domains.contains_key("review"));
        let loaded = LoadedPolicy {
            config,
            root: PathBuf::new(),
            path: None,
        };
        let session = policy_source(&loaded, Some("session")).unwrap();
        assert!(session.contains("no-git-branch"));
        assert!(session.contains("test-before-commit"));
        assert!(!session.contains("readonly-review"));
        dsl::compile_str(&session).unwrap();

        let review = policy_source(&loaded, Some("review")).unwrap();
        assert!(review.contains("no-git-branch"));
        assert!(!review.contains("test-before-commit"));
        assert!(review.contains("readonly-review"));
        dsl::compile_str(&review).unwrap();
    }
}
