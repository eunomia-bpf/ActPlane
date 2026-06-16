use std::collections::{BTreeMap, BTreeSet};

use crate::Result;

#[derive(Debug)]
pub(crate) struct PolicyTemplate {
    pub(crate) id: &'static str,
    pub(crate) title: &'static str,
    pub(crate) category: &'static str,
    pub(crate) effect: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) notes: &'static [&'static str],
    pub(crate) params: &'static [TemplateParam],
    pub(crate) dsl: &'static str,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct TemplateParam {
    pub(crate) name: &'static str,
    pub(crate) value_name: &'static str,
    pub(crate) default: &'static str,
    pub(crate) description: &'static str,
}

static PARAM_AGENT_EXEC: &[TemplateParam] = &[TemplateParam {
    name: "agent_exec",
    value_name: "EXEC_GLOB",
    default: "**",
    description: "exec glob that identifies the protected agent/process tree",
}];

static PARAM_NO_GIT_PUSH: &[TemplateParam] = &[
    TemplateParam {
        name: "agent_exec",
        value_name: "EXEC_GLOB",
        default: "**",
        description: "exec glob that identifies the protected agent/process tree",
    },
    TemplateParam {
        name: "git_exec",
        value_name: "EXEC_GLOB",
        default: "git",
        description: "exec glob for the git executable or approved wrapper",
    },
    TemplateParam {
        name: "push_arg",
        value_name: "ARGV_TOKEN",
        default: "push",
        description: "argv token that identifies a push command",
    },
];

static PARAM_NO_SECRET_EGRESS: &[TemplateParam] = &[
    TemplateParam {
        name: "secret_paths",
        value_name: "GLOB[,GLOB...]",
        default: "**/.env,**/.npmrc,**/.pypirc,**/secrets/**",
        description: "comma-separated file globs that seed the SECRET label",
    },
    TemplateParam {
        name: "redactor_exec",
        value_name: "EXEC_GLOB",
        default: "**/redact",
        description: "exec glob for the command allowed to declassify SECRET",
    },
];

static PARAM_TEST_BEFORE_COMMIT: &[TemplateParam] = &[
    TemplateParam {
        name: "agent_exec",
        value_name: "EXEC_GLOB",
        default: "**",
        description: "exec glob that identifies the protected agent/process tree",
    },
    TemplateParam {
        name: "test_exec",
        value_name: "EXEC_GLOB",
        default: "**/pytest",
        description: "exec glob for the successful test command",
    },
    TemplateParam {
        name: "changed_paths",
        value_name: "GLOB[,GLOB...]",
        default: "src/**,tests/**",
        description: "comma-separated file globs whose writes require a fresh test",
    },
];

static PARAM_DEPENDENCY_UPDATE_GATE: &[TemplateParam] = &[
    TemplateParam {
        name: "agent_exec",
        value_name: "EXEC_GLOB",
        default: "**",
        description: "exec glob that identifies the protected agent/process tree",
    },
    TemplateParam {
        name: "test_exec",
        value_name: "EXEC_GLOB",
        default: "**/pytest",
        description: "exec glob for the successful validation command",
    },
    TemplateParam {
        name: "dependency_paths",
        value_name: "GLOB[,GLOB...]",
        default: "Cargo.lock,package-lock.json,pnpm-lock.yaml,yarn.lock,go.sum,requirements*.txt,pyproject.toml",
        description: "comma-separated dependency manifest or lockfile globs",
    },
    TemplateParam {
        name: "git_exec",
        value_name: "EXEC_GLOB",
        default: "git",
        description: "exec glob for the git executable or approved wrapper",
    },
    TemplateParam {
        name: "commit_arg",
        value_name: "ARGV_TOKEN",
        default: "commit",
        description: "argv token that identifies a commit command",
    },
];

static PARAM_PROTECTED_BRANCH_PUSH: &[TemplateParam] = &[
    TemplateParam {
        name: "agent_exec",
        value_name: "EXEC_GLOB",
        default: "**",
        description: "exec glob that identifies the protected agent/process tree",
    },
    TemplateParam {
        name: "git_exec",
        value_name: "EXEC_GLOB",
        default: "git",
        description: "exec glob for the git executable or approved wrapper",
    },
    TemplateParam {
        name: "push_arg",
        value_name: "ARGV_TOKEN",
        default: "push",
        description: "argv token that identifies a push command",
    },
    TemplateParam {
        name: "protected_ref",
        value_name: "REF_NAME",
        default: "main",
        description: "protected branch or ref name used in generated guidance",
    },
    TemplateParam {
        name: "approval_exec",
        value_name: "EXEC_GLOB",
        default: "**/approve-push",
        description: "exec glob for the command that records explicit push approval",
    },
];

static PARAM_WORKSPACE_CONFINEMENT: &[TemplateParam] = &[
    TemplateParam {
        name: "agent_exec",
        value_name: "EXEC_GLOB",
        default: "**",
        description: "exec glob that identifies the protected agent/process tree",
    },
    TemplateParam {
        name: "writable_path",
        value_name: "FILE_GLOB",
        default: "/work/**",
        description: "file glob that remains writable",
    },
];

static PARAM_NO_NETWORK: &[TemplateParam] = &[
    TemplateParam {
        name: "agent_exec",
        value_name: "EXEC_GLOB",
        default: "**",
        description: "exec glob that identifies the protected agent/process tree",
    },
    TemplateParam {
        name: "loopback_endpoint",
        value_name: "IP_PREFIX",
        default: "127.",
        description: "numeric IPv4 prefix exempted from the no-network rule",
    },
];

static PARAM_PROD_DB: &[TemplateParam] = &[
    TemplateParam {
        name: "database_path",
        value_name: "FILE_GLOB",
        default: "**/prod.db",
        description: "file glob for the protected database or resource",
    },
    TemplateParam {
        name: "mediator_exec",
        value_name: "EXEC_GLOB",
        default: "**/migrate",
        description: "exec glob for the required mediation tool",
    },
];

const TEMPLATES: &[PolicyTemplate] = &[
    PolicyTemplate {
        id: "no-git-branch",
        title: "Prevent agent-created git branches and worktrees",
        category: "process",
        effect: "kill",
        summary: "Terminates git branch/worktree attempts from the protected process tree.",
        notes: &[
            "Uses kill rather than block because argv-sensitive exec predicates are observed after exec.",
            "Good default for repos where branch/worktree management should stay with the human/operator.",
            "With `actplane run` or `watch`, the protected root is also seeded with the COMMAND label. Standalone users can narrow `exec \"**\"` to their agent executable.",
        ],
        params: PARAM_AGENT_EXEC,
        dsl: r#"source COMMAND = exec "{{agent_exec}}"

rule no-git-branch:
  kill exec "git" "branch"   if COMMAND
  kill exec "git" "worktree" if COMMAND
  because "This workspace forbids creating git branches or worktrees. Use other git commands, or ask the user to manage branches."
"#,
    },
    PolicyTemplate {
        id: "no-git-push",
        title: "Prevent agent-created git pushes",
        category: "process",
        effect: "kill",
        summary: "Terminates git push attempts from the protected process tree.",
        notes: &[
            "Uses kill rather than block because argv-sensitive exec predicates are observed after exec.",
            "Good default for repos where network publication must stay with the human/operator.",
            "With `actplane run` or `watch`, the protected root is also seeded with the COMMAND label. Standalone users can narrow `exec \"**\"` to their agent executable.",
        ],
        params: PARAM_NO_GIT_PUSH,
        dsl: r#"source COMMAND = exec "{{agent_exec}}"

rule no-git-push:
  kill exec "{{git_exec}}" "{{push_arg}}" if COMMAND
  because "This workspace forbids agent-run git push. Ask the user or release operator to publish changes."
"#,
    },
    PolicyTemplate {
        id: "no-secret-egress",
        title: "Stop local secret-derived data from reaching the network",
        category: "ifc",
        effect: "block",
        summary: "Labels common secret files and denies network egress after secret-derived reads when BPF-LSM block support is active.",
        notes: &[
            "Endpoint matching is numeric IPv4-oriented in the kernel. Use `actplane compile --explain` to review host support.",
            "Edit the source paths and redactor command for the project before enforcing broadly.",
        ],
        params: PARAM_NO_SECRET_EGRESS,
        dsl: r#"{{secret_source_lines}}

rule no-secret-egress:
  block connect endpoint "*" if SECRET
  because "Data derived from local secrets must not leave the host. Redact or declassify first."

declassify SECRET by exec "{{redactor_exec}}"
"#,
    },
    PolicyTemplate {
        id: "test-before-commit",
        title: "Require a fresh test run before git commit",
        category: "causal",
        effect: "kill",
        summary: "Requires pytest to exit 0 after source/test edits before git commit.",
        notes: &[
            "Uses kill for the argv-sensitive git commit predicate.",
            "Replace pytest and path globs with the repo's real test command and source roots.",
            "With `actplane run` or `watch`, the protected root is also seeded with the AGENT label. Standalone users can narrow `exec \"**\"` to their agent executable.",
        ],
        params: PARAM_TEST_BEFORE_COMMIT,
        dsl: r#"source AGENT = exec "{{agent_exec}}"

rule test-before-commit:
  kill exec "git" "commit" if AGENT
    unless after exec "{{test_exec}}" exits 0 since {{changed_write_events}}
  because "Source or test files changed since the last successful test run. Run {{test_exec}} before committing."
"#,
    },
    PolicyTemplate {
        id: "dependency-update-gate",
        title: "Require validation before dependency-aware commits",
        category: "causal",
        effect: "kill",
        summary: "Terminates git commit until validation exits 0, with dependency manifest or lockfile writes making that validation stale.",
        notes: &[
            "Uses kill for the argv-sensitive git commit predicate.",
            "This is conservative: commits require a successful validation command, and dependency manifest or lockfile writes make that validation stale.",
            "ActPlane's current DSL cannot express branch/content-aware dependency commits, so this template avoids missing direct lockfile writes.",
            "Replace the dependency path list and validation command with the repo's real dependency-update workflow.",
            "With `actplane run` or `watch`, the protected root is also seeded with the AGENT label. Standalone users can narrow `exec \"**\"` to their agent executable.",
        ],
        params: PARAM_DEPENDENCY_UPDATE_GATE,
        dsl: r#"source AGENT = exec "{{agent_exec}}"

rule dependency-update-gate:
  kill exec "{{git_exec}}" "{{commit_arg}}" if AGENT
    unless after exec "{{test_exec}}" exits 0 since {{dependency_write_events}}
  because "A commit needs successful validation, and dependency manifests or lockfiles make validation stale. Run {{test_exec}} before committing."
"#,
    },
    PolicyTemplate {
        id: "protected-branch-push",
        title: "Require session approval before protected push",
        category: "vcs",
        effect: "kill",
        summary: "Terminates git push from the protected process tree unless a push approval command succeeded earlier in the session.",
        notes: &[
            "Uses kill rather than block because argv-sensitive exec predicates are observed after exec.",
            "Approval is latching for the session. Single-shot approvals require a repository-specific wrapper or future pre-tokenized argv invalidators.",
            "The current DSL matches one argv token, so this template gates push commands and names the protected ref in feedback rather than enforcing the ref directly.",
            "Set git_exec to a repository-specific push wrapper if branch-exact enforcement is required.",
            "With `actplane run` or `watch`, the protected root is also seeded with the AGENT label. Standalone users can narrow `exec \"**\"` to their agent executable.",
        ],
        params: PARAM_PROTECTED_BRANCH_PUSH,
        dsl: r#"source AGENT = exec "{{agent_exec}}"

rule protected-branch-push:
  kill exec "{{git_exec}}" "{{push_arg}}" if AGENT
    unless after exec "{{approval_exec}}" exits 0
  because "Pushes that may update protected ref {{protected_ref}} require a successful {{approval_exec}} approval in this session."
"#,
    },
    PolicyTemplate {
        id: "workspace-confinement",
        title: "Confine writes to an allowed workspace path",
        category: "sandbox",
        effect: "block",
        summary: "Denies writes and deletes outside /work when BPF-LSM block support is active.",
        notes: &[
            "Change /work/** to the repo or task-specific writable area before use.",
            "Run `actplane compile --explain` before enforcing. Without BPF-LSM, block rules are reported as unsupported.",
            "With `actplane run` or `watch`, the protected root is also seeded with the AGENT label. Standalone users can narrow `exec \"**\"` to their agent executable.",
        ],
        params: PARAM_WORKSPACE_CONFINEMENT,
        dsl: r#"source AGENT = exec "{{agent_exec}}"

rule workspace-confinement:
  block write file "/**"  if AGENT unless target "{{writable_path}}"
  block unlink file "/**" if AGENT unless target "{{writable_path}}"
  because "Modify only files matching {{writable_path}}, or ask the user to approve a different writable path."
"#,
    },
    PolicyTemplate {
        id: "readonly-review",
        title: "Make a review domain read-only",
        category: "sandbox",
        effect: "block",
        summary: "Denies file writes and deletes when BPF-LSM block support is active.",
        notes: &[
            "Useful for review-only subagents or untrusted tool invocations.",
            "Pair with runtime domains when multiple agents share one host workspace.",
            "Run `actplane compile --explain` before enforcing. Without BPF-LSM, block rules are reported as unsupported.",
            "With `actplane run` or `watch`, the protected root is also seeded with the AGENT label. Standalone users can narrow `exec \"**\"` to their agent executable.",
        ],
        params: PARAM_AGENT_EXEC,
        dsl: r#"source AGENT = exec "{{agent_exec}}"

rule readonly-review:
  block write file "/**"  if AGENT
  block unlink file "/**" if AGENT
  because "This review domain is read-only. Ask the user before modifying files."
"#,
    },
    PolicyTemplate {
        id: "no-network",
        title: "Disable external network egress",
        category: "network",
        effect: "block",
        summary: "Denies outbound connects except loopback numeric IPv4 destinations when BPF-LSM block support is active.",
        notes: &[
            "Loopback is allowed with target prefix 127.; remove the exception for stricter isolation.",
            "Hostname and IPv6 endpoint globs are not kernel-enforced today.",
            "Run `actplane compile --explain` before enforcing. Without BPF-LSM, block rules are reported as unsupported.",
            "With `actplane run` or `watch`, the protected root is also seeded with the AGENT label. Standalone users can narrow `exec \"**\"` to their agent executable.",
        ],
        params: PARAM_NO_NETWORK,
        dsl: r#"source AGENT = exec "{{agent_exec}}"

rule no-network:
  block connect endpoint "*" if AGENT unless target "{{loopback_endpoint}}"
  because "This domain cannot use external network egress."
"#,
    },
    PolicyTemplate {
        id: "prod-db-via-migrate",
        title: "Require a mediation tool for production database access",
        category: "mediation",
        effect: "block",
        summary: "Pre-op blocks prod.db opens unless the lineage includes the migration tool.",
        notes: &[
            "This is intended as a BPF-LSM block policy. Check host support before relying on pre-op denial.",
            "Replace prod.db and migrate with the project's real protected resource and access tool.",
        ],
        params: PARAM_PROD_DB,
        dsl: r#"rule prod-db-via-migrate:
  block open file "{{database_path}}" if true unless lineage-includes exec "{{mediator_exec}}"
  because "Access {{database_path}} only through {{mediator_exec}}."
"#,
    },
];

pub(crate) fn all() -> &'static [PolicyTemplate] {
    TEMPLATES
}

pub(crate) fn get(id: &str) -> Result<&'static PolicyTemplate> {
    TEMPLATES
        .iter()
        .find(|template| template.id == id)
        .ok_or_else(|| {
            format!(
                "unknown template `{}` (available: {})",
                id,
                TEMPLATES
                    .iter()
                    .map(|template| template.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into()
        })
}

pub(crate) fn render_dsl(template: &PolicyTemplate, overrides: &[String]) -> Result<String> {
    let values = template_values(template, overrides)?;
    let mut replacements = values.clone();
    if let Some(secret_paths) = values.get("secret_paths") {
        replacements.insert(
            "secret_source_lines".into(),
            split_list(secret_paths)?
                .into_iter()
                .map(|path| format!("source SECRET = file \"{path}\""))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    if let Some(changed_paths) = values.get("changed_paths") {
        replacements.insert(
            "changed_write_events".into(),
            split_list(changed_paths)?
                .into_iter()
                .map(|path| format!("write \"{path}\""))
                .collect::<Vec<_>>()
                .join(" or "),
        );
    }
    if let Some(dependency_paths) = values.get("dependency_paths") {
        replacements.insert(
            "dependency_write_events".into(),
            split_list(dependency_paths)?
                .into_iter()
                .map(|path| format!("write \"{path}\""))
                .collect::<Vec<_>>()
                .join(" or "),
        );
    }

    let mut out = template.dsl.to_string();
    for (key, value) in replacements {
        out = out.replace(&format!("{{{{{key}}}}}"), &value);
    }
    if out.contains("{{") || out.contains("}}") {
        return Err(format!(
            "template `{}` contains an unresolved parameter",
            template.id
        )
        .into());
    }
    Ok(out)
}

pub(crate) fn render_yaml(template: &PolicyTemplate, overrides: &[String]) -> Result<String> {
    let dsl = render_dsl(template, overrides)?;
    let values = template_values(template, overrides)?;
    let mut out = String::new();
    out.push_str("# ActPlane policy generated from template `");
    out.push_str(template.id);
    out.push_str("`.\n");
    out.push_str("# ");
    out.push_str(template.summary);
    out.push('\n');
    for note in template.notes {
        out.push_str("# Note: ");
        out.push_str(note);
        out.push('\n');
    }
    for param in template.params {
        if let Some(value) = values.get(param.name) {
            out.push_str("# Parameter ");
            out.push_str(param.name);
            out.push_str(": ");
            out.push_str(value);
            out.push('\n');
        }
    }
    out.push_str("version: 1\npolicy: |\n");
    for line in dsl.trim_end().lines() {
        if !line.is_empty() {
            out.push_str("  ");
            out.push_str(line);
        }
        out.push('\n');
    }
    Ok(out)
}

fn template_values(
    template: &PolicyTemplate,
    overrides: &[String],
) -> Result<BTreeMap<String, String>> {
    let mut values = template
        .params
        .iter()
        .map(|param| (param.name.to_string(), param.default.to_string()))
        .collect::<BTreeMap<_, _>>();
    let allowed = template
        .params
        .iter()
        .map(|param| param.name)
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for raw in overrides {
        let (key, value) = raw
            .split_once('=')
            .ok_or_else(|| format!("template parameter `{raw}` must use key=value"))?;
        if key.trim() != key || key.is_empty() {
            return Err(format!("invalid template parameter key `{key}`").into());
        }
        if !allowed.contains(key) {
            return Err(format!(
                "unknown parameter `{}` for template `{}` (available: {})",
                key,
                template.id,
                template
                    .params
                    .iter()
                    .map(|param| param.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into());
        }
        if !seen.insert(key.to_string()) {
            return Err(format!("parameter `{key}` was provided more than once").into());
        }
        validate_value(key, value)?;
        if key == "secret_paths" || key == "changed_paths" || key == "dependency_paths" {
            let _ = split_list(value)?;
        }
        values.insert(key.to_string(), value.to_string());
    }
    for (key, value) in &values {
        validate_value(key, value)?;
        if key == "secret_paths" || key == "changed_paths" || key == "dependency_paths" {
            let _ = split_list(value)?;
        }
    }
    Ok(values)
}

fn validate_value(key: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("parameter `{key}` must not be empty").into());
    }
    if value.contains('"')
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('{')
        || value.contains('}')
    {
        return Err(format!(
            "parameter `{key}` contains characters unsupported by the current DSL string syntax"
        )
        .into());
    }
    Ok(())
}

fn split_list(value: &str) -> Result<Vec<&str>> {
    let items = value.split(',').map(str::trim).collect::<Vec<_>>();
    if items.iter().any(|item| item.is_empty()) {
        return Err("comma-separated template parameters must not contain empty items".into());
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileConfig, LoadedPolicy, policy_source};
    use crate::dsl;
    use std::path::PathBuf;

    #[test]
    fn all_templates_compile_as_dsl_and_yaml() {
        assert!(all().len() >= 6);
        for template in all() {
            let rendered = render_dsl(template, &[])
                .unwrap_or_else(|e| panic!("template {} render DSL: {e}", template.id));
            dsl::compile_str(&rendered)
                .unwrap_or_else(|e| panic!("template {} DSL compile: {e}", template.id));

            let yaml = render_yaml(template, &[])
                .unwrap_or_else(|e| panic!("template {} render YAML: {e}", template.id));
            let config: FileConfig = serde_yaml::from_str(&yaml)
                .unwrap_or_else(|e| panic!("template {} YAML parse: {e}", template.id));
            let loaded = LoadedPolicy {
                config,
                root: PathBuf::new(),
                path: None,
            };
            let source = policy_source(&loaded, None)
                .unwrap_or_else(|e| panic!("template {} policy source: {e}", template.id));
            dsl::compile_str(&source)
                .unwrap_or_else(|e| panic!("template {} YAML compile: {e}", template.id));
        }
    }

    #[test]
    fn unknown_template_lists_available_ids() {
        let err = get("missing-template").unwrap_err().to_string();
        assert!(err.contains("unknown template `missing-template`"));
        assert!(err.contains("no-secret-egress"));
    }

    #[test]
    fn template_parameters_render_and_compile() {
        let rendered = render_dsl(
            get("test-before-commit").unwrap(),
            &[
                "agent_exec=codex".into(),
                "test_exec=**/pnpm".into(),
                "changed_paths=packages/**,src/**".into(),
            ],
        )
        .unwrap();
        assert!(rendered.contains("source AGENT = exec \"codex\""));
        assert!(rendered.contains("after exec \"**/pnpm\""));
        assert!(rendered.contains("write \"packages/**\" or write \"src/**\""));
        dsl::compile_str(&rendered).unwrap();
    }

    #[test]
    fn dependency_and_protected_push_templates_apply_parameters() {
        let rendered = render_dsl(
            get("dependency-update-gate").unwrap(),
            &[
                "agent_exec=codex".into(),
                "test_exec=**/cargo".into(),
                "dependency_paths=Cargo.lock,Cargo.toml".into(),
                "git_exec=git".into(),
                "commit_arg=commit".into(),
            ],
        )
        .unwrap();
        assert!(rendered.contains("source AGENT = exec \"codex\""));
        assert!(rendered.contains("kill exec \"git\" \"commit\" if AGENT"));
        assert!(rendered.contains("write \"Cargo.lock\" or write \"Cargo.toml\""));
        assert!(rendered.contains("after exec \"**/cargo\" exits 0"));
        dsl::compile_str(&rendered).unwrap();

        let rendered = render_dsl(
            get("protected-branch-push").unwrap(),
            &[
                "agent_exec=codex".into(),
                "git_exec=git".into(),
                "push_arg=push".into(),
                "protected_ref=main".into(),
                "approval_exec=**/approve-release".into(),
            ],
        )
        .unwrap();
        assert!(rendered.contains("kill exec \"git\" \"push\" if AGENT"));
        assert!(rendered.contains("after exec \"**/approve-release\" exits 0"));
        assert!(!rendered.contains("since exec \"git\" \"push\""));
        assert!(rendered.contains("protected ref main"));
        dsl::compile_str(&rendered).unwrap();
    }

    #[test]
    fn template_parameters_reject_unknown_duplicate_and_unsafe_values() {
        let template = get("no-network").unwrap();
        let err = render_dsl(template, &["missing=value".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown parameter `missing`"));
        let err = render_dsl(
            template,
            &["agent_exec=codex".into(), "agent_exec=claude".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("provided more than once"));
        let err = render_dsl(template, &["agent_exec=bad\"quote".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported by the current DSL string syntax"));
    }
}
