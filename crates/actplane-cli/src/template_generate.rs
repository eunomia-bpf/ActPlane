use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{Result, templates};

const MAX_INSTRUCTION_BYTES: usize = 128 * 1024;

#[derive(Debug)]
pub(crate) struct GeneratedTemplate {
    pub(crate) id: &'static str,
    pub(crate) params: Vec<String>,
    pub(crate) reasons: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct GeneratedPolicy {
    pub(crate) root: PathBuf,
    pub(crate) instruction_files: Vec<PathBuf>,
    pub(crate) task: Option<String>,
    pub(crate) templates: Vec<GeneratedTemplate>,
    pub(crate) notes: Vec<String>,
}

pub(crate) fn generate(
    root: &Path,
    instruction_files: &[PathBuf],
    task: Option<&str>,
) -> Result<GeneratedPolicy> {
    let instruction_files = if instruction_files.is_empty() {
        discover_instruction_files(root)
    } else {
        instruction_files.to_vec()
    };
    let mut notes = Vec::new();
    let mut instruction_text = String::new();
    for path in &instruction_files {
        match std::fs::read_to_string(path) {
            Ok(mut text) => {
                if truncate_to_char_boundary(&mut text, MAX_INSTRUCTION_BYTES) {
                    notes.push(format!("truncated {} to 128 KiB", path.display()));
                }
                instruction_text.push_str(&text);
                instruction_text.push('\n');
            }
            Err(e) => {
                return Err(format!("reading instructions {}: {}", path.display(), e).into());
            }
        }
    }
    if let Some(task) = task {
        instruction_text.push_str(task);
        instruction_text.push('\n');
    }
    let lower = instruction_text.to_lowercase();
    let agent_exec = infer_agent_exec(&lower);
    let mut out = Vec::new();

    if mentions_any(
        &lower,
        &["git branch", "git worktree", "no-git-branch", "worktree"],
    ) {
        out.push(GeneratedTemplate {
            id: "no-git-branch",
            params: vec![format!("agent_exec={agent_exec}")],
            reasons: vec![
                "project instructions restrict agent-created git branches/worktrees".into(),
            ],
        });
    }

    if mentions_no_git_push(&lower) && !mentions_push_approval_exception(&lower) {
        out.push(GeneratedTemplate {
            id: "no-git-push",
            params: vec![
                format!("agent_exec={agent_exec}"),
                "git_exec=git".into(),
                "push_arg=push".into(),
            ],
            reasons: vec!["project instructions forbid agent-run git push".into()],
        });
    }

    if mentions_test_before_commit(&lower) || has_source_tree(root) {
        out.push(GeneratedTemplate {
            id: "test-before-commit",
            params: vec![
                format!("agent_exec={agent_exec}"),
                format!("test_exec={}", infer_test_exec(root, &lower)),
                format!("changed_paths={}", infer_changed_paths(root)),
            ],
            reasons: vec![
                "project appears to have source/test files or instructions about tests before commit"
                    .into(),
            ],
        });
    }

    if mentions_dependency_update_gate(&lower) {
        out.push(GeneratedTemplate {
            id: "dependency-update-gate",
            params: vec![
                format!("agent_exec={agent_exec}"),
                format!("test_exec={}", infer_test_exec(root, &lower)),
                format!("dependency_paths={}", infer_dependency_paths(root)),
                "git_exec=git".into(),
                "commit_arg=commit".into(),
            ],
            reasons: vec![
                "project instructions mention dependency or lockfile update validation".into(),
            ],
        });
    }

    if mentions_protected_push_approval(&lower) {
        out.push(GeneratedTemplate {
            id: "protected-branch-push",
            params: vec![
                format!("agent_exec={agent_exec}"),
                "git_exec=git".into(),
                "push_arg=push".into(),
                format!("protected_ref={}", infer_protected_ref(root, &lower)),
                "approval_exec=**/approve-push".into(),
            ],
            reasons: vec![
                "project instructions mention protected branches, refs, or git push approval"
                    .into(),
            ],
        });
    }

    if mentions_any(
        &lower,
        &[
            "secret",
            "credential",
            "token",
            "api key",
            ".env",
            ".npmrc",
            ".pypirc",
        ],
    ) || root.join(".env").exists()
        || root.join("secrets").exists()
    {
        out.push(GeneratedTemplate {
            id: "no-secret-egress",
            params: vec![
                format!("secret_paths={}", infer_secret_paths(root)),
                "redactor_exec=**/redact".into(),
            ],
            reasons: vec![
                "project contains secret-like files or instructions mention secrets".into(),
            ],
        });
    }

    if mentions_any(&lower, &["no network", "offline", "external network"]) {
        out.push(GeneratedTemplate {
            id: "no-network",
            params: vec![
                format!("agent_exec={agent_exec}"),
                "loopback_endpoint=127.".into(),
            ],
            reasons: vec!["project instructions mention network isolation".into()],
        });
    }

    if mentions_any(&lower, &["read-only", "readonly"])
        && mentions_any(&lower, &["review", "subagent", "sub-agent"])
    {
        out.push(GeneratedTemplate {
            id: "readonly-review",
            params: vec![format!("agent_exec={agent_exec}")],
            reasons: vec!["project instructions mention read-only review work".into()],
        });
    }

    if mentions_any(&lower, &["prod.db", "production database", "migrate"]) {
        out.push(GeneratedTemplate {
            id: "prod-db-via-migrate",
            params: vec![
                "database_path=**/prod.db".into(),
                "mediator_exec=**/migrate".into(),
            ],
            reasons: vec!["project instructions mention production database mediation".into()],
        });
    }

    if out.is_empty() {
        notes.push(
            "no explicit guardrail instructions matched; emitted conservative repository defaults"
                .into(),
        );
        out.push(GeneratedTemplate {
            id: "no-git-branch",
            params: vec![format!("agent_exec={agent_exec}")],
            reasons: vec!["conservative default for agent-managed repositories".into()],
        });
        out.push(GeneratedTemplate {
            id: "test-before-commit",
            params: vec![
                format!("agent_exec={agent_exec}"),
                format!("test_exec={}", infer_test_exec(root, &lower)),
                format!("changed_paths={}", infer_changed_paths(root)),
            ],
            reasons: vec!["conservative default for source repositories".into()],
        });
    }

    Ok(GeneratedPolicy {
        root: root.to_path_buf(),
        instruction_files,
        task: task.map(ToOwned::to_owned),
        templates: out,
        notes,
    })
}

pub(crate) fn render_yaml(generated: &GeneratedPolicy) -> Result<String> {
    let mut out = String::new();
    out.push_str("# ActPlane candidate policy generated by `actplane init --generate`.\n");
    out.push_str("# Review before enforcement. The generator is deterministic and heuristic.\n");
    out.push_str("# Project root: ");
    out.push_str(&generated.root.display().to_string());
    out.push('\n');
    if generated.instruction_files.is_empty() {
        out.push_str("# Instructions considered: none found\n");
    } else {
        out.push_str("# Instructions considered:\n");
        for path in &generated.instruction_files {
            out.push_str("# - ");
            out.push_str(&path.display().to_string());
            out.push('\n');
        }
    }
    if let Some(task) = &generated.task {
        append_comment_block(&mut out, "Task hint", task);
    }
    for note in &generated.notes {
        out.push_str("# Note: ");
        out.push_str(note);
        out.push('\n');
    }
    out.push_str("version: 1\npolicy: |\n");
    for selection in &generated.templates {
        let template = templates::get(selection.id)?;
        out.push_str("  # template: ");
        out.push_str(selection.id);
        out.push('\n');
        for reason in &selection.reasons {
            out.push_str("  # reason: ");
            out.push_str(reason);
            out.push('\n');
        }
        for param in &selection.params {
            out.push_str("  # set: ");
            out.push_str(param);
            out.push('\n');
        }
        let dsl = templates::render_dsl(template, &selection.params)?;
        for line in dsl.trim_end().lines() {
            if !line.is_empty() {
                out.push_str("  ");
                out.push_str(line);
            }
            out.push('\n');
        }
        out.push('\n');
    }
    Ok(out)
}

pub(crate) fn summary(generated: &GeneratedPolicy) -> Vec<String> {
    generated
        .templates
        .iter()
        .map(|selection| {
            format!(
                "{} ({})",
                selection.id,
                selection
                    .reasons
                    .first()
                    .map(String::as_str)
                    .unwrap_or("selected")
            )
        })
        .collect()
}

fn discover_instruction_files(root: &Path) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for rel in [
        "AGENTS.md",
        "CLAUDE.md",
        ".agents/AGENTS.md",
        ".agents/instructions.md",
        ".codex/AGENTS.md",
    ] {
        let candidate = root.join(rel);
        if !candidate.is_file() {
            continue;
        }
        let key = candidate
            .canonicalize()
            .unwrap_or_else(|_| candidate.clone());
        if seen.insert(key) {
            out.push(candidate);
        }
    }
    out
}

fn truncate_to_char_boundary(text: &mut String, max_bytes: usize) -> bool {
    if text.len() <= max_bytes {
        return false;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}

fn infer_agent_exec(lower: &str) -> &'static str {
    let mentions_codex = lower.contains("codex");
    let mentions_claude = lower.contains("claude");
    if mentions_codex && !mentions_claude {
        "codex"
    } else if mentions_claude && !mentions_codex {
        "claude"
    } else {
        "**"
    }
}

fn infer_test_exec(root: &Path, lower: &str) -> &'static str {
    if lower.contains("pytest") || root.join("pytest.ini").exists() {
        "**/pytest"
    } else if lower.contains("pnpm test") {
        "**/pnpm"
    } else if lower.contains("npm test") {
        "**/npm"
    } else if lower.contains("cargo test") {
        "**/cargo"
    } else if lower.contains("go test") {
        "**/go"
    } else {
        "**/pytest"
    }
}

fn infer_changed_paths(root: &Path) -> String {
    let mut paths = Vec::new();
    for rel in [
        "src/**",
        "tests/**",
        "crates/**/src/**",
        "crates/**/tests/**",
        "bpf/src/**",
        "bpf/tests/**",
        "cmd/**",
        "pkg/**",
    ] {
        let dir = rel.trim_end_matches("/**");
        if root.join(dir).is_dir() {
            paths.push(rel);
        }
    }
    if paths.is_empty() {
        "src/**,tests/**".into()
    } else {
        paths.join(",")
    }
}

fn infer_secret_paths(root: &Path) -> String {
    let mut paths = vec!["**/.env", "**/.npmrc", "**/.pypirc"];
    if root.join("secrets").exists() {
        paths.push("**/secrets/**");
    }
    paths.join(",")
}

fn infer_dependency_paths(root: &Path) -> String {
    let mut paths = BTreeSet::new();
    collect_dependency_paths(root, root, 0, &mut paths);
    if paths.is_empty() {
        "Cargo.lock,package-lock.json,pnpm-lock.yaml,yarn.lock,go.sum,requirements*.txt,pyproject.toml".into()
    } else {
        paths.into_iter().take(24).collect::<Vec<_>>().join(",")
    }
}

fn collect_dependency_paths(root: &Path, dir: &Path, depth: usize, out: &mut BTreeSet<String>) {
    if depth > 3 || out.len() >= 24 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if path.is_file() {
            if is_dependency_manifest_name(&name) {
                if let Ok(rel) = path.strip_prefix(root) {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    if !rel.contains(|c| matches!(c, ',' | '"' | '{' | '}' | '\n' | '\r')) {
                        out.insert(rel);
                    }
                }
            }
        } else if path.is_dir() && !skip_dependency_scan_dir(&name) {
            subdirs.push(path);
        }
    }
    subdirs.sort();
    for subdir in subdirs {
        if out.len() >= 24 {
            break;
        }
        collect_dependency_paths(root, &subdir, depth + 1, out);
    }
}

fn is_dependency_manifest_name(name: &str) -> bool {
    matches!(
        name,
        "Cargo.lock"
            | "Cargo.toml"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lockb"
            | "package.json"
            | "go.sum"
            | "go.mod"
            | "requirements.txt"
            | "requirements-dev.txt"
            | "pyproject.toml"
            | "poetry.lock"
            | "uv.lock"
    ) || (name.starts_with("requirements") && name.ends_with(".txt"))
}

fn skip_dependency_scan_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".venv" | "venv" | "__pycache__"
    )
}

fn infer_protected_ref(root: &Path, lower: &str) -> String {
    for needle in [
        ("refs/heads/main", "refs/heads/main"),
        ("refs/heads/master", "refs/heads/master"),
        ("push to main", "main"),
        ("push main", "main"),
        ("main branch", "main"),
        ("branch main", "main"),
        ("protected main", "main"),
        ("push to master", "master"),
        ("push master", "master"),
        ("master branch", "master"),
        ("branch master", "master"),
        ("protected master", "master"),
        ("release branch", "release"),
        ("release/", "release/*"),
        ("protected ref", "protected-ref"),
        ("protected branch", "protected-branch"),
    ] {
        if lower.contains(needle.0) {
            return needle.1.into();
        }
    }
    if let Ok(head) = std::fs::read_to_string(root.join(".git").join("HEAD")) {
        if let Some(name) = head.trim().strip_prefix("ref: refs/heads/") {
            if !name.is_empty() {
                return name.into();
            }
        }
    }
    "main".into()
}

fn has_source_tree(root: &Path) -> bool {
    [
        "src",
        "tests",
        "crates",
        "bpf/src",
        "bpf/tests",
        "cmd",
        "pkg",
    ]
    .iter()
    .any(|rel| root.join(rel).is_dir())
}

fn mentions_test_before_commit(lower: &str) -> bool {
    (mentions_any(lower, &["before commit", "before committing", "git commit"])
        && mentions_any(
            lower,
            &["test", "pytest", "cargo test", "pnpm test", "npm test"],
        ))
        || lower.contains("test-before-commit")
}

fn mentions_dependency_update_gate(lower: &str) -> bool {
    if lower.contains("dependency-update-gate") {
        return true;
    }
    let dependency_context = mentions_any(
        lower,
        &[
            "dependency update",
            "dependency updates",
            "dependency change",
            "dependency changes",
            "dependency validation",
            "third-party dependency",
            "lockfile",
            "lock file",
            "cargo.lock",
            "package-lock",
            "pnpm-lock",
            "yarn.lock",
            "go.sum",
            "requirements.txt",
            "pyproject.toml",
            "poetry.lock",
            "uv.lock",
            "npm install",
            "pnpm install",
            "cargo update",
            "go get",
        ],
    );
    let validation_context = mentions_any(
        lower,
        &[
            "before commit",
            "before committing",
            "commit",
            "validation",
            "validate",
            "verification",
            "verify",
            "test",
            "pytest",
            "cargo test",
            "pnpm test",
            "npm test",
            "go test",
        ],
    );
    dependency_context && validation_context
}

fn mentions_no_git_push(lower: &str) -> bool {
    mentions_any(
        lower,
        &[
            "do not push",
            "don't push",
            "do not git push",
            "don't git push",
            "do not run git push",
            "don't run git push",
            "do not run `git push`",
            "don't run `git push`",
            "no git push",
            "never push",
            "forbid git push",
            "forbids git push",
        ],
    )
}

fn mentions_push_approval_exception(lower: &str) -> bool {
    let push_context = mentions_any(
        lower,
        &[
            "git push",
            "`git push`",
            "push to main",
            "push to master",
            "push protected",
            "protected push",
        ],
    );
    push_context
        && mentions_any(
            lower,
            &[
                "without approval",
                "unless approved",
                "unless approval",
                "requires approval",
                "require approval",
                "approval before push",
                "approval before git push",
                "approve-push",
                "permission before push",
                "ask the user before git push",
                "ask user before git push",
            ],
        )
}

fn mentions_push_approval_context(lower: &str) -> bool {
    mentions_push_approval_exception(lower)
        || mentions_any(
            lower,
            &[
                "push approval",
                "approve-push",
                "approval for git push",
                "approved git push",
                "permission for git push",
            ],
        )
}

fn mentions_release_protected_push_context(lower: &str) -> bool {
    mentions_any(
        lower,
        &[
            "protected branch",
            "protected branches",
            "protected ref",
            "protected refs",
            "push to main",
            "push to master",
            "release branch",
        ],
    )
}

fn mentions_protected_push_approval(lower: &str) -> bool {
    if !mentions_push_approval_context(lower) {
        return false;
    }
    mentions_any(
        lower,
        &["git push", "`git push`", "push approval", "approve-push"],
    ) || mentions_release_protected_push_context(lower)
}

fn mentions_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn append_comment_block(out: &mut String, label: &str, text: &str) {
    let mut lines = text.lines();
    if let Some(first) = lines.next() {
        out.push_str("# ");
        out.push_str(label);
        out.push_str(": ");
        out.push_str(first);
        out.push('\n');
    } else {
        out.push_str("# ");
        out.push_str(label);
        out.push_str(": \n");
        return;
    }
    for line in lines {
        out.push_str("# ");
        out.push_str(label);
        out.push_str(": ");
        out.push_str(line);
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_selects_templates_from_instructions_and_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("AGENTS.md"),
            "Do not run git branch. Run pytest before committing. Keep secrets safe.",
        )
        .unwrap();
        std::fs::create_dir(tmp.path().join("src")).unwrap();
        let generated = generate(tmp.path(), &[], None).unwrap();
        let ids = generated
            .templates
            .iter()
            .map(|selection| selection.id)
            .collect::<Vec<_>>();
        assert!(ids.contains(&"no-git-branch"));
        assert!(ids.contains(&"test-before-commit"));
        assert!(ids.contains(&"no-secret-egress"));
        let yaml = render_yaml(&generated).unwrap();
        assert!(yaml.contains("rule no-git-branch:"));
        assert!(yaml.contains("rule test-before-commit:"));
        assert!(yaml.contains("source SECRET = file"));
    }

    #[test]
    fn generator_selects_dependency_and_protected_push_templates() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("AGENTS.md"),
            "Dependency updates must run cargo test before committing. Do not git push to main without approval.",
        )
        .unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        std::fs::write(tmp.path().join("Cargo.lock"), "").unwrap();

        let generated = generate(tmp.path(), &[], None).unwrap();
        let dependency_gate = generated
            .templates
            .iter()
            .find(|selection| selection.id == "dependency-update-gate")
            .expect("dependency-update-gate selection");
        assert!(
            dependency_gate
                .params
                .iter()
                .any(|param| param == "test_exec=**/cargo")
        );
        assert!(
            dependency_gate
                .params
                .iter()
                .any(|param| param == "dependency_paths=Cargo.lock,Cargo.toml")
        );

        let protected_push = generated
            .templates
            .iter()
            .find(|selection| selection.id == "protected-branch-push")
            .expect("protected-branch-push selection");
        assert!(
            protected_push
                .params
                .iter()
                .any(|param| param == "protected_ref=main")
        );
        assert!(
            !generated
                .templates
                .iter()
                .any(|selection| selection.id == "no-git-push")
        );

        let yaml = render_yaml(&generated).unwrap();
        assert!(yaml.contains("rule dependency-update-gate:"));
        assert!(yaml.contains("write \"Cargo.lock\" or write \"Cargo.toml\""));
        assert!(yaml.contains("rule protected-branch-push:"));
        assert!(yaml.contains("protected ref main"));
    }

    #[test]
    fn generator_maps_absolute_push_ban_to_no_git_push() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("AGENTS.md"),
            "Do not run `git push` yourself. Ask the user before editing generated files.",
        )
        .unwrap();

        let generated = generate(tmp.path(), &[], None).unwrap();

        assert!(
            generated
                .templates
                .iter()
                .any(|selection| selection.id == "no-git-push")
        );
        assert!(
            !generated
                .templates
                .iter()
                .any(|selection| selection.id == "protected-branch-push")
        );
        let yaml = render_yaml(&generated).unwrap();
        assert!(yaml.contains("rule no-git-push:"));
        assert!(!yaml.contains("rule protected-branch-push:"));
    }

    #[test]
    fn generator_keeps_push_approval_separate_from_absolute_push_ban() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("AGENTS.md"),
            "Do not git push to main without approval.",
        )
        .unwrap();

        let generated = generate(tmp.path(), &[], None).unwrap();

        assert!(
            generated
                .templates
                .iter()
                .any(|selection| selection.id == "protected-branch-push")
        );
        assert!(
            !generated
                .templates
                .iter()
                .any(|selection| selection.id == "no-git-push")
        );
    }

    #[test]
    fn generator_finds_nested_dependency_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("AGENTS.md"),
            "Dependency updates require npm test before committing.",
        )
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("packages/web")).unwrap();
        std::fs::write(tmp.path().join("packages/web/package.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("packages/web/pnpm-lock.yaml"), "").unwrap();

        let generated = generate(tmp.path(), &[], None).unwrap();
        let dependency_gate = generated
            .templates
            .iter()
            .find(|selection| selection.id == "dependency-update-gate")
            .expect("dependency-update-gate selection");
        let dependency_paths = dependency_gate
            .params
            .iter()
            .find_map(|param| param.strip_prefix("dependency_paths="))
            .expect("dependency_paths param");
        assert!(dependency_paths.contains("packages/web/package.json"));
        assert!(dependency_paths.contains("packages/web/pnpm-lock.yaml"));
    }

    #[test]
    fn generator_uses_task_hint_without_instruction_files() {
        let tmp = tempfile::tempdir().unwrap();
        let generated = generate(tmp.path(), &[], Some("offline readonly review")).unwrap();
        let ids = generated
            .templates
            .iter()
            .map(|selection| selection.id)
            .collect::<Vec<_>>();
        assert!(ids.contains(&"no-network"));
        assert!(ids.contains(&"readonly-review"));
    }

    #[test]
    fn generator_task_comment_handles_multiline_text() {
        let tmp = tempfile::tempdir().unwrap();
        let generated = generate(tmp.path(), &[], Some("offline\nreadonly review")).unwrap();
        let yaml = render_yaml(&generated).unwrap();
        assert!(yaml.contains("# Task hint: offline\n# Task hint: readonly review"));
        let config: crate::config::FileConfig = serde_yaml::from_str(&yaml).unwrap();
        let loaded = crate::config::LoadedPolicy {
            config,
            root: PathBuf::new(),
            path: None,
        };
        let source = crate::config::policy_source(&loaded, None).unwrap();
        crate::dsl::compile_str(&source).unwrap();
    }

    #[test]
    fn generator_does_not_infer_broad_package_manager_as_test_without_test_phrase() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let generated = generate(tmp.path(), &[], None).unwrap();
        assert!(
            !generated
                .templates
                .iter()
                .any(|selection| selection.id == "dependency-update-gate")
        );
        let test_before_commit = generated
            .templates
            .iter()
            .find(|selection| selection.id == "test-before-commit")
            .unwrap();
        assert!(
            test_before_commit
                .params
                .iter()
                .any(|param| param == "test_exec=**/pytest")
        );
        let generated =
            generate(tmp.path(), &[], Some("this repo uses a package manager")).unwrap();
        assert!(
            !generated
                .templates
                .iter()
                .any(|selection| selection.id == "dependency-update-gate")
        );
        let generated = generate(
            tmp.path(),
            &[],
            Some("Use pnpm as the package manager. Run tests before commit."),
        )
        .unwrap();
        assert!(
            !generated
                .templates
                .iter()
                .any(|selection| selection.id == "dependency-update-gate")
        );
        let generated =
            generate(tmp.path(), &[], Some("run cargo test before committing")).unwrap();
        let test_before_commit = generated
            .templates
            .iter()
            .find(|selection| selection.id == "test-before-commit")
            .unwrap();
        assert!(
            test_before_commit
                .params
                .iter()
                .any(|param| param == "test_exec=**/cargo")
        );
    }

    #[test]
    fn generator_truncates_large_unicode_instruction_on_char_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = "Do not run git branch.\n";
        let mut text = String::from(prefix);
        text.push_str(&"a".repeat(MAX_INSTRUCTION_BYTES - prefix.len() - 1));
        text.push('é');
        std::fs::write(tmp.path().join("AGENTS.md"), text).unwrap();

        let generated = generate(tmp.path(), &[], None).unwrap();

        assert!(
            generated
                .notes
                .iter()
                .any(|note| note.contains("truncated"))
        );
        assert!(
            generated
                .templates
                .iter()
                .any(|selection| selection.id == "no-git-branch")
        );
    }
    #[test]
    fn append_comment_block_renders_one_line_per_source_line() {
        let mut out = String::new();
        append_comment_block(&mut out, "task", "first\nsecond");
        assert_eq!(out, "# task: first\n# task: second\n");

        let mut out2 = String::new();
        append_comment_block(&mut out2, "task", "a\nb\n");
        assert_eq!(out2, "# task: a\n# task: b\n");

        let mut out3 = String::new();
        append_comment_block(&mut out3, "task", "");
        assert_eq!(out3, "# task: \n");
    }

    #[test]
    fn dependency_scan_finds_manifests_and_skips_vendor_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();
        std::fs::write(root.join("package-lock.json"), "{}").unwrap();
        std::fs::create_dir(root.join("crates")).unwrap();
        std::fs::create_dir(root.join("crates/app")).unwrap();
        std::fs::write(root.join("crates/app/go.mod"), "module app").unwrap();

        std::fs::create_dir(root.join("node_modules")).unwrap();
        std::fs::write(root.join("node_modules/package.json"), "{}").unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::write(root.join("target/Cargo.toml"), "[package]").unwrap();

        let found = infer_dependency_paths(root);
        let items = found.split(',').collect::<Vec<_>>();
        assert!(items.contains(&"Cargo.toml"), "{found}");
        assert!(items.contains(&"package-lock.json"), "{found}");
        assert!(items.contains(&"crates/app/go.mod"), "{found}");
        assert!(!items.iter().any(|p| p.contains("node_modules")), "{found}");
        assert!(!items.iter().any(|p| p.starts_with("target/")), "{found}");
    }

    #[test]
    fn dependency_scan_falls_back_to_default_globs_when_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let found = infer_dependency_paths(tmp.path());
        assert!(found.starts_with("Cargo.lock,package-lock.json"), "{found}");

        assert!(is_dependency_manifest_name("Cargo.lock"));
        assert!(is_dependency_manifest_name("pyproject.toml"));
        assert!(!is_dependency_manifest_name("README.md"));
        assert!(skip_dependency_scan_dir(".git"));
        assert!(skip_dependency_scan_dir("node_modules"));
        assert!(!skip_dependency_scan_dir("src"));
    }

    #[test]
    fn infer_agent_exec_only_names_an_agent_when_one_is_mentioned() {
        assert_eq!(infer_agent_exec("run codex before editing"), "codex");
        assert_eq!(infer_agent_exec("use claude code"), "claude");
        assert_eq!(infer_agent_exec("codex and claude both"), "**");
        assert_eq!(infer_agent_exec("no agent named"), "**");
    }

    #[test]
    fn infer_test_exec_prefers_explicit_phrase_then_marker_file() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(infer_test_exec(tmp.path(), "run pytest first"), "**/pytest");
        assert_eq!(infer_test_exec(tmp.path(), "then pnpm test"), "**/pnpm");
        assert_eq!(infer_test_exec(tmp.path(), "use npm test"), "**/npm");
        assert_eq!(infer_test_exec(tmp.path(), "run cargo test"), "**/cargo");
        assert_eq!(infer_test_exec(tmp.path(), "go test ./..."), "**/go");
        assert_eq!(infer_test_exec(tmp.path(), "run the suite"), "**/pytest");
        std::fs::write(tmp.path().join("pytest.ini"), "").unwrap();
        assert_eq!(
            infer_test_exec(tmp.path(), "cargo test is also fine"),
            "**/pytest"
        );
    }

    #[test]
    fn infer_changed_paths_uses_present_source_roots_or_a_default() {
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(infer_changed_paths(empty.path()), "src/**,tests/**");

        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::create_dir_all(tmp.path().join("tests")).unwrap();
        std::fs::create_dir_all(tmp.path().join("cmd")).unwrap();
        let paths = infer_changed_paths(tmp.path());
        assert!(paths.contains("src/**"));
        assert!(paths.contains("tests/**"));
        assert!(paths.contains("cmd/**"));
        assert!(!paths.contains("pkg/**"));
    }

    #[test]
    fn infer_secret_paths_includes_secrets_dir_only_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let base = infer_secret_paths(tmp.path());
        assert_eq!(base, "**/.env,**/.npmrc,**/.pypirc");
        std::fs::create_dir(tmp.path().join("secrets")).unwrap();
        assert!(infer_secret_paths(tmp.path()).contains("**/secrets/**"));
    }

    #[test]
    fn mentions_push_approval_exception_needs_push_and_approval() {
        assert!(mentions_push_approval_exception(
            "do not git push without approval"
        ));
        assert!(mentions_push_approval_exception(
            "push to main requires approval"
        ));
        assert!(!mentions_push_approval_exception("git push the branch"));
        assert!(!mentions_push_approval_exception(
            "needs approval for the change"
        ));
    }

    #[test]
    fn mentions_push_approval_context_accepts_short_forms() {
        assert!(mentions_push_approval_context("push approval needed"));
        assert!(mentions_push_approval_context("approve-push required"));
        assert!(mentions_push_approval_context(
            "do not git push without approval"
        ));
        assert!(!mentions_push_approval_context("push the branch"));
    }

    #[test]
    fn mentions_release_protected_push_context_matches_protected_wording() {
        assert!(mentions_release_protected_push_context(
            "a protected branch"
        ));
        assert!(mentions_release_protected_push_context("push to main"));
        assert!(mentions_release_protected_push_context(
            "release branch rules"
        ));
        assert!(!mentions_release_protected_push_context(
            "push to a feature branch"
        ));
    }

    #[test]
    fn mentions_protected_push_approval_combines_context_and_target() {
        assert!(mentions_protected_push_approval(
            "git push to main requires approval"
        ));
        assert!(mentions_protected_push_approval(
            "push approval for the release branch"
        ));
        // Approval context from "protected push" only, which is absent from the
        // secondary target list and is not a protected/release scope phrase.
        assert!(!mentions_protected_push_approval(
            "protected push needs approval"
        ));
        assert!(!mentions_protected_push_approval("git push the branch"));
    }

    #[test]
    fn dependency_manifest_names_include_known_files_and_requirements_globs() {
        assert!(is_dependency_manifest_name("Cargo.toml"));
        assert!(is_dependency_manifest_name("go.mod"));
        assert!(is_dependency_manifest_name("requirements.txt"));
        assert!(is_dependency_manifest_name("requirements-dev.txt"));
        assert!(!is_dependency_manifest_name("Cargo.lock.md"));
        assert!(!is_dependency_manifest_name("requirements.txt.bak"));
        assert!(!is_dependency_manifest_name("README.md"));
    }

    #[test]
    fn skip_dependency_scan_dir_skips_only_vendored_dirs() {
        for dir in [
            ".git",
            "target",
            "node_modules",
            ".venv",
            "venv",
            "__pycache__",
        ] {
            assert!(skip_dependency_scan_dir(dir), "{dir} should be skipped");
        }
        assert!(!skip_dependency_scan_dir("src"));
        assert!(!skip_dependency_scan_dir("crates"));
    }

    #[test]
    fn collect_dependency_paths_walks_nested_manifests_and_skips_vendored() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        std::fs::create_dir_all(tmp.path().join("crates/inner")).unwrap();
        std::fs::write(tmp.path().join("crates/inner/Cargo.lock"), "").unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules/pkg")).unwrap();
        std::fs::write(tmp.path().join("node_modules/pkg/package.json"), "").unwrap();

        let mut out = BTreeSet::new();
        collect_dependency_paths(tmp.path(), tmp.path(), 0, &mut out);
        assert!(out.contains("Cargo.toml"));
        assert!(out.contains("crates/inner/Cargo.lock"));
        assert!(!out.iter().any(|p| p.contains("node_modules")));
    }

    #[test]
    fn infer_protected_ref_prefers_instructions_then_head_then_main() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            infer_protected_ref(tmp.path(), "never push to main"),
            "main"
        );
        assert_eq!(
            infer_protected_ref(tmp.path(), "protect the release branch"),
            "release"
        );
        assert_eq!(infer_protected_ref(tmp.path(), "no ref named"), "main");

        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join(".git/HEAD"), "ref: refs/heads/develop\n").unwrap();
        assert_eq!(infer_protected_ref(tmp.path(), "no ref named"), "develop");
    }

    #[test]
    fn has_source_tree_detects_any_known_source_root() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!has_source_tree(tmp.path()));
        std::fs::create_dir(tmp.path().join("crates")).unwrap();
        assert!(has_source_tree(tmp.path()));
    }

    #[test]
    fn discover_instruction_files_returns_only_existing_candidates() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(discover_instruction_files(tmp.path()).is_empty());
        std::fs::write(tmp.path().join("CLAUDE.md"), "x").unwrap();
        std::fs::create_dir_all(tmp.path().join(".agents")).unwrap();
        std::fs::write(tmp.path().join(".agents/AGENTS.md"), "x").unwrap();
        let found = discover_instruction_files(tmp.path());
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|p| p.ends_with("CLAUDE.md")));
        assert!(found.iter().any(|p| p.ends_with("AGENTS.md")));
    }

    #[test]
    fn truncate_to_char_boundary_never_splits_a_codepoint() {
        let mut ascii = "abcdef".to_string();
        assert!(truncate_to_char_boundary(&mut ascii, 3));
        assert_eq!(ascii, "abc");

        let mut short = "abc".to_string();
        assert!(!truncate_to_char_boundary(&mut short, 3));
        assert_eq!(short, "abc");

        // "é" is two bytes, so a byte limit landing inside it backs up one byte.
        let mut unicode = "aé".to_string();
        assert!(truncate_to_char_boundary(&mut unicode, 2));
        assert_eq!(unicode, "a");
        assert!(unicode.len() <= 2);
    }

    #[test]
    fn mentions_helpers_match_any_listed_phrase() {
        assert!(!mentions_any("run the tests", &["pytest", "cargo test"]));
        assert!(mentions_any(
            "run cargo test now",
            &["pytest", "cargo test"]
        ));
    }

    #[test]
    fn mentions_no_git_push_matches_ban_phrasings() {
        assert!(mentions_no_git_push("do not push to main"));
        assert!(mentions_no_git_push("never push directly"));
        assert!(mentions_no_git_push("no git push allowed"));
        assert!(!mentions_no_git_push("push the branch when ready"));
    }

    #[test]
    fn mentions_test_before_commit_requires_both_phrases() {
        assert!(mentions_test_before_commit("run pytest before committing"));
        assert!(mentions_test_before_commit("test-before-commit applies"));
        assert!(!mentions_test_before_commit("run pytest"));
        assert!(!mentions_test_before_commit("commit the change"));
    }

    #[test]
    fn mentions_dependency_update_gate_needs_dependency_and_validation() {
        assert!(mentions_dependency_update_gate("dependency-update-gate"));
        assert!(mentions_dependency_update_gate(
            "a lockfile change must be validated with cargo test"
        ));
        assert!(!mentions_dependency_update_gate(
            "a lockfile change happens"
        ));
        assert!(!mentions_dependency_update_gate("run cargo test"));
    }

    #[test]
    fn append_comment_block_prefixes_every_line_under_the_label() {
        let mut out = String::new();
        append_comment_block(&mut out, "why", "first\nsecond");
        assert_eq!(out, "# why: first\n# why: second\n");

        let mut empty = String::new();
        append_comment_block(&mut empty, "why", "");
        assert_eq!(empty, "# why: \n");
    }

    #[test]
    fn summary_reports_id_and_first_reason() {
        let generated = GeneratedPolicy {
            root: PathBuf::from("."),
            instruction_files: Vec::new(),
            task: None,
            templates: vec![
                GeneratedTemplate {
                    id: "no-git-branch",
                    params: Vec::new(),
                    reasons: vec!["workflow mentions branches".into(), "other".into()],
                },
                GeneratedTemplate {
                    id: "dependency-gate",
                    params: Vec::new(),
                    reasons: Vec::new(),
                },
            ],
            notes: Vec::new(),
        };
        assert_eq!(
            summary(&generated),
            vec![
                "no-git-branch (workflow mentions branches)".to_string(),
                "dependency-gate (selected)".to_string(),
            ]
        );
        let empty = GeneratedPolicy {
            templates: Vec::new(),
            ..generated
        };
        assert!(summary(&empty).is_empty());
    }
    #[test]
    fn mentions_dependency_update_gate_requires_both_contexts() {
        // `mentions_dependency_update_gate` reports whether the lowercased
        // task text carries a dependency-update gate: either the literal
        // tag, or both a dependency context AND a validation context. No
        // base or branch test pins this predicate directly.
        // The explicit tag short-circuits the two-context requirement.
        assert!(mentions_dependency_update_gate(
            "use the dependency-update-gate policy"
        ));

        // Both a dependency context and a validation context present.
        assert!(mentions_dependency_update_gate(
            "validate the lockfile before commit"
        ));
        assert!(mentions_dependency_update_gate(
            "run cargo test after the dependency update"
        ));

        // Dependency context alone, with no validation context, is not a
        // gate.
        assert!(!mentions_dependency_update_gate("update the dependencies"));
        // Validation context alone, with no dependency context, is not a
        // gate.
        assert!(!mentions_dependency_update_gate(
            "run the test suite before commit"
        ));
        assert!(!mentions_dependency_update_gate(""));
    }
    #[test]
    fn dependency_manifest_name_recognizes_lockfiles_and_requirements_txt() {
        // `is_dependency_manifest_name` matches an explicit lockfile whitelist
        // plus any `requirements*.txt` file. No base or branch test pins this
        // classifier directly; it is only reached through the dependency-path
        // inference.
        let manifest = [
            "Cargo.lock",
            "Cargo.toml",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lockb",
            "package.json",
            "go.sum",
            "go.mod",
            "requirements.txt",
            "requirements-dev.txt",
            "pyproject.toml",
            "poetry.lock",
            "uv.lock",
        ];
        for name in manifest {
            assert!(
                is_dependency_manifest_name(name),
                "{name} should be a manifest"
            );
        }

        // The `requirements*.txt` suffix rule covers arbitrary variants.
        assert!(is_dependency_manifest_name("requirements-prod.txt"));
        assert!(is_dependency_manifest_name("requirements-test.txt"));

        // Not a manifest: wrong extension, missing suffix, or not a lockfile.
        assert!(!is_dependency_manifest_name("Makefile"));
        assert!(!is_dependency_manifest_name("cargo.toml")); // case-sensitive
        assert!(!is_dependency_manifest_name("requirements")); // no .txt
        assert!(!is_dependency_manifest_name("requirements.md"));
        assert!(!is_dependency_manifest_name("lock.json"));
    }
    #[test]
    fn infer_agent_exec_maps_task_text_to_agent_identity() {
        // `infer_agent_exec` reads the lowercased task text and maps a
        // codex-only mention to "codex", a claude-only mention to "claude",
        // and anything else (no mention, or both mentioned) to the wildcard
        // "**". No base or branch test pins this classifier directly.
        assert_eq!(infer_agent_exec("run the codex plan"), "codex");
        assert_eq!(infer_agent_exec("use claude to review"), "claude");

        // No agent mention falls back to the wildcard.
        assert_eq!(infer_agent_exec("apply the patch"), "**");

        // Ambiguous (both named) falls back to the wildcard too.
        assert_eq!(infer_agent_exec("codex and claude together"), "**");
    }
    #[test]
    fn mentions_any_reports_first_matched_needle() {
        // `mentions_any` reports whether any needle is a substring of the
        // haystack; it is the primitive every `mentions_*` template predicate
        // builds on. No base or branch test pins this helper directly.
        assert!(mentions_any(
            "the release branch must stay clean",
            &["main", "release branch", "push"]
        ));
        // An empty needle list never matches.
        assert!(!mentions_any("any text", &[]));
        // An empty haystack never matches a non-empty needle list.
        assert!(!mentions_any("", &["release"]));
        // A partial substring match counts as a hit.
        assert!(mentions_any("push to main", &["main"]));
    }
    #[test]
    fn mentions_no_git_push_flags_push_ban_phrasings() {
        // `mentions_no_git_push` reports whether the lowercased task text
        // carries an absolute no-push instruction, matching a fixed set of
        // phrasings. No base or branch test pins this predicate directly.
        assert!(mentions_no_git_push("do not push to origin"));
        assert!(mentions_no_git_push("never push these commits"));
        assert!(mentions_no_git_push("forbid git push"));
        // The backtick-wrapped phrasing is a distinct needle.
        assert!(mentions_no_git_push("do not run `git push`"));

        // A plain instruction that is not a push ban is not flagged.
        assert!(!mentions_no_git_push(
            "run the test suite before committing"
        ));
        assert!(!mentions_no_git_push(""));
    }
    #[test]
    fn mentions_protected_push_approval_requires_context_and_push_or_protected() {
        // `mentions_protected_push_approval` reports whether the lowercased
        // task text asks for a protected-push approval: a push-approval
        // context, AND either an explicit git-push / push-approval needle or
        // a protected-branch / release-branch context. No base or branch
        // test pins this predicate directly.
        assert!(mentions_protected_push_approval(
            "git push requires approval"
        ));
        assert!(mentions_protected_push_approval("approval for git push"));
        // Push-approval context plus a protected-branch context.
        assert!(mentions_protected_push_approval(
            "push to master with push approval"
        ));

        // A git-push context without any push-approval context is not a
        // match.
        assert!(!mentions_protected_push_approval("git push the branch"));
        assert!(!mentions_protected_push_approval(
            "run the test suite before commit"
        ));
        assert!(!mentions_protected_push_approval(""));
    }
    #[test]
    fn mentions_push_approval_context_matches_exception_or_approval_needles() {
        // `mentions_push_approval_context` reports whether the lowercased
        // task text carries a push-approval context: either a push-approval
        // exception (push context AND approval context) or a direct
        // approval needle. No base or branch test pins this predicate
        // directly.
        // The exception path (push + approval context).
        assert!(mentions_push_approval_context("git push requires approval"));
        // The direct-needle path.
        assert!(mentions_push_approval_context("require push approval"));
        assert!(mentions_push_approval_context("approval for git push"));

        // A bare git-push with no approval context is not a match.
        assert!(!mentions_push_approval_context("git push the branch"));
        assert!(!mentions_push_approval_context(
            "run the test suite before commit"
        ));
        assert!(!mentions_push_approval_context(""));
    }
    #[test]
    fn mentions_push_approval_exception_requires_push_and_approval_contexts() {
        // `mentions_push_approval_exception` reports whether the lowercased
        // task text asks for a push-approval exception: a push context AND
        // an approval context. No base or branch test pins this predicate
        // directly.
        // A push context alone, with no approval context, is not a match.
        assert!(!mentions_push_approval_exception("git push the branch"));
        // An approval context alone, with no push context, is not a match.
        assert!(!mentions_push_approval_exception(
            "approval is required for the change"
        ));

        // Both a push context and an approval context present.
        assert!(mentions_push_approval_exception(
            "git push requires approval"
        ));
        assert!(mentions_push_approval_exception("approval before git push"));
        assert!(!mentions_push_approval_exception(""));
    }
    #[test]
    fn mentions_release_protected_push_context_flags_protected_push_phrasings() {
        // `mentions_release_protected_push_context` reports whether the
        // lowercased task text mentions a protected-branch / release-branch
        // push context, matching a fixed set of phrasings. No base or branch
        // test pins this predicate directly.
        assert!(mentions_release_protected_push_context(
            "push to main only after review"
        ));
        assert!(mentions_release_protected_push_context(
            "protect the release branch"
        ));
        assert!(mentions_release_protected_push_context(
            "the protected ref must stay clean"
        ));

        // Text without a protected-push context is not flagged.
        assert!(!mentions_release_protected_push_context(
            "run the test suite before committing"
        ));
        assert!(!mentions_release_protected_push_context(""));
    }
    #[test]
    fn skip_dependency_scan_dir_flags_vcs_build_and_interpreter_dirs() {
        // `skip_dependency_scan_dir` reports whether a directory name is a
        // VCS, build-output, or interpreter cache directory that the
        // dependency scan must skip. No base or branch test pins this
        // predicate directly.
        assert!(skip_dependency_scan_dir(".git"));
        assert!(skip_dependency_scan_dir("target"));
        assert!(skip_dependency_scan_dir("node_modules"));
        assert!(skip_dependency_scan_dir(".venv"));
        assert!(skip_dependency_scan_dir("venv"));
        assert!(skip_dependency_scan_dir("__pycache__"));

        // A source directory is not skipped.
        assert!(!skip_dependency_scan_dir("src"));
        assert!(!skip_dependency_scan_dir("deps"));
        assert!(!skip_dependency_scan_dir(""));
    }
    #[test]
    fn mentions_test_before_commit_requires_test_and_commit_contexts() {
        // `mentions_test_before_commit` reports whether the lowercased task
        // text asks for a test before a commit: either the literal
        // `test-before-commit` tag, or both a commit context and a test
        // context. No base or branch test pins this predicate directly.
        // The explicit tag short-circuits the two-context requirement.
        assert!(mentions_test_before_commit(
            "use the test-before-commit policy"
        ));

        // Both a commit context and a test context present.
        assert!(mentions_test_before_commit(
            "run cargo test before committing"
        ));
        assert!(mentions_test_before_commit("pytest before git commit"));

        // A commit context alone, with no test context, is not a match.
        assert!(!mentions_test_before_commit("run the build before commit"));
        // A test context alone, with no commit context, is not a match.
        assert!(!mentions_test_before_commit("run the test suite"));
        assert!(!mentions_test_before_commit(""));
    }
    #[test]
    fn truncate_to_char_boundary_backs_off_across_multi_byte_chars() {
        // `truncate_to_char_boundary` shortens a `String` to at most
        // `max_bytes`, stepping back off a byte that falls inside a
        // multi-byte char so the result stays a valid string. It reports
        // whether it changed anything. No base or branch test pins this
        // helper directly.
        let mut ascii = String::from("abcdefghij");
        assert!(truncate_to_char_boundary(&mut ascii, 5));
        assert_eq!(ascii, "abcde");

        // Already within the limit: no change, reports false.
        let mut short = String::from("abc");
        assert!(!truncate_to_char_boundary(&mut short, 5));
        assert_eq!(short, "abc");

        // Exactly at the limit is also a no-op.
        let mut exact = String::from("abcde");
        assert!(!truncate_to_char_boundary(&mut exact, 5));
        assert_eq!(exact, "abcde");

        // A 2-byte char (`é`): the cut point lands mid-char, so the
        // truncation backs off to the start of the char.
        let mut two_byte = String::from("abé"); // 4 bytes: a b é(2)
        assert!(truncate_to_char_boundary(&mut two_byte, 3));
        assert_eq!(two_byte, "ab");

        // A 3-byte char: backing off to a boundary can empty the string.
        let mut three_byte = String::from("あ"); // 3 bytes
        assert!(truncate_to_char_boundary(&mut three_byte, 2));
        assert_eq!(three_byte, "");
    }
}
