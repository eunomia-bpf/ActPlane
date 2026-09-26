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
    let mut task_text = String::new();
    if let Some(task) = task {
        task_text.push_str(task);
        task_text.push('\n');
    }
    // Selection runs on the merged text, while attribution runs on each source
    // separately so an emitted reason can name the one that actually matched.
    let lower = format!("{instruction_text}{task_text}").to_lowercase();
    let instructions_lower = instruction_text.to_lowercase();
    let task_lower = task_text.to_lowercase();
    let agent_exec = infer_agent_exec(&lower);
    let mut out = Vec::new();

    if mentions_any(&lower, BRANCH_NEEDLES) {
        out.push(GeneratedTemplate {
            id: "no-git-branch",
            params: vec![format!("agent_exec={agent_exec}")],
            reasons: vec![mention_reason(
                &instructions_lower,
                &task_lower,
                BRANCH_NEEDLES,
                "agent-created git branches or worktrees",
            )],
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
            reasons: vec![
                mentioned_source(&instructions_lower, &task_lower, mentions_no_git_push)
                    .reason("agent-run git push"),
            ],
        });
    }

    let mentions_tests = mentions_test_before_commit(&lower);
    if mentions_tests || has_source_tree(root) {
        let reason = if mentions_tests {
            mentioned_source(
                &instructions_lower,
                &task_lower,
                mentions_test_before_commit,
            )
            .reason("tests before commit")
        } else {
            "project appears to have source/test files".to_string()
        };
        out.push(GeneratedTemplate {
            id: "test-before-commit",
            params: vec![
                format!("agent_exec={agent_exec}"),
                format!("test_exec={}", infer_test_exec(root, &lower)),
                format!("changed_paths={}", infer_changed_paths(root)),
            ],
            reasons: vec![reason],
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
                mentioned_source(
                    &instructions_lower,
                    &task_lower,
                    mentions_dependency_update_gate,
                )
                .reason("dependency or lockfile update validation"),
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
                mentioned_source(
                    &instructions_lower,
                    &task_lower,
                    mentions_protected_push_approval,
                )
                .reason("protected branches, refs, or git push approval"),
            ],
        });
    }

    let mentions_secrets = mentions_any(&lower, SECRET_NEEDLES);
    let has_secret_files = root.join(".env").exists() || root.join("secrets").exists();
    if mentions_secrets || has_secret_files {
        let mut reasons = Vec::new();
        if mentions_secrets {
            reasons.push(mention_reason(
                &instructions_lower,
                &task_lower,
                SECRET_NEEDLES,
                "secrets",
            ));
        }
        if has_secret_files {
            reasons.push("project contains secret-like files such as .env or secrets/".into());
        }
        out.push(GeneratedTemplate {
            id: "no-secret-egress",
            params: vec![
                format!("secret_paths={}", infer_secret_paths(root)),
                "redactor_exec=**/redact".into(),
            ],
            reasons,
        });
    }

    if mentions_any(&lower, NETWORK_NEEDLES) {
        out.push(GeneratedTemplate {
            id: "no-network",
            params: vec![
                format!("agent_exec={agent_exec}"),
                "loopback_endpoint=127.".into(),
            ],
            reasons: vec![mention_reason(
                &instructions_lower,
                &task_lower,
                NETWORK_NEEDLES,
                "network isolation",
            )],
        });
    }

    if mentions_any(&lower, READONLY_NEEDLES) && mentions_any(&lower, REVIEW_NEEDLES) {
        out.push(GeneratedTemplate {
            id: "readonly-review",
            params: vec![format!("agent_exec={agent_exec}")],
            reasons: vec![
                mentioned_source(&instructions_lower, &task_lower, |text| {
                    mentions_any(text, READONLY_NEEDLES) && mentions_any(text, REVIEW_NEEDLES)
                })
                .reason("read-only review work"),
            ],
        });
    }

    if mentions_any(&lower, PROD_DB_NEEDLES) {
        out.push(GeneratedTemplate {
            id: "prod-db-via-migrate",
            params: vec![
                "database_path=**/prod.db".into(),
                "mediator_exec=**/migrate".into(),
            ],
            reasons: vec![mention_reason(
                &instructions_lower,
                &task_lower,
                PROD_DB_NEEDLES,
                "production database mediation",
            )],
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
    collect_dependency_paths(root, 0, &mut paths);
    if paths.is_empty() {
        DEFAULT_DEPENDENCY_PATHS.into()
    } else {
        paths.into_iter().take(24).collect::<Vec<_>>().join(",")
    }
}

/// Dependency manifests used when the scan finds none in the repository.
///
/// Each entry must lower to a matcher within the kernel's `contains` window
/// (`TAINT_SUF_MAX`, 16 bytes), so `package-lock.*` stands in for the 17-byte
/// `package-lock.json`, which would otherwise be shortened to a substring that
/// matches strictly more than the manifest.
pub(crate) const DEFAULT_DEPENDENCY_PATHS: &str =
    "Cargo.lock,package-lock.*,pnpm-lock.yaml,yarn.lock,go.sum,requirements*.txt,pyproject.toml";

/// Map a discovered manifest file name to a warning-free invalidator glob.
///
/// Emitting the repository-relative path instead would fail the same window: a
/// nested `packages/web/package.json` lowers to a `contains` literal longer than
/// 16 bytes and is shortened to its parent directory (`web/package.json` then
/// `packages/web/`), naming a directory rather than the manifest. A basename
/// glob matches any depth, so nested manifests also collapse to one entry.
fn manifest_glob(name: &str) -> &str {
    match name {
        // 17 bytes, one over the kernel's 16-byte window.
        "package-lock.json" => "package-lock.*",
        _ if name.len() > 16 && name.starts_with("requirements") && name.ends_with(".txt") => {
            "requirements*.txt"
        }
        _ => name,
    }
}

fn collect_dependency_paths(dir: &Path, depth: usize, out: &mut BTreeSet<String>) {
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
                out.insert(manifest_glob(&name).to_string());
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
        collect_dependency_paths(&subdir, depth + 1, out);
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

const BRANCH_NEEDLES: &[&str] = &["git branch", "git worktree", "no-git-branch", "worktree"];
const SECRET_NEEDLES: &[&str] = &[
    "secret",
    "credential",
    "token",
    "api key",
    ".env",
    ".npmrc",
    ".pypirc",
];
const NETWORK_NEEDLES: &[&str] = &["no network", "offline", "external network"];
const READONLY_NEEDLES: &[&str] = &["read-only", "readonly"];
const REVIEW_NEEDLES: &[&str] = &["review", "subagent", "sub-agent"];
const PROD_DB_NEEDLES: &[&str] = &["prod.db", "production database", "migrate"];

/// Which of the two generator text sources matched a heuristic.
enum MentionedSource {
    Instructions,
    Task,
    Both,
    Neither,
}

impl MentionedSource {
    /// Reason clause naming the matched source. A reason must never credit
    /// project instructions for a match found only in the `--task` hint.
    fn reason(self, object: &str) -> String {
        match self {
            MentionedSource::Instructions => format!("project instructions mention {object}"),
            MentionedSource::Task => format!("the task hint mentions {object}"),
            MentionedSource::Both => {
                format!("project instructions and the task hint mention {object}")
            }
            MentionedSource::Neither => format!("instructions or the task hint mention {object}"),
        }
    }
}

/// Evaluate `predicate` against each source independently so the reason can name
/// the matching one. `Neither` covers a match that only spans the merge boundary.
fn mentioned_source(
    instructions: &str,
    task: &str,
    predicate: impl Fn(&str) -> bool,
) -> MentionedSource {
    match (predicate(instructions), predicate(task)) {
        (true, true) => MentionedSource::Both,
        (true, false) => MentionedSource::Instructions,
        (false, true) => MentionedSource::Task,
        (false, false) => MentionedSource::Neither,
    }
}

/// Attribution for the common "any of these needles" predicate.
fn mention_reason(instructions: &str, task: &str, needles: &[&str], object: &str) -> String {
    mentioned_source(instructions, task, |text| mentions_any(text, needles)).reason(object)
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
        // Variants at any depth collapse to one basename glob, which lowers
        // within the kernel's pattern window; a repo-relative path would not.
        assert_eq!(dependency_paths, "package.json,pnpm-lock.yaml");
    }

    #[test]
    fn generator_uses_task_hint_without_instruction_files() {
        let tmp = tempfile::tempdir().unwrap();
        let generated = generate(tmp.path(), &[], Some("offline readonly review")).unwrap();
        assert!(generated.instruction_files.is_empty());
        let reasons = generated
            .templates
            .iter()
            .map(|selection| (selection.id, selection.reasons.join("; ")))
            .collect::<Vec<_>>();
        assert!(reasons.contains(&(
            "no-network",
            "the task hint mentions network isolation".into()
        )));
        assert!(reasons.contains(&(
            "readonly-review",
            "the task hint mentions read-only review work".into()
        )));
        // A reason crediting project instructions here would contradict the
        // header's "Instructions considered: none found".
        let yaml = render_yaml(&generated).unwrap();
        assert!(yaml.contains("# Instructions considered: none found"));
        assert!(!yaml.contains("project instructions"));
    }

    #[test]
    fn generator_attributes_reasons_to_the_matching_source() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "The agent must work offline.").unwrap();
        let from_instructions = generate(tmp.path(), &[], None).unwrap();
        let no_network = from_instructions
            .templates
            .iter()
            .find(|selection| selection.id == "no-network")
            .expect("no-network selection from instruction file");
        assert_eq!(
            no_network.reasons,
            vec!["project instructions mention network isolation".to_string()]
        );

        let both = generate(tmp.path(), &[], Some("no network egress")).unwrap();
        let no_network = both
            .templates
            .iter()
            .find(|selection| selection.id == "no-network")
            .unwrap();
        assert_eq!(
            no_network.reasons,
            vec!["project instructions and the task hint mention network isolation".to_string()]
        );
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
}
