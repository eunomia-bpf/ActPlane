use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::{PolicyInput, Result};

const DEFAULT_POLICY_FILES: &[&str] = &["actplane.yaml", ".actplane/policy.yaml"];
pub const DEFAULT_FEEDBACK_FILE: &str = ".actplane/last-violation.txt";
pub const DEFAULT_HOOK_STATE_FILE: &str = ".actplane/feedback-hook.state.json";
pub const DEFAULT_AUDIT_FILE: &str = ".actplane/audit.jsonl";
pub const DEFAULT_EVENTS_FILE: &str = ".actplane/events.jsonl";

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default, rename = "version")]
    _version: Option<u32>,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub rules: BTreeMap<String, RuleEntry>,
    #[serde(default)]
    pub domains: BTreeMap<String, DomainEntry>,
    #[serde(default)]
    pub default_domain: Option<String>,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    feedback: FeedbackConfig,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleEntry {
    #[serde(default)]
    pub ifc: Option<String>,
    #[serde(default)]
    pub policy: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainEntry {
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub bind: Vec<RuleBinding>,
    #[serde(default)]
    pub disable: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBinding {
    pub rule: String,
    pub mode: BindingMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindingMode {
    Locked,
    Default,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub approval: RuntimeApprovalConfig,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeApprovalConfig {
    #[serde(default)]
    pub append_delta: AppendDeltaApprovalConfig,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendDeltaApprovalConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub require_approval_ref: bool,
    #[serde(default)]
    pub require_generated_by: bool,
    #[serde(default)]
    pub allowed_approvers: Vec<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct FeedbackConfig {
    path: Option<PathBuf>,
    audit: Option<PathBuf>,
    events: Option<PathBuf>,
}

pub struct LoadedPolicy {
    pub config: FileConfig,
    pub root: PathBuf,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSummary {
    pub name: String,
    pub parent: Option<String>,
    pub disabled: Vec<String>,
    pub locked: Vec<String>,
    pub defaults: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub source: String,
    pub domain: Option<DomainSummary>,
}

#[derive(Clone)]
pub struct FeedbackPaths {
    pub feedback: PathBuf,
    pub state: PathBuf,
    pub audit: PathBuf,
    pub events: PathBuf,
}

pub fn load_policy(cli: &PolicyInput) -> Result<LoadedPolicy> {
    if let Some(rule) = &cli.rule {
        return Ok(LoadedPolicy {
            config: FileConfig {
                policy: Some(rule.clone()),
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
    let loaded = load_policy_path(&path, explicit_policy, &cwd)?;
    let _ = resolve_policy(&loaded, cli.domain.as_deref())?;
    Ok(loaded)
}

pub fn load_policy_path(path: &Path, explicit_policy: bool, cwd: &Path) -> Result<LoadedPolicy> {
    if path.extension().is_some_and(|ext| ext == "dsl") {
        return Err(format!(
            "{} is a raw DSL file; policy files must be YAML with `policy: |`. Use `--rule` for one-off inline DSL.",
            path.display()
        )
        .into());
    }
    let src =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {}", path.display(), e))?;
    let config: FileConfig =
        serde_yaml::from_str(&src).map_err(|e| format!("parsing {}: {}", path.display(), e))?;
    validate_policy_shape(&config, path)?;
    let loaded = LoadedPolicy {
        config,
        root: if explicit_policy {
            cwd.to_path_buf()
        } else {
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| cwd.to_path_buf())
        },
        path: Some(path.to_path_buf()),
    };
    Ok(loaded)
}

fn validate_policy_shape(config: &FileConfig, path: &Path) -> Result<()> {
    let has_legacy = config
        .policy
        .as_ref()
        .is_some_and(|policy| !policy.trim().is_empty());
    let has_domains = !config.domains.is_empty() || !config.rules.is_empty();

    if has_legacy && has_domains {
        return Err(format!(
            "{} cannot mix legacy `policy: |` with `rules:`/`domains:`",
            path.display()
        )
        .into());
    }
    if has_legacy {
        validate_runtime_config(config, path)?;
        return Ok(());
    }
    if config.rules.is_empty() || config.domains.is_empty() {
        return Err(format!(
            "{} must contain either a non-empty `policy: |` block or both `rules:` and `domains:`",
            path.display()
        )
        .into());
    }
    validate_runtime_config(config, path)?;
    Ok(())
}

fn validate_runtime_config(config: &FileConfig, path: &Path) -> Result<()> {
    for approver in &config.runtime.approval.append_delta.allowed_approvers {
        if approver.trim().is_empty() {
            return Err(format!(
                "{} runtime.approval.append_delta.allowed_approvers must not contain empty entries",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

pub fn policy_source(loaded: &LoadedPolicy, domain: Option<&str>) -> Result<String> {
    Ok(resolve_policy(loaded, domain)?.source)
}

pub fn resolve_policy(loaded: &LoadedPolicy, domain: Option<&str>) -> Result<ResolvedPolicy> {
    if let Some(policy) = &loaded.config.policy {
        if domain.is_some() {
            return Err("`--domain` requires a policy file with `rules:` and `domains:`".into());
        }
        if policy.trim().is_empty() {
            return Err("`policy: |` block must not be empty".into());
        }
        return Ok(ResolvedPolicy {
            source: policy.clone(),
            domain: None,
        });
    }
    let domain = select_domain(&loaded.config, domain)?;
    let resolved = resolve_domain(&loaded.config, &domain)?;
    let mut out = String::new();
    for (mode, rule) in resolved
        .locked
        .iter()
        .map(|rule| ("locked", rule))
        .chain(resolved.defaults.iter().map(|rule| ("default", rule)))
    {
        let entry = loaded
            .config
            .rules
            .get(rule)
            .ok_or_else(|| format!("domain `{domain}` references unknown rule `{rule}`"))?;
        let ifc = entry.ifc_source(rule)?;
        out.push_str("\n# actplane-rule-source ref=rules.");
        out.push_str(rule);
        out.push_str(".ifc mode=");
        out.push_str(mode);
        out.push_str("\n# rule ");
        out.push_str(rule);
        out.push('\n');
        out.push_str(ifc.trim());
        out.push('\n');
    }
    if out.trim().is_empty() {
        return Err(format!("domain `{domain}` has no effective rules").into());
    }
    Ok(ResolvedPolicy {
        source: out,
        domain: Some(summary_for_domain(&loaded.config, &domain, resolved)?),
    })
}

fn select_domain(config: &FileConfig, requested: Option<&str>) -> Result<String> {
    if let Some(domain) = requested {
        if config.domains.contains_key(domain) {
            return Ok(domain.to_string());
        }
        return Err(format!(
            "unknown domain `{domain}` (available: {})",
            domain_names(config)
        )
        .into());
    }
    if let Some(domain) = &config.default_domain {
        if config.domains.contains_key(domain) {
            return Ok(domain.clone());
        }
        return Err(format!(
            "default_domain `{domain}` is not defined (available: {})",
            domain_names(config)
        )
        .into());
    }
    if config.domains.contains_key("session") {
        return Ok("session".into());
    }
    if config.domains.len() == 1 {
        return Ok(config.domains.keys().next().unwrap().clone());
    }
    Err(format!(
        "policy defines multiple domains ({}); pass `--domain <name>` or set `default_domain`",
        domain_names(config)
    )
    .into())
}

fn domain_names(config: &FileConfig) -> String {
    if config.domains.is_empty() {
        "none".into()
    } else {
        config
            .domains
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl RuleEntry {
    fn ifc_source(&self, name: &str) -> Result<&str> {
        match (&self.ifc, &self.policy) {
            (Some(_), Some(_)) => {
                Err(format!("rule `{name}` cannot contain both `ifc` and `policy`").into())
            }
            (Some(ifc), None) if !ifc.trim().is_empty() => Ok(ifc),
            (None, Some(policy)) if !policy.trim().is_empty() => Ok(policy),
            _ => Err(format!("rule `{name}` must contain non-empty `ifc: |`").into()),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ResolvedDomain {
    locked: BTreeSet<String>,
    defaults: BTreeSet<String>,
}

fn resolve_domain(config: &FileConfig, domain: &str) -> Result<ResolvedDomain> {
    let mut visiting = BTreeSet::new();
    resolve_domain_inner(config, domain, &mut visiting)
}

pub fn domain_summaries(config: &FileConfig) -> Result<Vec<DomainSummary>> {
    let mut out = Vec::new();
    for domain in config.domains.keys() {
        let resolved = resolve_domain(config, domain)?;
        out.push(summary_for_domain(config, domain, resolved)?);
    }
    Ok(out)
}

fn summary_for_domain(
    config: &FileConfig,
    domain: &str,
    resolved: ResolvedDomain,
) -> Result<DomainSummary> {
    let entry = config
        .domains
        .get(domain)
        .ok_or_else(|| format!("unknown domain `{domain}`"))?;
    Ok(DomainSummary {
        name: domain.to_string(),
        parent: entry.parent.clone(),
        disabled: entry.disable.clone(),
        locked: resolved.locked.into_iter().collect(),
        defaults: resolved.defaults.into_iter().collect(),
    })
}

fn resolve_domain_inner(
    config: &FileConfig,
    domain: &str,
    visiting: &mut BTreeSet<String>,
) -> Result<ResolvedDomain> {
    if !visiting.insert(domain.to_string()) {
        return Err(format!("domain parent cycle includes `{domain}`").into());
    }
    let entry = config
        .domains
        .get(domain)
        .ok_or_else(|| format!("unknown domain `{domain}`"))?;

    let mut resolved = if let Some(parent) = &entry.parent {
        resolve_domain_inner(config, parent, visiting)?
    } else {
        ResolvedDomain::default()
    };

    for rule in &entry.disable {
        if resolved.locked.contains(rule) {
            return Err(
                format!("domain `{domain}` cannot disable locked inherited rule `{rule}`").into(),
            );
        }
        if !resolved.defaults.remove(rule) {
            return Err(format!(
                "domain `{domain}` disables `{rule}`, but it is not an inherited default rule"
            )
            .into());
        }
    }

    for binding in &entry.bind {
        if !config.rules.contains_key(&binding.rule) {
            return Err(format!("domain `{domain}` binds unknown rule `{}`", binding.rule).into());
        }
        match binding.mode {
            BindingMode::Locked => {
                resolved.defaults.remove(&binding.rule);
                resolved.locked.insert(binding.rule.clone());
            }
            BindingMode::Default => {
                if !resolved.locked.contains(&binding.rule) {
                    resolved.defaults.insert(binding.rule.clone());
                }
            }
        }
    }
    visiting.remove(domain);
    Ok(resolved)
}

pub fn discover_policy(start: &Path) -> Option<PathBuf> {
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

pub fn feedback_paths(loaded: &LoadedPolicy) -> FeedbackPaths {
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
    let audit = loaded
        .config
        .feedback
        .audit
        .as_ref()
        .map(|p| absolutize(p, &loaded.root))
        .unwrap_or_else(|| {
            feedback
                .parent()
                .map(|p| p.join("audit.jsonl"))
                .unwrap_or_else(|| loaded.root.join(DEFAULT_AUDIT_FILE))
        });
    let events = loaded
        .config
        .feedback
        .events
        .as_ref()
        .map(|p| absolutize(p, &loaded.root))
        .unwrap_or_else(|| {
            feedback
                .parent()
                .map(|p| p.join("events.jsonl"))
                .unwrap_or_else(|| loaded.root.join(DEFAULT_EVENTS_FILE))
        });
    FeedbackPaths {
        feedback,
        state,
        audit,
        events,
    }
}

pub fn absolutize(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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

    fn load(src: &str) -> LoadedPolicy {
        LoadedPolicy {
            config: serde_yaml::from_str(src).unwrap(),
            root: PathBuf::new(),
            path: None,
        }
    }

    #[test]
    fn legacy_policy_source_still_works() {
        let loaded = load(
            r#"
policy: |
  rule r:
    block exec "git"
    because "x"
"#,
        );
        assert!(policy_source(&loaded, None).unwrap().contains("rule r"));
        assert!(policy_source(&loaded, Some("session")).is_err());
    }

    #[test]
    fn feedback_paths_include_default_and_custom_audit_log() {
        let loaded = LoadedPolicy {
            config: serde_yaml::from_str(
                r#"
feedback:
  path: run/feedback.txt
policy: |
  rule r:
    notify exec "git"
    because "x"
"#,
            )
            .unwrap(),
            root: PathBuf::from("/repo"),
            path: None,
        };
        let paths = feedback_paths(&loaded);
        assert_eq!(paths.feedback, PathBuf::from("/repo/run/feedback.txt"));
        assert_eq!(paths.audit, PathBuf::from("/repo/run/audit.jsonl"));
        assert_eq!(paths.events, PathBuf::from("/repo/run/events.jsonl"));

        let custom = LoadedPolicy {
            config: serde_yaml::from_str(
                r#"
feedback:
  path: run/feedback.txt
  audit: logs/control.jsonl
  events: logs/events.jsonl
policy: |
  rule r:
    notify exec "git"
    because "x"
"#,
            )
            .unwrap(),
            root: PathBuf::from("/repo"),
            path: None,
        };
        assert_eq!(
            feedback_paths(&custom).audit,
            PathBuf::from("/repo/logs/control.jsonl")
        );
        assert_eq!(
            feedback_paths(&custom).events,
            PathBuf::from("/repo/logs/events.jsonl")
        );
    }

    #[test]
    fn runtime_append_delta_approval_config_parses() {
        let loaded = load(
            r#"
runtime:
  approval:
    append_delta:
      required: true
      require_approval_ref: true
      require_generated_by: true
      allowed_approvers:
        - repo-supervisor
policy: |
  rule r:
    notify exec "git"
    because "x"
"#,
        );
        let approval = &loaded.config.runtime.approval.append_delta;
        assert!(approval.required);
        assert!(approval.require_approval_ref);
        assert!(approval.require_generated_by);
        assert_eq!(approval.allowed_approvers, vec!["repo-supervisor"]);
    }

    #[test]
    fn runtime_append_delta_approval_rejects_empty_approver() {
        let config: FileConfig = serde_yaml::from_str(
            r#"
runtime:
  approval:
    append_delta:
      required: true
      allowed_approvers:
        - ""
policy: |
  rule r:
    notify exec "git"
    because "x"
"#,
        )
        .unwrap();
        let err = validate_policy_shape(&config, Path::new("/repo/actplane.yaml")).unwrap_err();
        assert!(
            err.to_string()
                .contains("allowed_approvers must not contain empty entries"),
            "{err}"
        );
    }

    #[test]
    fn domain_can_disable_default_but_not_locked() {
        let loaded = load(
            r#"
rules:
  locked-rule:
    ifc: |
      rule locked-rule:
        kill exec "git" "branch"
        because "locked"
  default-rule:
    ifc: |
      rule default-rule:
        kill connect endpoint "*"
        because "default"
domains:
  session:
    bind:
      - rule: locked-rule
        mode: locked
      - rule: default-rule
        mode: default
  review:
    parent: session
    disable:
      - default-rule
"#,
        );
        let policy = policy_source(&loaded, Some("review")).unwrap();
        assert!(policy.contains("locked-rule"));
        assert!(policy.contains("# actplane-rule-source ref=rules.locked-rule.ifc mode=locked"));
        assert!(!policy.contains("default-rule"));

        let mut bad = loaded;
        bad.config
            .domains
            .get_mut("review")
            .unwrap()
            .disable
            .push("locked-rule".into());
        let err = policy_source(&bad, Some("review")).unwrap_err();
        assert!(err.to_string().contains("cannot disable locked"));
    }

    #[test]
    fn child_locked_binding_is_mandatory_for_grandchild() {
        let loaded = load(
            r#"
rules:
  readonly:
    ifc: |
      rule readonly:
        kill write file "/**"
        because "readonly"
domains:
  session: {}
  review:
    parent: session
    bind:
      - rule: readonly
        mode: locked
  helper:
    parent: review
    disable:
      - readonly
"#,
        );
        let err = policy_source(&loaded, Some("helper")).unwrap_err();
        assert!(err.to_string().contains("cannot disable locked"));
    }

    #[test]
    fn domain_parent_cycles_are_rejected() {
        let loaded = load(
            r#"
rules:
  r:
    ifc: |
      rule r:
        block exec "git"
        because "x"
domains:
  a:
    parent: b
    bind:
      - rule: r
        mode: default
  b:
    parent: a
"#,
        );
        let err = policy_source(&loaded, Some("a")).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn domain_selection_errors_show_available_domains() {
        let loaded = load(
            r#"
rules:
  r:
    ifc: |
      rule r:
        kill exec "git"
        because "x"
domains:
  alpha:
    bind:
      - rule: r
        mode: default
  beta:
    bind:
      - rule: r
        mode: default
"#,
        );
        let err = policy_source(&loaded, None).unwrap_err();
        assert!(err.to_string().contains("alpha, beta"));
        assert!(err.to_string().contains("--domain"));

        let err = policy_source(&loaded, Some("missing")).unwrap_err();
        assert!(err.to_string().contains("available: alpha, beta"));
    }

    #[test]
    fn domain_summaries_include_effective_bindings() {
        let loaded = load(
            r#"
default_domain: review
rules:
  locked:
    ifc: |
      rule locked:
        kill exec "git"
        because "locked"
  defaulted:
    ifc: |
      rule defaulted:
        kill exec "curl"
        because "defaulted"
  readonly:
    ifc: |
      rule readonly:
        kill write file "/**"
        because "readonly"
domains:
  session:
    bind:
      - rule: locked
        mode: locked
      - rule: defaulted
        mode: default
  review:
    parent: session
    disable:
      - defaulted
    bind:
      - rule: readonly
        mode: locked
"#,
        );
        let resolved = resolve_policy(&loaded, None).unwrap();
        let selected = resolved.domain.unwrap();
        assert_eq!(selected.name, "review");
        assert_eq!(selected.locked, vec!["locked", "readonly"]);
        assert!(selected.defaults.is_empty());

        let summaries = domain_summaries(&loaded.config).unwrap();
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().any(|d| d.name == "session"));
        assert!(summaries.iter().any(|d| d.name == "review"));
    }

    #[test]
    fn invalid_policy_corpus_is_rejected() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/policies/invalid");
        let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|ent| ent.expect("invalid policy dir entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
            .collect();
        paths.sort();
        assert!(
            paths.len() >= 7,
            "expected invalid policy corpus files in {}",
            dir.display()
        );

        for path in paths {
            let src = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let rejected = match serde_yaml::from_str::<FileConfig>(&src) {
                Err(e) => e.to_string(),
                Ok(config) => {
                    let loaded = LoadedPolicy {
                        config,
                        root: PathBuf::new(),
                        path: Some(path.clone()),
                    };
                    if let Err(e) = validate_policy_shape(&loaded.config, &path) {
                        e.to_string()
                    } else {
                        let mut errors = Vec::new();
                        if let Err(e) = policy_source(&loaded, None) {
                            errors.push(e.to_string());
                        }
                        for domain in loaded.config.domains.keys() {
                            if let Err(e) = policy_source(&loaded, Some(domain)) {
                                errors.push(e.to_string());
                            }
                        }
                        if errors.is_empty() {
                            panic!("{} should be rejected", path.display());
                        }
                        errors.join("; ")
                    }
                }
            };
            assert!(
                !rejected.trim().is_empty(),
                "{} rejection should explain why",
                path.display()
            );
        }
    }
    #[test]
    fn absolutize_keeps_absolute_paths_and_joins_relative_paths_to_base() {
        // `absolutize` resolves a policy-referenced path against a base dir:
        // absolute paths pass through unchanged, relative paths join to the
        // base. No base or branch test pins both branches directly.
        let base = Path::new("/srv/actplane");

        // An absolute path is returned verbatim.
        assert_eq!(
            absolutize(Path::new("/etc/actplane/policy.dsl"), base),
            Path::new("/etc/actplane/policy.dsl").to_path_buf()
        );

        // A relative path joins to the base.
        assert_eq!(
            absolutize(Path::new("policies/local.dsl"), base),
            Path::new("/srv/actplane/policies/local.dsl").to_path_buf()
        );
    }

    #[test]
    fn discover_policy_walks_up_to_nearest_policy_file() {
        // `discover_policy` climbs from a start directory to the filesystem
        // root, returning the first DEFAULT_POLICY_FILES hit. No base or branch
        // test calls it.
        let root = std::env::temp_dir().join(format!(
            "actplane-discover-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let deep = root.join("a").join("b");
        fs::create_dir_all(&deep).unwrap();

        // No policy anywhere under the tree: the walk escapes to the root.
        assert_eq!(discover_policy(&deep), None);

        // Nearest ancestor wins: a policy two levels up.
        let top_policy = root.join("actplane.yaml");
        fs::write(&top_policy, "policy: |\n").unwrap();
        assert_eq!(
            discover_policy(&deep).as_deref(),
            Some(top_policy.as_path())
        );

        // A policy in the start directory shadows the ancestor.
        let near_policy = deep.join(".actplane").join("policy.yaml");
        fs::create_dir_all(near_policy.parent().unwrap()).unwrap();
        fs::write(&near_policy, "policy: |\n").unwrap();
        assert_eq!(
            discover_policy(&deep).as_deref(),
            Some(near_policy.as_path())
        );

        // DEFAULT_POLICY_FILES order: actplane.yaml beats .actplane/policy.yaml
        // within the same directory.
        let same_plain = root.join("a").join("actplane.yaml");
        let same_nested = root.join("a").join(".actplane").join("policy.yaml");
        fs::create_dir_all(same_nested.parent().unwrap()).unwrap();
        fs::write(&same_plain, "policy: |\n").unwrap();
        fs::write(&same_nested, "policy: |\n").unwrap();
        let sub = root.join("a").join("c").join("d");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(discover_policy(&sub).as_deref(), Some(same_plain.as_path()));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_domain_inner_and_summary_map_fields() {
        // `resolve_domain_inner` accumulates inherited locked rules and
        // `summary_for_domain` projects them (plus parent/disabled) into a
        // DomainSummary; both report unknown domains. Neither has a direct
        // caller in the base or branch tests.
        let config: FileConfig = serde_yaml::from_str(
            r#"
default_domain: review
rules:
  locked:
    ifc: |
      rule locked:
        kill exec "git"
        because "locked"
  extra:
    ifc: |
      rule extra:
        kill exec "curl"
        because "extra"
domains:
  base:
    bind:
      - rule: locked
        mode: locked
  review:
    parent: base
    bind:
      - rule: extra
        mode: locked
"#,
        )
        .expect("config");

        assert!(
            resolve_domain_inner(&config, "nope", &mut BTreeSet::new())
                .unwrap_err()
                .to_string()
                .contains("unknown domain")
        );

        let bound = vec!["extra".to_string(), "locked".to_string()];
        let resolved =
            resolve_domain_inner(&config, "review", &mut BTreeSet::new()).expect("resolved");
        assert_eq!(resolved.locked.iter().cloned().collect::<Vec<_>>(), bound);
        assert!(resolved.defaults.is_empty());

        let summary = summary_for_domain(&config, "review", resolved.clone()).expect("summary");
        assert_eq!(summary.name, "review");
        assert_eq!(summary.parent.as_deref(), Some("base"));
        assert_eq!(summary.locked, bound);
        assert!(summary.defaults.is_empty());
        assert!(summary.disabled.is_empty());
        assert!(
            summary_for_domain(&config, "nope", resolved)
                .unwrap_err()
                .to_string()
                .contains("unknown domain")
        );
    }
    #[test]
    fn domain_names_joins_sorted_keys_and_reports_none_when_empty() {
        // `domain_names` renders the domain names for a config: the
        // `BTreeMap` keys joined by ", ", or "none" when there are no
        // domains. No base or branch test pins either branch directly.

        // Empty config -> "none".
        let empty: FileConfig = serde_yaml::from_str("").unwrap();
        assert_eq!(domain_names(&empty), "none");

        // Populated domains -> sorted keys joined by ", ".
        let cfg: FileConfig =
            serde_yaml::from_str("domains:\n  beta: {}\n  alpha: {}\n  gamma: {}\n").unwrap();
        assert_eq!(domain_names(&cfg), "alpha, beta, gamma");
    }

    #[test]
    fn ifc_source_accepts_one_non_empty_body_only() {
        // `RuleEntry::ifc_source` picks the rule body from `ifc:` or legacy
        // `policy:`, rejecting both-at-once and empty bodies; no base or branch
        // test calls it.
        let entry = |ifc: Option<&str>, policy: Option<&str>| RuleEntry {
            ifc: ifc.map(ToString::to_string),
            policy: policy.map(ToString::to_string),
        };

        assert_eq!(
            entry(Some("rule r:\n  block exec \"git\"\n"), None)
                .ifc_source("r")
                .unwrap(),
            "rule r:\n  block exec \"git\"\n"
        );
        assert_eq!(
            entry(None, Some("legacy body")).ifc_source("r").unwrap(),
            "legacy body"
        );

        let err = entry(Some("a"), Some("b"))
            .ifc_source("r")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot contain both `ifc` and `policy`"),
            "{err}"
        );

        for empty in [
            entry(None, None),
            entry(Some("  "), None),
            entry(None, Some("")),
        ] {
            let err = empty.ifc_source("r").unwrap_err().to_string();
            assert!(err.contains("must contain non-empty `ifc: |`"), "{err}");
        }
    }

    #[test]
    fn load_policy_path_guards_shape_extension_and_root() {
        // `load_policy_path` reads a YAML policy file, validates its shape, and
        // picks the root; no base or branch test calls it.
        let dir = std::env::temp_dir().join(format!("actplane-lpp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        // A `.dsl` path is rejected before any read.
        let dsl = dir.join("policy.dsl");
        let err = load_policy_path(&dsl, false, &dir)
            .err()
            .expect("dsl rejected")
            .to_string();
        assert!(err.contains("raw DSL file"), "{err}");

        // A missing file reports a read error.
        let missing = dir.join("missing.yaml");
        let err = load_policy_path(&missing, false, &dir)
            .err()
            .expect("missing rejected")
            .to_string();
        assert!(err.contains("reading"), "{err}");

        // Mixing legacy `policy: |` with `rules:`/`domains:` is rejected.
        let mixed = dir.join("mixed.yaml");
        fs::write(
            &mixed,
            "policy: |\n  rule r:\n    block exec \"git\"\nrules:\n  r:\n    ifc: |\n      rule r:\n        block exec \"git\"\ndomains:\n  session: {}\n",
        )
        .unwrap();
        let err = load_policy_path(&mixed, false, &dir)
            .err()
            .expect("mixed rejected")
            .to_string();
        assert!(err.contains("cannot mix legacy"), "{err}");

        // Neither a legacy block nor both `rules:`+`domains:` is rejected.
        let neither = dir.join("neither.yaml");
        fs::write(
            &neither,
            "rules:\n  r:\n    ifc: |\n      rule r:\n        block exec \"git\"\n",
        )
        .unwrap();
        let err = load_policy_path(&neither, false, &dir)
            .err()
            .expect("neither rejected")
            .to_string();
        assert!(err.contains("must contain either"), "{err}");

        // A valid file loads; the root is the file's parent, or cwd when the
        // policy was named explicitly.
        let good = dir.join("good.yaml");
        fs::write(&good, "policy: |\n  rule r:\n    block exec \"git\"\n").unwrap();
        let loaded = load_policy_path(&good, false, &dir).unwrap();
        assert_eq!(loaded.root, dir);
        assert_eq!(loaded.path.as_deref(), Some(good.as_path()));
        let explicit = load_policy_path(&good, true, Path::new("/cwd-root")).unwrap();
        assert_eq!(explicit.root, PathBuf::from("/cwd-root"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_policy_path_gates_suffix_shape_and_root() {
        // `load_policy_path` rejects raw DSL, enforces the legacy/rules shape,
        // and picks the policy root (cwd for an explicit policy, else the file's
        // parent); no base or branch test calls it directly.
        let dir = tempfile::tempdir().expect("tempdir");
        let cwd = dir.path();
        let policy_dir = cwd.join("nested");
        std::fs::create_dir_all(&policy_dir).unwrap();

        // Raw DSL file -> rejected before parsing.
        let dsl = cwd.join("rules.dsl");
        std::fs::write(&dsl, "rule r:\n  notify exec \"ls\"\n  because \"x\"\n").unwrap();
        let err = load_policy_path(&dsl, false, cwd)
            .err()
            .expect("dsl")
            .to_string();
        assert!(err.contains("raw DSL file"), "{err}");

        // Legacy policy root: implicit path uses the file's parent, explicit uses cwd.
        let legacy = policy_dir.join("actplane.yaml");
        std::fs::write(
            &legacy,
            "policy: \"rule r:\\n  notify exec \\\"ls\\\"\\n  because \\\"x\\\"\\n\"\n",
        )
        .unwrap();
        let implicit = load_policy_path(&legacy, false, cwd).expect("implicit");
        assert_eq!(implicit.root, policy_dir);
        assert_eq!(implicit.path.as_deref(), Some(legacy.as_path()));
        let explicit = load_policy_path(&legacy, true, cwd).expect("explicit");
        assert_eq!(explicit.root, cwd);

        // Mixing legacy policy with rules/domains is rejected.
        let mixed = cwd.join("mixed.yaml");
        std::fs::write(
            &mixed,
            "policy: \"rule r:\\n  notify exec \\\"ls\\\"\\n  because \\\"x\\\"\\n\"\nrules:\n  r:\n    ifc: \"rule r:\\n  notify exec \\\"ls\\\"\\n  because \\\"x\\\"\\n\"\ndomains:\n  d:\n    bind: []\n",
        )
        .unwrap();
        let err = load_policy_path(&mixed, false, cwd)
            .err()
            .expect("mixed")
            .to_string();
        assert!(err.contains("cannot mix legacy"), "{err}");
    }

    #[test]
    fn load_policy_handles_rule_and_discovery() {
        // `load_policy` short-circuits an inline `--rule` into a rootless
        // config, falls back to `discover_policy` when no `--policy` is given,
        // surfaces the missing-policy error shape, and rejects an explicit
        // path. No base or branch test calls it.
        let rule = PolicyInput {
            rule: Some("rule r:\n  block exec \"x\" if A\n  because \"z\"\n".to_string()),
            ..Default::default()
        };
        let loaded = load_policy(&rule).expect("inline rule loads");
        assert!(loaded.path.is_none());
        assert_eq!(
            loaded.config.policy.as_deref(),
            Some("rule r:\n  block exec \"x\" if A\n  because \"z\"\n")
        );

        // Repository root has an `actplane.yaml`, so running from here exercises
        // the discovery fallback (result is not asserted, only that it is taken).
        let discovered = PolicyInput::default();
        if discover_policy(&std::env::current_dir().expect("cwd")).is_some() {
            assert!(load_policy(&discovered).is_ok());
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let missing = PolicyInput {
            policy: Some(dir.path().join("nope.yaml")),
            ..Default::default()
        };
        let err = load_policy(&missing).err().expect("missing policy");
        assert!(err.to_string().contains("nope.yaml"), "{err}");

        let raw_dsl = dir.path().join("rule.dsl");
        std::fs::write(&raw_dsl, "rule r:\n  block exec \"x\"\n").unwrap();
        let explicit = PolicyInput {
            policy: Some(raw_dsl),
            ..Default::default()
        };
        let err = load_policy(&explicit).err().expect("raw dsl rejected");
        assert!(err.to_string().contains("raw DSL file"), "{err}");
    }

    fn domain_config(src: &str) -> FileConfig {
        serde_yaml::from_str(src).unwrap()
    }

    #[test]
    fn resolve_domain_merges_inherited_bindings() {
        // `resolve_domain` resolves a domain's effective locked/default rule
        // sets through its parent chain; no base or branch test calls it.
        let config = domain_config(
            r#"
rules:
  locked-rule:
    ifc: |
      rule locked-rule:
        kill exec "git"
        because "locked"
  default-rule:
    ifc: |
      rule default-rule:
        notify exec "ls"
        because "default"
domains:
  session:
    bind:
      - rule: locked-rule
        mode: locked
      - rule: default-rule
        mode: default
  review:
    parent: session
    disable:
      - default-rule
"#,
        );

        let session = resolve_domain(&config, "session").unwrap();
        assert_eq!(session.locked, BTreeSet::from(["locked-rule".to_string()]));
        assert_eq!(
            session.defaults,
            BTreeSet::from(["default-rule".to_string()])
        );

        let review = resolve_domain(&config, "review").unwrap();
        assert!(review.locked.contains("locked-rule"));
        assert!(!review.defaults.contains("default-rule"));

        let unknown = resolve_domain(&config, "missing").unwrap_err().to_string();
        assert!(unknown.contains("unknown domain `missing`"), "{unknown}");
    }
    #[test]
    fn select_domain_resolves_explicit_default_and_single_domain() {
        // `select_domain` picks the domain a policy run targets. No base or
        // branch test pins its branch precedence directly.
        fn cfg(y: &str) -> FileConfig {
            serde_yaml::from_str(y).unwrap()
        }

        // Two domains, no default: an explicit request that exists resolves.
        let multi = cfg("domains:\n  alpha: {}\n  beta: {}\n");
        assert_eq!(select_domain(&multi, Some("beta")).unwrap(), "beta");

        // An explicit request that does not exist fails, listing the options.
        let err = select_domain(&multi, Some("gamma"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown domain `gamma`"));

        // With two domains and no `default_domain` / `session`, no domain can
        // be auto-selected.
        let err = select_domain(&multi, None).unwrap_err().to_string();
        assert!(err.contains("policy defines multiple domains"));

        // `default_domain` that is defined resolves to it.
        let def_ok = cfg("default_domain: alpha\ndomains:\n  alpha: {}\n  beta: {}\n");
        assert_eq!(select_domain(&def_ok, None).unwrap(), "alpha");

        // `default_domain` that is not a real domain fails.
        let def_bad = cfg("default_domain: gamma\ndomains:\n  alpha: {}\n  beta: {}\n");
        let err = select_domain(&def_bad, None).unwrap_err().to_string();
        assert!(err.contains("default_domain `gamma` is not defined"));

        // A `session` domain is the preferred auto-selection when present.
        let sess = cfg("domains:\n  session: {}\n  alpha: {}\n");
        assert_eq!(select_domain(&sess, None).unwrap(), "session");

        // A single domain auto-selects even without `default_domain`.
        let single = cfg("domains:\n  alpha: {}\n");
        assert_eq!(select_domain(&single, None).unwrap(), "alpha");

        // An explicit request wins over the auto-selection.
        let explicit = cfg("domains:\n  alpha: {}\n  beta: {}\n");
        assert_eq!(select_domain(&explicit, Some("alpha")).unwrap(), "alpha");
    }
    #[test]
    fn validate_runtime_config_rejects_empty_approver_entries() {
        // `validate_runtime_config` rejects a runtime config whose
        // `allowed_approvers` list contains an empty (or whitespace) entry;
        // a config with only well-formed approvers (or none) validates. No
        // base or branch test pins both branches directly.
        let path = Path::new("/repo/actplane.yaml");

        // A whitespace-only approver is rejected, naming the offending path.
        let bad: FileConfig = serde_yaml::from_str(
            "runtime:\n  approval:\n    append_delta:\n      allowed_approvers:\n        - repo-supervisor\n        - \"   \"\n",
        )
        .unwrap();
        let err = validate_runtime_config(&bad, path).unwrap_err().to_string();
        assert!(err.contains("must not contain empty entries"));
        assert!(err.contains("/repo/actplane.yaml"));

        // Well-formed approvers validate.
        let good: FileConfig = serde_yaml::from_str(
            "runtime:\n  approval:\n    append_delta:\n      allowed_approvers:\n        - repo-supervisor\n        - owner\n",
        )
        .unwrap();
        assert!(validate_runtime_config(&good, path).is_ok());

        // No approvers configured validates trivially.
        let empty: FileConfig = serde_yaml::from_str("").unwrap();
        assert!(validate_runtime_config(&empty, path).is_ok());
    }
    #[test]
    fn policy_shape_errors_name_the_conflict() {
        let mixed = serde_yaml::from_str::<FileConfig>(
            r#"
policy: |
  rule r:
    block exec "git"
    because "x"
rules:
  r:
    ifc: |
      rule r:
        block exec "git"
        because "x"
domains:
  session: {}
"#,
        )
        .unwrap();
        let err = validate_policy_shape(&mixed, Path::new("actplane.yaml")).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot mix legacy `policy: |` with `rules:`/`domains:`"),
            "err: {err}"
        );

        let domainless = serde_yaml::from_str::<FileConfig>(
            r#"
rules:
  r:
    ifc: |
      rule r:
        block exec "git"
        because "x"
"#,
        )
        .unwrap();
        let err = validate_policy_shape(&domainless, Path::new("actplane.yaml")).unwrap_err();
        assert!(
            err.to_string().contains(
                "must contain either a non-empty `policy: |` block or both `rules:` and `domains:`"
            ),
            "err: {err}"
        );
    }

    #[test]
    fn empty_policy_block_is_rejected_at_resolve_time() {
        let loaded = load("policy: |\n");
        let err = policy_source(&loaded, None).unwrap_err();
        assert_eq!(err.to_string(), "`policy: |` block must not be empty");

        let err = policy_source(&loaded, Some("session")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "`--domain` requires a policy file with `rules:` and `domains:`"
        );
    }

    fn domain_load(rules: &str, domains: &str) -> LoadedPolicy {
        load(&format!("rules:\n{rules}domains:\n{domains}"))
    }

    const ONE_RULE: &str =
        "  r:\n    ifc: |\n      rule r:\n        notify exec \"git\"\n        because \"x\"\n";

    #[test]
    fn select_domain_reports_unknown_and_undefined_defaults() {
        let loaded = domain_load(ONE_RULE, "  d: {}\n");
        assert_eq!(
            policy_source(&loaded, Some("zzz")).unwrap_err().to_string(),
            "unknown domain `zzz` (available: d)"
        );

        let loaded = load(&format!(
            "rules:\n{ONE_RULE}domains:\n  a: {{}}\ndefault_domain: zzz\n"
        ));
        assert_eq!(
            policy_source(&loaded, None).unwrap_err().to_string(),
            "default_domain `zzz` is not defined (available: a)"
        );
    }

    #[test]
    fn resolve_domain_reports_empty_cycles_and_bad_bindings() {
        let empty = domain_load(ONE_RULE, "  d: {}\n");
        assert_eq!(
            policy_source(&empty, Some("d")).unwrap_err().to_string(),
            "domain `d` has no effective rules"
        );

        let cycle = domain_load(ONE_RULE, "  a:\n    parent: b\n  b:\n    parent: a\n");
        assert_eq!(
            policy_source(&cycle, Some("a")).unwrap_err().to_string(),
            "domain parent cycle includes `a`"
        );

        let bind = domain_load(
            ONE_RULE,
            "  d:\n    bind:\n      - rule: nope\n        mode: locked\n",
        );
        assert_eq!(
            policy_source(&bind, Some("d")).unwrap_err().to_string(),
            "domain `d` binds unknown rule `nope`"
        );

        let disable = domain_load(ONE_RULE, "  d:\n    disable: [r]\n");
        assert_eq!(
            policy_source(&disable, Some("d")).unwrap_err().to_string(),
            "domain `d` disables `r`, but it is not an inherited default rule"
        );
    }
    #[test]
    fn load_policy_path_reports_raw_dsl_and_read_failures() {
        let dir = tempfile::tempdir().unwrap();

        let dsl = dir.path().join("policy.dsl");
        fs::write(&dsl, "rule r:\n  block exec \"git\"\n  because \"x\"\n").unwrap();
        let err = match load_policy_path(&dsl, true, dir.path()) {
            Ok(_) => panic!("raw DSL file must be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("is a raw DSL file"), "err: {err}");

        let missing = dir.path().join("absent.yaml");
        let err = match load_policy_path(&missing, true, dir.path()) {
            Ok(_) => panic!("missing policy file must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .starts_with(&format!("reading {}:", missing.display())),
            "err: {err}"
        );
    }

    const READY_POLICY: &str = "version: 1\npolicy: |\n  source COMMAND = exec \"**\"\n  rule noop:\n    notify exec \"__never__\" if COMMAND\n    because \"b\"\n";

    #[test]
    fn discover_policy_walks_up_and_prefers_actplane_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(discover_policy(&nested), None);

        let yaml = dir.path().join("actplane.yaml");
        fs::write(&yaml, READY_POLICY).unwrap();
        assert_eq!(discover_policy(&nested).as_deref(), Some(yaml.as_path()));
        assert_eq!(discover_policy(dir.path()).as_deref(), Some(yaml.as_path()));

        // The dotdir candidate is found when no actplane.yaml exists.
        fs::remove_file(&yaml).unwrap();
        let dotdir = dir.path().join(".actplane").join("policy.yaml");
        fs::create_dir_all(dotdir.parent().unwrap()).unwrap();
        fs::write(&dotdir, READY_POLICY).unwrap();
        assert_eq!(discover_policy(&nested).as_deref(), Some(dotdir.as_path()));
    }

    #[test]
    fn load_policy_path_sets_root_from_explicit_flag() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("actplane.yaml");
        fs::write(&policy, READY_POLICY).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();

        // Explicit --policy keeps the invocation cwd as the project root.
        let loaded = load_policy_path(&policy, true, &elsewhere).unwrap();
        assert_eq!(loaded.root, elsewhere);
        assert_eq!(loaded.path.as_deref(), Some(policy.as_path()));

        // A discovered policy uses its own directory as the root.
        let loaded = load_policy_path(&policy, false, &elsewhere).unwrap();
        assert_eq!(loaded.root, dir.path());
    }

    #[test]
    fn load_policy_path_rejects_raw_dsl() {
        let dir = tempfile::tempdir().unwrap();
        let dsl = dir.path().join("child.dsl");
        fs::write(&dsl, "rule r:\n").unwrap();
        let err = load_policy_path(&dsl, true, dir.path())
            .err()
            .expect("raw DSL rejected")
            .to_string();
        assert_eq!(
            err,
            format!(
                "{} is a raw DSL file; policy files must be YAML with `policy: |`. Use `--rule` for one-off inline DSL.",
                dsl.display()
            )
        );
    }

    #[test]
    fn absolutize_joins_relative_paths_only() {
        let base = Path::new("/base/dir");
        assert_eq!(
            absolutize(Path::new("actplane.yaml"), base),
            base.join("actplane.yaml")
        );
        assert_eq!(absolutize(base, base), base);
    }
}
