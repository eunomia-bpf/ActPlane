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
}
