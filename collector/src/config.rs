use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::{Cli, Result};

const DEFAULT_POLICY_FILES: &[&str] = &["actplane.yaml", ".actplane/policy.yaml"];
pub(crate) const DEFAULT_FEEDBACK_FILE: &str = ".actplane/last-violation.txt";
pub(crate) const DEFAULT_HOOK_STATE_FILE: &str = ".actplane/feedback-hook.state.json";

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileConfig {
    #[serde(default, rename = "version")]
    _version: Option<u32>,
    #[serde(default)]
    pub(crate) policy: Option<String>,
    #[serde(default)]
    pub(crate) rules: BTreeMap<String, RuleEntry>,
    #[serde(default)]
    pub(crate) domains: BTreeMap<String, DomainEntry>,
    #[serde(default)]
    pub(crate) default_domain: Option<String>,
    #[serde(default)]
    feedback: FeedbackConfig,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleEntry {
    #[serde(default)]
    pub(crate) ifc: Option<String>,
    #[serde(default)]
    pub(crate) policy: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainEntry {
    #[serde(default)]
    pub(crate) parent: Option<String>,
    #[serde(default)]
    pub(crate) bind: Vec<RuleBinding>,
    #[serde(default)]
    pub(crate) disable: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleBinding {
    pub(crate) rule: String,
    pub(crate) mode: BindingMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BindingMode {
    Locked,
    Default,
}

#[derive(Debug, Default, serde::Deserialize)]
struct FeedbackConfig {
    path: Option<PathBuf>,
}

pub(crate) struct LoadedPolicy {
    pub(crate) config: FileConfig,
    pub(crate) root: PathBuf,
    pub(crate) path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DomainSummary {
    pub(crate) name: String,
    pub(crate) parent: Option<String>,
    pub(crate) disabled: Vec<String>,
    pub(crate) locked: Vec<String>,
    pub(crate) defaults: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPolicy {
    pub(crate) source: String,
    pub(crate) domain: Option<DomainSummary>,
}

#[derive(Clone)]
pub(crate) struct FeedbackPaths {
    pub(crate) feedback: PathBuf,
    pub(crate) state: PathBuf,
}

pub(crate) fn load_policy(cli: &Cli) -> Result<LoadedPolicy> {
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
    if path.extension().is_some_and(|ext| ext == "dsl") {
        return Err(format!(
            "{} is a raw DSL file; policy files must be YAML with `policy: |`. Use `--rule` for one-off inline DSL.",
            path.display()
        )
        .into());
    }
    let src =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {}", path.display(), e))?;
    let config: FileConfig =
        serde_yaml::from_str(&src).map_err(|e| format!("parsing {}: {}", path.display(), e))?;
    validate_policy_shape(&config, &path)?;
    let loaded = LoadedPolicy {
        config,
        root: if explicit_policy {
            cwd
        } else {
            path.parent().map(Path::to_path_buf).unwrap_or(cwd)
        },
        path: Some(path),
    };
    let _ = resolve_policy(&loaded, cli.domain.as_deref())?;
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
        return Ok(());
    }
    if config.rules.is_empty() || config.domains.is_empty() {
        return Err(format!(
            "{} must contain either a non-empty `policy: |` block or both `rules:` and `domains:`",
            path.display()
        )
        .into());
    }
    Ok(())
}

pub(crate) fn policy_source(loaded: &LoadedPolicy, domain: Option<&str>) -> Result<String> {
    Ok(resolve_policy(loaded, domain)?.source)
}

pub(crate) fn resolve_policy(loaded: &LoadedPolicy, domain: Option<&str>) -> Result<ResolvedPolicy> {
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
    for rule in resolved.locked.iter().chain(resolved.defaults.iter()) {
        let entry = loaded
            .config
            .rules
            .get(rule)
            .ok_or_else(|| format!("domain `{domain}` references unknown rule `{rule}`"))?;
        let ifc = entry.ifc_source(rule)?;
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

pub(crate) fn domain_summaries(config: &FileConfig) -> Result<Vec<DomainSummary>> {
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

pub(crate) fn discover_policy(start: &Path) -> Option<PathBuf> {
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

pub(crate) fn feedback_paths(loaded: &LoadedPolicy) -> FeedbackPaths {
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
    FeedbackPaths { feedback, state }
}

pub(crate) fn absolutize(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
