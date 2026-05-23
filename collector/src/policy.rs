// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane policy layer.
//!
//! This is where taint rules are authored (YAML) and compiled to the flat
//! `source:sink` edges the eBPF program enforces. The kernel only knows edge
//! indices (`rule_id`); the human-facing name/reason stay here and are looked
//! up by index when a violation is reported.
//!
//! YAML schema:
//! ```yaml
//! rules:
//!   - name: codex-no-git
//!     source: codex            # this exe and all its descendants are tainted
//!     deny: [git, ssh]         # tainted processes may not exec these
//!     reason: "Codex may not use git/ssh; use the review workflow."
//! ```
//! `deny: [a, b]` and a single `sink: a` are both accepted. Each (source, sink)
//! pair becomes one compiled edge, in declaration order, matching the
//! `rule_id = edge index`, `label = 1 << index` convention in the loader.

/// One compiled taint edge: descendants of `source` may not exec `sink`.
#[derive(Debug, Clone, PartialEq)]
pub struct Edge {
    pub source: String,
    pub sink: String,
    pub rule_name: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Policy {
    edges: Vec<Edge>,
}

impl Policy {
    /// Parse a YAML policy document. Tolerant of the small schema above;
    /// returns an error string on malformed input.
    pub fn from_yaml(text: &str) -> Result<Policy, String> {
        let mut edges = Vec::new();

        // Current rule being assembled.
        let mut name = String::new();
        let mut source = String::new();
        let mut sinks: Vec<String> = Vec::new();
        let mut reason = String::new();
        let mut in_rule = false;

        // Flush the rule under construction into `edges`.
        fn flush(
            edges: &mut Vec<Edge>,
            name: &str,
            source: &str,
            sinks: &[String],
            reason: &str,
        ) -> Result<(), String> {
            if source.is_empty() {
                return Err(format!("rule '{}' has no source", name));
            }
            if sinks.is_empty() {
                return Err(format!("rule '{}' has no deny/sink entries", name));
            }
            for sink in sinks {
                edges.push(Edge {
                    source: source.to_string(),
                    sink: sink.clone(),
                    rule_name: name.to_string(),
                    reason: reason.to_string(),
                });
            }
            Ok(())
        }

        for raw in text.lines() {
            // strip comments
            let line = match raw.find('#') {
                Some(i) => &raw[..i],
                None => raw,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut rest = trimmed;
            let starts_item = rest.starts_with('-');
            if starts_item {
                // close the previous rule, start a new one
                if in_rule {
                    flush(&mut edges, &name, &source, &sinks, &reason)?;
                }
                in_rule = true;
                name.clear();
                source.clear();
                sinks.clear();
                reason.clear();
                rest = rest[1..].trim();
                if rest.is_empty() {
                    continue; // "-" alone; key/values follow on next lines
                }
            }

            let (key, val) = match rest.split_once(':') {
                Some((k, v)) => (k.trim(), unquote(v.trim())),
                None => continue,
            };

            if key == "rules" {
                continue;
            }
            if !in_rule {
                return Err(format!("'{}' appears before any rule item", key));
            }

            match key {
                "name" => name = val.to_string(),
                "source" => source = val.to_string(),
                "reason" => reason = val.to_string(),
                "sink" => sinks.push(val.to_string()),
                "deny" => sinks.extend(parse_list(val)),
                _ => {} // ignore unknown keys
            }
        }

        if in_rule {
            flush(&mut edges, &name, &source, &sinks, &reason)?;
        }

        Ok(Policy { edges })
    }

    /// Build a policy directly from compiled edges (used for inline `--rule`
    /// and for concatenating policies). Edge order is preserved as rule_id.
    pub fn from_edges(edges: Vec<Edge>) -> Policy {
        Policy { edges }
    }

    /// Consume the policy, yielding its edges (for concatenation).
    pub fn into_edges(self) -> Vec<Edge> {
        self.edges
    }

    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// `SOURCE:SINK` argv strings, one per edge, in `rule_id` order.
    pub fn edge_args(&self) -> Vec<String> {
        self.edges
            .iter()
            .map(|e| format!("{}:{}", e.source, e.sink))
            .collect()
    }

    /// Look up the edge a kernel `rule_id` refers to.
    pub fn edge(&self, rule_id: usize) -> Option<&Edge> {
        self.edges.get(rule_id)
    }
}

/// Strip one layer of matching surrounding quotes.
fn unquote(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"')
            || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Parse an inline YAML flow list like `[git, ssh]` (brackets optional).
fn parse_list(s: &str) -> Vec<String> {
    let inner = s.trim().trim_start_matches('[').trim_end_matches(']');
    inner
        .split(',')
        .map(|t| unquote(t.trim()).to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_deny_list_into_edges() {
        let yaml = r#"
            rules:
              - name: codex-no-git
                source: codex
                deny: [git, ssh]
                reason: "no git for codex"
        "#;
        let p = Policy::from_yaml(yaml).unwrap();
        assert_eq!(p.edges().len(), 2);
        assert_eq!(p.edge_args(), vec!["codex:git", "codex:ssh"]);
        assert_eq!(p.edge(0).unwrap().sink, "git");
        assert_eq!(p.edge(1).unwrap().sink, "ssh");
        assert_eq!(p.edge(0).unwrap().reason, "no git for codex");
        assert_eq!(p.edge(0).unwrap().rule_name, "codex-no-git");
    }

    #[test]
    fn parses_single_sink_and_multiple_rules() {
        let yaml = r#"
            rules:
              - source: codex
                sink: git
              - source: agent
                sink: curl
                reason: no exfil
        "#;
        let p = Policy::from_yaml(yaml).unwrap();
        assert_eq!(p.edge_args(), vec!["codex:git", "agent:curl"]);
        assert_eq!(p.edge(1).unwrap().source, "agent");
        assert_eq!(p.edge(1).unwrap().reason, "no exfil");
    }

    #[test]
    fn rule_id_indexes_match_loader_convention() {
        // edge order must match the kernel's rule_id = arg index
        let yaml = "rules:\n  - source: a\n    deny: [x, y, z]\n";
        let p = Policy::from_yaml(yaml).unwrap();
        assert_eq!(p.edge_args(), vec!["a:x", "a:y", "a:z"]);
        for (i, want) in ["x", "y", "z"].iter().enumerate() {
            assert_eq!(&p.edge(i).unwrap().sink, want);
        }
    }

    #[test]
    fn missing_source_is_error() {
        let yaml = "rules:\n  - sink: git\n";
        assert!(Policy::from_yaml(yaml).is_err());
    }

    #[test]
    fn missing_sink_is_error() {
        let yaml = "rules:\n  - source: codex\n";
        assert!(Policy::from_yaml(yaml).is_err());
    }

    #[test]
    fn empty_doc_is_empty_policy() {
        let p = Policy::from_yaml("# nothing\n").unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn key_before_item_is_error() {
        assert!(Policy::from_yaml("source: codex\n").is_err());
    }
}
