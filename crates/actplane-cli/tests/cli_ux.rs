use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

#[cfg(unix)]
use std::io::{BufRead, Write};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::time::Duration;

fn actplane() -> &'static str {
    env!("CARGO_BIN_EXE_actplane")
}

fn fixture(name: &str) -> String {
    format!(
        "{}/../../test/policies/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

fn run(args: &[&str]) -> Output {
    Command::new(actplane())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run actplane {args:?}: {e}"))
}

/// Every `code: "..."` string literal in the doctor's source, sorted and
/// deduplicated.
///
/// The doc-completeness guard needs the set of codes the doctor can emit, and
/// `actplane` is a binary crate, so no library export carries them. Scanning the
/// source keeps the guard tied to what the doctor actually emits: a renamed or
/// new code fails the guard until `docs/rule-language.md` lists it.
fn doctor_warning_codes(src: &str) -> Vec<&str> {
    let mut codes: Vec<&str> = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("code:") {
        rest = &rest[at + "code:".len()..];
        let trimmed = rest.trim_start();
        let Some(after_quote) = trimmed.strip_prefix('"') else {
            continue;
        };
        let Some(end) = after_quote.find('"') else {
            continue;
        };
        let code = &after_quote[..end];
        if !code.is_empty()
            && code
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && !codes.contains(&code)
        {
            codes.push(code);
        }
        rest = &after_quote[end..];
    }
    codes.sort_unstable();
    codes
}

#[test]
fn top_level_help_is_engine_focused() {
    let output = run(&["--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    for command in [
        "run", "compile", "init", "doctor", "watch", "attach", "mcp", "control",
    ] {
        assert!(
            stdout.contains(command),
            "missing {command} in help:\n{stdout}"
        );
    }
    for removed in [
        "check",
        "templates",
        "setup",
        "domains",
        "rollout",
        "child-run",
    ] {
        assert!(
            !stdout.contains(&format!("  {removed}")),
            "removed command {removed} still appears in help:\n{stdout}"
        );
    }
}

#[test]
fn policy_help_names_every_discovery_candidate() {
    // `--policy` defaults to `config::discover_policy`, which walks upward for
    // `actplane.yaml` or `.actplane/policy.yaml` (config.rs:9,429). Help that
    // named only `actplane.yaml` would hide the second candidate from a user
    // who placed their policy under `.actplane/`.
    let output = run(&["--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(
        stdout.contains("actplane.yaml") && stdout.contains(".actplane/policy.yaml"),
        "policy help did not name both discovery candidates:\n{stdout}"
    );
}

#[test]
fn removed_top_level_commands_are_not_accepted() {
    for command in [
        "check",
        "templates",
        "setup",
        "domains",
        "rollout",
        "delta",
        "child-run",
    ] {
        let output = run(&[command, "--help"]);
        assert!(
            !output.status.success(),
            "removed command {command} unexpectedly succeeded"
        );
    }
}

#[test]
fn compile_default_prints_domain_summary() {
    let policy = fixture("15_domain_bindings.yaml");
    let output = run(&["--policy", &policy, "--domain", "review", "compile"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("domain: review"));
    assert!(stdout.contains("parent: session"));
    assert!(stdout.contains("policy: no-git-branch, readonly"));
    assert!(!stdout.contains("no-network —"));
}

#[test]
fn compile_json_reports_backend_support_and_static_warnings() {
    let policy = r#"
source NET = endpoint "localhost"
source WILD = endpoint "*.internal"

rule recv-soft:
  notify recv endpoint "*" if true
  because "recv notify"

rule host-connect:
  notify connect endpoint "localhost" if true
  because "hostname connect"
"#;
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");

    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["matrix_scope"], "static_policy_host_support");
    assert_eq!(value["rule_count"], 2);
    assert_eq!(value["backend_support"]["sources"][0]["label"], "NET");
    assert_eq!(value["backend_support"]["sources"][0]["supported"], true);
    assert!(
        value["backend_support"]["sources"][0]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("hostname resolved")
    );
    assert_eq!(value["backend_support"]["sources"][1]["label"], "WILD");
    assert_eq!(value["backend_support"]["sources"][1]["supported"], false);
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "endpoint_source_unsupported")
    );
}

#[test]
fn compile_json_warns_that_repo_relative_target_exception_is_partial() {
    // A repo-relative `unless target` over a `**/<dir>/**` pattern cannot express
    // the primary+companion disjunction in one cond slot, so the exception
    // over-fires on the first-segment-relative form. That must be discoverable,
    // not silent.
    let policy = r#"
source AGENT = exec "claude"

rule js-outside-dist:
  notify write file "**/*.js" if AGENT unless target "**/dist/**"
  because "new JS sources must be TypeScript"
"#;
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "repo_relative_target_condition_partial"),
        "expected partial-exception warning, got {}",
        value["warnings"]
    );

    // An absolute exception has no companion and must not warn.
    let abs = r#"
source AGENT = exec "claude"

rule js-outside-dist:
  notify write file "**/*.js" if AGENT unless target "/work/dist/**"
  because "new JS sources must be TypeScript"
"#;
    let output = run(&["--rule", abs, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "repo_relative_target_condition_partial"),
        "absolute exception must not warn, got {}",
        value["warnings"]
    );

    // An `exec` clause has no companion forms: both the target and the
    // condition lower through `lower_exec`, which matches the basename on
    // `comm`, so `**/pytest` and `pytest` are identical and the exception
    // covers every form. Warning there would be a false positive.
    let exec_clause = r#"
rule tests-not-pytest:
  notify exec "**/git" unless target "**/pytest"
  because "git must not be replaced by pytest"
"#;
    let output = run(&["--rule", exec_clause, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "repo_relative_target_condition_partial"),
        "an exec clause has no companion form, so the exception is exact; got {}",
        value["warnings"]
    );
    // A negated exception over the same repo-relative pattern warns too, and
    // the consequence text must name the opposite direction: the missing
    // companion leaves the condition unsatisfied on the bare-relative form, so
    // the kernel's negation suppresses the rule there (under-fire), not
    // over-fire.
    let negated = r#"
source AGENT = exec "claude"

rule js-outside-dist:
  notify write file "**/*.js" if AGENT unless target not "**/dist/**"
  because "new JS sources must be TypeScript"
"#;
    let output = run(&["--rule", negated, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    let warning = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|warning| warning["code"] == "repo_relative_target_condition_partial")
        .expect("expected partial-exception warning for the negated form");
    let message = warning["message"].as_str().unwrap();
    assert!(
        message.contains("unless target not \"**/dist/**\""),
        "message should name the negated condition: {message}"
    );
    assert!(
        message.contains("under-fires") && !message.contains("over-fires"),
        "a negated exception under-fires, not over-fires: {message}"
    );
}

#[test]
fn compile_json_warns_when_a_pattern_literal_is_truncated() {
    // Kernel pattern fields are 64 bytes (63 usable), so a longer literal is
    // stored as a prefix of what the policy wrote. For an exact absolute path
    // that means the rule can never match the intended target, which must be
    // discoverable rather than silent.
    let long = "/var/lib/some/deeply/nested/directory/structure/that/is/very/long/target.txt";
    assert!(long.len() > 63);
    let policy = format!("rule r:\n  block write file \"{long}\" if A\n  because \"x\"\n");
    let output = run(&["--rule", &policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    let warning = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|warning| warning["code"] == "pattern_literal_truncated")
        .unwrap_or_else(|| panic!("expected truncation warning, got {}", value["warnings"]));
    assert!(
        warning["message"].as_str().unwrap().contains(long),
        "warning should name the literal: {}",
        warning["message"]
    );

    // A literal that fits must not warn.
    let short = format!("rule r:\n  block write file \"/tmp/short.txt\" if A\n  because \"x\"\n");
    let output = run(&["--rule", &short, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "pattern_literal_truncated"),
        "short literal must not warn, got {}",
        value["warnings"]
    );
}

#[test]
fn compile_json_warns_when_a_suffix_literal_exceeds_the_matcher_bound() {
    // The kernel's `taint_suffix` rejects any literal longer than TAINT_SUF_MAX
    // (16 bytes), so `**/<long basename>` lowers to a literal that can never
    // match: the rule is dead. That must be discoverable, and reported as its own
    // code rather than as buffer truncation.
    let policy =
        "rule r:\n  block write file \"**/*config.production.json\" if A\n  because \"x\"\n";
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "pattern_matcher_length_exceeded"),
        "expected matcher-length warning, got {}",
        value["warnings"]
    );
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "pattern_literal_truncated"),
        "a 22-byte literal fits the 63-byte buffer, so it is not a truncation: {}",
        value["warnings"]
    );

    // An in-bound basename pattern must not warn.
    let short = "rule r:\n  notify write file \"**/.env\" if A\n  because \"x\"\n";
    let output = run(&["--rule", short, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "pattern_matcher_length_exceeded"),
        "in-bound suffix must not warn, got {}",
        value["warnings"]
    );
}

#[test]
fn compile_json_warns_when_a_pattern_lowers_to_an_empty_literal() {
    // An exec pattern whose basename is `*` (e.g. `exec "src/*"`) lowers to a
    // PREFIX matcher with an empty literal, and the kernel rejects an empty
    // pattern, so the rule can never match.
    let policy = "rule r:\n  kill exec \"src/*\" if A\n  because \"x\"\n";
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "pattern_empty_literal"),
        "expected empty-literal warning, got {}",
        value["warnings"]
    );

    // `*` is ANY and always matches, so it must not warn.
    let any = "rule r:\n  kill exec \"*\" if A\n  because \"x\"\n";
    let output = run(&["--rule", any, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "pattern_empty_literal"),
        "ANY must not warn, got {}",
        value["warnings"]
    );
}

#[test]
fn compile_json_warns_that_an_argv_token_on_a_non_exec_clause_is_ignored() {
    // The kernel consults `@arg` only for exec clauses (argv exists only after
    // exec). On any other op the token is stored but never checked, so the
    // clause silently matches every target the pattern names: an over-match, not
    // a narrower rule.
    let policy = "rule r:\n  block write file \"/y/**\" \"tok\" if A\n  because \"x\"\n";
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "argv_token_ignored_for_non_exec"),
        "expected ignored-argv warning, got {}",
        value["warnings"]
    );

    // An exec clause with an argv token is the supported form and must not warn.
    let exec = "rule r:\n  kill exec \"git\" \"push\" if A\n  because \"x\"\n";
    let output = run(&["--rule", exec, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "argv_token_ignored_for_non_exec"),
        "exec argv must not warn, got {}",
        value["warnings"]
    );
}

#[test]
fn compile_to_blob_reports_policy_warnings_on_stderr() {
    // The minimal `compile --out` path (the documented way to produce a blob)
    // must not write a blob containing a dead rule and report success silently.
    // Every warning it prints is derived from the policy and the blob alone, so
    // it holds wherever the blob is enforced.
    let dir = std::env::temp_dir().join("actplane-plain-compile-warn");
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("policy.bin");
    let out_s = out.to_str().unwrap();

    // `block exec` with an argv token can never block: argv exists only after
    // exec, so the LSM pre-op hook skips the rule. This is the highest-value
    // warning to surface, because the policy reads as an enforcement it is not.
    let dead =
        "source A = exec \"a\"\nrule r:\n  block exec \"git\" \"push\" if A\n  because \"x\"\n";
    let output = run(&["--rule", dead, "compile", "--out", out_s, "--force"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let err = stderr(&output);
    assert!(
        err.contains("argv_block_exec_post_exec_only"),
        "expected the dead-clause warning on stderr, got: {err}"
    );
    assert!(
        err.contains("compiled"),
        "compile should still report the blob it wrote"
    );

    // The host-dependent BPF-LSM warning must NOT appear here: this machine may
    // not be the one enforcing the blob, so a warning about its LSM is noise.
    assert!(
        !err.contains("bpf_lsm_inactive_for_block"),
        "host-dependent warning leaked into the portable path: {err}"
    );

    let good = "source A = exec \"a\"\nrule r:\n  kill exec \"git\" if A\n  because \"x\"\n";
    let output = run(&["--rule", good, "compile", "--out", out_s, "--force"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        !stderr(&output).contains("ActPlane: warning"),
        "clean policy must not warn, got: {}",
        stderr(&output)
    );
}

#[test]
fn lsm_inactive_warning_applies_only_to_block_clauses() {
    // Only `block` needs BPF-LSM: `notify` and `kill` run on tracepoint paths,
    // so an inactive LSM does not affect them. The warning message names
    // "`block <op>`", so firing it on a `notify`/`kill` clause both misdescribes
    // the clause and points at a fix (enable LSM) irrelevant to it.
    let warnings_for = |rule: &str| -> Vec<String> {
        let output = run(&["--rule", rule, "compile", "--json"]);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("compile --json stdout");
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|w| w["code"].as_str().map(str::to_string))
            .collect()
    };

    for (effect, rule) in [
        (
            "notify",
            "rule r:\n  notify exec \"git\"\n  because \"x\"\n",
        ),
        ("kill", "rule r:\n  kill exec \"git\"\n  because \"x\"\n"),
        (
            "block+argv",
            "rule r:\n  block exec \"git\" \"push\"\n  because \"x\"\n",
        ),
        (
            "block+unsupported-endpoint",
            "rule r:\n  block connect endpoint \"*.example.com\"\n  because \"x\"\n",
        ),
    ] {
        let codes = warnings_for(rule);
        assert!(
            !codes.iter().any(|c| c == "bpf_lsm_inactive_for_block"),
            "`{effect}` does not depend on BPF-LSM, so it must not warn; got {codes:?}"
        );
    }

    // The `block exec` with an argv token is unsupported for the argv reason,
    // which is host-independent and should be the warning reported.
    let argv_codes = warnings_for("rule r:\n  block exec \"git\" \"push\"\n  because \"x\"\n");
    assert!(
        argv_codes
            .iter()
            .any(|c| c == "argv_block_exec_post_exec_only"),
        "argv-token block is dead regardless of LSM; got {argv_codes:?}"
    );
}

#[test]
fn shipped_policies_compile_without_warnings() {
    // Every policy the repo ships or documents is a worked example. If one uses
    // a form the kernel cannot enforce, the example teaches a policy that does
    // not do what it says (the `block exec "git" "commit"` trap: argv exists only
    // after exec, so the pre-op hook skips the rule; or a gate literal longer
    // than the kernel's 16-byte contains window, which the compiler shortens to
    // an over-matching substring). Compile each one and fail on any warning, so
    // a dead rule or a truncating literal cannot re-enter.
    //
    // The corpus is every tracked `*.yaml`/`*.yml` that carries a policy body,
    // not just `test/policies/`: this repo's own live `actplane.yaml` sits at the
    // root, and a directory-only scan let its over-matching gate ship unnoticed.
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let listing = Command::new("git")
        .args(["-C", &root, "ls-files", "*.yaml", "*.yml"])
        .output()
        .unwrap_or_else(|e| panic!("run git ls-files: {e}"));
    assert!(
        listing.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let tracked = String::from_utf8(listing.stdout).expect("git ls-files utf8");
    let mut checked = 0usize;
    for rel in tracked.lines() {
        let path = format!("{root}/{rel}");
        let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        // A policy file declares a top-level `policy:` block (flat or per-domain)
        // or `rules:`/`domains:` maps. Skip data files such as `e2e_cases.yaml`
        // and CI/dependabot config.
        let is_policy = body.lines().any(|l| {
            let t = l.trim_end();
            t.starts_with("policy:") || t.starts_with("rules:") || t.starts_with("domains:")
        });
        if !is_policy {
            continue;
        }
        // `test/policies/invalid/` fixtures exist to fail compilation.
        if rel.starts_with("test/policies/invalid/") {
            continue;
        }
        let out = std::env::temp_dir().join("actplane-corpus-warn-check.bin");
        let output = run(&[
            "--policy",
            &path,
            "compile",
            "--out",
            out.to_str().unwrap(),
            "--force",
        ]);
        assert!(
            output.status.success(),
            "{rel} failed to compile: {}",
            stderr(&output)
        );
        let err = stderr(&output);
        assert!(
            !err.contains("ActPlane: warning"),
            "{rel} compiles with a warning, so the example may not enforce what it states:\n{err}"
        );
        // An absolute policy target lowers to a prefix matcher over the literal
        // text, so a path baked into the author's home directory compiles
        // warning-free yet matches nothing on any other machine: the shipped
        // `policies/readonly.yaml` confined writes to
        // `/home/yunwei37/workspace/ActPlane/**` and was a no-op everywhere else
        // while its `because` claimed a workspace-wide read-only policy. A
        // shipped example must name a host-independent scope (`/**`, a repo
        // path), never a `/home/<user>/` or `/Users/<user>/` path.
        for (n, line) in body.lines().enumerate() {
            for marker in ["/home/", "/Users/"] {
                if let Some(at) = line.find(marker) {
                    let tail = &line[at..];
                    panic!(
                        "{rel}:{} hardcodes a user path `{}` in a shipped policy, so the rule \
                         matches only on the author's machine",
                        n + 1,
                        tail.split_whitespace().next().unwrap_or(tail)
                    );
                }
            }
        }
        checked += 1;
    }
    // An exact count: a tracked policy that stops being recognized as one (its
    // `policy:`/`rules:`/`domains:` head renamed) would otherwise drop out of
    // the population unnoticed.
    assert_eq!(checked, 28, "expected the policy corpus, found {checked}");
}

/// Inline policies embedded under `policy: |-` in a case file.
///
/// `test/e2e_cases.yaml` and `test/e2e_file_flow_cases.yaml` are case tables,
/// not policy configs, so `shipped_policies_compile_without_warnings` skips
/// them. Their per-case policies are still shipped, CI-executed examples, and
/// `script/e2e_examples.sh` fails only on a compile *error*: a policy that
/// compiles with an over-matching pattern would run green while not enforcing
/// what the case's `expect:` block claims. Extract and compile them here.
fn embedded_case_policies(yaml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines: Vec<&str> = yaml.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        // A case policy header sits at four spaces; its body is indented six.
        if lines[i].trim_end() == "    policy: |-" {
            let mut body = String::new();
            i += 1;
            while i < lines.len() && lines[i].starts_with("      ") {
                body.push_str(&lines[i][6..]);
                body.push('\n');
                i += 1;
            }
            if !body.trim().is_empty() {
                out.push(body);
            }
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn embedded_e2e_case_policies_compile_without_warnings() {
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    // `script/e2e_examples.sh:17,44` binds `${D}` to an absolute workspace and
    // substitutes it into every case's policy before compiling. An absolute path
    // is cut at its first wildcard, so it lowers to a `prefix`/`suffix` matcher
    // rather than the 16-byte-capped `contains` a repo-relative path uses; pass a
    // concrete absolute path here so the compile sees the same form the runner
    // does, not the literal `${D}` (which would warn spuriously).
    let concrete = "/tmp/actplane-e2e";
    let mut checked = 0usize;
    for rel in ["test/e2e_cases.yaml", "test/e2e_file_flow_cases.yaml"] {
        let path = format!("{root}/{rel}");
        let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let policies = embedded_case_policies(&body);
        assert!(
            !policies.is_empty(),
            "{rel} has no embedded case policies; the extractor drifted"
        );
        for (n, policy) in policies.iter().enumerate() {
            let substituted = policy.replace("${D}", concrete);
            let mut yaml = String::from("version: 1\npolicy: |\n");
            for line in substituted.lines() {
                yaml.push_str("  ");
                yaml.push_str(line);
                yaml.push('\n');
            }
            let file = std::env::temp_dir().join(format!("actplane-e2e-policy-{n}.yaml"));
            fs::write(&file, &yaml).unwrap_or_else(|e| panic!("write {}: {e}", file.display()));
            let out = std::env::temp_dir().join("actplane-e2e-policy.bin");
            let output = run(&[
                "--policy",
                file.to_str().unwrap(),
                "compile",
                "--out",
                out.to_str().unwrap(),
                "--force",
            ]);
            assert!(
                output.status.success(),
                "{rel} case {n} failed to compile: {}",
                stderr(&output)
            );
            let err = stderr(&output);
            assert!(
                !err.contains("ActPlane: warning"),
                "{rel} case {n} compiles with a warning, so the case may not test what its `expect:` block states:\n{err}\npolicy:\n{substituted}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 26, "expected 16 + 10 e2e case policies");
}

#[test]
fn live_e2e_cases_do_not_depend_on_bpf_lsm() {
    // A case's `expect:` block states a violation count observed on the CI
    // runner. `block` needs BPF-LSM, and the privileged job's runner has none
    // (`/sys/kernel/security/lsm` carries no `bpf`), so a case whose clause is
    // `block` is admitted as unsupported there and can never fire: the stated
    // count is unsatisfiable and the live step fails. `compile --out` does not
    // expose this: its blob is portable, and the host-dependent warning is
    // attached only where a host is known, so `Some(false)` vs `None` is the
    // whole difference. Force the tracepoint backend, which is exactly the
    // runner's mode, and read the warning the case would meet there.
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let forced = |policy: &str| -> Vec<String> {
        let file = std::env::temp_dir().join("actplane-e2e-lsm.yaml");
        fs::write(&file, policy).unwrap_or_else(|e| panic!("write {}: {e}", file.display()));
        let out = Command::new(actplane())
            .env("ACTPLANE_FORCE_TRACEPOINT", "1")
            .args(["--policy", file.to_str().unwrap(), "compile", "--json"])
            .output()
            .unwrap_or_else(|e| panic!("run actplane: {e}"));
        assert!(out.status.success(), "stderr: {}", stderr(&out));
        let value: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("compile --json stdout");
        value["warnings"]
            .as_array()
            .expect("warnings array")
            .iter()
            .filter_map(|w| w["code"].as_str().map(str::to_string))
            .collect()
    };

    // Non-vacuous: a `block write` clause under the forced tracepoint backend
    // must report the code, so a case that carried one would be caught. This is
    // the shape the E13 case had before the guard existed.
    let block_case = "version: 1\npolicy: |\n  source AGENT = exec \"**/codex\"\n  rule r:\n    block write file \"/tmp/x/prod.db\" if AGENT\n    because \"x\"\n";
    assert!(
        forced(block_case)
            .iter()
            .any(|c| c == "bpf_lsm_inactive_for_block"),
        "a `block` clause must warn under the forced tracepoint backend; the probe did not fire"
    );

    let mut checked = 0usize;
    for rel in ["test/e2e_cases.yaml", "test/e2e_file_flow_cases.yaml"] {
        let path = format!("{root}/{rel}");
        let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        for (n, policy) in embedded_case_policies(&body).iter().enumerate() {
            let substituted = policy.replace("${D}", "/tmp/actplane-e2e");
            let mut yaml = String::from("version: 1\npolicy: |\n");
            for line in substituted.lines() {
                yaml.push_str("  ");
                yaml.push_str(line);
                yaml.push('\n');
            }
            let codes = forced(&yaml);
            assert!(
                !codes.iter().any(|c| c == "bpf_lsm_inactive_for_block"),
                "{rel} case {n} uses a `block` clause, which the no-LSM CI runner admits as \
                 unsupported, so its `expect:` count can never be met:\n{substituted}\n\
                 warnings: {codes:?}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 26, "expected 16 + 10 e2e case policies");
}

#[test]
fn doctor_reports_the_forced_tracepoint_backend() {
    // The doctor's BPF-LSM line must describe what the engine will actually do.
    // `compile --json`/`--explain` and `ebpf_ifc_engine::bpf_lsm_active` all
    // fold in `ACTPLANE_FORCE_TRACEPOINT`, but the doctor once read the raw
    // `/sys/kernel/security/lsm` list, so on a host with `bpf` in that list it
    // printed `active` under the flag while `block` could never fire. Asserting
    // the flag's own text keeps this host-independent: without the flag the
    // message is the ordinary active/not-active line, which the CI runner's
    // LSM list decides.
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("actplane.yaml");
    fs::write(
        &policy,
        "version: 1\npolicy: |\n  source AGENT = exec \"**/codex\"\n  rule r:\n    \
         block write file \"/tmp/x/prod.db\" if AGENT\n    because \"x\"\n",
    )
    .unwrap();

    let forced = Command::new(actplane())
        .env("ACTPLANE_FORCE_TRACEPOINT", "1")
        .args(["--policy", policy.to_str().unwrap(), "doctor"])
        .output()
        .unwrap_or_else(|e| panic!("run actplane doctor: {e}"));
    let out = stdout(&forced);
    assert!(
        out.contains("treated as unavailable by ACTPLANE_FORCE_TRACEPOINT"),
        "doctor ignored ACTPLANE_FORCE_TRACEPOINT in its BPF-LSM line:\n{out}"
    );
    assert!(
        !out.contains("✓ BPF-LSM: active"),
        "doctor reported BPF-LSM active under the forced tracepoint backend:\n{out}"
    );
    // The line must not end in a dangling `()` when the host exposes no LSM
    // list (a container has no `/sys/kernel/security/lsm`), which read like a
    // value failed to render.
    for line in out.lines().filter(|l| l.contains("BPF-LSM:")) {
        assert!(
            !line.trim_end().ends_with("()"),
            "doctor BPF-LSM line has an empty parenthetical:\n{line}"
        );
    }
}

#[test]
fn e2e_case_header_lists_every_seeded_fixture() {
    // `test/e2e_cases.yaml`'s header tells a reader (and a future case author)
    // which fixtures the driver seeds in `${D}`. A case may only use a fixture
    // that appears there, and the header drifted once: the driver seeds `pnpm`
    // (`script/e2e_examples.sh`, the `/bin/bash` copy list) and the E5b case
    // runs `${D}/pnpm`, but the header omitted it. Read both lists from the
    // driver rather than restating them, so a fixture added to the driver
    // without the header fails here instead of surfacing as a case with no
    // binary to run.
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let script = fs::read_to_string(format!("{root}/script/e2e_examples.sh")).expect("read driver");
    let header = fs::read_to_string(format!("{root}/test/e2e_cases.yaml")).expect("read e2e cases");
    let header: String = header
        .lines()
        .take_while(|l| l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    // The driver seeds four classes, each on its own line: directories
    // (`mkdir -p "$D/..."`), `/bin/bash` copies (`for h in ...; do cp
    // /bin/bash`), `/bin/true` copies (`cp /bin/true "$D/..."`), and file
    // fixtures (`echo ... > "$D/..."`). Extract each from the driver and
    // require the header to mention it, rather than restating the lists.
    let dollar = |s: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = s;
        while let Some(at) = rest.find("$D/") {
            rest = &rest[at + 3..];
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '/' || c == '.'))
                .unwrap_or(rest.len());
            out.push(rest[..end].to_string());
            rest = &rest[end..];
        }
        out
    };
    // Scan only the driver's fixture block, bounded by its `# --- fixtures`
    // banner and the next section banner: elsewhere in the driver `${D}/p.yaml`
    // and `${D}/cc.txt` are *produced* per case, not seeded, so the whole-file
    // scan mistook them for fixtures.
    let fixtures: Vec<&str> = script
        .split("# --- fixtures")
        .nth(1)
        .expect("the driver must keep a `# --- fixtures` banner")
        .lines()
        .take_while(|l| !l.starts_with("# ---"))
        .collect();
    let mut seeded: Vec<String> = Vec::new();
    for line in &fixtures {
        let line = line.trim();
        if line.contains("mkdir") || line.starts_with("cp /bin/true") || line.starts_with("echo") {
            seeded.extend(dollar(line));
        } else if let Some(rest) = line.strip_prefix("for h in ") {
            let names = rest
                .split_once("; do cp /bin/")
                .map(|(n, _)| n)
                .unwrap_or(rest);
            seeded.extend(names.split_whitespace().map(str::to_string));
        }
    }
    assert!(
        seeded.contains(&"pnpm".to_string()) && seeded.contains(&"work".to_string()),
        "the driver fixture scan found {seeded:?}; did the fixture block move?"
    );
    for name in &seeded {
        assert!(
            header.contains(name.as_str()),
            "`script/e2e_examples.sh` seeds `${{D}}/{name}`, but the `test/e2e_cases.yaml` header \
             does not list it, so a case using it reads an undocumented fixture"
        );
    }
}

#[test]
fn claude_md_names_tests_that_exist_in_the_file_it_cites() {
    // `CLAUDE.md` is the repo's operating manual, and it pins the ABI guards by
    // name: "`config_blob_is_fixed_size` in `dsl/mod.rs`", "`test_abi_layout` in
    // `bpf/test_taint.c`", and so on. A reader who greps one of those names must
    // find the test. The size guard shipped as "the `fixed-size` test in
    // `dsl/mod.rs`", a name no test carried, so the grep found only comments.
    // Every `<ident>` in `<file>` claim is checked against that file.
    let root = std::path::PathBuf::from(format!("{}/../..", env!("CARGO_MANIFEST_DIR")));
    let doc = fs::read_to_string(root.join("CLAUDE.md")).expect("read CLAUDE.md");
    // A claim may wrap a line, so flatten whitespace before scanning.
    let flat = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    let quotes: Vec<&str> = flat.split('`').collect();
    // The citation is relative to the citing crate (`dsl/mod.rs`, `lower.rs`),
    // so resolve it as a suffix of any tracked file. One `ls-files` serves the
    // whole scan.
    let listing = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "ls-files"])
        .output()
        .unwrap_or_else(|e| panic!("run git ls-files: {e}"));
    let tracked = String::from_utf8_lossy(&listing.stdout);
    let tracked: Vec<&str> = tracked.lines().collect();
    let mut checked = 0usize;
    for win in quotes.windows(4) {
        let [ident, mid, path, _] = win else { continue };
        // Two phrasings appear: "`X` in `Y`" and "the `X` test in `Y`". The
        // second is exactly how the phantom shipped, so both must be scanned.
        if !matches!(mid.trim(), "in" | "test in")
            || !path.ends_with(".rs") && !path.ends_with(".c")
        {
            continue;
        }
        if !ident
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            || !ident
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            continue;
        }
        let matches: Vec<std::path::PathBuf> = tracked
            .iter()
            .filter(|f| *f == path || f.ends_with(&format!("/{path}")))
            .map(|f| root.join(f))
            .collect();
        assert!(
            !matches.is_empty(),
            "CLAUDE.md cites `{ident}` in `{path}`, but no tracked file has that path"
        );
        // The claim is "the `<ident>` test lives in `<path>`", so a mention in a
        // comment or string is not enough: the file must *define* it. The
        // phantom `fixed-size` name passed a plain substring check because
        // `dsl/mod.rs` mentions "fixed-size" in three comments while no test
        // carries it. Match a definition shape (`fn`/`void`/`int` + name +
        // `(`), which covers both the Rust `fn` tests and the C `void` ones.
        let defined = |s: &str| {
            ["fn ", "void ", "int "]
                .iter()
                .any(|kw| s.contains(&format!("{kw}{ident}(")))
        };
        assert!(
            matches
                .iter()
                .any(|c| fs::read_to_string(c).is_ok_and(|s| defined(&s))),
            "CLAUDE.md cites `{ident}` in `{path}`, but no `{path}` defines that \
             identifier (a mention in a comment or string does not count), so a \
             reader grepping it for the test finds nothing to run"
        );
        checked += 1;
    }
    // Non-vacuity: the ABI paragraph names seven guards this way. A parsing
    // change that stops matching them would otherwise pass silently.
    assert!(
        checked >= 5,
        "expected the CLAUDE.md ABI paragraph to name at least five tests, found {checked}"
    );
}

/// Every fenced code block in a markdown file, with its opening fence stripped.
fn fenced_blocks(md: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_block = false;
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            if in_block {
                out.push(std::mem::take(&mut cur));
            }
            in_block = !in_block;
        } else if in_block {
            cur.push_str(line);
            cur.push('\n');
        }
    }
    out
}

#[test]
fn documented_dsl_snippets_compile_without_warnings() {
    // The fenced DSL blocks in the docs are the rule language's worked examples.
    // A block that quietly lowers to an over-matching pattern (a repo-relative
    // literal longer than the kernel's 16-byte contains window, or a `*` that
    // survives into a matcher) shows a rule that does not mean what the prose
    // beside it says. Compile every block that is a complete policy and fail on
    // any warning. Grammar sketches (`rule NAME` with no clause body) and raw
    // YAML blocks are not complete policies and are skipped by the compile
    // itself, so they do not need a special case here.
    let root = std::path::PathBuf::from(format!("{}/../..", env!("CARGO_MANIFEST_DIR")));
    // Every tracked `.md`, not just `docs/`: the root `README.md` carries the
    // most-read worked example, and a `docs/`-only walk left it unchecked. The
    // paper tree is a submodule, so `git ls-files '*.md'` never descends into it.
    let listing = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "ls-files", "*.md"])
        .output()
        .unwrap_or_else(|e| panic!("run git ls-files: {e}"));
    assert!(
        listing.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let tracked = String::from_utf8(listing.stdout).expect("git ls-files utf8");
    let files: Vec<std::path::PathBuf> = tracked.lines().map(|r| root.join(r)).collect();
    assert!(
        files.len() > 5,
        "expected tracked markdown, found {}",
        files.len()
    );
    let mut checked = 0usize;
    for file in &files {
        let Ok(md) = fs::read_to_string(file) else {
            continue;
        };
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string();
        for (n, block) in fenced_blocks(&md).iter().enumerate() {
            let is_dsl = block.lines().any(|l| {
                let t = l.trim_start();
                t.starts_with("source ") || t.starts_with("rule ")
            });
            if !is_dsl {
                continue;
            }
            // A block may be bare DSL or a complete `actplane.yaml`. Wrapping
            // the latter in another `policy: |` nests its top-level keys under a
            // scalar and turns it into a parse error the `continue` below hides,
            // so detect the YAML form and compile it verbatim.
            let is_yaml = block
                .lines()
                .any(|l| l.trim_start().starts_with("version:"))
                && block.lines().any(|l| {
                    let t = l.trim_start();
                    t.starts_with("policy:") || t.starts_with("rules:") || t.starts_with("domains:")
                });
            let yaml = if is_yaml {
                block.to_string()
            } else {
                let mut yaml = String::from("version: 1\npolicy: |\n");
                for line in block.lines() {
                    yaml.push_str("  ");
                    yaml.push_str(line);
                    yaml.push('\n');
                }
                yaml
            };
            // A documented example that names an absolute path under `/home/`
            // or `/Users/` lowers to a prefix matcher over that literal, so on a
            // reader's machine it matches nothing while the prose describes a
            // workspace-wide rule (the `policies/readonly.yaml` defect). Skip no
            // block for this: even a fragment that will not compile is still a
            // path a reader may copy.
            for line in block.lines() {
                if let Some(at) = line.find("/home/").or_else(|| line.find("/Users/")) {
                    panic!(
                        "{rel} block {n} hardcodes a user path `{}`, which matches only on the \
                         author's machine:\n{block}",
                        &line[at..].split_whitespace().next().unwrap_or(&line[at..])
                    );
                }
            }
            let policy = std::env::temp_dir().join("actplane-doc-snippet.yaml");
            fs::write(&policy, &yaml).unwrap_or_else(|e| panic!("write {}: {e}", policy.display()));
            let out = std::env::temp_dir().join("actplane-doc-snippet.bin");
            let output = run(&[
                "--policy",
                policy.to_str().unwrap(),
                "compile",
                "--out",
                out.to_str().unwrap(),
                "--force",
            ]);
            if !output.status.success() {
                // Not a complete policy: a grammar fragment or a domain map.
                continue;
            }
            let err = stderr(&output);
            assert!(
                !err.contains("ActPlane: warning"),
                "{rel} block {n} compiles with a warning, so the documented rule does not \
                 enforce what the surrounding prose states:\n{err}\nblock:\n{block}"
            );
            checked += 1;
        }
    }
    // An exact count: the tree's complete-policy blocks all compile, so a block
    // that silently starts failing the compile (and taking the `continue`
    // above) would otherwise drop out of the population unnoticed.
    assert_eq!(
        checked, 25,
        "expected 25 documented complete-policy DSL examples, found {checked}"
    );
}

#[test]
fn worked_example_counts_in_prose_match_the_section_list() {
    // `docs/rule-language.md` section 3 is titled "Worked examples" and numbers
    // each one (`### E1`, `### E2`, ...). `crates/actplane-cli/README.md` states
    // how many there are ("the policy grammar and N worked examples"), and that
    // number went stale at 13 while the doc had grown to E14. A reader counting
    // the sections finds a mismatch, and no guard noticed because the numeral is
    // prose, not a fenced block the snippet walk compiles.
    let root = std::path::PathBuf::from(format!("{}/../..", env!("CARGO_MANIFEST_DIR")));
    let doc =
        fs::read_to_string(root.join("docs/rule-language.md")).expect("read rule-language.md");
    let sections = doc
        .lines()
        .filter(|l| {
            l.strip_prefix("### E").is_some_and(|rest| {
                rest.split_once(' ')
                    .is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
            })
        })
        .count();
    assert!(
        sections >= 10,
        "expected the rule-language doc to number its worked examples; found {sections}"
    );

    let listing = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "ls-files", "*.md"])
        .output()
        .unwrap_or_else(|e| panic!("run git ls-files: {e}"));
    assert!(listing.status.success(), "git ls-files failed");
    let tracked = String::from_utf8(listing.stdout).expect("git ls-files utf8");
    let mut stated = 0usize;
    for rel in tracked.lines() {
        let Ok(md) = fs::read_to_string(root.join(rel)) else {
            continue;
        };
        // Match "N worked examples" (the phrase the crate README uses) without a
        // regex dependency: find the phrase, then read the trailing integer off
        // the preceding word.
        for (at, _) in md.match_indices("worked examples") {
            let before = &md[..at];
            let word = before.split_whitespace().last().unwrap_or("");
            let Ok(n) = word.parse::<usize>() else {
                continue;
            };
            assert_eq!(
                n, sections,
                "{rel} states `{n} worked examples`, but docs/rule-language.md \
                 numbers {sections} of them"
            );
            stated += 1;
        }
    }
    assert!(
        stated >= 1,
        "no markdown states a worked-example count; did the phrasing move?"
    );
}

#[test]
fn cookbook_run_examples_use_a_policy_that_declares_the_runner_label() {
    // `run`/auto-attach seeds the protected process with the runner label
    // (`runner_label` in actplane-runtime rejects a policy that declares or
    // references neither COMMAND nor AGENT), so a cookbook command that runs a
    // policy lacking both is dead on arrival. The failure happens at policy
    // validation, before attach, so it is checkable without privileges.
    let doc = fs::read_to_string(format!(
        "{}/../../docs/cookbook.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read docs/cookbook.md");
    let dir = format!("{}/../../test/policies", env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0usize;
    for line in doc.lines() {
        let Some(idx) = line.find("run --") else {
            continue;
        };
        let Some(start) = line.find("test/policies/") else {
            continue;
        };
        let rest = &line[start..];
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let rel = &rest[..end];
        let policy = format!("{dir}/{}", rel.strip_prefix("test/policies/").unwrap());
        let src = fs::read_to_string(&policy)
            .unwrap_or_else(|e| panic!("read {policy} named by `{line}` (at {idx}): {e}"));
        assert!(
            src.contains("COMMAND") || src.contains("AGENT"),
            "`{line}` runs {rel}, which declares neither COMMAND nor AGENT, so \
             `actplane run` rejects it before attach"
        );
        checked += 1;
    }
    assert!(
        checked >= 1,
        "expected at least one `run --` cookbook example, found {checked}"
    );
}

#[test]
fn documented_template_blocks_match_the_shipped_template() {
    // `docs/cookbook.md` shows a DSL block for a scenario and then tells the
    // reader to get the same policy with `actplane init --template <id>`. The
    // block and the template can disagree: the read-only review section showed
    // a three-clause rule (`block write`, `block unlink`, `block exec "git"`)
    // and claimed git execution reports `readonly-review`, while the shipped
    // template (`crates/actplane-cli/src/templates.rs:360`) carries only the
    // write and unlink clauses. A reader who follows the command gets a policy
    // that does not stop git, and the prose told them it would. Compare the
    // clauses of any documented block that sits directly above an
    // `init --template <id>` whose rule name is the template id.
    let root = std::path::PathBuf::from(format!("{}/../..", env!("CARGO_MANIFEST_DIR")));
    let listing = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "ls-files", "*.md"])
        .output()
        .unwrap_or_else(|e| panic!("run git ls-files: {e}"));
    let tracked = String::from_utf8(listing.stdout).expect("git ls-files utf8");
    // Clause lines a rule body can carry, normalized to their whitespace runs.
    let clauses = |src: &str| -> Vec<String> {
        let mut out: Vec<String> = src
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                t.starts_with("block ") || t.starts_with("kill ") || t.starts_with("notify ")
            })
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        out.sort();
        out
    };
    let mut checked = 0usize;
    for rel in tracked.lines() {
        let Ok(md) = fs::read_to_string(root.join(rel)) else {
            continue;
        };
        // Fenced blocks with their end line, so a block can be tied to a later
        // command without a second parse of the fence delimiters.
        let mut blocks: Vec<(usize, String)> = Vec::new();
        let mut cur = String::new();
        let mut end = 0usize;
        let mut in_block = false;
        for (n, line) in md.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                if in_block {
                    blocks.push((end, std::mem::take(&mut cur)));
                }
                in_block = !in_block;
            } else if in_block {
                cur.push_str(line);
                cur.push('\n');
                end = n + 1;
            }
        }
        // Section start lines, so a block is only paired with a command in its
        // own `##` section: the "From Template to Policy" section cites
        // `test-before-commit`, whose block lives in an earlier section, and a
        // document-wide search would pair them across section boundaries.
        let section_starts: Vec<usize> = md
            .lines()
            .enumerate()
            .filter(|(_, l)| l.starts_with("## "))
            .map(|(n, _)| n)
            .collect();
        for (n, line) in md.lines().enumerate() {
            let Some(at) = line.find("init --template ") else {
                continue;
            };
            let id: String = line[at + "init --template ".len()..]
                .chars()
                .take_while(|c| !c.is_whitespace())
                .collect();
            if id.is_empty() {
                continue;
            }
            let section_start = section_starts
                .iter()
                .copied()
                .filter(|s| *s < n)
                .next_back()
                .unwrap_or(0);
            // The nearest block in this section whose rule is named for the
            // template.
            let doc_block = blocks
                .iter()
                .filter(|(bend, _)| *bend < n + 1 && *bend > section_start)
                .rev()
                .find(|(_, text)| {
                    text.lines()
                        .any(|l| l.trim_start().starts_with(&format!("rule {id}:")))
                });
            let Some((_, doc_block)) = doc_block else {
                continue;
            };
            let rendered = run(&["init", "--template", &id, "--print"]);
            assert!(
                rendered.status.success(),
                "render template {id}: {}",
                stderr(&rendered)
            );
            let template = stdout(&rendered);
            assert_eq!(
                clauses(doc_block),
                clauses(&template),
                "{rel} block above `init --template {id}` (line {}) has different clauses \
                 than the shipped template, so following the command gives a policy the \
                 prose did not describe",
                n + 1
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 1,
        "expected a documented block above an `init --template` whose rule matches the id"
    );
}

#[test]
fn documented_warning_codes_match_the_cli() {
    // `docs/rule-language.md` lists the warning codes a user may see. A code that
    // reaches users but is undocumented is a gap; a documented code that no
    // the pattern family and the rule-condition family. The doctor-owned codes
    // are pinned both directions too: their emitted set is read from the
    // doctor's `code: "..."` literals, and their documented set is selected by
    // the first segments those emitted codes themselves carry (`argv`, `bpf`,
    // `endpoint`, `repo`, `rule`), so neither direction needs a hand-written
    // code list to drift.
    let doc = fs::read_to_string(format!(
        "{}/../../docs/rule-language.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read docs/rule-language.md");
    let documented: std::collections::BTreeSet<&str> = doc
        .split("`")
        .filter(|tok| {
            // Warning codes are lower_snake with an underscore and no spaces.
            !tok.is_empty()
                && tok.contains('_')
                && tok
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && tok.len() > 8
        })
        .collect();

    // Every code the CLI can emit. The pattern-lowering and rule-condition
    // families are read from the compiler's own lists rather than restated,
    // because a hand-written copy drifted: `pattern_empty_literal` was emitted
    // by the binary but omitted here, so this guard would not have caught its
    // doc changing.
    //
    // The doctor codes are read from the doctor's source the same way. They are
    // not compiler-owned, but they are all `code: "..."` literals in
    // `src/doctor.rs`, so scanning that file enumerates them without a second
    // list to drift: renaming a code there now fails this guard until the doc
    // is updated.
    let doctor_src = fs::read_to_string(format!("{}/src/doctor.rs", env!("CARGO_MANIFEST_DIR")))
        .expect("read crates/actplane-cli/src/doctor.rs");
    let doctor_codes: Vec<&str> = doctor_warning_codes(&doctor_src);
    assert!(
        doctor_codes.contains(&"rule_missing_because"),
        "the doctor-code scan found no known code; did `code: \"...\"` literals move? got {doctor_codes:?}"
    );
    // The pattern-lowering family and the rule-condition codes all come from
    // the compiler; binding them keeps a new code from reaching users
    // undocumented. Both families are read from the compiler's own lists rather
    // than restated, because a hand-written copy drifts (see
    // `PATTERN_WARNING_CODES`).
    let mut emitted: Vec<&str> = doctor_codes.clone();
    emitted.extend(actplane_ifc_compiler::dsl::PATTERN_WARNING_CODES);
    emitted.extend(actplane_ifc_compiler::dsl::RULE_CONDITION_WARNING_CODES);
    for code in &emitted {
        assert!(
            documented.contains(code),
            "warning code `{code}` is emitted but not documented in docs/rule-language.md"
        );
    }

    // Reverse direction, for the family the doc lists explicitly: the pattern
    // codes named in that sentence must be exactly the ones the compiler can
    // emit, so a code added to the doc but not the compiler (a phantom) fails.
    let doc_pattern_list: std::collections::BTreeSet<&str> = doc
        .split("pattern-lowering warnings (")
        .nth(1)
        .expect("docs must list the pattern-lowering warnings")
        .split(" are stored")
        .next()
        .expect("the pattern-lowering list must end in `are stored`")
        .split('`')
        .filter(|t| {
            t.contains('_')
                && t.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .collect();
    let compiled_pattern_codes: std::collections::BTreeSet<&str> =
        actplane_ifc_compiler::dsl::PATTERN_WARNING_CODES
            .iter()
            .copied()
            .collect();
    assert_eq!(
        doc_pattern_list, compiled_pattern_codes,
        "the pattern codes listed in docs/rule-language.md must be exactly \
         `PATTERN_WARNING_CODES`"
    );

    // The `rule_condition_*` family heads its own bullet list ("- `code`: ..."),
    // so a phantom code there is representable the same way. A code added to
    // the doc but not the compiler would send the reader chasing a warning the
    // binary cannot emit.
    let doc_rule_condition_list: std::collections::BTreeSet<&str> = doc
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("- `")?;
            let code = rest.split('`').next()?;
            code.starts_with("rule_condition_").then_some(code)
        })
        .collect();
    let compiled_rule_condition_codes: std::collections::BTreeSet<&str> =
        actplane_ifc_compiler::dsl::RULE_CONDITION_WARNING_CODES
            .iter()
            .copied()
            .collect();
    assert_eq!(
        doc_rule_condition_list, compiled_rule_condition_codes,
        "the `rule_condition_*` codes bulleted in docs/rule-language.md must be \
         exactly `RULE_CONDITION_WARNING_CODES`"
    );

    // The doctor family's documented set is selected by the first segments its
    // own emitted codes carry. `rule_condition_*` shares the `rule` first
    // segment but is compiler-owned, so it is excluded explicitly rather than
    // by prefix.
    let compiler_codes: std::collections::BTreeSet<&str> =
        actplane_ifc_compiler::dsl::PATTERN_WARNING_CODES
            .iter()
            .chain(actplane_ifc_compiler::dsl::RULE_CONDITION_WARNING_CODES.iter())
            .copied()
            .collect();
    let doctor_prefixes: std::collections::BTreeSet<&str> = doctor_codes
        .iter()
        .filter_map(|c| c.split('_').next())
        .collect();
    let doc_doctor_list: std::collections::BTreeSet<&str> = doc
        .split('`')
        .filter(|t| {
            t.contains('_')
                && t.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !compiler_codes.contains(*t)
                && t.split('_')
                    .next()
                    .is_some_and(|p| doctor_prefixes.contains(p))
        })
        .collect();
    let emitted_doctor: std::collections::BTreeSet<&str> = doctor_codes.iter().copied().collect();
    assert_eq!(
        doc_doctor_list, emitted_doctor,
        "the doctor warning codes in docs/rule-language.md must be exactly the \
         codes src/doctor.rs emits"
    );
}

#[test]
fn the_capped_literal_witness_in_the_doc_caps_and_empties() {
    // §1.8's capped-`contains` bullet justifies why an emptied literal drops the
    // `pattern_contains_capped` warning by citing a concrete pattern that caps
    // and then empties. The witness must actually exceed the 16-byte window,
    // because a shorter one never caps and reports `pattern_literal_widened`
    // instead, which the sentence's "only `pattern_empty_literal` is reported"
    // claim then contradicts. Bind the doc's own string to the compiler so a
    // placeholder that reads long but lowers short fails here.
    let doc = fs::read_to_string(format!(
        "{}/../../docs/rule-language.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read docs/rule-language.md");
    let sentence = doc
        .lines()
        .find(|l| l.contains("wildcard cleanup above empties it"))
        .expect("the capped-`contains` bullet must cite an emptied witness");
    let witness = sentence
        .split("empties it (`")
        .nth(1)
        .and_then(|rest| rest.split('`').next())
        .expect("the sentence must name its witness in backticks right after `empties it (`");
    let policy = format!("rule r:\n  block write file \"{witness}\" if A\n  because \"x\"\n");
    let output = run(&["--rule", &policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    let codes: Vec<&str> = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["code"].as_str())
        .filter(|c| c.starts_with("pattern_"))
        .collect();
    assert_eq!(
        codes,
        vec!["pattern_empty_literal"],
        "the witness `{witness}` cited for the cap-then-empty path must report \
         exactly `pattern_empty_literal`; a shorter literal reports \
         `pattern_literal_widened` instead and the doc's claim is false"
    );
}

#[test]
fn compile_json_warns_when_a_rule_has_no_because() {
    // The `because` string is the payload forwarded to the agent on a match.
    // Without it a violation carries an empty reason, so the agent learns it was
    // stopped but not why.
    let policy = "rule r:\n  block exec \"git\" if A\n";
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "rule_missing_because"),
        "expected missing-because warning, got {}",
        value["warnings"]
    );

    // A rule with a reason must not warn.
    let with_reason = "rule r:\n  kill exec \"git\" if A\n  because \"explain\"\n";
    let output = run(&["--rule", with_reason, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "rule_missing_because"),
        "reasoned rule must not warn, got {}",
        value["warnings"]
    );
}

#[test]
fn compile_json_warns_that_a_malformed_numeric_endpoint_does_not_fire() {
    // A `connect`/`recv` target with more than four octets has no numeric
    // matcher. The compiler must agree with the doctor and report it, rather
    // than silently truncating `1.2.3.4.5` to a /32 on `1.2.3.4` that then
    // fires for `1.2.3.4` while the doctor says the rule will not fire.
    let policy = "rule r:\n  kill connect endpoint \"1.2.3.4.5\"\n  because \"y\"\n";
    let output = run(&["--rule", policy, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "endpoint_target_unsupported"),
        "expected endpoint_target_unsupported for a 5-octet pattern, got {}",
        value["warnings"]
    );

    // A well-formed 4-octet address must stay silent.
    let ok = "rule r:\n  kill connect endpoint \"1.2.3.4\"\n  because \"y\"\n";
    let output = run(&["--rule", ok, "compile", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json stdout");
    assert!(
        !value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "endpoint_target_unsupported"),
        "a numeric IPv4 target must not warn, got {}",
        value["warnings"]
    );
}

#[test]
fn compile_json_reports_policy_load_errors_as_json() {
    let missing = "/tmp/actplane-definitely-missing-policy.yaml";
    let output = run(&["--policy", missing, "compile", "--json"]);
    assert!(!output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compile --json error stdout");
    assert_eq!(value["schema"], "actplane.compile.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["policy_ref"], missing);
    assert!(
        value["error"]
            .as_str()
            .unwrap_or("")
            .contains("reading /tmp/actplane-definitely-missing-policy.yaml")
    );
}

#[test]
fn compile_explain_writes_report_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("review.txt");
    let policy = r#"
source AGENT = exec "**"

rule no-network:
  notify connect endpoint "*" if AGENT unless target "127."
  because "network review"
"#;
    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--explain",
        "--report-out",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty when writing --report-out: {}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("wrote policy review"));
    let artifact = fs::read_to_string(&out).unwrap();
    assert!(artifact.contains("ActPlane policy review"));
    assert!(artifact.contains("rule no-network"));
    assert!(artifact.contains("review scope: selected policy"));
}

#[test]
fn compile_report_out_requires_report_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("review.txt");
    let policy = r#"
rule noop:
  notify exec "git" if true
  because "noop"
"#;
    let output = run(&[
        "--rule",
        policy,
        "compile",
        "--report-out",
        out.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--report-out requires --json or --explain"));
}

#[test]
fn compile_domains_lists_effective_bindings() {
    let policy = fixture("15_domain_bindings.yaml");
    let output = run(&["--policy", &policy, "compile", "--domains"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("* review"));
    assert!(stdout.contains("  session"));
    assert!(stdout.contains("policy: no-git-branch, no-network"));
    assert!(stdout.contains("policy: no-git-branch, readonly"));
}

#[test]
fn compile_writes_kernel_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("policy.bin");
    let policy = fixture("15_domain_bindings.yaml");
    let output = run(&[
        "--policy",
        &policy,
        "--domain",
        "review",
        "compile",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(out.is_file());
    let stderr = stderr(&output);
    assert!(stderr.contains("domain `review`"));
    assert!(stderr.contains("policy: no-git-branch, readonly"));
    assert!(stderr.contains("compiled 2 DSL rule(s), 2 lowered kernel matcher(s)"));
}

#[test]
fn compile_out_respects_force() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("policy.bin");
    fs::write(&out, b"keep").unwrap();
    let policy = fixture("15_domain_bindings.yaml");

    let output = run(&[
        "--policy",
        &policy,
        "compile",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("already exists"));
    assert_eq!(fs::read(&out).unwrap(), b"keep");

    let output = run(&[
        "--policy",
        &policy,
        "compile",
        "--out",
        out.to_str().unwrap(),
        "--force",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_ne!(fs::read(&out).unwrap(), b"keep");
}

#[test]
fn init_lists_and_writes_templates_without_templates_command() {
    let output = run(&["init", "--list-templates"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let list_stdout = stdout(&output);
    assert!(list_stdout.contains("ActPlane policy templates"));
    assert!(list_stdout.contains("no-secret-egress"));
    assert!(list_stdout.contains("test-before-commit"));

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("actplane.yaml");
    let output = run(&[
        "init",
        "--template",
        "workspace-confinement",
        "--set",
        "agent_exec=codex",
        "--set",
        "writable_path=/repo/**",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let written = fs::read_to_string(&out).unwrap();
    assert!(written.contains("# Parameter writable_path: /repo/**"));
    assert!(written.contains("source AGENT = exec \"codex\""));
    assert!(written.contains("unless target \"/repo/**\""));

    let compile = run(&["--policy", out.to_str().unwrap(), "compile", "--explain"]);
    assert!(compile.status.success(), "stderr: {}", stderr(&compile));
    assert!(stdout(&compile).contains("rule workspace-confinement"));
}

#[test]
fn shipped_init_templates_compile_without_warnings() {
    // `actplane init --template <name>` is the first policy most users get. A
    // template whose rule lowers to a widened matcher (a repo-relative literal
    // over the kernel's 16-byte contains window, or a `*` surviving into the
    // literal) would hand the user a starter rule that fires on paths it never
    // names. Only `workspace-confinement` is compile-tested today, and none is
    // checked for warnings. Render every template at its defaults, compile it,
    // and fail on any warning.
    let listing = run(&["init", "--list-templates"]);
    assert!(listing.status.success(), "stderr: {}", stderr(&listing));
    let names: Vec<String> = stdout(&listing)
        .lines()
        .filter(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect();
    // An exact count: a template dropped from the list (renamed, or its row no
    // longer indented) would otherwise leave the population silently short.
    assert_eq!(
        names.len(),
        10,
        "expected the 10 shipped templates, found {names:?}"
    );
    let tmp = tempfile::tempdir().unwrap();
    for name in &names {
        let out = tmp.path().join(format!("{name}.yaml"));
        let init = run(&["init", "--template", name, "--out", out.to_str().unwrap()]);
        assert!(
            init.status.success(),
            "render template {name}: {}",
            stderr(&init)
        );
        // A default parameter that names a user path lowers to a `prefix`
        // matcher over that literal: warning-free, but a no-op on every
        // machine except the author's (the `policies/readonly.yaml` defect).
        // The default set is what a user keeps, so it must stay host-independent.
        let rendered = fs::read_to_string(&out)
            .unwrap_or_else(|e| panic!("read rendered template {name}: {e}"));
        for marker in ["/home/", "/Users/"] {
            assert!(
                !rendered.contains(marker),
                "template {name} default hardcodes a user path `{marker}`, so on a \
                 reader's machine the policy matches nothing it claims to"
            );
        }
        let bin = tmp.path().join(format!("{name}.bin"));
        let output = run(&[
            "--policy",
            out.to_str().unwrap(),
            "compile",
            "--out",
            bin.to_str().unwrap(),
            "--force",
        ]);
        assert!(
            output.status.success(),
            "template {name} failed to compile at its defaults: {}",
            stderr(&output)
        );
        let err = stderr(&output);
        assert!(
            !err.contains("ActPlane: warning"),
            "template {name} compiles with a warning at its defaults, so the starter policy \
             may not enforce what its `# ...` header states:\n{err}"
        );
    }
}

#[test]
fn init_generate_writes_candidate_policy() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("AGENTS.md"),
        "Do not run git branch or git worktree. Run pytest before committing. Keep secrets safe.",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::create_dir(tmp.path().join("tests")).unwrap();
    let policy = tmp.path().join("candidate.yaml");

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["init", "--generate", "--out", policy.to_str().unwrap()])
        .output()
        .expect("run init --generate");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("selected no-git-branch"));
    assert!(stderr(&output).contains("selected test-before-commit"));
    let written = fs::read_to_string(&policy).unwrap();
    assert!(written.contains("ActPlane candidate policy generated"));
    assert!(written.contains("# template: no-git-branch"));
    assert!(written.contains("rule no-git-branch:"));
    // The candidate is what the user is told to review and then enforce. A
    // generated path under the author's home would lower warning-free yet match
    // nothing on the reader's machine, so the generated file must stay
    // host-independent the way the tracked policies and the docs do.
    for marker in ["/home/", "/Users/"] {
        assert!(
            !written.contains(marker),
            "generated candidate hardcodes a user path `{marker}`"
        );
    }

    // The candidate is what the user is told to review and then enforce, and it
    // composes several templates into one file. A warning here would mean the
    // generated policy fires on paths none of the selected templates named, so
    // compile it and require the same warning-free result the templates carry.
    let bin = tmp.path().join("candidate.bin");
    let compile = run(&[
        "--policy",
        policy.to_str().unwrap(),
        "compile",
        "--out",
        bin.to_str().unwrap(),
        "--force",
    ]);
    assert!(
        compile.status.success(),
        "generated candidate failed to compile: {}",
        stderr(&compile)
    );
    assert!(
        !stderr(&compile).contains("ActPlane: warning"),
        "generated candidate compiles with a warning:\n{}",
        stderr(&compile)
    );
}

#[test]
fn run_help_exposes_child_domain_delta_flags() {
    let output = run(&["run", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--parent-domain"));
    assert!(stdout.contains("--child-id"));
    assert!(stdout.contains("--scope-id"));
    assert!(stdout.contains("--delta"));
    assert!(stdout.contains("--delta-text"));
    assert!(stdout.contains("--approved-by"));
    assert!(stdout.contains("--approval-ref"));
    assert!(stdout.contains("--generated-by"));
}

#[test]
fn run_accepts_global_domain_flag_after_subcommand() {
    let output = run(&["run", "--domain", "review", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--domain <DOMAIN>"));
    assert!(stdout.contains("--parent-domain"));
}

#[test]
fn watch_help_exposes_parent_domain_flag() {
    let output = run(&["watch", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--parent-domain"));
}

#[test]
fn attach_help_exposes_existing_process_domain_flags() {
    let output = run(&["attach", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--pid"));
    assert!(stdout.contains("--parent-domain"));
    assert!(stdout.contains("--child-domain"));
    assert!(stdout.contains("--domain-id"));
    assert!(stdout.contains("--child-id"));
    assert!(stdout.contains("--scope-id"));
    assert!(stdout.contains("--delta"));
    assert!(stdout.contains("--delta-text"));
    assert!(stdout.contains("--approved-by"));
    assert!(stdout.contains("--approval-ref"));
    assert!(stdout.contains("--generated-by"));
    assert!(stdout.contains("foreground engine"));
    assert!(stdout.contains("post-hoc"));
}

#[test]
fn run_parent_domain_rejects_runtime_delta_mode() {
    let output = run(&[
        "run",
        "--parent-domain",
        "--domain",
        "review",
        "--delta-text",
        "rule child:\n  notify exec \"git\" if true\n  because \"child\"",
        "/bin/true",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--parent-domain cannot be combined"));
}

#[test]
fn control_help_exposes_already_running_engine_commands() {
    let output = run(&["control", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    for command in [
        "status",
        "bind-child",
        "delta",
        "launch-child",
        "children",
        "logs",
        "stop",
        "restart",
    ] {
        assert!(
            stdout.contains(command),
            "missing {command} in help:\n{stdout}"
        );
    }
    for removed in [
        "append-delta",
        "list-children",
        "terminate-child",
        "restart-child",
    ] {
        assert!(
            !stdout.contains(removed),
            "old control command {removed} still appears in help:\n{stdout}"
        );
    }
}

#[test]
fn control_delta_add_help_exposes_delta_inputs() {
    let output = run(&["control", "delta", "add", "--help"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("--target-id"));
    assert!(stdout.contains("--domain-id"));
    assert!(stdout.contains("--delta"));
    assert!(stdout.contains("--delta-text"));
    assert!(stdout.contains("--approved-by"));
    assert!(stdout.contains("--approval-ref"));
    assert!(stdout.contains("--generated-by"));
}

#[test]
fn renamed_control_commands_report_new_command_names_in_errors() {
    for (args, expected) in [
        (&["control", "logs"][..], "control logs requires"),
        (&["control", "stop"][..], "control stop requires"),
        (&["control", "restart"][..], "control restart requires"),
    ] {
        let output = run(args);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains(expected),
            "missing `{expected}` in stderr:\n{}",
            stderr(&output)
        );
    }
}

#[cfg(unix)]
#[test]
fn parent_domain_control_mutations_are_rejected_before_socket_connect() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": tmp.path().join("missing-control.sock"),
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": u32::MAX,
        }))
        .unwrap(),
    )
    .unwrap();

    for args in [
        vec!["attach", "--pid", "1234", "--child-domain"],
        vec!["control", "bind-child", "--pid", "1234"],
        vec![
            "control",
            "delta",
            "add",
            "--delta-text",
            "rule added:\n  notify exec \"git\" if true\n  because \"added\"",
        ],
        vec!["control", "launch-child", "/bin/true"],
    ] {
        let output = Command::new(actplane())
            .current_dir(tmp.path())
            .args(args)
            .output()
            .expect("run parent-domain control mutation");
        assert!(!output.status.success());
        let stderr = stderr(&output);
        assert!(
            stderr.contains("unavailable in --parent-domain mode"),
            "stderr did not explain parent-domain mode:\n{stderr}"
        );
        assert!(
            !stderr.contains("missing-control.sock"),
            "command attempted to connect before rejecting parent-domain mode:\n{stderr}"
        );
    }
}

#[cfg(unix)]
#[test]
fn attach_sends_bind_then_child_delta_over_repo_control_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        r#"
version: 1
policy: |
  source COMMAND = exec "**"
  rule noop:
    notify exec "__actplane_never__" if COMMAND
    because "noop"
"#,
    )
    .unwrap();

    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        for response in ["attached", "delta accepted"] {
            let (mut stream, _) = listener.accept().expect("accept control client");
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read request");
            let request: serde_json::Value = serde_json::from_str(&line).expect("request JSON");
            tx.send(request).expect("send request");
            serde_json::to_writer(
                &mut stream,
                &serde_json::json!({ "ok": true, "text": response }),
            )
            .expect("write response");
            writeln!(stream).expect("write response newline");
        }
    });

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "--policy",
            policy.to_str().unwrap(),
            "attach",
            "--pid",
            "1234",
            "--child-domain",
            "--domain-id",
            "4242",
            "--scope-id",
            "7",
            "--delta-text",
            "rule added:\n  notify exec \"git\" if true\n  because \"added\"",
            "--approved-by",
            "reviewer",
            "--approval-ref",
            "ticket-7",
            "--generated-by",
            "cli-test",
        ])
        .output()
        .expect("run attach");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("attached"));
    assert!(stdout.contains("delta accepted"));

    let bind_request = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("bind control request");
    assert_eq!(bind_request["op"], "bind_child_domain");
    assert_eq!(bind_request["pid"], 1234);
    assert_eq!(bind_request["child_id"], 4242);
    assert_eq!(bind_request["scope_id"], 7);

    let delta_request = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("delta control request");
    assert_eq!(delta_request["op"], "append_policy_delta");
    assert_eq!(delta_request["target_id"], 4242);
    assert!(
        delta_request["policy"]
            .as_str()
            .unwrap()
            .contains("rule added")
    );
    assert_eq!(delta_request["policy_ref"], "--delta-text[0]");
    assert_eq!(delta_request["approved_by"], "reviewer");
    assert_eq!(delta_request["approval_ref"], "ticket-7");
    assert_eq!(delta_request["generated_by"], "cli-test");
    handle.join().expect("control server thread");
}

#[cfg(unix)]
#[test]
fn control_delta_add_sends_append_delta_over_repo_control_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("actplane.yaml");
    fs::write(
        &policy,
        r#"
version: 1
policy: |
  source COMMAND = exec "**"
  rule noop:
    notify exec "__actplane_never__" if COMMAND
    because "noop"
"#,
    )
    .unwrap();

    let socket_path = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_dir = tmp.path().join(".actplane");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("control.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "actplane.control.v1",
            "pid": std::process::id() as i32,
            "proc_start_time": null,
            "socket_path": socket_path,
            "project_dir": tmp.path(),
            "parent_pid": 1111,
            "parent_domain_id": 2222,
        }))
        .unwrap(),
    )
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let mut line = String::new();
        std::io::BufReader::new(stream.try_clone().expect("clone stream"))
            .read_line(&mut line)
            .expect("read request");
        let request: serde_json::Value = serde_json::from_str(&line).expect("request JSON");
        tx.send(request).expect("send request");
        serde_json::to_writer(
            &mut stream,
            &serde_json::json!({ "ok": true, "text": "delta accepted" }),
        )
        .expect("write response");
        writeln!(stream).expect("write response newline");
    });

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args([
            "--policy",
            policy.to_str().unwrap(),
            "control",
            "delta",
            "add",
            "--target-id",
            "4242",
            "--delta-text",
            "rule added:\n  notify exec \"git\" if true\n  because \"added\"",
            "--approved-by",
            "reviewer",
            "--approval-ref",
            "ticket-7",
            "--generated-by",
            "cli-test",
        ])
        .output()
        .expect("run control delta add");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("delta accepted"));

    let request = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("control request");
    assert_eq!(request["op"], "append_policy_delta");
    assert_eq!(request["target_id"], 4242);
    assert!(request["policy"].as_str().unwrap().contains("rule added"));
    assert_eq!(request["policy_ref"], "--delta-text[0]");
    assert_eq!(request["approved_by"], "reviewer");
    assert_eq!(request["approval_ref"], "ticket-7");
    assert_eq!(request["generated_by"], "cli-test");

    handle.join().expect("control server thread");
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// One command level's accepted long flags, split into all flags and the
/// value-taking subset, plus the names of the subcommands nested under it.
struct CliLevel {
    flags: BTreeSet<String>,
    valued: BTreeSet<String>,
    subcommands: Vec<String>,
}

fn parse_help(text: &str) -> CliLevel {
    let mut flags = BTreeSet::new();
    let mut valued = BTreeSet::new();
    let mut subcommands = Vec::new();
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        for (idx, token) in toks.iter().enumerate() {
            // `--flag` or `--flag <VALUE>`; clap prints the value placeholder as
            // its own token, so value-taking is read from the next token.
            let Some(flag) = token.strip_prefix("--") else {
                continue;
            };
            let name: String = flag
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                .collect();
            if name.is_empty() || flag.len() != name.len() {
                continue;
            }
            if toks
                .get(idx + 1)
                .is_some_and(|n| n.starts_with('<') && n.ends_with('>'))
            {
                valued.insert(name.clone());
            }
            flags.insert(name);
        }
    }
    let mut in_commands = false;
    for line in text.lines() {
        if line.trim_end() == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands {
            if line.trim().is_empty() {
                in_commands = false;
                continue;
            }
            let name = line.trim().split_whitespace().next().unwrap_or("");
            if !name.is_empty() && name != "help" && !name.starts_with('-') {
                subcommands.push(name.to_string());
            }
        }
    }
    CliLevel {
        flags,
        valued,
        subcommands,
    }
}

/// The CLI's command tree keyed by command path (empty = the root), each with
/// the long flags it accepts and the help-derived value-taking subset.
///
/// Deriving this from the binary rather than a hardcoded list keeps the guard
/// honest: a flag removed from clap stops being accepted here, so a doc still
/// naming it under that command fails. `--help` is the same surface a reader
/// consults.
fn cli_flag_inventory() -> std::collections::BTreeMap<Vec<String>, CliLevel> {
    let mut tree = std::collections::BTreeMap::new();
    let mut queue: VecDeque<Vec<String>> = VecDeque::from([Vec::new()]);
    while let Some(path) = queue.pop_front() {
        if tree.contains_key(&path) {
            continue;
        }
        let out = if path.is_empty() {
            run(&["--help"])
        } else {
            let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
            args.push("--help");
            run(&args)
        };
        let level = parse_help(&stdout(&out));
        for name in &level.subcommands {
            let mut child = path.clone();
            child.push(name.clone());
            queue.push_back(child);
        }
        tree.insert(path, level);
    }
    tree
}

/// Every fenced code block in a markdown file, with the fence line number of
/// each content line.
fn fenced_lines(md: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_block = false;
    for (idx, line) in md.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            in_block = !in_block;
        } else if in_block {
            out.push((idx + 1, line.to_string()));
        }
    }
    out
}

#[test]
fn documented_actplane_flags_exist() {
    // A fenced example that spells `actplane run --flag` teaches that flag, and
    // a reader who copies the line expects it to work. Check each documented
    // flag against the command level the line names, not against the union of
    // every command: `compile` and `run` accept different flags, so a `run
    // --force` that only `compile` defines is a real break. The scan reads only
    // the flags that belong to `actplane` itself: a value-taking flag consumes
    // its value, the scan stops at the `--` that hands the rest of the line to
    // the child command (`codex --cd`, `cargo build --release`), and a token
    // that is not a known subcommand ends the scan (an aspirational example).
    let tree = cli_flag_inventory();
    let root_level = tree.get(&Vec::new()).expect("root help");
    assert!(
        root_level.flags.len() > 12,
        "expected the root command to define many long flags, found {}",
        root_level.flags.len()
    );
    assert!(
        tree.len() > 8,
        "expected a command tree, found {} levels",
        tree.len()
    );
    let root = PathBuf::from(format!("{}/../..", env!("CARGO_MANIFEST_DIR")));
    let listing = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "ls-files", "*.md"])
        .output()
        .unwrap_or_else(|e| panic!("run git ls-files: {e}"));
    assert!(listing.status.success(), "git ls-files failed");
    let tracked = String::from_utf8(listing.stdout).expect("git ls-files utf8");
    let mut checked = 0usize;
    let mut problems: Vec<String> = Vec::new();
    // The token after `actplane` names a subcommand; a flag scan cannot check
    // it (an unknown subcommand ends the scan), so verify it directly and count
    // the checks to keep this from passing on an empty set.
    let mut subcommands_checked = 0usize;
    let mut sub_problems: Vec<String> = Vec::new();
    let mut accepted: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    // `actplane init --template <name>` names a shipped template, and the flag
    // scan skips the value because `--template` takes one. Check the value
    // against the listing the CLI prints, so a renamed or removed template fails
    // here rather than leaving the reader to copy a name that does not exist.
    let template_listing = stdout(&run(&["init", "--list-templates"]));
    let templates: std::collections::BTreeSet<&str> = template_listing
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    let mut templates_checked = 0usize;
    let mut template_problems: Vec<String> = Vec::new();
    for rel in tracked.lines() {
        if rel.starts_with("docs/papers") {
            continue;
        }
        let Ok(md) = fs::read_to_string(root.join(rel)) else {
            continue;
        };
        for (line_no, line) in fenced_lines(&md) {
            if !line.contains("actplane") {
                continue;
            }
            let toks: Vec<&str> = line.split_whitespace().collect();
            let Some(at) = toks
                .iter()
                .position(|t| t.rsplit('/').next() == Some("actplane"))
            else {
                continue;
            };
            // The word after `actplane` is the subcommand. Verify it against the
            // binary (a real but hidden subcommand such as `feedback-hook` still
            // runs, so probing is truer than reading the help text). The scan of
            // flags below stops at an unknown word, so without this a renamed
            // subcommand would silently drop its flags from the count.
            //
            // `docs/design/` is the design record and names planned commands
            // (`delegate`, `replay`) that the shipped CLI does not have yet, so
            // it is excluded here as it is for the flag floor.
            if !rel.starts_with("docs/design/") {
                if let Some(next) = toks.get(at + 1) {
                    let ok = !next.is_empty()
                        && !next.starts_with('-')
                        && next
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
                    if ok {
                        subcommands_checked += 1;
                        let known = *accepted
                            .entry((*next).to_string())
                            .or_insert_with(|| !run(&[next, "--help"]).stdout.is_empty());
                        if !known {
                            sub_problems.push(format!("{rel}:{line_no}: actplane {next}"));
                        }
                    }
                }
            }
            // `--template <name>` names a shipped template. The flag scan
            // consumes the value of a value-taking flag, so without this a
            // renamed template would leave the reader copying a name that does
            // not exist. A placeholder (`--template <name>`) teaches no name, so
            // only a real-looking word is checked. `docs/design/` names planned
            // material and is excluded here as it is above.
            if !rel.starts_with("docs/design/") {
                for pair in toks.windows(2) {
                    if pair[0] != "--template" || pair[1].starts_with('<') {
                        continue;
                    }
                    templates_checked += 1;
                    if !templates.contains(pair[1]) {
                        template_problems.push(format!("{rel}:{line_no}: --template {}", pair[1]));
                    }
                }
            }
            let mut i = at + 1;
            // Start at the root command; descend into a known subcommand when
            // the line names one, until the flags run out or the child begins.
            let mut path: Vec<String> = Vec::new();

            while let Some(tok) = toks.get(i) {
                if *tok == "--" {
                    break;
                }
                let Some(flag) = tok.strip_prefix("--") else {
                    // A bare word is either a subcommand we can descend into, or
                    // the child command (or an aspirational token): stop.
                    if !path.is_empty() || tree.get(&path).is_none() {
                        break;
                    }
                    let next = {
                        let mut p = path.clone();
                        p.push((*tok).to_string());
                        p
                    };
                    if tree.contains_key(&next) {
                        path = next;
                        i += 1;
                        continue;
                    }
                    break;
                };
                let name: String = flag
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                    .collect();
                if name.is_empty() || flag.len() != name.len() {
                    break;
                }
                checked += 1;
                let level = tree.get(&path).expect("visited level");
                if !level.flags.contains(&name) {
                    let cmd = if path.is_empty() {
                        "actplane".to_string()
                    } else {
                        format!("actplane {}", path.join(" "))
                    };
                    problems.push(format!("{rel}:{line_no}: --{name} ({cmd})"));
                }
                i += 1;
                if level.valued.contains(&name) {
                    i += 1;
                }
            }
        }
    }
    // 100 documented flags measured; pin below that so a scanner that stops
    // finding them fails rather than passing on an empty set.
    assert!(
        checked > 80,
        "expected many documented actplane flags, found {checked}"
    );
    assert!(
        subcommands_checked > 60,
        "expected many documented actplane subcommands, found {subcommands_checked}"
    );
    assert!(
        problems.is_empty(),
        "documented actplane flags the binary does not define at that command: {problems:?}"
    );
    assert!(
        sub_problems.is_empty(),
        "documented actplane subcommands the binary does not accept: {sub_problems:?}"
    );
    // 7 documented `--template` values measured; a floor just below keeps a
    // scanner that stops matching them from passing on an empty set.
    assert!(
        templates_checked > 4,
        "expected many documented actplane templates, found {templates_checked}"
    );
    assert!(
        template_problems.is_empty(),
        "documented actplane templates the binary does not ship: {template_problems:?}"
    );
}

fn audit_project(dir: &std::path::Path, run: &str, log: &str) {
    fs::write(
        dir.join("actplane.yaml"),
        "version: 1\npolicy: |\n  rule noop:\n    notify exec \"__never__\"\n    because \"noop\"\n",
    )
    .unwrap();
    let run_dir = dir.join(".actplane").join("runs").join(run);
    fs::create_dir_all(&run_dir).unwrap();
    fs::write(run_dir.join("audit.jsonl"), log).unwrap();
}

#[test]
fn audit_show_summarizes_the_resolved_run_log() {
    // `audit show` must find the log the runtime actually wrote under
    // `.actplane/runs/*/`, not the default path, so the CLI and the
    // `actplane:///audit` MCP resource report the same history.
    let tmp = tempfile::tempdir().unwrap();
    audit_project(
        tmp.path(),
        "run-a",
        "{\"event\":\"engine_attach\"}\n{\"event\":\"append_policy_delta\",\"status\":\"accepted\"}\n",
    );

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["audit", "show"])
        .output()
        .expect("run audit show");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("2 record(s)"), "{stdout}");
    assert!(stdout.contains("engine_attach"), "{stdout}");
    assert!(
        stdout.contains("append_policy_delta (accepted)"),
        "{stdout}"
    );
    assert!(
        stdout.contains(".actplane/runs/run-a/audit.jsonl"),
        "{stdout}"
    );
}

#[test]
fn audit_show_reports_an_empty_log_instead_of_failing() {
    let tmp = tempfile::tempdir().unwrap();
    audit_project(tmp.path(), "run-a", "");

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["audit", "show"])
        .output()
        .expect("run audit show");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("No ActPlane audit records"));
}

#[test]
fn audit_export_jsonl_reproduces_each_record_verbatim() {
    // Export is the machine-readable form, so it must emit exactly the records
    // the log holds, one per line, without inventing an envelope.
    let tmp = tempfile::tempdir().unwrap();
    let log = "{\"event\":\"engine_attach\"}\n{\"event\":\"append_policy_delta\",\"status\":\"accepted\"}\n";
    audit_project(tmp.path(), "run-a", log);

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["audit", "export", "--jsonl"])
        .output()
        .expect("run audit export");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert_eq!(lines[0], "{\"event\":\"engine_attach\"}");
    assert_eq!(
        lines[1],
        "{\"event\":\"append_policy_delta\",\"status\":\"accepted\"}"
    );
    // A malformed line survives export rather than silently vanishing. Use a
    // fresh project: two run dirs written in the same instant would tie on
    // mtime, and the resolver's "latest run" pick would be nondeterministic.
    let tmp2 = tempfile::tempdir().unwrap();
    audit_project(tmp2.path(), "run-b", "{\"event\":\"a\"}\nnot json\n");
    let output = Command::new(actplane())
        .current_dir(tmp2.path())
        .args(["audit", "export", "--jsonl"])
        .output()
        .expect("run audit export");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let bad = stdout(&output);
    assert_eq!(bad.lines().count(), 2, "{bad}");
    assert!(bad.lines().any(|l| l == "\"not json\""), "{bad}");
}

#[test]
fn audit_export_reads_an_explicit_path() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("explicit.jsonl");
    fs::write(&log, "{\"event\":\"only\"}\n").unwrap();
    // Run from a directory with no project so the explicit path is the only
    // way the record can be found.
    let empty = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(empty.path())
        .args([
            "audit",
            "export",
            "--jsonl",
            "--path",
            log.to_str().unwrap(),
        ])
        .output()
        .expect("run audit export --path");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "{\"event\":\"only\"}\n");
}

#[test]
fn replay_orders_the_resolved_run_log_into_a_timeline() {
    // `replay` must read the same log `audit show` reads and keep the log's own
    // order, because the run's append order is the causal order.
    let tmp = tempfile::tempdir().unwrap();
    audit_project(
        tmp.path(),
        "run-a",
        "{\"event\":\"engine_attach\",\"timestamp_unix_ns\":\"5\"}\n\
         {\"event\":\"append_policy_delta\",\"status\":\"accepted\",\"target_id\":42,\"timestamp_unix_ns\":\"5\"}\n\
         {\"event\":\"taint_violation\",\"op\":\"open\",\"action\":\"block\",\"target\":\"/etc/shadow\"}\n",
    );

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["replay"])
        .output()
        .expect("run replay");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("3 step(s)"), "{stdout}");
    let lines: Vec<&str> = stdout.lines().skip(1).collect();
    assert!(lines[0].contains("[attach] engine_attach"), "{stdout}");
    assert!(
        lines[1].contains("[delta] append_policy_delta accepted target 42"),
        "{stdout}"
    );
    assert!(
        lines[2].contains("[violation] taint_violation open action block target /etc/shadow"),
        "{stdout}"
    );
}

#[test]
fn replay_json_emits_classified_steps_with_their_records() {
    // The `--json` form is the machine-readable one, so each step carries its
    // kind and the record it came from rather than a rendered line.
    let tmp = tempfile::tempdir().unwrap();
    audit_project(
        tmp.path(),
        "run-a",
        "{\"event\":\"new_fangled_event\",\"timestamp_unix_ns\":\"7\"}\n",
    );

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["replay", "--json"])
        .output()
        .expect("run replay --json");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let body: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("replay json");
    assert_eq!(body["step_count"], serde_json::json!(1));
    assert_eq!(body["steps"][0]["kind"], "other");
    assert_eq!(body["steps"][0]["summary"], "new_fangled_event");
    assert_eq!(body["steps"][0]["timestamp_unix_ns"], "7");
    assert_eq!(body["steps"][0]["record"]["event"], "new_fangled_event");
}

#[test]
fn replay_reports_an_empty_log_instead_of_failing() {
    let tmp = tempfile::tempdir().unwrap();
    audit_project(tmp.path(), "run-a", "");

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["replay"])
        .output()
        .expect("run replay");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("No ActPlane audit records to replay"));
}

fn explain_project(dir: &std::path::Path, run: &str, feedback: &str) {
    fs::write(
        dir.join("actplane.yaml"),
        "version: 1\npolicy: |\n  rule noop:\n    notify exec \"__never__\"\n    because \"noop\"\n",
    )
    .unwrap();
    let run_dir = dir.join(".actplane").join("runs").join(run);
    fs::create_dir_all(&run_dir).unwrap();
    fs::write(run_dir.join("feedback.txt"), feedback).unwrap();
}

#[test]
fn explain_last_reports_the_resolved_payload_rule_and_action() {
    // `explain last` must find the newest run's feedback the runtime wrote
    // under `.actplane/runs/*/`, the same file the feedback MCP resource and
    // the hook read, then name the rule and its effect without the machine tag.
    let tmp = tempfile::tempdir().unwrap();
    explain_project(
        tmp.path(),
        "run-a",
        "[ActPlane] Operation blocked by rule `no-git-branch`.\n\
         - Target operation: exec git branch\n\
         - Reason: create a branch via the host\n\
         {\"actplane_rule\":\"no-git-branch\",\"effect\":\"block\",\"action\":\"block\",\"retry_useful\":false}\n\
         ----\n",
    );

    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["explain", "last"])
        .output()
        .expect("run explain last");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Last ActPlane match (block)"), "{text}");
    assert!(text.contains("rule: no-git-branch"), "{text}");
    assert!(text.contains("action: block"), "{text}");
    assert!(text.contains("retry_useful: false"), "{text}");
    assert!(text.contains("blocked by rule `no-git-branch`"), "{text}");
    assert!(!text.contains("\"actplane_rule\""), "{text}");
    assert!(text.contains(".actplane/runs/run-a/feedback.txt"), "{text}");
}

#[test]
fn explain_last_reports_no_match_instead_of_failing() {
    let tmp = tempfile::tempdir().unwrap();
    explain_project(tmp.path(), "run-a", "");
    let output = Command::new(actplane())
        .current_dir(tmp.path())
        .args(["explain", "last"])
        .output()
        .expect("run explain last");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("No ActPlane policy match recorded yet"));
}

#[test]
fn explain_last_reads_an_explicit_path() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("feedback.txt");
    fs::write(
        &log,
        "[ActPlane] Operation killed by rule `no-secret-exfil`.\n\
         {\"actplane_rule\":\"no-secret-exfil\",\"effect\":\"kill\",\"action\":\"kill\",\"retry_useful\":false}\n\
         ----\n",
    )
    .unwrap();
    let empty = tempfile::tempdir().unwrap();
    let output = Command::new(actplane())
        .current_dir(empty.path())
        .args(["explain", "last", "--path", log.to_str().unwrap()])
        .output()
        .expect("run explain last --path");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Last ActPlane match (kill)"), "{text}");
    assert!(text.contains("rule: no-secret-exfil"), "{text}");
}
