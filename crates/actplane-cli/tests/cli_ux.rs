use std::fs;
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
    assert_eq!(checked, 25, "expected 15 + 10 e2e case policies");
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
        checked, 24,
        "expected 24 documented complete-policy DSL examples, found {checked}"
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
