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
    let dead = "rule r:\n  block exec \"git\" \"push\" if A\n  because \"x\"\n";
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

    // A policy with nothing to warn about stays quiet.
    let good = "rule r:\n  kill exec \"git\" if A\n  because \"x\"\n";
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
    // after exec, so the pre-op hook skips the rule). Compile each one and fail
    // on any warning, so a dead rule or a truncating literal cannot re-enter.
    let dir = format!("{}/../../test/policies", env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0usize;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {dir}: {e}")) {
        let path = entry.expect("policy dir entry").path();
        if path.extension().is_none_or(|e| e != "yaml") {
            continue;
        }
        let out = std::env::temp_dir().join("actplane-corpus-warn-check.bin");
        let output = run(&[
            "--policy",
            path.to_str().unwrap(),
            "compile",
            "--out",
            out.to_str().unwrap(),
            "--force",
        ]);
        assert!(
            output.status.success(),
            "{} failed to compile: {}",
            path.display(),
            stderr(&output)
        );
        let err = stderr(&output);
        assert!(
            !err.contains("ActPlane: warning"),
            "{} compiles with a warning, so the example may not enforce what it states:\n{err}",
            path.display()
        );
        checked += 1;
    }
    assert!(checked >= 10, "expected the policy corpus, found {checked}");
}

#[test]
fn documented_warning_codes_match_the_cli() {
    // `docs/rule-language.md` lists the warning codes a user may see. A code that
    // reaches users but is undocumented is a gap; a documented code that no
    // longer exists sends the reader chasing a phantom. Pin both directions for
    // the pattern family: the doc's own list of pattern-lowering codes must be
    // exactly the compiler's `PATTERN_WARNING_CODES`. The doctor-owned codes
    // below are pinned only emitted -> documented, because the doc interleaves
    // them with unrelated backticked identifiers, so the reverse direction is
    // not representable from the doc alone.
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

    // Every code the CLI can emit. The pattern-lowering family is read from the
    // compiler (`PATTERN_WARNING_CODES`) rather than restated, because a
    // hand-written copy drifted: `pattern_empty_literal` was emitted by the
    // binary but omitted here, so this guard would not have caught its doc
    // changing. The rest stay explicit: they are produced by the CLI's doctor,
    // not the compiler, so no crate can enumerate them for us.
    let mut emitted: Vec<&str> = vec![
        "argv_block_exec_post_exec_only",
        "argv_token_ignored_for_non_exec",
        "bpf_lsm_inactive_for_block",
        "endpoint_source_unsupported",
        "endpoint_target_condition_multi_ipv4_hostname",
        "endpoint_target_condition_unresolved_hostname",
        "endpoint_target_condition_unsupported_pattern",
        "endpoint_target_unsupported",
        "repo_relative_target_condition_partial",
        "rule_missing_because",
    ];
    emitted.extend(actplane_ifc_compiler::dsl::PATTERN_WARNING_CODES);
    for code in emitted {
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
    assert!(stderr.contains("compiled 2 rule(s)"));
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
    assert!(stderr(&output).contains("selected no-secret-egress"));

    let written = fs::read_to_string(&policy).unwrap();
    assert!(written.contains("ActPlane candidate policy generated"));
    assert!(written.contains("# template: no-git-branch"));
    assert!(written.contains("rule no-git-branch:"));
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
