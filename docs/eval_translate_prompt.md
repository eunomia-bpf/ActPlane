# Agent Translation Prompt (RQ1 + RQ2)

Translate natural-language directives into ActPlane DSL rules.

## Input (per repo `{REPO}`)

1. `docs/corpus/{REPO}/agent_rules.yaml` — fill the `rule:` field
2. `docs/corpus/{REPO}/CLAUDE.md` or `AGENTS.md` — project context
3. `docs/corpus/{REPO}/meta.json` — repo name, language
4. `docs/corpus-evaluated/{REPO}/repo/` — cloned source (browse structure, don't read every file)
5. `docs/rule-language.md` §2-3 — DSL grammar + examples (read once)

Output goes to `docs/corpus/{REPO}/agent_rules.yaml`. Do NOT touch `corpus-evaluated/`.

## DSL quick reference

```
source LABEL = exec|file|endpoint PATTERN
rule name:
    notify|block|kill OP TARGET [ARGS...] [if EXPR] [unless COND]
    because "reason"
```

- Basename matching: `exec "git"` matches `/usr/bin/git`
- Path globs: `file "src/**/*.py"`
- Effects: `notify` (guidance) < `block` (prevent) < `kill` (terminate)
- Conditions: `if LABEL`, `unless after exec PAT [since write PAT]`, `unless lineage-includes exec PAT`

## Rules

1. **Partial > null.** Translate what you CAN. Put untranslatable parts in `because`. Only null when NOTHING maps to syscalls (pure content/semantic).
2. **No duplicates.** If two directives produce identical rules, find the distinguishing signal. "No secrets in code" → label tracking, not another "run tests before commit".
3. **Use project context.** Actual binary names (`pytest` vs `go test`), actual paths from the cloned repo.
4. **Effect choice.** `notify` for guidance ("should", checklists). `block` for hard requirements ("must", "never"). `kill` for catastrophic actions.
5. **Validate.** Run `actplane check --policy /tmp/test.yaml` on each rule. Fix errors. Ignore BPF-LSM warnings.
6. **Each rule needs its `source` declarations.** If a rule uses `if AGENT`, declare `source AGENT = exec "**"` (matches any binary — the runner seeds it). For data-flow labels, use specific patterns: `source SECRET = file "**/.env"`.

## Testing

After writing each rule, test it on this machine:

1. **Syntax check**: write a temp policy and run
   `/home/yunwei37/workspace/ActPlane/collector/target/release/actplane check --policy /tmp/test.yaml`.
   Fix errors. Ignore BPF-LSM warnings.

2. **Kernel test**: `cd` into the cloned repo and load the rule into
   the kernel. Run a command that should trigger it:
   ```bash
   cd /home/yunwei37/workspace/ActPlane/docs/corpus-evaluated/{REPO}/repo/
   sudo /home/yunwei37/workspace/ActPlane/collector/target/release/actplane run --policy /tmp/test.yaml -- bash -c "<trigger command>"
   ```
   Verify the rule matched in the output. Then run a compliant command
   and verify it does NOT match. If the rule doesn't behave as
   expected, fix it.

## Examples

```yaml
# "Run tests before committing: go test ./..."  → full translation
rule: |
  source AGENT = exec "**"
  rule tests-before-commit:
    block exec "git" "commit"
      if AGENT unless after exec "go" "test" since write "**/*.go"
    because "Source files changed. Run `go test ./...`, then commit."

# "Adding new platform (7 steps)" → partial (steps 5-7 expressible)
rule: |
  source AGENT = exec "**"
  source PLATFORM_CHANGED = file "platform/**/*.go"
  rule platform-checklist:
    notify exec "git" "commit"
      if PLATFORM_CHANGED unless after exec "go" "test" since write "platform/**"
    because "Platform files changed. Run tests. Also verify: update Makefile, add config example, add build tag."

# "Keep Rust and TS wire renames aligned" → pure content inspection
rule: null
```
