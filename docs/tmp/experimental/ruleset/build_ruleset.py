#!/usr/bin/env python3
# Build the corpus-grounded ActPlane ruleset.
#
# Methodology (see protocol.md): candidate behavioral-constraint lines were extracted (with
# per-repo provenance) from the 144 in-corpus CLAUDE.md/AGENTS.md in docs/corpus and pre-coded
# into D1 categories (docs/tmp/candidate_rules_144.tsv; LLM-assisted keyword coding, cf.
# arXiv 2509.14744 / 2511.12884). Here we (a) author canonical, ENFORCEABLE rules + their
# ActPlane DSL encoding, and (b) compute each rule's cross-repo frequency and representative
# verbatim quotes DETERMINISTICALLY from that candidate table — so provenance/frequency cannot
# be hallucinated. A separate verification pass spot-checks quotes against the real source files.
import csv, json, re, collections, sys, pathlib

HERE = pathlib.Path(__file__).parent
ROWS = list(csv.DictReader(open(HERE/'candidates_categorized.tsv'), delimiter='\t'))

# Each rule: a matcher = (category-substring or None, regex over text). A candidate row matches if
# its category contains cat_key (or cat_key is None) AND its text matches the regex (case-insensitive).
# freq_repos = # distinct repos with >=1 matching row; examples = up to 4 matching rows (distinct repos).
RULES = [
 # ---- VCS gating (E2/E5/E11) — the most frequent category ----
 dict(id="R01", category="vcs-gating", cat_key="vcs-commit/push",
      canonical="Agent must not commit without explicit user approval",
      rx=r"\b(not|never|don'?t|without).{0,40}\bcommit\b|commit.{0,30}\b(approval|permission|ask|confirm|explicit)",
      dsl='source AGENT = exec "**/codex"\nrule no-unapproved-commit:\n  deny exec "**/git" @arg "commit" if AGENT unless lineage-includes exec "**/approve"\n  effect kill\n  reason "do not commit without explicit user approval"',
      cons=["exec-sink","@arg","lineage"], tier=2),
 dict(id="R02", category="vcs-gating", cat_key="vcs-commit/push",
      canonical="Agent must not push without explicit user approval",
      rx=r"\bpush\b.{0,40}\b(approval|permission|ask|confirm|without|never|not|don'?t)|\b(never|don'?t|not|without).{0,20}\bpush\b",
      dsl='source AGENT = exec "**/codex"\nrule no-unapproved-push:\n  deny exec "**/git" @arg "push" if AGENT unless lineage-includes exec "**/approve"\n  effect kill\n  reason "do not push without explicit user approval"',
      cons=["exec-sink","@arg","lineage"], tier=2),
 dict(id="R03", category="vcs-mainbranch", cat_key="vcs-mainbranch",
      canonical="Agent must not push/commit directly to main/master",
      rx=r"\b(main|master)\b|protected branch|direct(ly)? to",
      dsl='source AGENT = exec "**/codex"\nrule no-direct-main:\n  deny exec "**/git" @arg "push" if AGENT unless after exec "**/open-pr"\n  effect kill\n  reason "no direct push to main/master; open a PR"',
      cons=["exec-sink","@arg","after"], tier=2),
 dict(id="R04", category="force-push", cat_key="force-push",
      canonical="Agent must not force-push or rewrite history",
      rx=r"force.?push|--force|force-with-lease|rewrite.{0,15}history|\brebase\b.{0,15}(shared|public)|git push -f",
      dsl='source AGENT = exec "**/codex"\nrule no-force-push:\n  deny exec "**/git" @arg "--force" if AGENT unless after exec "**/confirm"\n  effect kill\n  reason "destructive history rewrite needs an explicit confirm step"',
      cons=["exec-sink","@arg","after"], tier=2),
 # ---- test/lint before commit/push (E5) ----
 dict(id="R05", category="test-before", cat_key="test-before",
      canonical="Run the test suite before committing/pushing",
      rx=r"\btest",
      dsl='source AGENT = exec "**/codex"\nrule test-before-commit:\n  deny exec "**/git" @arg "commit" if AGENT unless after exec "**/pytest"\n  effect kill\n  reason "run the test suite before committing"',
      cons=["exec-sink","@arg","after"], tier=2),
 dict(id="R06", category="test-before", cat_key="test-before",
      canonical="Run lint/format before committing",
      rx=r"\b(lint|format|fmt|gofmt|prettier|eslint|ruff|clippy|black)\b",
      dsl='source AGENT = exec "**/codex"\nrule lint-before-commit:\n  deny exec "**/git" @arg "commit" if AGENT unless after exec "**/lint"\n  effect kill\n  reason "run lint/format before committing"',
      cons=["exec-sink","@arg","after"], tier=2),
 dict(id="R07", category="test-before", cat_key="test-before",
      canonical="Run typecheck/build before pushing",
      rx=r"\b(typecheck|type-check|tsc|mypy|build|compile)\b",
      dsl='source AGENT = exec "**/codex"\nrule typecheck-before-push:\n  deny exec "**/git" @arg "push" if AGENT unless after exec "**/typecheck"\n  effect kill\n  reason "typecheck/build must pass before pushing"',
      cons=["exec-sink","@arg","after"], tier=2),
 # ---- secrets (E1/E7) — taint-flow / tier 3 ----
 dict(id="R08", category="secrets-egress", cat_key="secrets",
      canonical="Secret/credential data must not leave the host over the network",
      rx=r"\b(secret|credential|api[_ -]?key|token|password|\.env|private key|id_rsa)\b",
      dsl='source SECRET = file "**/.env"\nsource SECRET = file "**/.envrc"\nsource SECRET = file "**/id_rsa"\nrule no-secret-egress:\n  deny connect endpoint "*" if SECRET\n  effect kill\n  reason "data derived from local secrets must not leave the host; redact first"\ndeclassify SECRET by exec "**/redact"',
      cons=["object-source","taint-flow","connect-sink","declassify"], tier=3),
 dict(id="R09", category="secrets-egress", cat_key="secrets",
      canonical="Secret/.env files must not be committed",
      rx=r"\.env|secret|credential|hardcod|api[_ -]?key|token|\.pem|id_rsa",
      dsl='source SECRET = file "**/.env"\nsource SECRET = file "**/.pem"\nrule no-commit-secret:\n  deny write file "**/.git/**" if SECRET\n  effect kill\n  reason "never stage/commit secret material"',
      cons=["object-source","taint-flow","write-sink"], tier=3),
 # ---- mediation (E3) — must go through a tool ----
 dict(id="R10", category="mediation", cat_key="mediation",
      canonical="Production/critical data file only via the designated tool",
      rx=r"\bonly\b.{0,40}(through|via|using)|must use|use the .* (tool|script|cli)|migrat",
      dsl='rule mediate-proddb:\n  deny open file "**/prod.db" unless lineage-includes exec "**/migrate"\n  effect kill\n  reason "prod data is reachable only through the migration tool"',
      cons=["open-sink","lineage"], tier=2),
 dict(id="R11", category="mediation", cat_key="mediation",
      canonical="Dependencies only via the package manager, not manual edits",
      rx=r"package manager|npm|pnpm|yarn|cargo|pip|poetry|uv\b|do not (hand-?edit|manually edit)",
      dsl='source AGENT = exec "**/codex"\nrule deps-via-pm:\n  deny write file "**/package-lock.json" if AGENT unless lineage-includes exec "**/npm"\n  effect kill\n  reason "lockfiles change only via the package manager"',
      cons=["object-source","write-sink","lineage"], tier=3),
 # ---- approval gate (E2/E11) ----
 dict(id="R12", category="approval-gate", cat_key="approval-gate",
      canonical="Destructive/irreversible actions require an explicit confirm step",
      rx=r"\b(confirm|approval|permission|human|review|ask)\b",
      dsl='source AGENT = exec "**/codex"\nrule confirm-destructive:\n  deny unlink file "/data/**" if AGENT unless after exec "**/confirm"\n  effect kill\n  reason "destructive action needs an explicit confirm step"',
      cons=["unlink-sink","after"], tier=2),
 # ---- readonly sub-agent (E6) ----
 dict(id="R13", category="readonly", cat_key="readonly",
      canonical="Read-only/research agent must not write, run git, or connect out",
      rx=r"read.?only|do not (modify|write|edit)|research|review.?only|must not change",
      dsl='source RESEARCH = exec "**/research-agent"\nrule research-readonly:\n  deny write   file "/**"   if RESEARCH\n  deny connect endpoint "*" if RESEARCH\n  deny exec    "**/git"     if RESEARCH\n  effect kill\n  reason "read-only sub-agent: no writes, no git, no network"',
      cons=["write-sink","connect-sink","exec-sink"], tier=2),
 dict(id="R14", category="readonly", cat_key="readonly",
      canonical="Do not edit generated/vendored files by hand",
      rx=r"generated|vendor|do not edit|autogenerat|\.pb\.go|node_modules",
      dsl='source AGENT = exec "**/codex"\nrule no-edit-generated:\n  deny write file "**/generated/**" if AGENT\n  effect kill\n  reason "generated/vendored files are not hand-edited"',
      cons=["object-source","write-sink"], tier=1),
 # ---- destructive fs/db (E11) ----
 dict(id="R15", category="destructive", cat_key="destructive",
      canonical="No mass/recursive deletion (rm -rf) of data",
      rx=r"rm -rf|recursiv|mass delet|\bdelete\b|\bdrop\b|truncate|destroy",
      dsl='source AGENT = exec "**/codex"\nrule no-rm-rf-data:\n  deny unlink file "/data/**" if AGENT unless after exec "**/confirm"\n  effect kill\n  reason "bulk deletion of data requires confirmation"',
      cons=["unlink-sink","after"], tier=2),
 dict(id="R16", category="destructive", cat_key="destructive",
      canonical="No dropping/truncating production database tables",
      rx=r"drop table|truncate|drop database|prod.{0,10}(db|database)|production data",
      dsl='source AGENT = exec "**/codex"\nrule no-drop-proddb:\n  deny open file "**/prod.db" if AGENT unless lineage-includes exec "**/migrate"\n  effect kill\n  reason "production DB only through migrations"',
      cons=["open-sink","lineage"], tier=2),
 # ---- network egress (E1/E10) ----
 dict(id="R17", category="network-egress", cat_key="network-egress",
      canonical="No outbound network during offline/build phases",
      rx=r"network|offline|no internet|do not.{0,15}(fetch|download|connect)|external (service|call|api)",
      dsl='source AGENT = exec "**/codex"\nrule no-egress:\n  deny connect endpoint "*" if AGENT unless target "127."\n  effect kill\n  reason "no outbound network in this phase"',
      cons=["connect-sink","target-scope"], tier=2),
 dict(id="R18", category="network-egress", cat_key=None,
      canonical="PII/customer/personal data may only reach internal endpoints",
      rx=r"\bPII\b|customer|personal data|personal info|user data|privacy|exfiltrat|GDPR",
      dsl='source PII = file "/data/customers/**"\nrule pii-internal-only:\n  deny connect endpoint "*" if PII unless target "127."\n  effect kill\n  reason "PII-handling process may only reach internal endpoints"',
      cons=["object-source","taint-flow","connect-sink","target-scope"], tier=3),
 # ---- workspace confinement (E4) ----
 dict(id="R19", category="workspace", cat_key="workspace",
      canonical="Agent may only modify files inside its workspace",
      rx=r"workspace|outside|sandbox|only.{0,15}(modify|write|edit).{0,15}(work|repo|project)|do not (touch|modify).{0,15}(system|/etc|home)",
      dsl='source AGENT = exec "**/codex"\nrule confine-writes:\n  deny write  file "/**" if AGENT unless target "/work/**"\n  deny unlink file "/**" if AGENT unless target "/work/**"\n  effect kill\n  reason "agent may only modify its workspace"',
      cons=["write-sink","unlink-sink","target-scope"], tier=2),
 # ---- untrusted input -> privileged action (E2) — multi-label/integrity ----
 dict(id="R20", category="untrusted-input", cat_key="untrusted-input",
      canonical="Action derived from untrusted input must be human-reviewed first",
      rx=r"untrust|injection|review|approve|external (input|content)",
      dsl='source UNTRUST = file "**/downloads/**"\nrule no-injected-priv:\n  deny exec "**/git" @arg "push" if UNTRUST and not REVIEWED\n  effect kill\n  reason "action derived from untrusted input needs human review"\nendorse REVIEWED by exec "**/human-approve"',
      cons=["object-source","taint-flow","@arg","multi-label","endorse"], tier=3),
]

# additional finer VCS / test rules to reach 30+ and exercise variety
RULES += [
 dict(id="R21", category="vcs-gating", cat_key="vcs-commit/push",
      canonical="Do not commit build artifacts / generated output",
      rx=r"artifact|generated|build output|dist/|do not commit.{0,20}(build|dist|artifact)",
      dsl='source AGENT = exec "**/codex"\nrule no-commit-artifacts:\n  deny write file "**/dist/**" if AGENT\n  effect kill\n  reason "build artifacts are not committed"',
      cons=["object-source","write-sink"], tier=1),
 dict(id="R22", category="vcs-gating", cat_key="vcs-commit/push",
      canonical="Do not amend or rewrite already-published commits",
      rx=r"amend|rewrite|--amend|published commit|already pushed",
      dsl='source AGENT = exec "**/codex"\nrule no-amend-published:\n  deny exec "**/git" @arg "--amend" if AGENT unless after exec "**/confirm"\n  effect kill\n  reason "amending published commits needs confirmation"',
      cons=["exec-sink","@arg","after"], tier=2),
 dict(id="R23", category="test-before", cat_key="test-before",
      canonical="CI / full checks must pass before merge/release",
      rx=r"\bCI\b|must pass|all checks|green|pipeline",
      dsl='source AGENT = exec "**/codex"\nrule ci-before-release:\n  deny exec "**/release*" if AGENT unless after exec "**/ci"\n  effect kill\n  reason "release only after CI/full checks pass"',
      cons=["exec-sink","after"], tier=2),
 dict(id="R24", category="secrets-egress", cat_key="secrets",
      canonical="Do not print/log secret values",
      rx=r"log|print|echo|console|expose|leak",
      dsl='source SECRET = file "**/.env"\nrule no-log-secret:\n  deny write file "**/*.log" if SECRET\n  effect kill\n  reason "secret-derived data must not be written to logs"',
      cons=["object-source","taint-flow","write-sink"], tier=3),
 dict(id="R25", category="mediation", cat_key="mediation",
      canonical="Builds only via the project build tool (make/just/task)",
      rx=r"\bmake\b|justfile|\btask\b|build (script|tool|command)|use .* to build",
      dsl='source AGENT = exec "**/codex"\nrule build-via-make:\n  deny exec "**/cc" if AGENT unless lineage-includes exec "**/make"\n  effect kill\n  reason "compile only through the project build tool"',
      cons=["exec-sink","lineage"], tier=2),
 dict(id="R26", category="approval-gate", cat_key="approval-gate",
      canonical="Deploy/publish requires explicit human approval",
      rx=r"deploy|publish|release|ship|production",
      dsl='source AGENT = exec "**/codex"\nrule approve-before-deploy:\n  deny exec "**/deploy*" if AGENT unless lineage-includes exec "**/human-approve"\n  effect kill\n  reason "deploy/publish needs explicit human approval"',
      cons=["exec-sink","lineage"], tier=2),
 dict(id="R27", category="readonly", cat_key=None,
      canonical="Do not modify lockfiles directly",
      rx=r"lock.?file|package-lock|yarn\.lock|Cargo\.lock|poetry\.lock|pnpm-lock|go\.sum",
      dsl='source AGENT = exec "**/codex"\nrule no-edit-lockfile:\n  deny write file "**/Cargo.lock" if AGENT unless lineage-includes exec "**/cargo"\n  effect kill\n  reason "lockfiles change only via their package manager"',
      cons=["object-source","write-sink","lineage"], tier=3),
 dict(id="R28", category="destructive", cat_key="destructive",
      canonical="No git clean -fdx / discarding uncommitted work",
      rx=r"git clean|reset --hard|discard|stash drop|checkout -- ",
      dsl='source AGENT = exec "**/codex"\nrule no-discard-work:\n  deny exec "**/git" @arg "clean" if AGENT unless after exec "**/confirm"\n  effect kill\n  reason "discarding working-tree changes needs confirmation"',
      cons=["exec-sink","@arg","after"], tier=2),
 dict(id="R29", category="vcs-gating", cat_key="vcs-commit/push",
      canonical="Do not create branches/worktrees without approval",
      rx=r"\bbranch\b|worktree|checkout -b|git switch -c",
      dsl='source AGENT = exec "**/codex"\nrule no-branch:\n  deny exec "**/git" @arg "branch"   if AGENT\n  deny exec "**/git" @arg "worktree" if AGENT\n  effect kill\n  reason "do not create branches/worktrees without approval"',
      cons=["exec-sink","@arg"], tier=1),
 dict(id="R30", category="test-before", cat_key="test-before",
      canonical="Format check before commit (gofmt/prettier/black)",
      rx=r"gofmt|goimports|prettier|black|rustfmt|clang-format|format before",
      dsl='source AGENT = exec "**/codex"\nrule fmt-before-commit:\n  deny exec "**/git" @arg "commit" if AGENT unless after exec "**/fmt"\n  effect kill\n  reason "format the code before committing"',
      cons=["exec-sink","@arg","after"], tier=2),
 dict(id="R31", category="secrets-egress", cat_key="secrets",
      canonical="Secret-tainted file must not be written to a shared/public dir",
      rx=r"share|public|upload|s3|bucket|gist|paste",
      dsl='source SECRET = file "**/.env"\nrule no-secret-to-shared:\n  deny write file "/shared/**" if SECRET\n  effect kill\n  reason "secret-derived data must not be written to shared storage"',
      cons=["object-source","taint-flow","write-sink"], tier=3),
 dict(id="R32", category="mediation", cat_key="mediation",
      canonical="DB migrations only through the migration tool",
      rx=r"migrat|schema|alter table|flyway|alembic|diesel",
      dsl='rule migrate-only:\n  deny open file "**/schema.sql" unless lineage-includes exec "**/migrate"\n  effect kill\n  reason "schema changes only via the migration tool"',
      cons=["open-sink","lineage"], tier=2),
]

def matches(rule, row):
    if rule["cat_key"] and rule["cat_key"] not in row["category_guess"]:
        return False
    return re.search(rule["rx"], row["text"], re.I) is not None

out=[]
for rule in RULES:
    hits=[r for r in ROWS if matches(rule, r)]
    repos=collections.OrderedDict()
    for r in hits:
        repos.setdefault(r["repo"], r)
    examples=[{"repo":r["repo"],"family":r["family"],"line_no":int(r["line_no"]),"quote":r["text"]}
              for r in list(repos.values())[:4]]
    out.append(dict(
        id=rule["id"], canonical=rule["canonical"], category=rule["category"],
        freq_repos=len(repos), example_repos=examples,
        dsl=rule["dsl"], dsl_constructs=rule["cons"], complexity_tier=rule["tier"],
        enforceable="observable+expressible", inducible=True,
    ))

out.sort(key=lambda r:-r["freq_repos"])
with open(HERE/'ruleset.jsonl','w') as f:
    for r in out: f.write(json.dumps(r,ensure_ascii=False)+"\n")

# human-readable summary
with open(HERE/'ruleset.md','w') as f:
    f.write("# ActPlane corpus-grounded ruleset\n\n")
    f.write(f"{len(out)} canonical enforceable rules, derived from {len(set(r['repo'] for r in ROWS))} repos' candidate lines.\n\n")
    f.write("| id | rule | category | #repos | tier | constructs |\n|---|---|---|---:|:---:|---|\n")
    for r in out:
        f.write(f"| {r['id']} | {r['canonical']} | {r['category']} | {r['freq_repos']} | T{r['complexity_tier']} | {','.join(r['dsl_constructs'])} |\n")

tiers=collections.Counter(r["complexity_tier"] for r in out)
print(f"wrote {len(out)} rules. tiers: {dict(tiers)}")
print(f"freq>=10: {sum(1 for r in out if r['freq_repos']>=10)}  freq>=3: {sum(1 for r in out if r['freq_repos']>=3)}  freq0: {sum(1 for r in out if r['freq_repos']==0)}")
print("top by freq:", [(r['id'],r['freq_repos']) for r in out[:6]])
PY = None
