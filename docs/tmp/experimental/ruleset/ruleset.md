# ActPlane corpus-grounded ruleset

32 canonical enforceable rules, derived from 101 repos' candidate lines.

| id | rule | category | #repos | tier | constructs |
|---|---|---|---:|:---:|---|
| R09 | Secret/.env files must not be committed | secrets-egress | 37 | T3 | object-source,taint-flow,write-sink |
| R01 | Agent must not commit without explicit user approval | vcs-gating | 28 | T2 | exec-sink,@arg,lineage |
| R05 | Run the test suite before committing/pushing | test-before | 24 | T2 | exec-sink,@arg,after |
| R06 | Run lint/format before committing | test-before | 23 | T2 | exec-sink,@arg,after |
| R12 | Destructive/irreversible actions require an explicit confirm step | approval-gate | 20 | T2 | unlink-sink,after |
| R10 | Production/critical data file only via the designated tool | mediation | 14 | T2 | open-sink,lineage |
| R23 | CI / full checks must pass before merge/release | test-before | 14 | T2 | exec-sink,after |
| R13 | Read-only/research agent must not write, run git, or connect out | readonly | 13 | T2 | write-sink,connect-sink,exec-sink |
| R02 | Agent must not push without explicit user approval | vcs-gating | 12 | T2 | exec-sink,@arg,lineage |
| R07 | Run typecheck/build before pushing | test-before | 12 | T2 | exec-sink,@arg,after |
| R08 | Secret/credential data must not leave the host over the network | secrets-egress | 11 | T3 | object-source,taint-flow,connect-sink,declassify |
| R17 | No outbound network during offline/build phases | network-egress | 8 | T2 | connect-sink,target-scope |
| R29 | Do not create branches/worktrees without approval | vcs-gating | 8 | T1 | exec-sink,@arg |
| R15 | No mass/recursive deletion (rm -rf) of data | destructive | 7 | T2 | unlink-sink,after |
| R21 | Do not commit build artifacts / generated output | vcs-gating | 7 | T1 | object-source,write-sink |
| R16 | No dropping/truncating production database tables | destructive | 6 | T2 | open-sink,lineage |
| R24 | Do not print/log secret values | secrets-egress | 6 | T3 | object-source,taint-flow,write-sink |
| R31 | Secret-tainted file must not be written to a shared/public dir | secrets-egress | 6 | T3 | object-source,taint-flow,write-sink |
| R30 | Format check before commit (gofmt/prettier/black) | test-before | 5 | T2 | exec-sink,@arg,after |
| R03 | Agent must not push/commit directly to main/master | vcs-mainbranch | 4 | T2 | exec-sink,@arg,after |
| R04 | Agent must not force-push or rewrite history | force-push | 4 | T2 | exec-sink,@arg,after |
| R18 | PII/customer/personal data may only reach internal endpoints | network-egress | 4 | T3 | object-source,taint-flow,connect-sink,target-scope |
| R26 | Deploy/publish requires explicit human approval | approval-gate | 3 | T2 | exec-sink,lineage |
| R27 | Do not modify lockfiles directly | readonly | 3 | T3 | object-source,write-sink,lineage |
| R11 | Dependencies only via the package manager, not manual edits | mediation | 2 | T3 | object-source,write-sink,lineage |
| R19 | Agent may only modify files inside its workspace | workspace | 2 | T2 | write-sink,unlink-sink,target-scope |
| R22 | Do not amend or rewrite already-published commits | vcs-gating | 2 | T2 | exec-sink,@arg,after |
| R14 | Do not edit generated/vendored files by hand | readonly | 1 | T1 | object-source,write-sink |
| R20 | Action derived from untrusted input must be human-reviewed first | untrusted-input | 1 | T3 | object-source,taint-flow,@arg,multi-label,endorse |
| R25 | Builds only via the project build tool (make/just/task) | mediation | 1 | T2 | exec-sink,lineage |
| R28 | No git clean -fdx / discarding uncommitted work | destructive | 1 | T2 | exec-sink,@arg,after |
| R32 | DB migrations only through the migration tool | mediation | 1 | T2 | open-sink,lineage |
