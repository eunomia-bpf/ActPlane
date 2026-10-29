# Independent plan review

Reviewer: fresh `review` subagent, before full comparison. Verdict: scientifically sound for bounded utility measurement; proceed with real preflight. Concrete task manifest, agent/model, versions, configuration, repetition count and annotation rules must be frozen before outcomes.

The experiment addresses the reviewers' utility concern using an official success metric and separates live task outcomes from counterfactual replay. No additional benchmark or baseline is necessary. The revised plan correctly limits interpretation when process labels do not reach retained model context.

Required implementation checks:

- Record protected roots, source-opening processes and subsequent connecting processes. Notification-only runs cannot supply defended utility results. Kernel `kill` is forced failure, not pre-operation denial. Untracked controller/tool-output IPC remains a limitation.
- Inspect compiled policies. `**/.env` lowers to suffix `/.env`, whereas `**/.env*` contains a literal `.env*` matcher. `Op::Read` maps to `OP_OPEN`, so source opens do not prove that content was read.
- Executable transforms use basename matching (`lower_exec`), so a path written in a declassification declaration does not authenticate the executable. Gate provenance, agent write access and scrub behavior require independent verification. Without a trustworthy gate execution, condition (c) measures narrowing only.
- Freeze policy intent independently of matches. Harmless fixture data and real credentials require distinct adjudication. A benign task label or success outcome cannot establish that an intervention is false. Retain unresolved cases as unknown.
- Select tasks before outcomes and preserve exclusions/failures. Pair time comparisons by task and separate execution from image download/build and infrastructure failure. Single repetitions yield descriptive comparisons with sampling uncertainty.

No conceptual blocker remains. Executability and any trusted-declassification claim remain contingent on these checks. Parent accepted the review and relayed all implementation checks to both workers. The plan now explicitly records the controller/model-context and enforcement boundaries. Gate execution will not be claimed without trust evidence.

## Targeted implementation review before full trials

The same reviewer inspected the evolving benchmark adapter and replay integration. Concrete checks found and relayed before model outcomes: malformed `**.pem`/`**.key` source patterns, an explicit initial label that could pre-taint the root, wall-clock versus kernel-monotonic timestamps, incomplete detection of mid-run instrumentation death, and different source families between benchmark and replay. The owners corrected the match patterns to supported suffix forms, confirmed zero initial labels, recorded monotonic call boundaries, added liveness receipts, and coordinated the source family. Final evidence review must verify these changes on the actual executed files.

Instruction inventories alone are not policy enforcement. Applicable enforceable directives must be applied; semantic requirements that the DSL cannot express need individual exclusions. Scoped sources must be justified by task instructions or an independent pretrial inventory. The fixed official OpenSSL task explicitly combines its private key and certificate in `server.pem`, so that file is sensitive in this task. A generic assumption that every PEM is public or private would be incorrect.

The reviewer independently inspected the fixed benchmark instructions and noted that Git-history secrets and executable flags may fall outside filename-based sources. Their absence from source events cannot be described as absence of semantic secret handling. The implementation review requested no broad product changes or additional test scaffolding.

## Namespace scope failure found in real preflight

The benchmark worker found actual agent command evidence with no corresponding root-mode observer activity. Workspace `/proc` PIDs differ from the initial-namespace PIDs used by eBPF. Thus readiness of a loader seeded with a Workspace PID did not establish protection. The replay worker confirmed the same issue affected its preliminary defended run, despite working comm-tagged observation. Those defended receipts are invalid for intervention rates and utility. Both workers are mapping each actual retained shell/worker to its kernel PID through an independent marker, then requiring a separate enforcement engagement check. Calibration actions are excluded from benchmark and replay outcomes and do not alter official tasks to force source exposure.

## ATIF interpretation correction during execution

The initial comparison of ATIF totals with dispatch counts incorrectly treated nonterminal completion markers as undispatched commands. Inspection of actual function names showed the surplus records were `mark_task_complete`, while native `bash_command` counts matched dispatches in the audited completed main trials. The unsupported causal explanation for failures is retracted. Annotation documentation and the benchmark producer now distinguish total logged calls, command calls, nonterminal markers and genuinely unmatched command records. Official verifier scores and actual-dispatch denominators are unchanged.
