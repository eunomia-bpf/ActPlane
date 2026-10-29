# Benign utility and session-position interventions

## Question and admission

Do realistic AgPlane policies reduce success on standard benign agent tasks, and does the intervention rate increase later in sessions? This directly addresses ATC reviewers B and D, especially D's `.env` example (`rebuttal/reviews.txt`, review 479D). The supplied lane request defines the question; `docs/idea-story.md` and `docs/evaluation.md` are absent in this checkout. No paper files will be edited.

This is potentially decisive evidence about the tested deployment boundary. High utility loss would require a qualified utility claim and an explicit policy-scoping limitation. Low loss with few actual secret reads would bound the workload only, rather than refute over-tainting. Existing synthetic long-session probes do not measure agent task success, so cannot replace this experiment. Public-trajectory replay supplies supporting longitudinal evidence, not an alternative success benchmark.

## Protocol

Use published Terminal-Bench 2.0 with the official Harbor harness, official task verifiers, and unchanged task timeouts and agent defaults. Record exact installed versions, dataset commit, task identifiers, model identity, and all nondefault configuration. Select tasks before examining agent outcomes; document practical selection criteria and all exclusions. If Terminal-Bench cannot execute, investigate the authorized official SWE-bench Verified fallback and record why the preferred route failed.

Compare the same selected tasks and agent/model under three conditions: (a) no AgPlane, (b) secret-file read sources plus tainted-process network denial and applicable repository instructions, and (c) the same rules with narrower actual-secret sources and a trusted declassification/redaction gate. No source or gate is inserted into an official task merely to force engagement. Trusted gate presence, execution and trust assumptions must be reported. A condition with no applicable gate execution measures narrowing only. Audit source matcher semantics against the compiler, rather than assume general shell-glob support.

Keep agent/model configuration and official verifier fixed between conditions. Preserve failed trials, retries and infrastructure errors. Use the official binary reward/pass metric. Report paired task outcomes and denominators, plus wall time and a matched wall-time ratio; agent sampling noise is a limitation of single repetitions. Do not interpret infrastructure errors as agent failures or count smoke tests as benchmark numbers.

Record whether labels actually reach the controlling agent. Reading a secret in a child shell does not necessarily taint its parent or the model context through the tool-output channel. Low intervention under this process topology cannot demonstrate safe session-wide information flow. Likewise, a kernel `kill` condition must be named as post-operation forced failure, not BPF-LSM pre-operation denial. If neither actual enforcement path works, mark defended utility unavailable and retain any valid baseline or replay evidence separately.

## Intervention verification

An intervention is a denied action or an action forced to fail by the engine; notification-only matches are separate observations. Report the denominator (all indexed agent calls, and relevant OS effects where observed) explicitly. A benign task does not make every attempted action policy compliant. Inspect each intervened action against the independently stated policy and action context. Count as false only when evidence establishes no real policy violation. Preserve `true violation`, `false intervention`, and `unknown` separately, with the verification evidence. Do not infer data-content safety from absence of attack instructions.

Use absolute agent tool-call index bins for session position, retaining raw indices and session lengths. The requested false-intervention rate is a study-specific diagnostic, since the benchmark defines success rather than security false-positive annotations. Report both confirmed false interventions and unresolved interventions; do not silently assign unknowns to negatives. Position plots are descriptive, not causal evidence of taint growth without matched secret-read and label-engagement evidence.

## Public trajectories

Copy the existing trajectory-indirect harness and its public trace inputs into this lane's remote raw directory without modifying the originals. Apply the same policy intent to all available public trajectories and preserve provenance. Report incomplete effects, replay abstraction, and whether kernel calls are reenacted or historical labels simulated. Replay measures counterfactual policy effects on recorded calls; it cannot measure how a live agent recovers or changes task success.

## Execution and artifacts

All computation runs inside actplane-dev through `ws.sh`; Windows is used for source edits and Git only. Large traces, images and logs remain under `/workspaces/exp/benign-utility/raw`. Detached jobs stream to the lane logs. Keep `/workspaces` under the supplied disk threshold and remove only lane-owned expendable images. Never alter an active observer, another lane, a deployment replica count, or the paper.

Official sources checked during setup: [Terminal-Bench 2.0 task repository](https://github.com/harbor-framework/terminal-bench-2), [Harbor official harness](https://github.com/harbor-framework/harbor), and [benchmark release announcement](https://www.tbench.ai/news/announcement-2-0). The official harness supports installed agents and container execution. Exact versions used locally must come from recorded installation metadata rather than these moving pages.

Independent benchmark and replay scripts live in `benchmark/` and `replay/`. This directory contains shared analysis, `results/`, a paper-ready README paragraph, a PDF figure (`pdf.fonttype=42`), `SUMMARY.md`, and any actual blockers in `BLOCKED.md`. Every reported numerical result must be derived from committed CSV files by committed scripts. A fresh reviewer will review this plan before the full comparison and review final evidence after execution.
