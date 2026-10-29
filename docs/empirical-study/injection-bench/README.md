# Standard prompt-injection evaluation with OS effects

## Benchmark decision, made before model runs

The preferred benchmark is [OS-Harm](https://github.com/tml-epfl/os-harm), published in the NeurIPS Datasets and Benchmarks track as a spotlight. It provides official prompt injections, real desktop/OS execution, matched clean execution, and official task/safety evaluation. Its official Docker VM setup cannot currently be installed while respecting this lane's shared-disk constraint. The measured archive and extracted-image sizes are recorded by `scripts/image_inventory.py`; see `BLOCKED.md` and the generated inventory in `results/`. A host eBPF observer around QEMU would not enforce guest filesystem operations, so wrapping QEMU is not a valid substitute.

The runnable fallback is [RepoGuardBench](https://github.com/DaoyuanLi2816/RepoGuardBench), accepted at the non-archival Deep Learning for Code workshop at ICML. This is a published coding-agent benchmark with repository-borne indirect injections, actual isolated filesystem operations and command execution, matched clean/poisoned repair tasks, and an official deterministic scoring implementation. Code is MIT licensed; data and released results are CC BY. The artifact supports an official action-gate defense. Broad independent adoption is **not established**. Consequently this fallback does not fully satisfy the requested widely-used-benchmark criterion and cannot by itself close that requirement. It is preferable to hand-built tasks or treating simulated tool calls as kernel effects.

[SURVEY.md](SURVEY.md) compares the requested benchmarks and newer published candidates using primary sources. RedCode-Exec measures direct unsafe requests rather than the required indirect-input boundary. ASB, InjecAgent and AgentDojo use simulated tool environments. An OS-backed AgentDojo port was not established. OpenAgentSafety is the existing paper evaluation and has a heavier service dependency. RTC-Bench is another published OS-backed candidate whose official environment exceeds this Workspace's storage envelope.

## Comparison and evidence contract

The comparison uses the official no-defense condition, the official published action-gate implementation, a task-only policy authored before repository context and installed by the parent authority, and a policy authored after the executing agent sees repository context and submitted within its own child domain. Each condition uses the direct Qwen endpoint and the named GLM gateway model, with the same official task, attack, agent-loop and scoring paths. Kernel enforcement must be demonstrated before a defended result can be reported.

Policies must not see attack goals, expected effects, hidden tests or injected context in the parent-authored condition. The child condition starts without a restrictive parent policy and therefore cannot establish the benefit of a trustworthy parent by construction. It tests the weakness of post-exposure self-authorship. Natural policy-update attempts are retained. No custom weakening attacks are added to the official benchmark.

We retain the benchmark's distinction between proposed malicious actions, landed unsafe actions and completed attacks. ASR is the official completed-attack fraction; utility is the official target-test pass fraction on clean and attacked tasks. Failures and timeouts stay in the planned denominator. Missing or failed evaluations remain visibly unknown when the state cannot be scored. Clean utility and attacked utility use matched base tasks.

Every policy submission records its text, caller identity, target domain, outcome and available kernel admission counters. User-space precheck rejections are labeled as such. An audit log saying `rejected` is not, by itself, a kernel rejection. There is no per-attempt kernel claim without kernel evidence. Natural absence of weakening attempts is a coverage limitation, not evidence of rejection.

## Run and artifacts

All execution takes place in `/workspaces/exp/injection-bench`. Only lane scripts and small derived results are committed here. Large raw requests, responses, trajectories, task workspaces and upstream clones remain in the remote `raw/` directory. See [PLAN.md](PLAN.md), [KERNEL.md](KERNEL.md) and [BLOCKED.md](BLOCKED.md).

Status: source and resource inspection completed; model benchmark results pending. A paper-ready paragraph, generated table, PDF figure and final `SUMMARY.md` will be added after the actual runs and validity review.
