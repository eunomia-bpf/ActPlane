# Scientific plan review

Reviewed: `PLAN.md`, `README.md`, `SURVEY.md`, `KERNEL.md`, and `BLOCKED.md` before benchmark execution. This review does not certify an unimplemented adapter or a future run.

## Verdict

**Conditional go for a supporting published-benchmark experiment.** The proposed comparison addresses the stated uncertainty, uses genuine indirect repository injection and real OS effects, and reuses official tasks, attacks, action defenses, agent loop, and scoring. It does not fulfill the stronger request for a widely used benchmark. That requirement remains open and must remain visible in the final summary and paper-ready paragraph.

The baseline roles are coherent: D0 is the common-sandbox null control; the official D3 action gate is an external published mechanism; parent-pre is the proposed deployment; child-post is an author-timing/authority ablation. A parent-pre versus child-post difference jointly changes timing, trust and authority, so it cannot isolate which component caused the difference. The experiment may support the combined deployment position, not separate causal claims about each component.

## Requirements before admitting defended results

1. **Protect the enforcement plane from the executing worker.** The Workspace itself is root. Before delivering untrusted context, the actual worker must lose privileges that could modify BPF maps, signal/ptrace the trusted engine, change its policy artifacts, or replace the trusted control plane. Record its effective credentials/capabilities and the actual parent/child domain membership. A distinct peer PID is necessary for scoped control requests but does not itself establish a security boundary. This is already identified in `KERNEL.md`; a worker retaining unrestricted Workspace root authority would invalidate the claimed deployment.
2. **Demonstrate enforcement, not only a configured engine.** Preflight must show a real protected syscall effect rejected within the bound worker and permitted legitimate task effects, using the actual loaded DSL and engine. Keep scorer/setup/cleanup outside the worker's policy domain. A successful CLI exit, audit notification, policy compilation or count increment alone does not establish effect prevention.
3. **Freeze the sampled matrix before outcomes.** Publish the deterministic selection algorithm and exact manifest before collecting benchmark results. Include at least fifty distinct official base tasks, balanced carrier/goal coverage, Applied coverage, and matched clean runs. A full-split expansion is acceptable if it is explicitly scheduled and completed across the matched matrix; do not choose the final task set using observed attack or utility outcomes.
4. **Resolve unknown outcomes explicitly.** Keep every planned cell in its denominator and retain operational failures. If a crash/timeout leaves final filesystem state unavailable, its attack outcome is unknown, rather than a demonstrated prevented attack. Report the unknown count and, where needed, ASR bounds over the full planned denominator. If official state can be inspected after a failure, score that state with the official scorer. Do not replace an unknown official result with a custom success predicate.

These are result-validity requirements, not requests to expand the task or add benchmark attacks. Unmet requirements block claims for the affected comparison rather than converting infrastructure failure into a proposed-method win.

## Fairness and interpretation checks

- Policy-construction prompts must supply grammar/interface knowledge without revealing carrier names, attack goals, canary paths, malicious markers, or expected hidden effects to the parent author. The parent can receive the legitimate task and clean issue description as the trusted task specification. Record the exact prompt, response, and ordering.
- The post-exposure policy request must genuinely contain the same untrusted context subsequently used by the executing agent. Preserve its model-produced policy text and conversation ordering. Do not submit that alleged child mutation from an unbound privileged supervisor.
- Keep the official action-turn budget and generation options aligned across systems. Document unsupported transport options. Record policy-author calls and costs separately so the comparison is not described as equal total inference cost.
- The official D0 sandbox is already restrictive. Results measure added defense on that common substrate. They cannot establish unrestricted-agent attack resistance or general prevention of network exfiltration.
- Completed-attack ASR must follow the pinned official scorer even when a benchmark goal's predicate is narrower than its name. Keep proposed unsafe actions, landed effects, and official completion distinct. Do not silently fix an official predicate for one system.
- A valid result may be negative: parent-generated policies can be incomplete, fail to compile, or prevent useful repairs. Such outcomes test policy construction and must remain in the comparison without an oracle fallback.
- The official attacks may never try to modify policy authority. Record natural attempts, but zero observed attempts supplies no evidence of kernel rejection. Retain parsing/precheck/kernel stages separately; aggregate kernel counters require correlation before per-attempt attribution.

## Expected decision value

A valid matched result can provide supporting evidence about pre-exposure, higher-authority policy construction on this coding artifact. It cannot establish broad non-coding generality, adaptive-attack resistance, independent timing-versus-authority effects, or the requested per-attempt kernel-rejection coverage if the official attacks never engage that path. The plan is worthwhile within those boundaries; no additional baselines or hand-built attacks are required to make the fallback publishable as bounded supporting evidence.
