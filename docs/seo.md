# ActPlane SEO & Terminology Decisions

## Core Positioning

**ActPlane: eBPF-Based Policy Engine for AI Agent Harnesses**

- **"agent harness"** — 2026 mainstream term coined by Mitchell Hashimoto (Agent = Model + Harness). Used by Salesforce, LangChain, Martin Fowler, HuggingFace, OpenAI. Guardrails and sandbox are subcomponents of harness. High SEO value, keep.
- **"policy engine"** — dominates over "rule engine" in runtime systems (OPA, KubeArmor, Tetragon). Keep for external positioning.
- **"observability and enforcement"** — Tetragon's tagline. Standard eBPF security framing (Cilium, KubeArmor, Falco). Keep in README headline for SEO.

## Terminology Matrix

| Context | Use | Rationale |
|---------|-----|-----------|
| README headline / SEO | "observability and enforcement" | Industry standard eBPF keyword pair |
| External positioning | "policy engine" + "agent harness" | Highest SEO value |
| Paper (ActPlane does what) | "observe and apply rules" | Covers notify + block + kill without implying only enforcement |
| Paper (empirical study taxonomy) | "enforcement level" / "enforcement layer" | Classification term about mechanisms in general, not ActPlane specifically |
| Paper (describing others' systems) | "enforcement" | They genuinely only enforce |
| Code / internal | "rule" / "rule match" | DSL unit is `rule`, kernel output is a rule match |
| Feedback JSON wire format | `"action"` field | Was `"enforcement"`, changed for consistency |

## Why Not "enforce" Everywhere

ActPlane has three effects:
- **notify** — observe and report, operation proceeds
- **block** — pre-op denial (BPF-LSM)
- **kill** — post-op termination

"Enforce" only covers block/kill. "Apply" covers all three (applying a rule by evaluating it and taking the declared action). The paper and internal code use "apply" / "rule" / "rule match" for precision.

Exception: README headline keeps "enforcement" for SEO — it pairs with "observability" as the established eBPF keyword pair.

## "policy" vs "rule"

- **"policy"** = the whole actplane.yaml with all its rules. Used externally.
- **"rule"** = an individual rule within the policy. Used in DSL, code, paper details.
- Both are correct at different granularity. "Policy engine" externally, "rules" internally.

## "policy" in Observability vs Security

- Observability tools (Prometheus, Grafana, Datadog, bpftrace) do NOT use "policy" — they use "rules", "alerts", "probes", "monitors"
- "Policy" carries enforcement/action connotation — used by OPA, Tetragon, KubeArmor (all security/enforcement)
- ActPlane's notify mode is still "condition + action" (notify agent), so "policy" is accurate

## Competitive Landscape (2026)

### eBPF + Agent

| Project | What it does | Gap ActPlane fills |
|---------|-------------|-------------------|
| ARMO (blog) | eBPF for AI agent enforcement at syscall level | Sees syscalls but not semantic intent |
| eBPF-PATROL | Kernel-level runtime policy enforcement in containers | Per-event predicates, no cross-event IFC |
| AgentCgroup | eBPF + cgroups for intent-driven resource control | Resource control, not information-flow |

### Agent Harness Frameworks

| Project | Stars | Focus | vs ActPlane |
|---------|-------|-------|-------------|
| OpenHarness (HKU) | 9.1k | CLI-first agent runtime, 43+ tools | Tool-layer, no OS-level |
| AURA (Mezmo) | — | Rust-based, declarative TOML config | No kernel enforcement |
| Deep Agents (LangChain) | — | Batteries-included harness | Framework-level, bypassable |

### Agent Guardrails

| Project | Focus | vs ActPlane |
|---------|-------|-------------|
| AgentSpec | Tool-call name/arg validation | Bypassable via subprocess |
| Progent | Framework action policies | Same bypass issue |
| FIDES / CaMeL | Typed IFC within agent loop | Agent-loop level, not OS level |

### Key Differentiator

None of the above does **OS-level labeled information-flow control** with **cross-event state tracking** and **corrective semantic feedback**. ActPlane is unique in combining all three.

## Sources

- [Tetragon: eBPF-based Security Observability and Runtime Enforcement](https://tetragon.io/)
- [2025 Was Agents. 2026 Is Agent Harnesses](https://aakashgupta.medium.com/2025-was-agents-2026-is-agent-harnesses)
- [Mitchell Hashimoto: Agent = Model + Harness](https://mitchellh.com/)
- [LangChain: Anatomy of an Agent Harness](https://www.langchain.com/blog/the-anatomy-of-an-agent-harness)
- [Martin Fowler: Harness Engineering](https://martinfowler.com/articles/harness-engineering.html)
- [ARMO: eBPF-based AI Agent Enforcement](https://www.armosec.io/blog/ebpf-based-ai-agent-enforcement/)
- [eBPF-PATROL](https://arxiv.org/html/2511.18155v1)
- [AgentCgroup](https://arxiv.org/pdf/2602.09345)
- [Salesforce Agentforce Harness](https://www.salesforce.com/agentforce/ai-agents/agent-harness/)
