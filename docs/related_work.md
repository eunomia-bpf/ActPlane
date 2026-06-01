# Related Work

**ActPlane** is an OS-level agent harness that enforces **labeled information-flow** / provenance
rules across **process, file, and network** channels for AI agents (a labeled, dynamic form of
the DIFT/taint mechanism of §1, used here as a harness substrate rather than for attack
detection). It runs in the kernel
(eBPF / BPF-LSM), propagates information-flow labels along fork/exec, file-read/file-write, and socket
send/recv edges, blocks forbidden source→sink flows at the relevant LSM hook (returning
`-EPERM` / killing), and closes the loop with **corrective semantic feedback** delivered back to
the agent. The threat model is a **cooperative-but-forgetful agent** — an autonomous LLM agent
that is not actively adversarial but will, through carelessness or prompt-injection drift, take
actions that trigger a data-handling policy rule — though the same mechanism also raises the bar
against some active misuse.

This document situates ActPlane against the literature, grouped by theme. Each entry gives a
short summary and an explicit **vs ActPlane** line stating what it shares and what it lacks. A
comparison table and an honest synthesis of the remaining gap follow. Local PDFs are in
`docs/reference/`; web sources are linked inline.

The dimensions that matter throughout:

- **Layer** — kernel vs userspace (does the monitored agent control the enforcement point?).
- **Enforce vs detect** — does the system *block/prevent* the action, or only *record/alert*?
- **Taint propagation** — does it carry a label that *flows* across objects, vs. a per-event
  point lookup?
- **Cross-channel** — does taint span **process + file + network**, or just one (usually
  fork/exec lineage)?
- **Agent-aware** — does it model an AI/LLM agent specifically?
- **Feedback loop** — does it return corrective, semantically meaningful feedback to the actor
  (vs. a silent `-EPERM` or a log line)?

---

## 1. Dynamic Information-Flow Tracking / Taint Analysis (DIFT)

These define ActPlane's core mechanic — mark at *sources*, propagate, check at *sinks* — but at
a finer granularity and (mostly) inside a single address space.

**TaintDroid** (Enck et al., OSDI 2010; `taintdroid.pdf`). System-wide dynamic taint tracking
inside the Android/Dalvik runtime. It taints privacy-sensitive sources (location, IMEI,
contacts), propagates labels transitively through variables, files, and IPC messages, and
**logs** when tainted data reaches a network sink. Threat model: untrusted third-party apps.
*vs ActPlane:* Shares the source→propagate→sink model and the insight that taint must cross
process/file/IPC boundaries. But TaintDroid lives *inside the managed runtime* (not the OS
kernel), is **detect-only** (it logs leaks, never blocks them), and is not agent-aware. ActPlane
lifts the same model to whole-OS granularity via eBPF and *enforces* at the sink.

**Dytan** (Clause et al., ISSTA 2007; `dytan.pdf`). A configurable x86 taint framework where
sources, sinks, and propagation (including optional implicit/control-flow) are *user-defined
policy*, not hardcoded engine behavior.
*vs ActPlane:* Motivates ActPlane's declarative source/sink/edge rule model. But Dytan is
in-process binary instrumentation, analysis-only, single-program, not OS-wide, not agent-aware.

**libdft** (Kemerlis et al., VEE 2012; `libdft.pdf`). Fast byte-granularity DFT over unmodified
binaries via Intel Pin, using a shadow-memory tag map.
*vs ActPlane:* Canonical reference for *how* to represent/propagate tags. ActPlane's per-object
graph labels are the coarse kernel analog of libdft's per-byte tags — trading instruction-level
precision for whole-system, low-overhead coverage. libdft is in-process, heavy DBI overhead, no
enforcement of agent policy.

**Panorama** (Yin et al., CCS 2007; `panorama.pdf`). Whole-system taint inside a QEMU emulator;
taints sensitive inputs and observes how malware accesses/exfiltrates them, building
system-wide information-flow graphs to *classify* behavior.
*vs ActPlane:* Early proof that *whole-system* information flow across processes/kernel/disk/net
reveals policy-violating behavior — exactly ActPlane's scope. But Panorama runs in an emulator
(not the real kernel), is detection/analysis, and is not real-time enforcement.

**Schwartz et al. survey** (IEEE S&P 2010; `taint-survey-schwartz.pdf`). Operational-semantics
treatment of DTA: precise source/sink/propagation definitions, soundness/completeness
trade-offs, and the canonical pitfalls (under-tainting, over-tainting, implicit flows).
*vs ActPlane:* Not a system — the reference for stating ActPlane's taint semantics rigorously
and being honest about its precision limits (coarse object-level taint *over-taints*; ActPlane
inherits exactly these trade-offs and must mitigate dependency explosion, see RAIN below).

---

## 2. OS Provenance Capture & Provenance-Based Access Control

ActPlane's substrate is a whole-system provenance graph. These build that graph in the kernel
and (in the later ones) attach policy to it.

**PASS** (Muniswamy-Reddy et al., USENIX ATC 2006; `pass.pdf`). First system to treat
provenance as a first-class storage primitive, auto-recording file lineage at the OS/storage
layer and supporting provenance queries.
*vs ActPlane:* Establishes the file-read/file-write provenance edges ActPlane propagates taint
along. Record/query only; no enforcement, no taint rules, not agent-aware.

**Hi-Fi** (Pohly et al., ACSAC 2012; `hifi.pdf`). Uses the LSM framework to capture complete,
tamper-evident whole-system provenance (process/file/IPC/socket) from boot, emphasizing not
missing security-relevant events.
*vs ActPlane:* Validates LSM hooks as the right placement for *complete* capture — directly
informing ActPlane's BPF-LSM hook points. But Hi-Fi is capture-only (no enforcement, no taint
policy).

**LPM — Linux Provenance Modules** (Bates et al., USENIX Security 2015;
`lpm-trustworthy-provenance.pdf`). Generalizes Hi-Fi into a modular secure-provenance framework
and introduces **provenance-based access control (PBAC)** plus a trusted provenance-aware
authority, addressing how to make the provenance record itself trustworthy.
*vs ActPlane:* The closest *classic* precursor to ActPlane's enforcement idea — access decisions
driven by provenance — and the source of ActPlane's integrity requirements (an attacker/forgetful
agent must not be able to forge or drop the edges taint depends on). But LPM's PBAC is about
access control over the provenance graph in general; it is not a *labeled information-flow* rule
engine, not eBPF, and not agent-aware.

**CamFlow** (Pasquier et al., SoCC 2017; `camflow.pdf`). Low-overhead whole-system provenance
capture for modern Linux (LSM + NetFilter kernel module), emitting W3C-PROV graphs over
process/file/socket/IPC, designed to feed downstream security/compliance apps.
*vs ActPlane:* The canonical modern blueprint for the exact graph ActPlane operates on. **Crucial
distinction (verified from the paper):** CamFlow as described is *record-only* — it is
deliberately ordered last among LSMs so it does not record flows other modules already blocked.
The *enforcement* capability lives in its successor, CamQuery (next).

**CamQuery** (Pasquier et al., CCS 2018; `camquery-runtime-provenance.pdf`). **The single
closest piece of prior art — and the load-bearing comparison for this project.** CamQuery runs
user-defined vertex-centric analyses *inline, in real time, in the kernel* over the live CamFlow
provenance stream at LSM hooks. **It enforces, not merely detects.** Verified directly from the
paper:

- "CamQuery exposes a general mechanism for **system mediation**, allowing security applications
  to **authorize or deny** new access based on the provenance history of the concerned
  principals." (§3.4)
- The `out_edge`/`in_edge` callbacks "are actually executed **before** the actions they describe
  ... This enables CamQuery to **prevent** policy violations rather than merely detecting them."
  (§4.3)
- "only the in-kernel implementations can **prevent** policy violations; like previous systems,
  the user space and remote implementations can only **detect**." (§4.3)
- Listing 1 implements a loss-prevention scheme that propagates a `confidential` label along
  `RL_WRITE / RL_READ / RL_SND / RL_RCV / RL_VERSION / RL_CLONE` edges (i.e., **process → file →
  process → socket** taint) using `add_label`, and acts at the socket sink. The paper states
  these labels let developers "easily implement ... taint tracking, information flow control, or
  access control."

So CamQuery already occupies most of ActPlane's headline cell: **in-kernel + enforce + label
(taint) propagation + cross-channel (process/file/network) + provenance-graph-based**.
*vs ActPlane:* This is where ActPlane must be honest. ActPlane is essentially "taint propagation
as an inline CamQuery-style program with a sources/sinks DSL." The genuine differences are
narrow and must be stated as such:
1. **Mechanism**: CamQuery runs as a CamFlow LKM / linked kernel object; ActPlane targets the
   upstream **eBPF / BPF-LSM** runtime (no kernel module, dynamically loadable, verifier-checked),
   which did not exist when CamQuery was built (the BPF LSM landed in Linux 5.7, 2020).
2. **Threat model & domain**: CamQuery targets a remote *adversary* on a host; ActPlane targets a
   **cooperative-but-forgetful AI agent** and exposes an agent-oriented rule vocabulary.
3. **Feedback loop**: CamQuery returns a kernel verdict (deny / `PROVENANCE_RAISE_WARNING`);
   ActPlane adds **corrective semantic feedback to the agent** (telling it *why* an action was
   blocked so it can self-correct) — a capability with no analog in CamQuery.
   CamQuery is not agent-aware and has no feedback loop. The taint-propagation + cross-channel +
   in-kernel-enforce combination, however, is **not novel** — CamQuery has it. ActPlane's novelty
   is the *agent harness* framing (eBPF substrate + agent-aware policy + corrective feedback) on
   top of a mechanism CamQuery proved feasible.

---

## 3. Provenance-Graph Intrusion / Attack Detection

These model OS activity as a graph and run detection over it. Architecturally the closest
relatives of ActPlane, but the goal is **detection, not prevention** (verified: all of these
alert/reconstruct after observing the flow).

**SLEUTH** (Hossain et al., USENIX Security 2017; `sleuth.pdf`). Builds an in-memory dependency
graph from COTS audit data and uses **tag-based** confidentiality/integrity *labels that
propagate along dependencies* to detect and reconstruct multi-stage attacks in real time.
*vs ActPlane:* SLEUTH's propagating trust/integrity tags over a system graph is almost exactly
ActPlane's taint propagation — but for **post-hoc scenario reconstruction and alerting**, not
prevention. ActPlane reuses the tag-propagation model to *block the sink*. Detect-only,
not agent-aware.

**HOLMES** (Milajerdi et al., IEEE S&P 2019; `holmes.pdf`). Correlates suspicious information
flows and maps low-level events to ATT&CK TTPs, producing a compact high-level scenario graph
for APT detection with few false alarms.
*vs ActPlane:* Shows how to express *policy-level meaning* over a low-level graph and how to keep
false positives low via flow correlation — relevant to ActPlane's over-taint problem. But
HOLMES alerts; it does not enforce.

**RAIN** (Ji et al., CCS 2017; `rain.pdf`). Combines coarse syscall provenance with on-demand
record-and-replay DIFT to tame *dependency explosion*, refining causality only where needed.
*vs ActPlane:* Directly addresses ActPlane's biggest accuracy risk — over-tainting/dependency
explosion in coarse OS-graph taint. RAIN's coarse-then-refine strategy is a concrete blueprint
for how ActPlane could tighten taint to avoid blocking benign operations. Investigation tool,
not an enforcer.

**UNICORN** (Han et al., NDSS 2020; `unicorn.pdf`). Anomaly detector that summarizes the
streaming whole-system provenance graph into fixed-size *graph sketches* and learns normal
behavior to flag slow APTs without signatures.
*vs ActPlane:* Demonstrates bounded-memory streaming computation over the same live graph
ActPlane consumes, and is the *learning-based* contrast to ActPlane's explicit declarative rules.
Detect-only.

**StreamSpot** (Manzoor et al., KDD 2016; `streamspot.pdf`). General streaming heterogeneous-graph
anomaly detector using shingling/sketch similarity; bounded memory, online.
*vs ActPlane:* The algorithmic foundation under UNICORN; evidence the system-activity-as-graph
abstraction is sound. Pure anomaly detection, no enforcement, no taint rules.

---

## 4. eBPF / LSM Runtime Enforcement

These are ActPlane's enforcement *mechanism*: turn a decision into allow/deny at a kernel hook.

**KRSI / BPF-LSM** (KP Singh, Linux Plumbers 2019; upstream in Linux 5.7; `krsi-talk.pdf`).
Attaches eBPF programs to LSM security hooks so they can return a permit/deny verdict per hook,
without rebuilding the kernel.
*vs ActPlane:* This *is* ActPlane's enforcement primitive — "tainted process may not exec git /
connect to host X" becomes a BPF-LSM program returning `-EPERM` at `bprm_check_security` /
`socket_connect`. KRSI is the mechanism, not a policy/taint engine; no graph, no agent semantics.

**eBPF-PATROL** (Ghimire et al., arXiv 2511.18155, 2025; `ebpf-patrol.pdf`). A recent eBPF
runtime-security agent for containers/VMs that intercepts syscalls, inspects arguments and
execution context, and **enforces** (Deny / Allow / Kill) against user-defined rules.
*vs ActPlane:* A contemporary point of comparison for eBPF enforcement. **Verified limitations:**
its pipeline is Probe → Event Analyzer → Policy Engine (match against rules) → Enforcement —
i.e., **per-event, argument-aware syscall matching with no taint propagation and no provenance
graph**. Its related-work section name-drops "process lineage analysis" as something prior tools
lack, but eBPF-PATROL itself does *not* build cross-edge taint — each decision is a single-event
match. Its threat model is an active container/VM adversary (LOLBins, container escape), not a
cooperative agent, and it is not agent-aware and has no semantic feedback.

**OAMAC — Origin-Aware Mandatory Access Control** (arXiv 2601.14021, 2026;
[abs](https://arxiv.org/abs/2601.14021), [html](https://arxiv.org/html/2601.14021v1)). Very
recent. Treats *execution origin* (physical-local / remote / service) as a first-class attribute,
**propagates origin across process creation**, and **enforces** origin-aware MAC on sensitive
filesystem interfaces and the BPF control plane — implemented **entirely in the eBPF LSM
framework**, policies in kernel-resident eBPF maps, reconfigurable at runtime.
*vs ActPlane:* The closest *2026* eBPF-LSM analog of ActPlane's "propagate a label across process
lineage and enforce at a hook." But (verified from the abstract) OAMAC propagates origin **only
across process creation** — *not* along file-read/write or network edges — its threat model is
post-compromise attack-surface reduction (not a forgetful agent), it is **not agent-aware**, and
it has **no corrective/semantic feedback**. It is single-channel (process lineage) typed
provenance enforcement; ActPlane is multi-channel taint enforcement with an agent feedback loop.

**STBAC — Suspicious-Taint-Based Access Control** (researchgate; one of several published
variants —
[v1](https://www.researchgate.net/publication/307537706_Suspicious-Taint-Based_Access_Control_for_Protecting_OS_from_Network_Attacks)).
Treats processes using non-trustable communications as suspicious-taint origins, spreads taint
flags through OS-kernel activity via taint rules, and **prevents** tainted processes from
accessing vital resources via protection rules.
*vs ActPlane:* Conceptually the oldest near-twin of ActPlane's taint+enforce idea at OS level
(taint spreads through kernel activity; protection rules block at sinks). But its threat model is
network intruders, it predates eBPF (kernel-modification based), and it is not agent-aware, has
no agent feedback, and is not a general typed cross-channel DSL.

**Production OSS enforcers** (no academic PDF; surveyed in `docs/reference/oss-landscape.md`):
**Cilium Tetragon** (BPF-LSM/kprobe, `Sigkill`/`Override` errno, and `matchBinaries` +
`followChildren` which propagates a *per-binary lineage flag* to descendants in a BPF map —
[selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/)); **KubeArmor** (BPF-LSM
`Block` with single-hop `fromSource`); **bpfbox**/**bpfcontain** (research eBPF-LSM default-deny
confinement); **Falco** (detect-only, userspace eval, `proc.aname[n]` ancestor *lookup*);
**Tracee** (eBPF capture + userspace signatures); **Landlock** (in-tree unprivileged
self-sandbox, path/net, `-EACCES`).
*vs ActPlane:* Tetragon's `followChildren` is the single most-overlapping OSS feature, but it
propagates only a boolean lineage flag along **fork/exec**, not labeled information flow across **file/network**
edges; it caps at 64 sections and does not match pre-existing children. None of these propagate
labeled information flow across file *and* network *and* process edges, none are agent-aware, none give
semantic feedback. They are the right enforcement substrate to reuse — not the policy model.

---

## 5. LLM-Agent Guardrails & Capability Control

ActPlane's application domain. Verified key point: these enforce at the **tool-call / userspace**
layer *inside* the agent framework, so they are **bypassable** by anything the agent does outside
its tool API (raw subprocess, direct socket, file write).

**Progent** (Shi et al., arXiv 2504.11703, 2026; `progent.pdf`). Privilege control via symbolic
rules over **tool names and arguments**; every tool call is checked deterministically (least
privilege), policies are LLM-generated and tightened by an SMT solver into "monotonic
confinement." Threat model: indirect prompt injection (adversarial).
*vs ActPlane:* The closest agent-security analog of ActPlane's rule model, and a strong design
for *deterministic* policy on agents. But Progent enforces at the **tool-call API inside the
agent framework** — it explicitly relies on "all external effects of an agent occur through
[tool calls]," which a forgetful agent shelling out or opening a raw socket breaks. ActPlane
enforces at the **OS syscall/LSM layer below it**, catching actions even when they bypass the
tool API, and adds cross-object taint that per-tool-call checks lack. Complementary, different
layer.

**AgentSpec** (Wang et al., arXiv 2503.18666, ICSE 2026; `agentspec.pdf`). A DSL of `rule =
trigger → check(predicate) → enforce` for runtime constraint of LLM agents, hooked into the
LangChain decision pipeline. **Verified enforcement mechanisms:** action termination, user
inspection, **corrective invocation**, and **self-reflection** (via an LLM before the agent
proceeds).
*vs ActPlane:* ActPlane's source/sink rule structure mirrors AgentSpec's trigger/predicate/enforce
structure, and AgentSpec is the closest analog of ActPlane's **corrective-feedback** idea
("corrective invocation"/"self-reflection" = give the agent a chance to fix itself). But AgentSpec
runs in userspace inside the agent runtime (bypassable), does **no OS-level cross-process/file/net
taint propagation** — its checks are per-action and logical, not data-flow over OS objects.
ActPlane complements it by enforcing in the kernel (uncircumventable) and adding cross-channel
taint, while borrowing AgentSpec's corrective-feedback philosophy.

**GuardAgent** (Xiang et al., arXiv 2406.09187, 2024; `guardagent.pdf`). A separate "guard" LLM
that reads a safety request, plans, and emits guardrail *code* to deterministically check a
target agent's actions.
*vs ActPlane:* The LLM-in-the-loop guardrail style. Motivates ActPlane's *deterministic,
low-overhead, kernel-level* alternative: ActPlane does not invoke an LLM to decide each action and
cannot be evaded by the monitored agent, at the cost of reasoning over lower-level (syscall/graph)
semantics rather than high-level intent. Userspace, framework-level, bypassable.

**Recent (2025–26) agent-IFC / guardrail work found via search:**

- **SAFEFLOW** (arXiv 2506.07564, 2025) — a protocol that enforces **fine-grained information-flow
  control** tracking provenance/integrity/confidentiality of data exchanged between agents, tools,
  users, and environments.
  *vs ActPlane:* Closest *agent-native* IFC, and it does taint/IFC with provenance — but at the
  **agent-protocol / orchestration layer**, not the OS kernel; it governs data between agent
  components, not syscalls, and is bypassable below the protocol. ActPlane is the kernel-level
  complement.
- **LlamaFirewall** (arXiv 2505.03574, 2025) and **Policy-as-Prompt** (arXiv 2509.23994, 2025) —
  layered guardrail pipelines / NL-policy-to-guardrail synthesis at the prompt/tool layer.
  *vs ActPlane:* Userspace guardrail stacks; deterministic-but-bypassable, no OS taint, no kernel
  enforcement.
- **AgentSight** (arXiv 2508.02736, 2025; the eBPF observability framework this repository is built
  on) — uses eBPF to capture a userspace *Intent Stream* (LLM prompts via SSL uprobes) and a kernel
  *Action Stream* (syscalls/process events), framing the **"semantic gap"** between agent intent and
  low-level actions.
  *vs ActPlane:* The substrate and motivation for ActPlane — but AgentSight **observes** (it is an
  observability framework), it does not enforce taint policy. ActPlane turns the AgentSight-style
  eBPF action stream into an *enforcing* taint engine with feedback.
- **ARM — Agentic Reference Monitor** (described in "Causality Laundering," arXiv 2604.04035) — a
  provenance-aware runtime enforcement layer for tool-calling agents that records *denials* as
  first-class nodes and propagates trust through an integrity lattice over data dependencies.
  *vs ActPlane:* Shares provenance-graph + enforcement + denial-as-feedback for agents — but
  operates over the **tool-call/agent execution graph**, not OS-level process/file/network objects;
  same bypass gap as other tool-layer guardrails.
- **FIDES — "Securing AI Agents with Information-Flow Control"** (Microsoft Research, arXiv
  2505.23643, 2025; `fides.pdf`). Decomposes the agent loop into a planner and a planning loop and
  carries **information-flow labels** through it, intercepting each suggested action to enforce a
  confidentiality/integrity policy *deterministically* before it runs.
  *vs ActPlane:* The **mechanism-cousin** — labeled information flow + deterministic pre-action block is exactly
  ActPlane's model. The difference is the *layer*: FIDES enforces inside the agent loop (L1), so a
  forgetful agent that shells out / opens a socket / makes a direct syscall escapes it; ActPlane
  runs the same labeled information-flow discipline at the kernel/LSM boundary (L3), cross-process/file/network,
  uncircumventable. The single closest paper to cite as "same idea, wrong layer for un-bypassable
  enforcement."
- **CaMeL — "Defeating Prompt Injections by Design"** (arXiv 2503.18813, 2025; `camel.pdf`). A
  dual-LLM design that separates a trusted control flow from untrusted data and attaches
  capabilities/data-flow provenance as "model scaffolding," giving verifiable security without
  retraining.
  *vs ActPlane:* A design-time L1 guarantee for prompt-injection; complementary but cannot see
  below the tool layer. Reinforces that the modern agent-security frontier is *typed/capability
  IFC at the application layer* — ActPlane's contribution is moving that frontier to the OS.

---

## 6. Sandboxing / Isolation

**gVisor** (Apache-2.0; userspace kernel via ptrace/KVM). Strong syscall-surface isolation for a
sandboxed workload.
*vs ActPlane:* Coarse isolation boundary; no taint, no provenance, no ancestry/data-flow policy
DSL, not agent-semantic. Orthogonal: a box, not a flow tracker.

**Landlock** (in-tree Linux LSM; [docs](https://docs.kernel.org/userspace-api/landlock.html)).
Unprivileged self-sandboxing of filesystem and (newer) network access; domain inheritance to
descendants; returns `-EACCES`.
*vs ActPlane:* Its descendant-scoped domain inheritance resembles ActPlane's "descendants of X"
scoping, and it is a viable enforcement primitive. But it is *static path/port rulesets* with no
taint, no data-flow, no graph, and no agent feedback.

**E2B / Firecracker microVM** (agent code sandboxes). Coarse VM isolation boundary for "run this
agent code in a box."
*vs ActPlane:* Agent-aware at the isolation-boundary level only; no fine-grained taint or
cross-channel data-flow policy.

---

## 7. Empirical Studies of Agent Instruction Files (CLAUDE.md / AGENTS.md)

ActPlane's empirical motivation comes from a corpus of real `CLAUDE.md` / `AGENTS.md` files
(`docs/corpus/`, analysis in `docs/tmp/corpus-analysis.md`). A small but fast-growing 2025–26 line of
work studies these files directly — but along **orthogonal axes** to ActPlane: they characterize
*what developers write* (content taxonomy), *how it is structured/maintained*, and *whether it
helps task performance*. **None asks which instructions are behavioral/flow constraints, nor
whether any are enforceable below the tool layer** — the question ActPlane is built around.

**Chatlatanagulchai et al.** ("On the Use of Agentic Coding Manifests," arXiv 2509.14744, 2025;
`claude-manifests-empirical.pdf`) give the first taxonomy: 253 CLAUDE.md / 242 repos, a 15-label
content scheme (LLM-assisted label creation + 3-inspector manual assignment, consensus-resolved,
**no κ**). Content is dominated by Build&Run (77.1%), Implementation Details (71.9%), Architecture
(64.8%), Testing (60.5%); **"Security" is only 8.7%**. **Chen/woraamy et al.** extend this to a
cross-tool corpus ("Agent READMEs," arXiv 2511.12884, 2025; `agent-readmes-context-files.pdf`):
2,303 files / 1,925 repos across Claude Code, Codex, and Copilot, a 16-label scheme (Security
14.5%), plus readability, maintenance, and feasibility of automatic classification.
**Santos et al.** ("Decoding the Configuration of AI Coding Agents," arXiv 2511.09268, 2025;
`claude-config-decoding.pdf`) analyze 328 Claude Code config files for SE concerns and their
co-occurrence, finding architecture-centric patterns.

*vs ActPlane:* Two points matter for our corpus study. (i) **Their "Security" category (8.7–14.5%)
is about the *product's* security** (vulnerabilities, secure-coding best practices), **not about
constraining the agent's behavior**, and their taxonomies have no "behavioral guardrail vs style"
or **enforceability** dimension. ActPlane's lens — *which instructions are information-flow /
behavioral invariants, and which are enforceable at the syscall layer* (`docs/agent-policy-survey.md`
D1/D5) — cross-cuts their categories: what ActPlane counts as an enforceable constraint is scattered
across their Development-Process, Testing, and Security buckets. Our corpus figure (≈70% of repos
carry ≥1 ActPlane-relevant behavioral constraint) is therefore **not** comparable to their "Security
%" and must not be read as such. (ii) These studies resolve inter-annotator disagreement by
consensus **without reporting κ**; our survey's double-coding with a reported κ is a reliability
improvement we can claim.

On the **effectiveness** question (orthogonal to enforcement, but useful background on whether these
files are worth maintaining), **Lulla et al.** ("On the Impact of AGENTS.md Files on the Efficiency
of AI Coding Agents," arXiv 2601.20404, 2026; `agentsmd-efficiency-impact.pdf`) run paired
same-task/same-repo PR experiments and find AGENTS.md *reduces* median runtime (≈28.6%) and output
tokens (≈16.6%) at comparable task quality. Finally, **Liu et al.** ("Dive into Claude Code," arXiv
2604.14228, 2026; `dive-into-claude-code.pdf`) reverse-engineer Claude Code's architecture and
contrast its **per-action safety evaluation (a tool/permission-layer, L1, ML-classifier-gated
permission system)** with OpenClaw's **perimeter-level access control** — a concrete datapoint that
today's deployed agent guardrails sit at the tool/permission layer and are therefore bypassable by
actions that do not pass through it, exactly the gap ActPlane closes at L3.

---

## Comparison Table

Columns: **Layer** (kernel/user) · **Enforce/Detect** · **Taint propagation** (label that
flows) · **Cross-channel** (P=process, F=file, N=network) · **Agent-aware** · **Feedback loop**
(corrective/semantic to actor).

| Work | Layer | Enforce/Detect | Taint propagation | Cross-channel (P/F/N) | Agent-aware | Feedback loop |
|---|---|---|---|---|---|---|
| TaintDroid | user (runtime) | detect | yes | P/F/(IPC) | no | no |
| Dytan | user (DBI) | detect/analyze | yes | in-process | no | no |
| libdft | user (DBI) | detect/analyze | yes | in-process | no | no |
| Panorama | emulator | detect | yes | P/F/N | no | no |
| Schwartz survey | — (theory) | — | yes (defines) | — | no | no |
| PASS | kernel | record only | no | F | no | no |
| Hi-Fi | kernel (LSM) | record only | no | P/F/N | no | no |
| LPM (PBAC) | kernel (LSM) | **enforce** | no (PBAC, not labeled flow) | P/F/N | no | no |
| CamFlow | kernel (LSM+NF) | record only | label-capable, used for audit | P/F/N | no | no |
| **CamQuery** | **kernel (LSM, LKM)** | **enforce** | **yes (label propagation)** | **P/F/N** | **no** | **no** |
| SLEUTH | user (audit) | detect | yes (tags) | P/F/N | no | no |
| HOLMES | user (audit) | detect | yes (flows) | P/F/N | no | no |
| RAIN | kernel+user | detect/investigate | yes (on-demand) | P/F/N | no | no |
| UNICORN | user (stream) | detect | no (sketches) | P/F/N | no | no |
| StreamSpot | user (stream) | detect | no (sketches) | graph | no | no |
| KRSI / BPF-LSM | kernel (eBPF-LSM) | **enforce** (primitive) | no | per-hook | no | no |
| eBPF-PATROL | kernel (eBPF) | **enforce** | no (per-event match) | P/(F/N per event) | no | no |
| OAMAC (2026) | kernel (eBPF-LSM) | **enforce** | yes (origin, process only) | P only | no | no |
| STBAC | kernel | **enforce** | yes (suspicious taint) | P/F/N | no | no |
| Tetragon | kernel (eBPF-LSM) | **enforce** | flag (fork/exec only) | P only | no | no |
| KubeArmor | kernel (eBPF-LSM) | **enforce** | no (1-hop fromSource) | P/F/N (per-rule) | no | no |
| Falco | user eval | detect | no (ancestor lookup) | P/F/N (per-event) | no | no |
| Landlock | kernel (LSM) | **enforce** | no | F/(N) | no | no |
| Progent | user (tool-call) | **enforce** | no (per tool call) | tool API | **yes** | partial (fallback) |
| AgentSpec | user (runtime) | **enforce** | no (per action) | agent action | **yes** | **yes (corrective/self-reflect)** |
| GuardAgent | user (LLM guard) | **enforce** | no | agent action | **yes** | partial |
| SAFEFLOW | user (agent protocol) | **enforce** | **yes (IFC)** | agent data flow | **yes** | partial |
| ARM (2026) | user (tool-call) | **enforce** | yes (trust lattice) | agent exec graph | **yes** | **yes (denial nodes)** |
| AgentSight | kernel+user (eBPF) | **observe only** | no | P/N (+intent) | **yes** | no |
| **ActPlane** | **kernel (eBPF-LSM)** | **enforce** | **yes (typed)** | **P/F/N** | **yes** | **yes (corrective semantic)** |

---

## Synthesis: where the gap actually is

Being rigorous and honest, **no single capability ActPlane claims is unprecedented**, and one
system in particular gets uncomfortably close:

- **In-kernel + enforce + label/taint propagation + cross-channel (process/file/network) over a
  provenance graph** is **already done by CamQuery** (CCS 2018), verified from its text and its
  loss-prevention Listing. ActPlane cannot claim this *combination* as novel. CamQuery is the
  honest baseline.
- **eBPF-LSM enforcement** is solved (KRSI, Tetragon, KubeArmor, bpfbox/bpfcontain, OAMAC).
- **Provenance/origin propagation across process lineage with eBPF-LSM enforcement** is solved as
  of 2026 by **OAMAC** — but only single-channel (process creation), not file/network.
- **Taint + OS-level enforcement** dates back to **STBAC**.
- **Agent-aware enforcement with corrective/self-reflective feedback** is solved at the
  **userspace/tool-call layer** by AgentSpec, Progent, GuardAgent, SAFEFLOW, and ARM — all
  bypassable below the agent framework.
- **eBPF observability of agents** (the intent/action "semantic gap") is solved by **AgentSight**,
  but it only observes.

What is **genuinely unoccupied** is the *intersection*, and it reduces to two specific points:

1. **Cross-channel labeled information flow (process → file → process → network) enforced in the
   kernel via the modern eBPF/BPF-LSM substrate.** CamQuery has the labeled-flow + cross-channel +
   enforce combination but on a CamFlow *kernel module*, not eBPF; every eBPF-LSM enforcer that
   exists (Tetragon, OAMAC, KubeArmor, eBPF-PATROL) is *single-channel* (process lineage flag, or
   per-event match) and does **not** propagate labels across file and network edges. So "full
   cross-channel labeled flow, on eBPF, enforced" is not occupied by any one system — it is split
   between CamQuery (labeled flow + cross-channel, wrong substrate) and the eBPF enforcers (right
   substrate, no cross-channel labeled flow).

2. **An AI-agent threat model with a corrective semantic feedback loop, fused with that
   kernel-level cross-channel labeled flow.** The agent-aware feedback-loop systems (AgentSpec,
   Progent, SAFEFLOW, ARM) all live at the bypassable userspace/tool-call layer and do no OS-object
   label tracking; the kernel information-flow/provenance systems (CamQuery, OAMAC, STBAC, the
   detectors) are *not* agent-aware and give *no* corrective feedback (at most a silent `-EPERM` or
   a `RAISE_WARNING`). **No system delivers semantic, corrective feedback to a cooperative agent
   from a kernel-level information-flow decision.**

**Precise gap statement.** ActPlane's defensible contribution is **not** "labeled flow in the
kernel" (CamQuery), **not** "eBPF agent enforcement" (eBPF-PATROL/OAMAC), and **not** "agent
guardrails with feedback" (AgentSpec/Progent). It is the **unification**: *multi-channel labeled
information-flow propagation
(process+file+network) running in the kernel on the eBPF/BPF-LSM substrate, driven by an
agent-aware source/sink rule model, that closes the loop with corrective semantic feedback to a
cooperative-but-forgetful agent.* The two cells empty in the comparison table for **every** prior
system simultaneously are **(agent-aware) × (kernel cross-channel taint enforcement) × (corrective
feedback loop)** — only the ActPlane row fills all three. The most serious overlap to acknowledge
explicitly in any writeup is **CamQuery** (mechanism is largely the same; differentiation is
substrate, agent domain, and feedback), and the closest *recent* neighbors to cite are **OAMAC**
(eBPF-LSM provenance enforcement, but process-only and not agent-aware) and **AgentSight** (eBPF
agent semantic gap, but observe-only).

---

## 8. Agent Safety Benchmarks

Benchmarks for evaluating AI agent safety and behavioral compliance. Most target a different
threat model from ActPlane (prompt injection or inherent agent unsafety, vs. enforcement of
project-defined behavioral policies), but they define the evaluation landscape ActPlane is
positioned against.

**AgentDojo** (Debenedetti et al., NeurIPS 2024 D&B; `agentdojo.pdf`;
[github](https://github.com/ethz-spylab/agentdojo)). The de facto standard benchmark for
agent safety papers. 97 user tasks across themed suites (Workspace, Slack, Banking, Travel),
629 security test cases created by combining tasks with injection scenarios. Metrics are
programmatic (state-inspection functions): utility rate (task completed) and attack success
rate (injected goal achieved). Jointly measures utility and security so defenses that kill
utility are penalized.
*vs ActPlane:* **Different threat model.** AgentDojo tests resistance to *prompt injection
attacks* — adversarial inputs embedded in tool responses. ActPlane enforces *behavioral policy
compliance* (project-defined workflow rules like "run tests before committing"). The two are
complementary but not substitutable: an agent can pass AgentDojo (no injection succeeds) while
violating every ActPlane rule (never runs tests, pushes to main, deletes vendor/). No
OS-level behavioral-policy benchmark exists in AgentDojo.

**OpenAgentSafety** (Vijayvargiya et al., ICLR 2026; `openagentsafety.pdf`;
[github](https://github.com/Open-Agent-Safety/OpenAgentSafety)). 350+ tasks across 8 risk
categories (security compromise, data loss, privacy breach, unsafe code execution, financial
loss, malicious content, legal violations, harmful decisions). Built on OpenHands; agents run
in Docker containers with real tools (bash, file system, GitLab, OwnCloud). Evaluation:
rule-based (Python `eval.py` per task, checks final environment state, binary safe/unsafe) +
LLM-as-Judge (GPT-4.1 scores trajectories). 49–73% unsafe rate across 7 frontier models.
*vs ActPlane:* Closer to ActPlane's domain — agents interact with real file systems and bash.
But the threat model is different: OA-Safety tests whether *the agent itself* is unsafe
(inherent model behavior), while ActPlane tests whether *an enforcement mechanism* prevents
policy violations. Only ~30–40% of OA-Safety's risk categories are OS-level enforceable (data
loss, code execution, some security compromise); the rest (financial loss, malicious content,
legal violations, harmful decisions) are semantic-layer and outside ActPlane's scope. Using
OA-Safety directly would show ActPlane covering only a subset, which misrepresents its design
intent. The evaluation approach (rule-based environment-state checks) is transferable.

**ODCV-Bench** (McGill, Dec 2025; arXiv 2512.20798; `odcv-bench.pdf`;
[github](https://github.com/McGill-DMaS/ODCV-Bench)). 40 multi-step scenarios across 6
domains (Healthcare, Finance, Logistics, etc.) in persistent Docker bash environments. Tests
whether agents violate behavioral constraints under KPI pressure. Two variants: "mandated"
(explicit instructions to violate) vs "incentivized" (KPI pressure only). Scoring: 0–5 rubric
(0=legitimate, 3=loophole exploitation, 5=systemic fraud); 4 independent LLM judges, median
aggregation, Krippendorff's α = 0.81.
*vs ActPlane:* Tests agent constraint compliance under pressure — thematically close. But
constraints are defined in natural language (system prompts), evaluation is purely post-hoc
(LLM judges score trajectories after execution), and there is **no runtime enforcement hook**.
Agents execute freely; the benchmark only *measures* violations, not *prevents* them.
ActPlane's contribution (runtime kernel-level enforcement + feedback) cannot be tested in
ODCV-Bench's framework without modification. However, the "with vs without ActPlane" unsafe
score comparison could be a supplementary experiment.

**Claw-Eval** (Apr 2026; arXiv). 300 tasks, 2,159 fine-grained rubric items, 14 frontier
models. Three dimensions: Completion, Safety, Robustness. Hybrid grader uses deterministic
matching on tool-call parameters; finds trajectory-opaque eval misses 44% of safety violations.
*vs ActPlane:* Demonstrates need for trajectory-level (not just outcome) safety eval. Focused
on service orchestration/dialogue, not CLI/coding policy enforcement.

**Agent-SafetyBench** (Zhang et al., Dec 2024; arXiv). 349 environments, 2,000 test cases, 8
risk categories, 10 failure modes. Best model (Claude-3-Opus) scores only 59.8% safe.
*vs ActPlane:* Broad tool-use safety benchmark, not CLI-specific. Measures agent behavior
without enforcement.

**Why ActPlane uses its own corpus.** No existing benchmark tests OS-level behavioral policy
enforcement for coding agents. AgentDojo tests injection resistance; OpenAgentSafety and
ODCV-Bench test inherent agent unsafety; neither provides runtime enforcement hooks or
project-defined workflow policies (the "run tests before committing" class of rules that
ActPlane targets). ActPlane's evaluation uses 580 policies extracted from 64 real agent
projects — the first corpus of OS-level behavioral directives — plus Terminal-Bench (89 tasks)
as an external capability benchmark. This combination tests the specific claim (kernel
enforcement + feedback improves policy compliance) that no existing benchmark is designed to
measure.

---

### Web sources

- eBPF for AI-agent enforcement (what kernel-level catches/misses): https://www.armosec.io/blog/ebpf-based-ai-agent-enforcement/
- AgentSight (eBPF agent observability, semantic gap): https://arxiv.org/html/2508.02736v1
- SAFEFLOW (agent IFC protocol): https://arxiv.org/pdf/2506.07564
- OAMAC (origin-aware MAC, eBPF-LSM, 2026): https://arxiv.org/abs/2601.14021 , https://arxiv.org/html/2601.14021v1
- STBAC (suspicious-taint-based access control): https://www.researchgate.net/publication/307537706_Suspicious-Taint-Based_Access_Control_for_Protecting_OS_from_Network_Attacks
- "Causality Laundering" / Agentic Reference Monitor (denial-feedback provenance for agents): https://arxiv.org/pdf/2604.04035
- LlamaFirewall (layered agent guardrails): https://arxiv.org/pdf/2505.03574
- Policy-as-Prompt (NL policy → agent guardrails): https://arxiv.org/html/2509.23994v1
- Tetragon selectors / followChildren: https://tetragon.io/docs/concepts/tracing-policy/selectors/
- Defeating prompt injections by design (CaMeL): https://arxiv.org/pdf/2503.18813
- Landlock kernel docs: https://docs.kernel.org/userspace-api/landlock.html
