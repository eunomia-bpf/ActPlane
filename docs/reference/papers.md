# ActPlane: Annotated Bibliography of Reference Papers

ActPlane is an eBPF-based system that performs **taint analysis over a process/file/network
provenance graph** to enforce policy rules on AI agents (e.g., "any process descended from
`codex` may not exec `git` or connect to `api.github.com`"). Taint propagates along
fork/exec/file-read/file-write/network edges; rules have **sources** (what gets tainted) and
**sinks** (forbidden operations); enforcement happens at the OS level via eBPF / BPF-LSM.

This bibliography groups the most relevant prior work into five areas. All listed PDFs live in
this directory (`docs/reference/`). Items without a downloaded PDF give a URL instead.

---

## 1. Dynamic Information Flow Tracking / Taint Analysis

These papers define the core mechanics ActPlane reuses at the graph level: marking data as
tainted at *sources*, propagating taint along data/control flow, and checking *sinks*.

- **TaintDroid: An Information-Flow Tracking System for Realtime Privacy Monitoring on
  Smartphones** — William Enck, Peter Gilbert, Byung-Gon Chun, Landon P. Cox, Jaeyeon Jung,
  Patrick McDaniel, Anmol N. Sheth. *OSDI 2010* (extended in ACM TOCS 2014).
  PDF: `taintdroid.pdf`
  System-wide dynamic taint tracking inside the Android (Dalvik) runtime that follows sensitive
  data (location, contacts, IMEI) from *taint sources* through variables, files, and IPC
  messages to *taint sinks* (network sends), flagging privacy leaks in real time with low
  overhead. Pioneered tracking taint across process and persistent-storage boundaries, not just
  within one address space.
  *Relevance to ActPlane:* ActPlane generalizes TaintDroid's source→propagate→sink model from
  one runtime to the whole OS, propagating taint across fork/exec/file/network edges of a
  provenance graph instead of through interpreter variables, and it *enforces* (blocks) at the
  sink rather than only auditing.

- **Dytan: A Generic Dynamic Taint Analysis Framework** — James Clause, Wanchun Li, Alessandro
  Orso. *ISSTA 2007*.
  PDF: `dytan.pdf`
  A configurable taint framework for x86 binaries that lets users define taint sources, sinks,
  and propagation policy (including optional control-flow / implicit-flow propagation) without
  rebuilding the analysis engine. It made the case that taint semantics should be *policy*, not
  hardcoded.
  *Relevance to ActPlane:* Motivates ActPlane's design of taint sources/sinks and propagation
  edges as declarative, user-supplied policy rather than fixed engine behavior; ActPlane lifts
  the same configurability to OS-graph granularity.

- **libdft: Practical Dynamic Data Flow Tracking for Commodity Systems** — Vasileios P.
  Kemerlis, Georgios Portokalidis, Kangkook Jee, Angelos D. Keromytis. *VEE 2012*.
  PDF: `libdft.pdf`
  A fast, reusable byte-granularity DFT library built on Intel Pin that tracks taint through
  registers and memory of unmodified binaries via a shadow-memory "tag map." A canonical
  reference for *how* to represent and propagate taint tags efficiently.
  *Relevance to ActPlane:* Provides the taint-tag/shadow-state vocabulary; ActPlane's per-object
  taint labels on graph nodes are the coarse-grained kernel analog of libdft's per-byte tags,
  trading instruction-level precision for whole-system, low-overhead coverage.

- **Panorama: Capturing System-wide Information Flow for Malware Detection and Analysis** —
  Heng Yin, Dawn Song, Manuel Egele, Christopher Kruegel, Engin Kirda. *CCS 2007*.
  PDF: `panorama.pdf`
  Whole-system taint tracking inside a QEMU-based emulator that taints sensitive inputs and
  observes how malware (keyloggers, spyware, rootkits) accesses and exfiltrates them, building
  system-wide information-flow graphs to classify behavior.
  *Relevance to ActPlane:* An early demonstration that *whole-system* information flow (across
  processes, the kernel, disk, and network) reveals policy-violating behavior — exactly the
  scope ActPlane targets, but ActPlane does it live in the real kernel via eBPF instead of in an
  emulator.

- **All You Ever Wanted to Know About Dynamic Taint Analysis and Forward Symbolic Execution
  (but Might Have Been Afraid to Ask)** — Edward J. Schwartz, Thanassis Avgerinos, David
  Brumley. *IEEE S&P (Oakland) 2010*.
  PDF: `taint-survey-schwartz.pdf`
  A formal, operational-semantics treatment of dynamic taint analysis: precise definitions of
  taint sources/sinks/propagation, the soundness/completeness trade-offs, and well-known
  pitfalls (under-tainting, over-tainting, implicit flows).
  *Relevance to ActPlane:* The reference for stating ActPlane's taint semantics rigorously and
  for being explicit about its precision limitations (e.g., coarse object-level taint can
  over-taint), framing it honestly against the theory.

---

## 2. Data Provenance & Provenance-Based Access Control in the OS

ActPlane's substrate is essentially a whole-system provenance graph. These define how to capture
that graph in the Linux kernel and how to attach policy to it.

- **Provenance-Aware Storage Systems (PASS)** — Kiran-Kumar Muniswamy-Reddy, David A. Holland,
  Uri Braun, Margo Seltzer. *USENIX ATC 2006*.
  PDF: `pass.pdf`
  The first system to treat provenance as a first-class storage primitive, automatically
  recording the lineage of files (which processes/inputs produced them) at the OS/storage layer
  and supporting provenance queries.
  *Relevance to ActPlane:* Establishes the file-read/file-write provenance edges that ActPlane
  uses to propagate taint through the filesystem (e.g., a tainted process writing a file taints
  that file, which then taints any later reader).

- **Hi-Fi: Collecting High-Fidelity Whole-System Provenance** — Devin J. Pohly, Stephen
  McLaughlin, Patrick McDaniel, Kevin Butler. *ACSAC 2012*.
  PDF: `hifi.pdf`
  Uses the Linux Security Module (LSM) framework to capture complete, tamper-evident
  whole-system provenance (process, file, IPC, socket events) from early boot, with a focus on
  not missing security-relevant events.
  *Relevance to ActPlane:* Demonstrates that LSM hooks are the right kernel placement for
  *complete* provenance capture — directly informing ActPlane's choice of BPF-LSM hook points
  for both observing edges and enforcing at sinks.

- **Trustworthy Whole-System Provenance for the Linux Kernel (Linux Provenance Modules / LPM)**
  — Adam Bates, Dave (Jing) Tian, Kevin R. B. Butler, Thomas Moyer. *USENIX Security 2015*.
  PDF: `lpm-trustworthy-provenance.pdf`
  Generalizes Hi-Fi into LPM, a modular framework for secure provenance collection, and
  introduces *provenance-based access control* and a trusted provenance-aware authority,
  addressing how to make the provenance record itself trustworthy and how to enforce policy on
  it.
  *Relevance to ActPlane:* The closest classic precursor to ActPlane's enforcement idea —
  policy decisions driven by provenance — and a guide to integrity concerns (an attacker must
  not be able to forge or drop the edges ActPlane's taint depends on).

- **Practical Whole-System Provenance Capture (CamFlow)** — Thomas Pasquier, Xueyuan Han, Mark
  Goldstein, Thomas Moyer, David Eyers, Margo Seltzer, Jean Bacon. *SoCC 2017.*
  arXiv: 1711.05296. PDF: `camflow.pdf`
  CamFlow is a low-overhead, maintainable LSM+NetFilter-based whole-system provenance capture
  system for modern Linux that emits W3C-PROV-style graphs and is designed to plug into security
  and compliance applications.
  *Relevance to ActPlane:* The canonical modern blueprint for the exact graph ActPlane operates
  on (processes, files, sockets as nodes; reads/writes/forks/execs/sends as edges) and proof
  that capturing it in production Linux is practical.

- **Runtime Analysis of Whole-System Provenance (CamQuery)** — Thomas Pasquier, Xueyuan Han,
  Thomas Moyer, Adam Bates, Olivier Hermant, David Eyers, Jean Bacon, Margo Seltzer. *CCS 2018.*
  arXiv: 1808.06049. PDF: `camquery-runtime-provenance.pdf`
  CamQuery runs user-defined analyses **inline, in real time, over the live provenance stream**
  inside the kernel (vertex-centric programs at LSM hooks), enabling data-loss prevention,
  intrusion detection, and compliance as the graph is built rather than after the fact.
  *Relevance to ActPlane:* The single closest piece of prior art. ActPlane is essentially "taint
  propagation as an inline CamQuery program enforced via BPF-LSM": both run policy on the live
  graph at LSM hooks. ActPlane's differentiators are eBPF (vs. CamFlow's kernel module), a taint-
  propagation policy model, and an AI-agent threat model.

---

## 3. System-call / eBPF / LSM Runtime Enforcement

These cover the *enforcement* mechanism: turning a policy decision into an allow/deny at a
kernel hook.

- **Kernel Runtime Security Instrumentation (KRSI / BPF-LSM)** — KP Singh (Google).
  *Linux Plumbers Conference 2019* (talk; upstreamed as the BPF LSM, Linux 5.7).
  PDF: `krsi-talk.pdf`
  Introduces attaching eBPF programs to LSM security hooks, so privileged users can implement
  MAC/audit policy dynamically without rebuilding the kernel — eBPF programs can return a
  permit/deny verdict at each hook.
  *Relevance to ActPlane:* This *is* ActPlane's enforcement primitive. ActPlane's "this tainted
  process may not exec git / connect to host X" rules are realized as BPF-LSM programs returning
  `-EPERM` at the relevant hook (`bprm_check_security`, `socket_connect`, etc.).

- **Landlock: unprivileged access control for Linux** — Mickaël Salaün et al.
  No standalone peer-reviewed paper; primary references are the upstream kernel documentation
  and LWN coverage.
  URLs: https://docs.kernel.org/userspace-api/landlock.html and
  https://lwn.net/Articles/698226/ (PDF not downloaded — no canonical academic PDF exists.)
  A stackable LSM letting even unprivileged processes sandbox themselves by declaring rulesets
  that restrict filesystem and (later) network access for themselves and their descendants.
  *Relevance to ActPlane:* A complementary, descendant-scoped self-sandboxing model in mainline
  Linux. ActPlane's "any process descended from `codex`" scoping is conceptually similar to
  Landlock's domain inheritance, but ActPlane derives scope dynamically from the provenance/taint
  graph and supports network/host sinks and data-flow taint that Landlock's static rulesets do
  not express.

- **eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation using eBPF in
  Containerized and Virtualized Environments** — *arXiv 2511.18155 (2025).*
  PDF: `ebpf-patrol.pdf`
  A recent eBPF-based runtime security agent that monitors syscalls/network activity and enforces
  policy (overreach limitation) in containerized/virtualized environments, representing the
  current generation of eBPF enforcement tooling (in the spirit of Tetragon/Tracee).
  *Relevance to ActPlane:* A contemporary point of comparison for eBPF-based enforcement;
  ActPlane differs by driving enforcement decisions from a stateful taint/provenance graph rather
  than from per-event syscall pattern rules. (Note: `seccomp`, Cilium **Tetragon**, and Aqua
  **Tracee** are the standard production systems in this space — referenced but no academic PDF
  downloaded.)

---

## 4. Provenance-Based Intrusion / Attack Detection over System Graphs

These model OS activity as a graph and run policies or detection over it — the closest
architectural relatives of ActPlane, differing mainly in goal (detection vs. enforcement).

- **SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data** — Md Nahid Hossain,
  Sadegh M. Milajerdi, Junao Wang, Birhanu Eshete, Rigel Gjomemo, R. Sekar, Scott Stoller,
  V.N. Venkatakrishnan. *USENIX Security 2017.* arXiv: 1801.02062. PDF: `sleuth.pdf`
  Builds an in-memory dependency (provenance) graph from OS audit logs and uses **tag-based**
  techniques — confidentiality/integrity *tags* that propagate along dependencies — to detect
  and reconstruct multi-stage attacks in real time.
  *Relevance to ActPlane:* SLEUTH's propagating integrity/trust *tags* over a system dependency
  graph is almost exactly ActPlane's taint propagation; ActPlane reuses this tag-propagation
  model but for *prevention* (block the sink) rather than post-hoc scenario reconstruction.

- **HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows** —
  Sadegh M. Milajerdi, Rigel Gjomemo, Birhanu Eshete, R. Sekar, V.N. Venkatakrishnan.
  *IEEE S&P 2019.* arXiv: 1810.01594. PDF: `holmes.pdf`
  Correlates suspicious information flows in the provenance graph and maps low-level events to
  high-level ATT&CK-style TTPs, producing a compact high-level scenario graph that signals an
  ongoing APT campaign with few false alarms.
  *Relevance to ActPlane:* Shows how to express *policy-level* meaning ("this flow pattern is
  forbidden/suspicious") over a low-level provenance graph — analogous to ActPlane's source→sink
  rules — and how to keep false positives manageable via flow correlation.

- **RAIN: Refinable Attack Investigation with On-demand Inter-Process Information Flow
  Tracking** — Yang Ji, Sangho Lee, Evan Downing, Weiren Wang, Mattia Fazzini, Taesoo Kim,
  Alessandro Orso, Wenke Lee. *CCS 2017.* PDF: `rain.pdf`
  Combines coarse system-call provenance with on-demand fine-grained record-and-replay DIFT to
  tame the "dependency explosion" problem, refining causality only where an investigation needs
  precision.
  *Relevance to ActPlane:* Directly relevant to ActPlane's biggest accuracy risk —
  over-tainting/dependency explosion in coarse OS-graph taint. RAIN's coarse-then-refine
  strategy suggests how ActPlane could selectively tighten taint to avoid blocking benign
  operations.

- **UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats** — Xueyuan Han,
  Thomas Pasquier, Adam Bates, James Mickens, Margo Seltzer. *NDSS 2020.* arXiv: 2001.01525.
  PDF: `unicorn.pdf`
  An anomaly detector that summarizes the streaming whole-system provenance graph into
  fixed-size *graph sketches* (histograms of local structure) and learns a model of normal
  behavior to flag long-running, slow-acting attacks without attack signatures.
  *Relevance to ActPlane:* Demonstrates efficient, bounded-memory streaming computation over the
  same live provenance graph ActPlane consumes, and represents the *learning-based* alternative
  to ActPlane's explicit-rule approach (useful contrast: ActPlane is precise/declarative, UNICORN
  is statistical).

- **StreamSpot: Fast Memory-efficient Anomaly Detection in Streaming Heterogeneous Graphs** —
  Emaad Manzoor, Sadegh M. Momeni, Venkat N. Venkatakrishnan, Leman Akoglu. *KDD 2016.*
  arXiv: 1602.04844. PDF: `streamspot.pdf`
  A general streaming-graph anomaly detector (applied to system-activity graphs) that uses a
  locality-sensitive shingling/sketch similarity to cluster normal graphs and flag outliers
  online with bounded memory.
  *Relevance to ActPlane:* The graph-sketching technique underlying UNICORN; relevant as the
  algorithmic foundation for any streaming anomaly layer ActPlane might add alongside its
  rule-based enforcement, and as evidence that the system-activity-as-graph abstraction is sound.

---

## 5. LLM-Agent Security / Sandboxing / Capability Control

The application domain and threat model: constraining what an autonomous LLM agent is allowed to
do. ActPlane provides an OS-level enforcement layer beneath these mostly application-level
approaches.

- **Progent: Programmable Privilege Control for LLM Agents** — *arXiv 2504.11703 (2025).*
  PDF: `progent.pdf`
  A privilege-control framework with a JSON-based domain-specific language for policies over
  agent *tool calls* — deciding when a tool call is permitted and what fallback to take —
  reducing prompt-injection attack success dramatically on AgentDojo/ASB benchmarks. Policies can
  be LLM-generated and are tightened via an SMT solver.
  *Relevance to ActPlane:* The closest agent-security analog of ActPlane's rule model, but
  Progent enforces at the *tool-call API* layer inside the agent framework, whereas ActPlane
  enforces at the *OS syscall* layer below it — catching actions even if the agent bypasses its
  own tool API (e.g., shelling out, raw sockets).

- **AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents** —
  *arXiv 2503.18666 (2025).*
  PDF: `agentspec.pdf`
  A lightweight DSL of *trigger → predicate → enforcement* rules for constraining LLM agents at
  runtime (stop, ask user, replace action, self-inspect), validated across code, embodied, and
  driving agents with millisecond overhead.
  *Relevance to ActPlane:* ActPlane's source/sink rule structure mirrors AgentSpec's
  trigger/predicate/enforcement structure. ActPlane complements it by enforcing at the kernel
  (uncircumventable by the agent) and by adding cross-process taint propagation that AgentSpec's
  per-action checks lack.

- **GuardAgent: Safeguard LLM Agents by a Guard Agent via Knowledge-Enabled Reasoning** —
  *arXiv 2406.09187 (2024).*
  PDF: `guardagent.pdf`
  Uses a separate "guard" LLM agent that reads a safety-guard request, generates a task plan, and
  emits guardrail *code* that deterministically checks whether a target agent's actions satisfy
  the safety requirements, achieving high guarding accuracy without retraining.
  *Relevance to ActPlane:* Represents the LLM-in-the-loop guardrail style. It motivates ActPlane's
  more deterministic, low-overhead, kernel-level alternative: ActPlane does not invoke an LLM to
  decide each action, and its checks cannot be evaded by the monitored agent, at the cost of
  reasoning about lower-level (syscall/graph) semantics rather than high-level intent.

---

## Notes on downloads

All 21 PDFs above were downloaded and verified as valid PDF files (>50 KB) in
`docs/reference/`. One item (**Landlock**) has no canonical academic PDF; its authoritative
references are the Linux kernel documentation and LWN article linked inline above. Standard
production enforcement tools (`seccomp`, Cilium **Tetragon**, Aqua **Tracee**) are mentioned for
context but are software projects without a single representative academic PDF.
