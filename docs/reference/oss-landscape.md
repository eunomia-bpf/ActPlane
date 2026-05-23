# OSS Landscape vs ActPlane

ActPlane = eBPF-based **taint analysis over a process/file/network provenance graph** that
**enforces policy on AI agents**. Taint propagates along fork/exec/file/network edges; a rule DSL
expresses *sources*, *sinks*, and *operation types*; enforcement happens at the OS level via eBPF,
optionally **BPF LSM returning `-EPERM`**.

Canonical example ActPlane wants to express:

> *"Any process descended from `codex` (no matter how many fork/exec hops) may not exec `git` or
> connect to `api.github.com`."*

This document surveys the open-source landscape, compares each project against ActPlane, and
concludes with what is already solved vs. what is genuinely novel.

---

## Comparison Table

| Project | License | Layer (kernel/user) | Policy format | Matches on | Enforce or detect | Taint/provenance propagation | Agent-aware |
|---|---|---|---|---|---|---|---|
| **Tetragon** (cilium) | Apache-2.0 (BPF: GPL/BSD dual) | Kernel eBPF (kprobe/tracepoint/LSM) + userspace | YAML `TracingPolicy` CRD | binary path, parent binary, PID, args, namespaces, **`followChildren` descendants**, labels | **Both** — `Sigkill`, `Override` (returns errno e.g. `-EPERM`), `Post` | No taint engine. Tracks lineage; `followChildren` flags descendants of a binary in a BPF map, but each rule is independent | No |
| **Falco** (falcosecurity) | Apache-2.0 | Kernel eBPF/kmod capture, **userspace rule eval** | YAML rules + macros/lists, condition DSL | `proc.name`, `proc.pname`, `proc.aname[n]` ancestors, fd/net fields | **Detect only** (alert). Response needs Falco Talon / external | No taint; ancestry queried per-event (`proc.aname`), not propagated state | No |
| **Tracee** (aquasecurity) | Apache-2.0 | Kernel eBPF capture, **userspace signatures** (Go / Rego) | Go or Rego signatures; K8s `Policy` CRD for scoping | events/syscalls, process fields, signature logic | Mostly **detect**; can block select syscalls; primarily forensics | No taint engine | No |
| **KubeArmor** | Apache-2.0 | **BPF-LSM** (or AppArmor/SELinux backend) | YAML `KubeArmorPolicy` (KSP/HSP/CSP) | `matchPaths` (exec/file), net proto/socket, **`fromSource`** (direct parent path), pod labels | **Enforce** (`Block`/`Audit`/`Allow`) via LSM | No taint; `fromSource` = immediate source binary only, no transitive ancestry | No |
| **bpfbox** (willfindlay) | GPL-2.0 | eBPF: uprobe/USDT/tracepoint/kprobe + **LSM probes** | Python-embedded DSL decorators (`@profile`, rule funcs) | per-binary profile keyed on exe; func/syscall/LSM-hook granularity | **Enforce** (LSM allow/deny, default-deny) | No multi-type taint; per-process state machine, not graph propagation | No (research PoC, 2020) |
| **bpfcontain** (willfindlay) | GPL-2.0 | **BPF-LSM** + Rust (libbpf-rs) daemon | YAML policy per container | container/binary, file, net, capability rights | **Enforce** (default-deny confinement via LSM) | No taint; confines a container as a unit | No (research, succeeds bpfbox) |
| **CamFlow** | GPL-2.0 | LSM + NetFilter, kernel module | Config + capture filters; not a deny-DSL | whole-system flows (process/file/socket/IPC) | **Record only** (audit/provenance); ordered last so it doesn't record blocked flows | **Full provenance graph** (W3C PROV) but for *audit*, no enforcement | No |
| **SPADE** | GPL-3.0 | Userspace (audit/Fuse/eBPF reporters) | Query interface, not enforcement | provenance graph nodes/edges | **Record/query only** | Full provenance graph + querying | No |
| **libdft / libdft64** | BSD-style | Userspace (Intel Pin DBI) | C++ API (define sources/sinks/propagation) | byte/register/memory tags | Analysis (instrument app to alert/abort) | **True byte-level DIFT**, but in-process, single program, instrumented | No |
| **Phosphor** | MIT | JVM bytecode instrumentation | Java API | object/variable tags | Analysis | **True taint** within one JVM | No |
| **Invariant Guardrails** (invariantlabs) | Apache-2.0 | Userspace MCP/LLM **proxy** | Python-inspired rule DSL (`raise ... if: (a) -> (b)`) | tool calls, tool outputs, dataflow `->` between calls, regex on args | **Enforce** at proxy (block/transform tool call) | Dataflow over *tool-call trace*, not OS objects | **Yes** (agent-native) |
| **AgentSpec** (academic) | research code | Userspace agent runtime hook | DSL: rule = trigger + predicate + enforcement | agent actions/observations | **Enforce** at agent action boundary | No OS taint; logical agent-action rules | **Yes** |
| **gVisor** | Apache-2.0 | Userspace kernel (ptrace/KVM) | OCI runtime config, seccomp-ish | syscall surface | **Enforce** (sandbox isolation) | No taint | No |
| **Landlock** (Linux LSM) | kernel (GPL) | Kernel LSM | C API rulesets (path access rights) | filesystem paths, (newer) net ports | **Enforce** (`-EACCES`), unprivileged self-sandbox | No taint/ancestry | No |
| **E2B** | (mixed; SDK MIT) | Firecracker microVM | SDK/config | VM boundary | **Enforce** (isolation) | No taint | **Yes** (agent code sandbox) |

---

## Per-project notes

### 1. eBPF runtime security & policy enforcement

#### Tetragon — the closest neighbor (study carefully)
- Repo: https://github.com/cilium/tetragon — Apache-2.0 (eBPF objects dual GPL/BSD).
- Kernel-side eBPF (kprobe, tracepoint, optional BPF LSM) with in-kernel enforcement; userspace agent
  for policy compilation and event export.
- **Policy DSL = `TracingPolicy` YAML CRD.** A kprobe/syscall hook + `selectors` (filters) +
  `matchActions`. Example (block any non-`/usr/bin/mount` binary from `sys_mount`):

  ```yaml
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
  metadata:
    name: "block-unauthorized-mount"
  spec:
    kprobes:
    - call: "sys_mount"
      syscall: true
      selectors:
      - matchBinaries:
        - operator: NotIn
          values: ["/usr/bin/mount"]
        matchActions:
        - action: Sigkill
  ```

- **Matching:** `matchBinaries` (operators `In`/`NotIn`/`Prefix`/`Postfix` on exe path),
  `matchParentBinaries` (direct or transitive parent), `matchPIDs`, args, namespaces, capabilities,
  and pod label selectors.
- **Descendant matching — most relevant to ActPlane:** `matchBinaries` (and
  `matchParentBinaries`) support **`followChildren: true`**, which makes the match apply to all
  children/descendants of a matching binary. This is the closest existing analog to
  "descendants of `codex`." Important limitations:
  - Children created **before** the policy was installed are not matched.
  - **At most 64** `followChildren` sections per policy.
  - It is implemented as a "tainted-PID set" maintained in a BPF map (a process is flagged when its
    ancestor matched, propagated on fork/exec) — but the propagation carries a *boolean lineage flag
    for that binary*, not a typed taint label that also flows along file or network edges.
- **Enforcement:** `Sigkill` (kill the caller), `Override` (set syscall return value, e.g.
  `-EPERM`; needs `CONFIG_BPF_KPROBE_OVERRIDE`), plus `NoPost`/`Post` for event control. So Tetragon
  *does* real in-kernel blocking, not just detection.
- **Gap vs ActPlane:** Tetragon already nails (a) eBPF in-kernel enforcement with errno override and
  (b) binary-based descendant matching via `followChildren`. What it does **not** do:
  - No **multi-type taint propagation**. `followChildren` propagates a per-binary lineage flag along
    fork/exec only. Tetragon has no notion of taint flowing **process → file → other process** or
    **process → network**, and no typed/multi-source taint lattice.
  - Rules are independent kprobe matchers; there is no unified **provenance graph** with sources/
    sinks/operation-type DSL spanning process+file+network.
  - No agent semantics / semantic feedback.
  - 64-section and "pre-existing children not matched" limits; ActPlane needs unbounded, retroactive
    descendant taint.
  - **Takeaway:** ActPlane should reuse Tetragon's proven mechanics (LSM/kprobe + `Override` errno,
    tainted-PID BPF maps, `followChildren` semantics) and *not* reinvent them. Novelty is the
    cross-edge typed taint graph + agent-focused DSL.

#### Falco
- Repo: https://github.com/falcosecurity/falco — Apache-2.0.
- eBPF/kmod **capture** in kernel, but **rule evaluation in userspace**.
- DSL: YAML rules with `condition`, reusable `macros`, `lists`, and rich fields including process
  ancestry: `proc.pname` (parent), `proc.aname[n]` / `proc.apid[n]` (nth ancestor). So you *can*
  express "an ancestor is X," but it is **queried per event from the process tree**, not a
  propagated taint.
- **Detect-only** by design: "Falco can only detect and alert, cannot react." Blocking/response is
  delegated to external tools (Falco Talon, Falcosidekick).
- **Gap vs ActPlane:** No enforcement, no taint propagation along file/network edges, ancestry is a
  point-in-time tree lookup, userspace eval adds a race window. Not agent-aware.

#### Tracee
- Repo: https://github.com/aquasecurity/tracee — Apache-2.0.
- eBPF capture; **signatures** in Go or Rego (OPA) evaluated in userspace; K8s `Policy` CRD scopes
  what to trace.
- Primarily detection/forensics; some syscall blocking exists but it's not a general LSM deny engine.
- **Gap vs ActPlane:** No taint graph, no typed cross-edge propagation, enforcement is limited and
  userspace-centric, not agent-aware.

#### KubeArmor
- Repo: https://github.com/kubearmor/KubeArmor — Apache-2.0.
- **BPF-LSM** (with AppArmor/SELinux fallbacks) — real in-kernel enforcement.
- DSL: YAML `KubeArmorPolicy`/`HostSecurityPolicy`/`ClusterSecurityPolicy`. Process/file via
  `matchPaths`, network via protocol/socket, action `Block`/`Audit`/`Allow`. Example shape:

  ```yaml
  spec:
    selector:
      matchLabels: { app: web }
    process:
      matchPaths:
      - path: /bin/sleep
        fromSource:
        - path: /bin/bash      # only when launched by bash
    action: Block
  ```

- **Matching:** path globs + label selectors + **`fromSource`** = the *immediate* source binary only.
  No transitive ancestry / descendant taint.
- **Gap vs ActPlane:** `fromSource` is one hop, not "any descendant N hops deep." No taint
  propagation across file/network edges, no provenance graph, not agent-aware. But it is a good model
  for the BPF-LSM enforcement backend and label-scoped policy.

#### bpfbox (research prototype — very relevant)
- Repo: https://github.com/willfindlay/bpfbox — GPL-2.0; CCSW 2020 paper.
- Pure-eBPF policy engine (<2000 LoC kernel). Uses USDT to load/update policy, uprobes/kprobes/
  tracepoints to track process state, and **LSM probes to enforce**.
- DSL: Python-embedded profile decorators; per-binary, default-deny, with rules at
  userspace-function / syscall / LSM-hook / kernel-function granularity.
- **Enforce** (allow/deny via LSM).
- **Gap vs ActPlane:** Confines **individual processes** with per-binary profiles; maintains process
  *state* but **no multi-type taint propagation across fork/exec/file/net** and no provenance graph.
  Single-host research PoC, not agent-aware. Confirms eBPF-LSM enforcement is feasible — ActPlane's
  novelty is the graph/taint layer above it.

#### bpfcontain (research, successor to bpfbox)
- Repo: https://github.com/willfindlay/bpfcontain-rs — GPL-2.0; Rust + libbpf-rs; needs kernel 5.10+
  with `CONFIG_BPF_LSM=y`.
- **BPF-LSM** default-deny **container** confinement (confines a *set* of processes + resources as a
  unit, vs bpfbox's per-process).
- DSL: YAML policy per container (file/net/capability rights). Full policy-language docs incomplete.
- **Enforce** via LSM.
- **Gap vs ActPlane:** Confinement is per-container/static-policy; no taint flowing along edges, no
  typed sources/sinks DSL, no provenance graph, not agent-aware. Closest "eBPF-LSM enforcement +
  Rust userspace" architecture to ActPlane — good engineering reference, but conceptually orthogonal
  (confinement boundary vs. dynamic taint).

### 2. Provenance capture systems

#### CamFlow
- https://camflow.org/ — GPL-2.0. LSM + NetFilter kernel module; relayfs to userspace.
- Captures a **full whole-system provenance graph** (W3C PROV) over process/file/socket/IPC — this is
  exactly the *graph substrate* ActPlane needs, but CamFlow is **record-only** (audit). It is
  deliberately ordered *last* among LSMs so it doesn't record flows other modules blocked.
- **Gap vs ActPlane:** Captures the graph but **never enforces**, and has no taint-propagation rule
  DSL for blocking. ActPlane = "CamFlow-style graph + Tetragon-style enforcement + taint rules."

#### SPADE
- https://github.com/ashish-gehani/SPADE — GPL-3.0. Userspace provenance via audit/eBPF reporters +
  a query/storage layer.
- **Record + query only**, no enforcement. Same gap as CamFlow.

### 3. Taint / DIFT engines

#### libdft / libdft64
- https://github.com/AngoraFuzzer/libdft64 — BSD-style. Intel Pin dynamic binary instrumentation.
- **True byte-level dynamic information-flow tracking**: define taint sources, sinks, and propagation;
  tags flow through registers/memory.
- **Gap vs ActPlane:** Operates **inside a single instrumented process** (heavy DBI overhead), not
  across OS objects (processes/files/sockets) and not at kernel level. ActPlane does *coarse-grained,
  system-wide* taint at the provenance-graph level instead of byte-level in-process — different
  granularity, different scope. No enforcement of agent policy.

#### Phosphor
- https://github.com/gmu-swe/phosphor — MIT. JVM bytecode-level taint tracking.
- True taint, but confined to one JVM; not system-wide, not enforcement, not agent-aware.

### 4. Process-lineage / ancestry-based policy
The only OSS systems that express ancestry/descendant policy at the OS level are:
- **Tetragon `followChildren`** (`matchBinaries`/`matchParentBinaries`) — propagates a per-binary
  lineage flag to descendants in a BPF map (closest analog; see §1).
- **Falco `proc.aname[n]`** — per-event ancestor lookup (detect-only, not propagated).
- **KubeArmor `fromSource`** — single-hop source only.
None of them propagate **typed taint across file and network edges** in addition to fork/exec, which
is ActPlane's core differentiator.

### 5. LLM-agent sandboxing / guardrails

#### Invariant Guardrails
- https://github.com/invariantlabs-ai/invariant — Apache-2.0. Userspace **MCP/LLM proxy**.
- DSL: Python-inspired matching rules over the tool-call trace, including **dataflow `->`** between
  calls. Example:

  ```python
  raise "External email to unknown address" if:
      (call: ToolCall) -> (call2: ToolCall)
      call is tool:get_inbox
      call2 is tool:send_email({ to: ".*@[^ourcompany.com$].*" })
  ```

- **Enforce** at the proxy (block/transform tool calls); **agent-native** semantics.
- **Gap vs ActPlane:** Dataflow is over the **logical tool-call trace inside the agent framework**,
  not OS-level process/file/network objects. It can be bypassed by anything the agent does outside
  MCP (raw subprocess, direct socket). ActPlane enforces at the kernel where bypass is much harder,
  and tracks OS-level taint. Complementary: Invariant = semantic/agent layer, ActPlane = OS layer.
  ActPlane's **agent-focused semantic feedback** borrows from this world.

#### AgentSpec
- arXiv:2503.18666. DSL for runtime enforcement of LLM-agent behavior (trigger + predicate +
  enforcement on agent actions). Userspace, in-framework. Same gap as Invariant: logical-action level,
  not OS-level, bypassable outside the agent runtime.

#### gVisor / Landlock / E2B
- **gVisor** (Apache-2.0): userspace kernel sandbox — strong syscall isolation, no taint, no ancestry
  policy DSL, not agent-semantic.
- **Landlock** (in-tree Linux LSM): unprivileged self-sandboxing of filesystem (and newer network)
  access; returns `-EACCES`. Path-based, no ancestry/taint, no graph. A possible *enforcement
  primitive* but far below ActPlane's policy model.
- **E2B** (SDK MIT): Firecracker microVM sandbox for agent code execution — coarse isolation boundary,
  no taint, no fine policy DSL. Agent-aware at the "run this code in a box" level.

---

## What's already solved vs. ActPlane's novelty

**Already solved by existing OSS (reuse, don't reinvent):**
- **In-kernel eBPF enforcement returning `-EPERM`/killing** — Tetragon (`Override`/`Sigkill`),
  KubeArmor, bpfbox, bpfcontain via BPF-LSM. ActPlane should build on BPF-LSM + kprobe override.
- **Binary-based descendant matching** — Tetragon `matchBinaries` + `followChildren` already
  propagates a lineage flag to descendants over fork/exec via a BPF tainted-PID map. ActPlane's
  fork/exec taint edge is essentially this mechanism generalized.
- **Whole-system provenance graph capture** — CamFlow/SPADE already build process/file/socket
  provenance graphs (record-only).
- **Byte-level dynamic taint** — libdft/Phosphor (in-process, different granularity).
- **Agent-semantic dataflow rules** — Invariant Guardrails / AgentSpec (userspace, tool-call level).
- **Path/label-scoped deny DSL** — KubeArmor, Tetragon selectors.

**Genuinely novel in ActPlane (the gap nobody fills together):**
1. **Multi-type taint propagation across heterogeneous edges in one engine** — taint flows not just
   fork/exec (Tetragon's flag) but also **process → file → process** and **process → network**, with
   typed/multi-source labels. No OSS combines file + network + process taint with enforcement.
2. **Provenance graph + enforcement unified** — CamFlow records the graph but never blocks; Tetragon
   blocks but has no real graph/typed taint. ActPlane fuses *graph-based taint state* with
   *BPF-LSM enforcement*.
3. **A sources/sinks/operation-type DSL over that graph** — expressing "descendants of X cannot exec
   git or connect to api.github.com" as a single taint rule, not as N independent per-syscall kprobe
   matchers, and without Tetragon's 64-section / no-pre-existing-children limits (retroactive,
   unbounded descendant taint).
4. **Agent-focused semantics + feedback** — targeting AI agents specifically, with semantic feedback
   to the agent (the Invariant/AgentSpec world) but enforced at the kernel where the agent cannot
   bypass it by going around the MCP/tool layer.

**Closest overlaps to watch:**
- **Tetragon `followChildren`** is the single most overlapping feature — ActPlane's fork/exec taint is
  a generalization. Differentiate by emphasizing cross-edge (file/network) typed taint and the unified
  graph DSL, and reuse Tetragon's BPF-LSM/override mechanics rather than rebuilding them.
- **bpfcontain** is the closest *architecture* (eBPF-LSM + Rust userspace daemon) — a good engineering
  reference; conceptually it does static container confinement, not dynamic taint.

---

## Sources
- Tetragon selectors: https://tetragon.io/docs/concepts/tracing-policy/selectors/ ,
  https://github.com/cilium/tetragon
- Falco: https://falco.org/docs/concepts/rules/conditions/ , https://github.com/falcosecurity/falco
- Tracee: https://github.com/aquasecurity/tracee , https://aquasecurity.github.io/tracee/
- KubeArmor: https://github.com/kubearmor/KubeArmor ,
  https://github.com/kubearmor/KubeArmor/blob/main/getting-started/security_policy_examples.md
- bpfbox: https://github.com/willfindlay/bpfbox , https://people.scs.carleton.ca/~barrera/publications/ccsw20-findlay.pdf
- bpfcontain: https://github.com/willfindlay/bpfcontain-rs
- CamFlow: https://camflow.org/ , https://arxiv.org/abs/1711.05296
- SPADE: https://github.com/ashish-gehani/SPADE
- libdft64: https://github.com/AngoraFuzzer/libdft64
- Phosphor: https://github.com/gmu-swe/phosphor
- Invariant Guardrails: https://github.com/invariantlabs-ai/invariant ,
  https://explorer.invariantlabs.ai/docs/guardrails/rules/
- AgentSpec: https://arxiv.org/pdf/2503.18666
- gVisor: https://github.com/google/gvisor ; Landlock: https://landlock.io/ ; E2B: https://github.com/e2b-dev/e2b
