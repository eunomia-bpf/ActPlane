# ActPlane — Rewritten Abstract + Introduction (Draft v2)

Target: OSDI/SOSP quality. Single narrative thread, no bullet lists in body.

---

## Abstract

AI coding agents operate as long-running processes with direct access to
shells, file systems, and networks, autonomously executing complex tasks
across extended sessions. Projects govern these agents with behavioral
policies—"do not leak secrets," "run tests before committing," "do not
modify production databases"—declared in harness instruction files. An
empirical study of 64 projects shows that 63% of harness instructions are
behavioral policies targeting system-level effects, and 78% of projects
require cross-event state tracking: constraints on information flow or
temporal ordering that span multiple operations across process, file, and
network boundaries.

Enforcing these policies is fundamentally harder than traditional access
control because agent behavior is emergent: determined at runtime by
natural-language prompts, not at compile time by source code. This
emergent behavior creates an intent–behavior gap—prompt-level enforcement
is probabilistic, tool-level guards are bypassed the moment an agent
shells out, and kernel-level sandboxes enforce per-operation access
control without cross-event state or semantic connection to the agent's
declared policies. No existing system combines unbypassable OS-level
enforcement with cross-event information-flow tracking and a policy
lifecycle that adapts to emergent behavior.

We present ActPlane, a programmable OS-level control plane for agent
harnesses. Agents declare behavioral policies in a compact DSL designed
to be both human-auditable and machine-writable; ActPlane compiles them
into labeled information-flow rules loaded into an eBPF/BPF-LSM kernel
backend. Named labels propagate across process, file, and network
boundaries, encoding cross-event execution history as per-node bitmasks
checkable in O(1) at each kernel hook. When a rule matches, ActPlane
returns semantic feedback that reconnects the OS-level event to the
agent's declared policy, enabling self-correction. Each rule
independently selects notify, block, or kill, supporting progressive
deployment from observation to enforcement. We evaluate ActPlane on
policies drawn from the empirical study, demonstrating bypass-free
enforcement of cross-event policies, actionable semantic feedback that
improves agent task-completion rates, and sub-microsecond per-event
overhead.

---

## 1  Introduction

AI coding agents have become a mainstream development tool. Systems like
Claude Code, Cursor Agent, and Codex operate as long-running processes
with full access to shells, source trees, package managers, and external
APIs, autonomously writing code, running tests, and managing
infrastructure across sessions that span hours or days.

**Agents need behavioral policies.** As agents gain autonomy, projects
constrain them through harness instruction files such as `CLAUDE.md` and
`AGENTS.md`: do not push to main without review; never expose `.env`
contents to the network; run `pytest` before every commit. An empirical
study of 64 popular open-source projects (§X) reveals that these
instructions are not merely coding-style guidance: 63% are behavioral
policies that constrain observable system effects, 80% of those target
system-level behavior (file access, process execution, network
connections), and 78% of projects contain at least one policy that
requires cross-event state—tracking information flow or temporal ordering
across multiple operations.

**Agent behavior is emergent.** Unlike traditional software, where source
code determines behavior at compile time, an agent's behavior is
determined by a natural-language prompt at runtime. The instruction "find
and fix the authentication bug" may produce any combination of file
reads, code edits, compilations, test runs, and network requests, and
the combination changes with every invocation. This emergent,
non-deterministic character is the root cause of three interrelated
system challenges that make behavioral policy enforcement fundamentally
harder for agents than for traditional software.

**Challenge 1: The intent–behavior gap.** An agent's execution spans
three abstraction levels: intent (the goals and constraints expressed in
natural language), action (the tool calls issued through the agent
runtime), and behavior (the actual OS operations—`open`, `execve`,
`connect`—that result). The mapping from intent to behavior is
many-to-many and opaque. A single `run_command("make")` triggers
hundreds of system calls; the same `git push` can be reached through a
direct tool call, a `bash -c` string, a Python `subprocess`, or a
compiled helper binary. Existing observability and enforcement tools are
trapped on one side of this gap: application-level monitors (LangSmith,
Langfuse) see the agent's intent—its prompts and tool selections—but are
blind to the system behavior those tools produce, because a single shell
command escapes their view. Kernel-level monitors (Falco, Tracee) see
every system call but lack the semantic context to distinguish a
legitimate data-analysis script from a malicious exfiltration payload.
Neither side alone can determine whether a sequence of system calls is a
faithful execution of the agent's stated intent or a deviation from it.

Compounding this opacity, an agent's subprocess tree generates a
high-volume stream of system calls, most of which are background OS
activity unrelated to the agent's task. Static, pre-configured filters
are brittle: a rule that monitors only `git` commands fails the moment
the agent achieves the same effect through `curl`, a Python script, or a
compiled binary. Effective observation requires dynamic filtering based
on process lineage—isolating the agent's causal chain from the
surrounding system noise.

A key observation, first articulated in the AgentSight project, is that
while agent frameworks and tool APIs evolve rapidly (LangChain's
callback interface, Claude Code's hook format, Codex's tool schema),
the system boundaries through which every agent must interact with the
world—the kernel system-call interface and the network protocol
stack—are stable. System-call ABIs and network protocols change on the
timescale of years, not weeks. Building enforcement at these stable
boundaries yields a mechanism that is both complete (every agent action
must pass through the kernel) and durable (it survives framework churn
without modification).

**Challenge 2: Cross-event policies require information-flow state.** The
intent–behavior gap would be manageable if policies were predicates on
individual operations, but real policies are not. Our corpus study finds
that 78% of projects contain policies whose enforcement depends on state
accumulated across multiple operations and objects. "A process that has
read `.env` must not connect to an external endpoint" is a
confidentiality constraint that requires tracking data provenance from a
file read to a network connect. "Run tests before committing" is a
temporal-ordering constraint that requires knowing that a test process
executed after the last source-file modification and before the commit.
"Do not mix data from independent tasks in a single commit" is a
non-interference constraint that requires tracking which labeled data
flows reached which files.

These cross-event policies cannot be expressed as per-operation access
control lists. They require a state model that tracks provenance across
process, file, and network boundaries and encodes it as checkable state
at each enforcement point. Labeled information-flow control provides
exactly this: labels assigned at sources propagate along
fork/exec/read/write/connect edges, accumulating as per-node bitmasks
that encode the full relevant history in O(1) checkable state. Temporal
gates extend this model to causal ordering with automatic invalidation
on state change.

No existing OS-level enforcement system provides cross-event
information-flow tracking. Kernel sandboxes (seccomp, Landlock, BPF
Jailer) enforce per-operation ACLs. Application-layer IFC systems
(FIDES, CaMeL) track information flow at the planner or interpreter
level but lose visibility the moment an agent spawns a subprocess—the
very scenario the intent–behavior gap makes routine.

**Challenge 3: Emergent behavior defeats static policy specification.**
Even with the right enforcement layer and state model, a prior question
remains: who writes the policies? Traditional security assumes an
administrator who understands the software's behavior and writes policies
accordingly. Agent behavior is emergent—the same agent produces different
system-call traces on every invocation—so no administrator can enumerate
the full behavior space upfront. Industry practitioners describe this as
"policy paralysis": policies written too tightly break legitimate agent
workflows; policies written too loosely leave security gaps; and many
teams, unable to find the right balance, deploy no policies at all.

The problem is not merely one of incomplete specification. It is a
fundamental mismatch between static policy and dynamic behavior.
Containerization and micro-VM isolation do not resolve it: an agent
inside the most isolated sandbox can still exfiltrate data through
legitimate API calls if influenced by a prompt injection. Containment
controls where an agent runs; behavioral policy controls what it does
within that boundary. The two are complementary, not substitutes.

This mismatch implies that the enforcement system cannot be a static
runtime that loads a policy and enforces it indefinitely. It must support
a policy lifecycle: observe the agent's behavior first (without
blocking), generate or refine policies from observations, verify them
mechanically, enforce them progressively, and provide feedback that
drives iteration. The policy language must therefore be not only
human-readable for auditing but also machine-writable—structured and
constrained enough that an LLM or a supervisory agent can generate valid
policies. A mechanical verification step provides the safety net that
makes machine-generated policies trustworthy.

**ActPlane.** We present ActPlane, a programmable OS-level control plane
for agent harnesses that addresses all three challenges. Agents and
developers declare behavioral policies in a compact DSL—a form of
voluntary confinement analogous to `pledge()` in OpenBSD. ActPlane
compiles these declarations into labeled information-flow rules and loads
them into an eBPF/BPF-LSM kernel backend.

For the intent–behavior gap, ActPlane enforces at the kernel's
system-call boundary—stable, complete, and framework-agnostic. Process
lineage tracking (`source AGENT = exec "codex"`) propagates labels along
fork edges, isolating the agent's causal chain from background system
noise. When a rule matches, ActPlane translates the OS-level event back
into intent-level semantic feedback: which declared policy was violated,
why, and what alternative path satisfies it—bridging the gap in reverse.

For cross-event policies, named labels propagate across process, file,
and network objects at each kernel hook, encoding execution history as
per-node u64 bitmasks checkable in O(1). Temporal gates (`after G since
S`) track causal ordering with epoch-based invalidation, capturing
staleness conditions like "tests must run after the last source edit."
Rules express predicates over label sets—no provenance graph is
maintained.

For emergent behavior, the DSL is declarative, fixed-structure, and
finite-grammar—designed for LLM generation as much as human authorship.
`actplane compile --explain` provides compile-time verification (syntax, label
consistency, contradiction detection) without requiring root privileges,
serving as a safety net for machine-generated policies. Each rule
independently selects one of three enforcement modes: notify (observe and
report, no blocking), block (pre-operation denial via BPF-LSM), or kill
(post-operation termination). This three-mode design is the mechanism
that enables progressive deployment: teams begin with all rules in
notify mode, build behavioral profiles from observations, and
selectively promote rules to block or kill as confidence grows. The
semantic feedback loop closes the cycle: agents receive
policy-violation explanations and can adjust their behavior or, in a
supervised setting, refine the policy itself.

**Contributions.** This paper makes three contributions.

1. We define the intent–behavior gap for AI agents, identify emergent
   behavior as its root cause, and ground the analysis with a corpus
   study of 64 projects showing that cross-event information-flow
   policies are pervasive in real agent instruction files (§X).

2. We present ActPlane, a programmable OS-level control plane that
   compiles agent-declared behavioral policies into eBPF/BPF-LSM labeled
   information-flow rules, enforcing cross-event constraints across
   process, file, and network boundaries with semantic feedback and
   progressive deployment (§X–§X).

3. We evaluate ActPlane on bypass coverage across five tool-invocation
   paths, agent task-completion rate under four feedback conditions,
   false-positive rate under benign workloads, and per-event overhead,
   comparing against action-level and behavior-level baselines (§X).
