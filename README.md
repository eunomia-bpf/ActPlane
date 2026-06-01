# ActPlane: eBPF-Based Policy Engine for AI Agent Harnesses

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Runtime `observability` and `enforcement` for AI agent harnesses and sandboxing: declare information-flow policies in a compact DSL, ActPlane enforces them at the kernel level.**

ActPlane sits below the tool layer, so a rule holds information-flow constraints
across every process, file access, and network connection the agent touches, no
matter what tool, subprocess, or script it uses to get there. 

Each rule sets its own mode: **notify** (observe and notify agent), **block**
(stop the action before it commits), or **kill** (terminate the process). In
every mode the rule match's reason is fed back to the agent as a reminder, so it
can self-correct instead of just hitting a wall. Agents can write and validate
 their own rules (`actplane check`).

Prompt constraints and model guardrails are probabilistic. ActPlane is deterministic.

**What you can express:**

- **"No `codex` may run `git push` or write outside `/src`"**: fine-grained sandboxing rules follow process lineage, no bypass via bash scripts or python.
- **"Never remove the build cache in makefile unless explicitly asked or debugging"**: bypassable with a specific argument when necessary, not just sandbox.
- **"When changing `specs/*`, also update the server, SDK, and docs"**: ActPlane never blocks the edit, it notifies the agent that downstream outputs are now stale.
- **"Run  `make check` & `npm tests` before committing"**: causal ordering, not just per-operation checks.


## Quickstart

Install with one command. The eBPF program ships prebuilt (CO-RE, architecture
independent), so there is **no clang/llvm/libbpf to install** — just a Rust
toolchain:

```bash
cargo install actplane
```

Write a policy and run an agent (or any command) under the harness:

```bash
actplane init                                  # write a starter actplane.yaml
actplane check                                 # validate rules (no privileges)

sudo -E actplane run claude -p "review this repo"
```

When a rule matches, ActPlane kills the action and tells the agent why:

```
🚫 KILLED: process 'git' (pid 4213, ppid 4210) — /usr/bin/git
   effect: kill
   reason: no git under the agent; use the review workflow
```

The agent receives this reason through its hook integration, understands the
constraint, and takes a different path to complete the task.

**Requirements:** Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`). `run`
and `watch` load the eBPF engine, so they need root (or `CAP_BPF` +
`CAP_SYS_ADMIN`); ActPlane drops the target command back to your user. With
BPF-LSM enabled, rules can `block` before the action commits; otherwise they
`notify` (report) or `kill`.

## Why an OS-level harness?

Agent constraints today come in three forms. Each solves a real problem but
leaves a gap that the next layer down needs to cover.

| Approach | What it does | What it can't cover |
|----------|-------------|---------------------|
| **Prompt constraints** (`CLAUDE.md`, `AGENTS.md`) | Tell the agent what to do and not do | Probabilistic: long-context agents forget or route around them, often non-maliciously |
| **Tool-layer guards** (MCP gateways, AgentSpec) | Intercept and authorize at the tool API | Bypassed the moment the agent shells out, links an SDK, or spawns a subprocess |
| **Sandboxes** (containers, VMs, E2B, Daytona) | Isolate the entire execution environment | All-or-nothing: can't express "file A must only be accessed via script A" or "run tests before committing" |

ActPlane sits below all three, at the OS level. Every `exec`, file open, and
network connect goes through the kernel, so a rule like *"nothing descended from
`codex`, however many hops, may run `git` or modify files outside `/work`"*
holds regardless of which tool path the agent takes.

The key differences:

- **OS-level coverage**: observation and enforcement happen at the kernel, not the tool API. Bash, Python subprocess, direct SDK calls, all covered.
- **Call-chain granularity**: rules follow process lineage, not just single operations. "Codex's entire subprocess tree cannot touch git" is one rule.
- **Data-flow constraints**: rules express "data read from A must never flow to B", tracked across arbitrary fork/exec and file read/write edges, not just at a boundary.
- **Causal ordering**: rules express "run tests before committing" via `since` clauses and gate invalidation, not just per-operation checks.
- **Corrective feedback, not just blocking**: rule matches feed a human-readable reason back to the agent, so it can retry a different way. This is what makes it a harness, not a sandbox.
- **Agent-maintained rules**: the rule language is designed so agents can write, validate (`actplane check`), and evolve their own policies.

## Harness, not just a sandbox

A sandbox draws an isolation boundary: everything inside is allowed, everything
outside is denied. That works for untrusted code, but agents need something
richer — the data-flow, causal-ordering, and corrective-feedback properties
above are things no isolation boundary can express.

Sandboxes answer "can this process access this resource?" A harness answers a
broader set of questions: not just security ("secret data must not reach the
network") but also software engineering discipline ("run tests before
committing", "don't mix data from independent tasks in one commit", "use the
migration tool to access prod.db"). These are workflow constraints, not access
control, and they are exactly the kind of rules agents need to operate
autonomously in real codebases.

A harness also subsumes sandboxing when you need it. When an agent spawns a
sub-agent or runs an untrusted command, you can write a rule that confines the
entire subtree to read-only, no-network, or a specific directory. This is
especially important when agents cross vendor boundaries: Codex calling Claude
Code, or the other way around. Framework-level guards from different vendors
don't compose, but OS-level rules follow process lineage regardless of which
runtime is underneath.

## How rules work

Rules are **labeled information-flow policies**, not static allow-lists.
Labels propagate along fork/exec edges and file read/write edges, so
constraints follow derived data across processes and files.

```yaml
# actplane.yaml
version: 1
policy: |
  source AGENT = exec "claude"

  # Track when protocol schema files are modified
  source SCHEMA_CHANGED = file "src/protocol/**/*.proto"

  rule no-git-branch:
    kill exec "git" "branch"   if AGENT
    kill exec "git" "worktree" if AGENT
    because "This workspace forbids creating git branches or worktrees. Use other git commands, or ask the user to manage branches."

  rule regenerate-after-schema:
    notify exec "git" "commit"
      if SCHEMA_CHANGED unless after exec "protoc" since write "src/protocol/**"
    because "Protocol schema changed — generated code may be stale. Run `make proto` to regenerate, then commit."

  rule test-before-commit:
    block exec "git" "commit"
      if AGENT unless after exec "pnpm" "test" since write "src/**"
    because "Source files changed since last test run. Run `pnpm test:changed`, then commit."
```

Three rules, three effects, three patterns:

- **`no-git-branch`** (kill): per-event rule — anything in the agent's
  process tree that tries `git branch` is terminated immediately.
- **`regenerate-after-schema`** (notify): cross-event conditional — if
  the agent modified a `.proto` file, ActPlane reminds it to run `protoc`
  before committing. The `since` clause re-arms the gate whenever the
  schema changes again.
- **`test-before-commit`** (block): cross-event temporal with staleness —
  the agent must run tests before committing, and editing any `src/`
  file invalidates the previous test run.

See [`docs/rule-language.md`](docs/rule-language.md) for the full rule language and
worked examples.

## Agent integration

ActPlane feeds rule-match reasons back to agents via their hook systems.

This repo includes a ready-to-use Codex hook at `.codex/hooks.json`. It runs
`./collector/target/release/actplane feedback-hook` after each tool call and
injects any new `.actplane/last-violation.txt` content into the next model turn.

**Claude Code** (`.claude/settings.local.json`):

```json
{
  "hooks": {
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "/path/to/actplane feedback-hook" }] }],
    "PostToolUseFailure": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "/path/to/actplane feedback-hook" }] }]
  }
}
```

**Codex** (`.codex/hooks.json`):

```json
{
  "hooks": {
    "PostToolUse": [{ "matcher": ".*", "hooks": [{ "type": "command", "command": "/path/to/actplane feedback-hook" }] }]
  }
}
```

The adapter forwards new rule matches as hook context. The kernel remains the sole
authority for observation and enforcement. See [`script/CLAUDE.snippet.md`](script/CLAUDE.snippet.md)
for the agent instruction snippet.

ActPlane also ships an MCP server:

```bash
actplane mcp
```

It exposes `actplane:///policy` for live policy validation and
`actplane:///feedback` for the latest corrective feedback. To have Codex start it
automatically, register the stdio server once:

```bash
codex mcp add actplane --env ACTPLANE_PROJECT_DIR=/path/to/repo -- /path/to/actplane mcp
```

## How it works

```
actplane.yaml ─▶ collector (Rust) ─▶ .rodata config ─▶ eBPF kernel engine
 policy: |        parse + lower DSL    (set_global)      propagate labels,
                                                          match rules,
 matches ◀─────── ring buffer (in-process, via aya) ◀─── emit on match only
```

- **Kernel** (`bpf/`): hooks `fork / exec / exit / open / unlink / rename / connect`,
  keeps a per-node label set (process / file / endpoint), propagates labels,
  evaluates compiled rules, emits only match events.
- **Collector** (`actplane`): discovers `actplane.yaml`, compiles the DSL to the
  kernel config, and loads the prebuilt eBPF object in-process via
  [`ebpf-ifc-engine`](bpf/) (aya) — no libbpf/clang at runtime — seeds the target
  process lineage, and reports rule matches with policy reasons.

## Build from source

`cargo install actplane` is all most users need. To hack on ActPlane:

```bash
git clone --recurse-submodules https://github.com/eunomia-bpf/ActPlane
cd ActPlane/collector && cargo build --release   # uses the prebuilt eBPF object
```

Editing the kernel eBPF (`bpf/*.bpf.c`) requires the BPF toolchain
(clang/llvm, libelf, zlib) and the `libbpf`/`bpftool` submodules. Rebuild and
refresh the committed object with:

```bash
ACTPLANE_REBUILD_BPF=1 cargo build -p ebpf-ifc-engine   # regenerates bpf/prebuilt/process.bpf.o
```

Run the tests:

```bash
make test                          # bpf C unit tests + collector Rust unit tests
sudo bash script/e2e_examples.sh   # live E1–E12 enforcement
```

## LICENSE

MIT License. See [LICENSE](LICENSE).
