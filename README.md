# ActPlane: OS-Enforce AI Agent Harnesses with eBPF

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

ActPlane is an **OS-level harness for AI agents**. It lets you write behavioral
contracts for your agent in YAML, and enforces them deterministically at the OS
level via eBPF, across every process, file access, and network connection, no
matter how the agent gets there. When a contract is violated, ActPlane blocks
the action and feeds the reason back to the agent so it self-corrects.

Prompt constraints are probabilistic. ActPlane is deterministic.

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

- **OS-level coverage**: enforcement happens at the kernel, not the tool API. Bash, Python subprocess, direct SDK calls, all covered.
- **Call-chain granularity**: rules follow process lineage, not just single operations. "Codex's entire subprocess tree cannot touch git" is one rule.
- **Corrective feedback, not just blocking**: violations feed a human-readable reason back to the agent, so it can retry a different way. This is what makes it a harness, not a sandbox.
- **Agent-maintained rules**: the rule language is designed so agents can write, validate (`actplane check`), and evolve their own contracts.

## Quickstart

```bash
make                                         # build eBPF programs + Rust collector
A=./collector/target/release/actplane

$A init                                      # write a starter actplane.yaml
$A check                                     # validate rules (no privileges needed)
```

```
✓ ./actplane.yaml: 3 rule(s) compile.
  1. no-git-branch     — deny exec    → kill (create branches/worktrees on the host…)
  2. no-secret-exfil   — deny connect → kill (data derived from local secrets must not leave…)
  3. test-before-commit — deny exec   → kill (run the tests before committing)
✓ no warnings.
```

Now run an agent (or any command) under enforcement:

```bash
sudo -E $A run -- claude -p "review this repo"
```

When the agent violates a rule, ActPlane kills the action and tells it why:

```
🚫 KILLED: process 'git' (pid 4213, ppid 4210) — /usr/bin/git
   effect: kill
   reason: Codex must not invoke git; use the review workflow.
```

The agent receives this reason through its hook integration, understands the
constraint, and takes a different path to complete the task.

`run`/`watch` load the eBPF enforcer, so they need root (or `CAP_BPF` +
`CAP_SYS_ADMIN`); ActPlane drops the target command back to your user.

## How rules work

Rules are **labeled information-flow contracts**, not static allow-lists.
Labels propagate along fork/exec edges and file read/write edges, so
constraints follow derived data across processes and files.

```yaml
# actplane.yaml
rules:
  - name: no-secret-exfil
    source: { file: "/etc/secrets/**" }
    deny:
      - { connect: "*" }
      - { write: "/tmp/**" }
    reason: "Data derived from secrets must not leave the machine."
    effect: kill
```

A process that reads `/etc/secrets/api-key` gets labeled. If any descendant of
that process (however many hops) tries to connect to the network or write to
`/tmp`, the kernel kills it and reports the reason.

See [`docs/taint-dsl.md`](docs/taint-dsl.md) for the full rule language and 12
worked examples.

## Agent integration

ActPlane feeds violation reasons back to agents via their hook systems.

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

The adapter forwards new violations as hook context. The kernel remains the sole
authority for enforcement. See [`script/CLAUDE.snippet.md`](script/CLAUDE.snippet.md)
for the agent instruction snippet.

## How it works

```
actplane.yaml ─▶ collector (Rust) ─▶ struct taint_config ─▶ eBPF kernel engine
 policy: |        parse + lower DSL      (rodata blob)       propagate labels,
                                                              match rules,
 violations ◀──── NDJSON (TAINT_VIOLATION + reason) ◀─────── emit on match only
```

- **Kernel** (`bpf/`): hooks `fork / exec / exit / open / unlink / rename / connect`,
  keeps a per-node label set (process / file / endpoint), propagates labels,
  evaluates compiled rules, emits only violation events.
- **Collector** (`collector/`): discovers `actplane.yaml`, compiles the DSL to
  kernel config, loads the eBPF program, seeds the target process lineage, and
  prints violations with policy reasons.

## Build

```bash
make            # builds bpf/ (eBPF programs) then collector/ (Rust)
make test       # bpf C unit tests + collector Rust unit tests
```

Requires clang/llvm, libelf, zlib, a recent kernel (5.8+; developed on 6.15), and
a Rust toolchain. `make install` installs system dependencies (Ubuntu/Debian).
