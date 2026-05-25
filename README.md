# ActPlane: OS-Enforce AI Agent Harnesses with eBPF

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

ActPlane is an **OS-level harness for AI agents**: it evaluates workflow,
capability, and provenance contracts over an agent's *whole* execution, across
any tool, subprocess, or direct syscall, from the kernel via eBPF. Enforcement is
defined at the harness level: a matching action either fails before the kernel
commits it (`block`) or the resulting task is immediately terminated (`kill`),
and the agent gets a human-readable reason (the corrective-feedback payload).

The motivation: agent constraints today live in prompts (`CLAUDE.md` / `AGENTS.md`),
which are only *probabilistic* — a long-context agent forgets or routes around
them, often non-maliciously. Tool-layer guards (AgentSpec, MCP gateways) only see
the tool API and are bypassed the moment the agent shells out or links an SDK.
ActPlane sits **below the tool layer**: every `exec` / file / network operation is
a syscall, so a rule like *"nothing descended from `codex`, however many hops, may
run `git` or modify files outside `/work`"* holds no matter how the agent gets there.

Rules are **information-flow / provenance** contracts, not static allow-lists.
Taint labels propagate along fork/exec edges and, as data flow, along file
read/write and network edges, so task boundaries and workflow obligations follow
derived data across processes and files. Security-relevant policies are one use
case, but the primary framing is a deterministic operating contract for
cooperative-but-forgetful agents. See [`docs/taint-dsl.md`](docs/taint-dsl.md) for
the rule language and 12 worked examples, [`docs/actplane-research-plan.md`](docs/actplane-research-plan.md)
for the framing, and [`docs/related_work.md`](docs/related_work.md) for positioning.

## How it works

```
actplane.yaml ─▶ collector (Rust compiler) ─▶ struct taint_config ─▶ eBPF kernel engine
 policy: |        parse + lower DSL to ABI       (rodata blob)       propagate taint,
                                                                      match rules,
 violations ◀───────── NDJSON (TAINT_VIOLATION + reason) ◀────────── emit on match only
```

- **Kernel** (`bpf/`): hooks `fork / exec / exit / open / unlink / rename / connect`,
  keeps a per-node taint label set (process / file / endpoint), propagates it,
  evaluates the compiled rules, and emits **only** `TAINT_VIOLATION` events through
  a single `emit_violation()` function.
- **Collector** (`collector/`): a Rust runner that discovers `actplane.yaml`,
  lowers the embedded `policy: |` DSL to the kernel config (`struct taint_config`),
  runs the embedded loader, seeds the target command's pid lineage as `AGENT`, and
  prints each violation with its policy reason.

## Build

```bash
make            # builds bpf/ (eBPF programs) then collector/ (Rust)
make test       # bpf C unit tests + collector Rust unit tests
```

Requires clang/llvm, libelf, zlib, a recent kernel (5.8+; developed on 6.15), and
a Rust toolchain. `make install` installs the system dependencies (Ubuntu/Debian).

## Quickstart (≈30 seconds)

```bash
A=./collector/target/release/actplane

$A init                  # write a starter actplane.yaml (commented guardrails)
$A check                 # validate it in plain language — no privileges needed
sudo -E $A run -- bash -lc 'git branch x'   # enforce around any command
```

`check` summarizes every rule and warns about anything that won't enforce as
written (e.g. `block` with no BPF-LSM, or a hostname where the kernel matches IPs):

```
✓ ./actplane.yaml: 3 rule(s) compile.
  1. no-git-branch    — deny exec    → kill (create branches/worktrees on the host…)
  2. no-secret-exfil  — deny connect → kill (data derived from local secrets must not leave…)
  3. test-before-commit — deny exec  → kill (run the tests before committing)
✓ no warnings.
```

`run`/`watch` load the eBPF enforcer, so they need root (or `CAP_BPF` +
`CAP_SYS_ADMIN`); ActPlane drops the target command back to your user. If you
forget `sudo`, it tells you how.

## Run (details)

```bash
sudo -E ./collector/target/release/actplane run -- bash -lc 'git status'
# compile only (no privileges): ./collector/target/release/actplane compile --out policy.bin
```

`actplane run` discovers `actplane.yaml` upward from the current directory,
creates `.actplane/last-violation.txt`, loads the embedded eBPF program, marks
the target command's pid lineage as `AGENT`, and prints whether the kernel denied
the operation, killed the violating task, or only audited it:

```
🚫 KILLED: process 'git' (pid 4213, ppid 4210) — /usr/bin/git
   effect: kill
   reason: Codex must not invoke git; use the review workflow.
```

`effect block` and `effect kill` are intentionally not equivalent. `block` means
BPF-LSM pre-operation denial (`-EPERM`) and is unsupported in tracepoint mode.
Use `effect audit` for tracepoint reporting or `effect kill` when the harness
should terminate the violating task from a tracepoint observation.

## Agent feedback

To make Codex or Claude receive the rule reason automatically, launch the agent
through `actplane run` and install the post-tool hook adapter:

```bash
sudo -E ./collector/target/release/actplane run -- codex --cd "$PWD"
sudo -E ./collector/target/release/actplane run -- claude -p "review this repo"
```

`run` always prepares the feedback file and exports `ACTPLANE_FEEDBACK_FILE` plus
`ACTPLANE_HOOK_STATE` to the child agent. Tracepoint mode does not support
`effect block`; those rules require BPF LSM and will not fire without it. Rules
that explicitly say `effect audit` report, and rules that explicitly say
`effect kill` terminate a task from tracepoint observations.

Codex reads hooks from `.codex/hooks.json` or `~/.codex/hooks.json`. Use an
absolute `actplane` binary path so the hook still works if the agent changes
directory. `PostToolUse` injects feedback after supported tool calls:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "/abs/ActPlane/collector/target/release/actplane feedback-hook",
            "statusMessage": "Checking ActPlane feedback"
          }
        ]
      }
    ]
  }
}
```

In interactive Codex, open `/hooks` once to review and trust the hook. For
one-off automation that already vets the hook source, Codex also accepts
`--dangerously-bypass-hook-trust`.

Claude Code uses the same adapter from `.claude/settings.local.json`. Register
both success and failure events:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/abs/ActPlane/collector/target/release/actplane feedback-hook"
          }
        ]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/abs/ActPlane/collector/target/release/actplane feedback-hook"
          }
        ]
      }
    ]
  }
}
```

The adapter only forwards new bytes from the feedback file as hook
`additionalContext`; it does not re-evaluate policy in userspace. The kernel is
still the sole authority for match/block/kill/audit. Keep the short instruction
snippet in [`script/CLAUDE.snippet.md`](script/CLAUDE.snippet.md) in the target
`CLAUDE.md` or `AGENTS.md` so the agent knows how to handle `[ActPlane]`
messages and EPERM failures.

## Layout

- `bpf/` — eBPF taint engine (`taint.h` ABI + matchers, `taint_engine.bpf.h` state +
  `te_*` helpers, `process.bpf.c` hooks) and loader (`process.c`); plus the retained
  capture programs (`sslsniff`, `stdiocap`, `browsertrace`). See [`bpf/README.md`](bpf/README.md).
- `collector/` — `src/dsl/` (DSL parser + lowering compiler), `src/main.rs` (driver),
  `src/binary_extractor.rs` (embeds/extracts the eBPF loader). See [`collector/README.md`](collector/README.md).
- `script/` — e2e examples and agent instruction snippets.
- `docs/` — research plan, the taint-DSL spec, related work, and reference PDFs.

## Status

The DSL compiler and the kernel matching predicates are unit-tested (`make test`).
The BPF program now has LSM hooks for exec, file access/mutation, and IPv4
connect blocking, with tracepoint violation reporting and explicit `effect kill`
termination when `bpf` is not present in `/sys/kernel/security/lsm`. Remaining
gaps include full `@arg` pre-exec blocking (currently post-exec report for
`audit`, post-exec termination for `kill`, and no tracepoint support for
`block`), hostname/SNI network
policy, inode-first file identity, and a clean live e2e suite.
This is a research prototype.
