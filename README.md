# ActPlane: OS-Enforced Agent Harnesses

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

ActPlane is an **OS-level harness for AI agents**: it evaluates workflow,
capability, and provenance contracts over an agent's *whole* execution, across
any tool, subprocess, or direct syscall, from the kernel via eBPF. When BPF LSM
is active it blocks matching operations; otherwise it runs in audit mode and
reports each violation with a human-readable reason (the corrective-feedback
payload).

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
policy.dsl ──▶ collector (Rust compiler) ──▶ struct taint_config ──▶ eBPF kernel engine
   (rules)        parse + lower to kernel ABI     (rodata blob)        propagate taint,
                                                                       match rules,
   violations ◀────────── NDJSON (TAINT_VIOLATION + reason) ◀───────── emit on match only
```

- **Kernel** (`bpf/`): hooks `fork / exec / exit / open / unlink / rename / connect`,
  keeps a per-node taint label set (process / file / endpoint), propagates it,
  evaluates the compiled rules, and emits **only** `TAINT_VIOLATION` events through
  a single `emit_violation()` function.
- **Collector** (`collector/`): a Rust DSL compiler that lowers a `.dsl` policy to
  the kernel config (`struct taint_config`), runs the embedded loader, and prints
  each violation with its policy reason.

## Build

```bash
make            # builds bpf/ (eBPF programs) then collector/ (Rust)
make test       # bpf C unit tests + collector Rust unit tests
```

Requires clang/llvm, libelf, zlib, a recent kernel (5.8+; developed on 6.15), and
a Rust toolchain. `make install` installs the system dependencies (Ubuntu/Debian).

## Run

```bash
# write a policy (full grammar in docs/taint-dsl.md)
cat > codex.dsl <<'EOF'
source AGENT = exec "**/codex"
rule no-git:
  deny exec "**/git" if AGENT
  effect block
  reason "Codex must not invoke git; use the review workflow."
EOF

sudo ./collector/target/release/actplane codex.dsl      # compile + enforce/audit
# compile only:  ./collector/target/release/actplane codex.dsl --out policy.bin
```

`actplane` compiles the policy, loads the embedded eBPF program, and prints
whether the kernel actually blocked the operation or only audited it:

```
🚫 BLOCKED: process 'git' (pid 4213, ppid 4210) — /usr/bin/git
   effect: block
   reason: Codex must not invoke git; use the review workflow.
```

## Layout

- `bpf/` — eBPF taint engine (`taint.h` ABI + matchers, `taint_engine.bpf.h` state +
  `te_*` helpers, `process.bpf.c` hooks) and loader (`process.c`); plus the retained
  capture programs (`sslsniff`, `stdiocap`, `browsertrace`). See [`bpf/README.md`](bpf/README.md).
- `collector/` — `src/dsl/` (DSL parser + lowering compiler), `src/main.rs` (driver),
  `src/binary_extractor.rs` (embeds/extracts the eBPF loader). See [`collector/README.md`](collector/README.md).
- `docs/` — research plan, the taint-DSL spec, related work, and reference PDFs.

## Status

The DSL compiler and the kernel matching predicates are unit-tested (`make test`).
The BPF program now has LSM hooks for exec, file access/mutation, and IPv4 connect
blocking, with tracepoint audit fallback when `bpf` is not present in
`/sys/kernel/security/lsm`. Remaining gaps include full `@arg` pre-exec blocking,
hostname/SNI network policy, inode-first file identity, and a clean live e2e suite.
This is a research prototype.
