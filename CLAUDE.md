# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

ActPlane is an **OS-level harness for AI agents**. It compiles a policy DSL
to an in-kernel eBPF engine that performs **labeled information-flow control**
across process / file / network edges and reports **only** rule matches —
each with a human-readable reason (the corrective-feedback payload). It applies
policies below the tool layer (at the syscall boundary), so constraints hold across any
tool, subprocess, or direct syscall the agent uses. (The mechanism is a labeled,
runtime form of information-flow control — unlike classic taint analysis, which
is single-bit, usually offline, and aimed at finding vulnerabilities. Code-level
identifiers still use `taint` — `taint.h`, `taint_config`, `te_*` — as the
implementation name.)

The repo descends from AgentSight (an eBPF observability framework); the SSL/HTTP
analyzer chain, runners, web server, and frontend were removed. What remains is the
labeled information-flow engine plus a minimal Rust compiler/driver.

## Agent change workflow

Develop experiments and other changes on a dedicated non-default branch in this
existing checkout. Changes entering the default `master` branch require a pull
request. Do not push implementation or experiment commits directly to `master`.
Creating and using a task branch is authorized, but do not create an additional
worktree unless the user explicitly requests one.

The repository still includes `no-git-branch` templates, examples, and test
fixtures as demonstrations of ActPlane policy behavior. They are product assets,
not an operational prohibition for this checkout, and should not be removed merely
because this workspace now uses branches.

When an operation fails with `EPERM` / `Operation not permitted`, or a tool hook
injects an `[ActPlane]` message, treat it as authoritative kernel feedback. Read
`.actplane/last-violation.txt` if you need the full reason, then follow the
suggested path instead of retrying the same operation unchanged.

## OSS Change Workflow

When changing code, tests, docs, or examples in this OSS repository, use the
`oss-change-workflow` skill before editing unless a more specific workflow skill
applies. Follow its scope-control, validation, docs/test synchronization, and
PR/CI handoff guidance.

## Build & Test Commands

```bash
make                                    # build bpf/ then the ActPlane CLI
make test                               # bpf C unit tests + Rust workspace tests
sudo bash script/e2e_examples.sh        # live policy match of every case in test/e2e_cases.yaml

# individual components
make -C bpf                             # eBPF programs + loaders
make -C bpf test                        # C unit tests (test_taint)
cargo build --release -p actplane       # Rust CLI (-> target/release/actplane)
cargo test -p actplane-ifc-compiler     # policy compiler tests
cargo test -p actplane-runtime          # runtime/control tests
cargo test -p actplane <name>           # a single CLI test/filter

make -C bpf debug                       # AddressSanitizer build of the loaders

# CI gates (run by the "Build and Test" job; run them before committing too)
bash script/check_prebuilt_fresh.sh     # committed eBPF objects match the source
bash script/check_evidence_tsv.sh       # committed evidence TSVs are well-formed
python3 script/check_doc_refs.py        # doc references resolve; evidence indexed
```

## Running

```bash
# compile + apply a policy
sudo ./target/release/actplane --rule "$(cat policy.dsl)" run <cmd>

# compile only -> kernel config blob (pattern hazards are printed to stderr;
# `compile --explain` for the full review)
./target/release/actplane --rule "$(cat policy.dsl)" compile --out policy.bin

# run the kernel engine directly against a compiled blob
sudo ./bpf/process --config policy.bin
```

Requires `sudo` (or `CAP_BPF` + `CAP_SYS_ADMIN`) and a recent kernel (5.8+,
developed on 6.15).

## Architecture

```
policy.dsl ─▶ actplane-ifc-compiler ─▶ struct taint_config ─▶ eBPF engine ─▶ TAINT_VIOLATION (+reason)
              parse + lower             (rodata blob)        propagate,
                                                               match, detect
```

### Kernel (`bpf/`)

- `taint.h` — the rule **ABI** (shared, byte-for-byte, with the Rust compiler) and
  the matching predicates. Structs: `taint_update`, `taint_rule`,
  `taint_config`. Enums: `taint_match` (EXACT/PREFIX/SUFFIX/ANY),
  `taint_op` (EXEC/OPEN/WRITE/CONNECT), `taint_cond`
  (NONE/LINEAGE/AFTER/TARGET). Matchers: `taint_streq/prefix/suffix/match`,
  `taint_mask_ok`, `taint_arg_match`.
- `taint_engine.bpf.h` — engine state + `te_*` helpers. Maps: `ts_proc`
  (pid → labels + lineage gates), `ts_root`, `ts_sess`, `ts_file` (fnv1a(path) →
  labels), `ts_endp` (IPv4 → labels). Rodata update/rule tables filled by the loader.
- `process.bpf.c` — the hooks (fork/exec/exit/open/unlink/rename/connect). The only
  output channel is `emit_violation()`.
- `process.c` — loader: `--config` reads the blob into rodata, attaches, prints
  `TAINT_VIOLATION` as NDJSON.

### Rust crates (`crates/`)

- `actplane-ifc-compiler` — DSL AST/parser/lowerer. It emits the fixed kernel
  config blob and compile metadata, but does not load eBPF or manage processes.
- `actplane-runtime` — policy-file resolution, runtime domains, engine loading,
  local control, MCP integration, corrective feedback, and reporting.
- `actplane-cli` — the `actplane` binary, clap command surface, init/doctor
  UX, templates, and project integration setup.

### Labeled information-flow model

Each node carries a `u64` label mask. Sources add labels (exec comm / file path /
endpoint IP). Propagation: fork→inherit, exec→apply source/xform/gate, read→file
labels into proc, write→proc labels into file, connect→proc labels to endpoint.
Sinks match a label mask (`req` AND / `forbid` NOT, DNF-expanded) + target pattern
+ optional positional argument + optional condition (lineage-includes / after / target-scope).
Full semantics and worked examples: `docs/rule-language.md`.

## Critical: the Rust↔C ABI

`crates/actplane-ifc-compiler/src/dsl/lower.rs`'s `#[repr(C)]` structs are **byte-identical** to the C
structs in `bpf/taint.h`. The blob is serialized with `from_raw_parts` and read
directly into the BPF rodata. Any change to `taint.h` MUST be mirrored in
`lower.rs` (and vice versa). Guards: the `fixed-size` test in `dsl/mod.rs` pins
total `CConfig` size, and `abi_layout_matches_the_c_header` in `lower.rs` plus
`test_abi_layout` in `bpf/test_taint.c` pin every field offset on both sides. The
size test alone does not catch a same-width field reorder, which reinterprets
every serialized field, so update both the offsets and the sizes together.

Constants shared outside `taint_config` are pinned separately, because the offset
tests do not cover them: `abi_constants_match_the_c_header` in `lower.rs` and
`test_abi_constants` in `bpf/test_taint.c` assert `TAINT_PAT_LEN`,
`TAINT_ARG_LEN`, `MAX_TAINT_UPDATES`, `MAX_TAINT_RULES`, `MAX_TAINT_GATES`,
`MAX_TAINT_INVALS`, and `TAINT_SUF_MAX`. The gate/invalidator limits must stay
equal on both sides and a power of two (the kernel masks slot indices with
`N - 1`), and `MAX_CONTAINS_LITERAL` must equal `TAINT_SUF_MAX`.

The enum discriminants are ABI values too, since `op`, `match`, `cond_kind`,
`effect`, and `gate_exit_code` are `u8`/`i32` fields written into the blob.
`abi_enum_values_match_the_c_header` in `lower.rs` and `test_abi_enum_values` in
`bpf/test_taint.c` pin `taint_match`, `taint_op`, `taint_cond`, `taint_effect`,
and `TAINT_GATE_IMMEDIATE`. A drift is silent: a `contains` matcher given
`ANY`'s value matches everything, and an `op` value change makes the kernel index
the wrong table.

The committed objects are tied to the source by `bpf/prebuilt/source.sha256`, a
digest over the kernel C and `bpf/Makefile` (the build input set minus the
generated, uncommitted `vmlinux.h`). `script/check_prebuilt_fresh.sh` fails if
that digest no longer matches, or if a committed object omits a `__noinline`
function the source defines. `ebpf-ifc-engine` embeds `prebuilt/process.bpf.o`,
so a stale object ships a broken engine: `master` currently ships one whose
`trace_recvfrom_exit`, `trace_recvmsg_exit`, and rename-exit programs fail to
load on Linux 6.8 (measured by loading every program at the pinned feature mask,
which is `ALL_HOOK_FEATURES`). After editing
any kernel C, regenerate both objects and the stamp together with
`ACTPLANE_REBUILD_BPF=1 cargo build -p ebpf-ifc-engine` (which runs the guard's
`--update`), and never edit the stamp by hand: `--update` refuses to stamp unless
the committed objects byte-match a fresh build. The gate keys on source and
symbols rather than object bytes, because bytes track the clang that produced
them.

## eBPF verifier gotchas (see bpf/README.md for detail)

- Keep the per-frame stack small; prefer inlining over `__noinline` for deep
  helpers. The 6.8 verifier sums the maximum depth along a call chain against 512
  bytes, so a helper marked `__noinline` adds a frame to every chain that reaches
  it: measured on this engine, marking `handle_io_exit_addr` `__noinline` took
  `trace_recvfrom_exit` from `6 calls is 576` to `7 calls is 640` (worse). The
  real lever is keeping `bpf_loop` contexts in per-CPU scratch maps rather than on
  the stack. Use `__noinline` only when a single helper's own frame is the
  problem, and re-check in a guest boot of the target kernel because the limit is
  per kernel version. Also keep `te_check_labels` small.
- Copy each rodata rule into a non-volatile local before matching; matchers take
  `const char *`, not `const volatile char *`.
- Use explicit `if (idx < N)` bound guards, never `idx & (N-1)` (pointer-OR reject).
- Match buffers must be ≥ `TAINT_PAT_LEN`.
- connect uses numeric IPv4 (net+mask) — no in-kernel string formatting.

## Development Patterns

### Adding a DSL construct

1. Extend the grammar in `dsl/parse.rs` and the AST in `dsl/ast.rs`.
2. Lower it in `dsl/lower.rs`; if it needs new kernel state, extend `taint.h`
   (both sides) and the engine in `taint_engine.bpf.h`.
3. Add a worked example + test in `dsl/mod.rs` and document it in `docs/rule-language.md`.

### Adding a kernel hook

1. Add a `SEC("tp/...")` handler in `process.bpf.c`.
2. Call the appropriate `te_*` propagation helper, then `te_check_labels`.
3. Emit only via `emit_violation()`.

## Running Codex CLI

When invoking OpenAI Codex CLI for cross-validation or review tasks, always use
`--dangerously-bypass-approvals-and-sandbox` so it runs non-interactively:

```bash
codex exec --dangerously-bypass-approvals-and-sandbox "<prompt>"
```

## Paper Writing Rules

- **No em-dashes (`---`)** in paper text. Use commas, parentheses, or
  restructure the sentence. Table cells using `---` for "not applicable" are OK.
- **Avoid semicolons** joining independent clauses. Use periods to start new
  sentences, commas with conjunctions (", and", ", but"), or causal connectors
  ("because", "so", "since"). Semicolons are OK inside parenthetical lists.
- **Write academic prose, not notes.** Use causal connectors and flowing
  sentences, not short declarative statements strung together. Introduce
  concepts with concrete examples before abstract definitions. Every design
  decision needs its "why" stated before its "what".

## Common Issues

- **eBPF permission errors**: needs `sudo` or `CAP_BPF` + `CAP_SYS_ADMIN`.
- **No rule matches fire**: confirm the loader printed `ActPlane: N sources, N rules,
  ...` (rodata loaded) and that exec patterns match `comm` (basename, ≤ 15 chars),
  not the full path.
- **ABI size mismatch on load** ("config size mismatch"): `lower.rs` and `taint.h`
  drifted — re-sync the structs.
