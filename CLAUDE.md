# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

ActPlane is an **OS-enforced harness for AI agents**. It compiles a taint-DSL
policy to an in-kernel eBPF enforcer that propagates information-flow taint across
process / file / network edges and reports **only** rule violations — each with a
human-readable reason (the corrective-feedback payload). It enforces below the
tool layer (at the syscall boundary), so constraints hold across any tool,
subprocess, or direct syscall the agent uses.

The repo descends from AgentSight (an eBPF observability framework); the SSL/HTTP
analyzer chain, runners, web server, and frontend were removed. What remains is the
taint enforcer plus a minimal Rust compiler/driver.

## Build & Test Commands

```bash
make                                    # build bpf/ then collector/
make test                               # bpf C unit tests + collector Rust tests
sudo bash test/e2e_examples.sh          # live enforcement of all 12 examples (E1–E12)

# individual components
make -C bpf                             # eBPF programs + loaders
make -C bpf test                        # C unit tests (test_taint)
cd collector && cargo build --release   # Rust compiler/driver (-> target/release/actplane)
cd collector && cargo test              # DSL compiler tests
cd collector && cargo test <name>       # a single test

make -C bpf debug                       # AddressSanitizer build of the loaders
```

## Running

```bash
# compile + enforce a policy
sudo ./collector/target/release/actplane policy.dsl

# compile only -> kernel config blob
./collector/target/release/actplane policy.dsl --out policy.bin

# run the kernel enforcer directly against a compiled blob
sudo ./bpf/process --config policy.bin
```

Requires `sudo` (or `CAP_BPF` + `CAP_SYS_ADMIN`) and a recent kernel (5.8+,
developed on 6.15).

## Architecture

```
policy.dsl ─▶ collector (Rust) ─▶ struct taint_config ─▶ eBPF engine ─▶ TAINT_VIOLATION (+reason)
              parse + lower          (rodata blob)         propagate,
                                                           match, detect
```

### Kernel (`bpf/`)

- `taint.h` — the rule **ABI** (shared, byte-for-byte, with the Rust compiler) and
  the matching predicates. Structs: `taint_source`, `taint_rule`, `taint_xform`,
  `taint_gate`, `taint_config`. Enums: `taint_match` (EXACT/PREFIX/SUFFIX/ANY),
  `taint_src_kind`, `taint_op` (EXEC/OPEN/WRITE/CONNECT), `taint_cond`
  (NONE/LINEAGE/AFTER/TARGET). Matchers: `taint_streq/prefix/suffix/match`,
  `taint_mask_ok`, `taint_arg_match`.
- `taint_engine.bpf.h` — engine state + `te_*` helpers. Maps: `ts_proc`
  (pid → labels + lineage gates), `ts_root`, `ts_sess`, `ts_file` (fnv1a(path) →
  labels), `ts_endp` (IPv4 → labels). Rodata rule tables filled by the loader.
- `process.bpf.c` — the hooks (fork/exec/exit/open/unlink/rename/connect). The only
  output channel is `emit_violation()`.
- `process.c` — loader: `--config` reads the blob into rodata, attaches, prints
  `TAINT_VIOLATION` as NDJSON.

### Collector (`collector/src/`)

- `main.rs` — driver: read policy → `dsl::compile_str` → temp blob → spawn loader →
  parse `Violation` lines → `report()` with the reason. `--feedback-file` appends
  the §6 corrective-feedback payload for each kernel-detected violation (channel
  a1 reason file the agent reads on EPERM).
- `feedback.rs` — `format_payload`: turns a kernel-detected violation (rule meta +
  target) into the model-facing §6 corrective-feedback string. No userspace
  re-detection — the kernel is the sole detector. Agent integration: `script/agent-feedback.md`.
- `dsl/` — `ast.rs`, `parse.rs` (lexer + recursive-descent), `lower.rs` (`#[repr(C)]`
  mirrors of the C structs + `compile()`: bit allocation, `dnf()` label-expr
  expansion, glob lowering), `mod.rs` (`compile_str` + tests E1–E12).
- `binary_extractor.rs` — embeds `bpf/process` via `include_bytes!`, extracts at
  runtime so `actplane` is self-contained.

### Taint model

Each node carries a `u64` label mask. Sources add labels (exec comm / file path /
endpoint IP). Propagation: fork→inherit, exec→apply source/xform/gate, read→file
labels into proc, write→proc labels into file, connect→proc labels to endpoint.
Sinks match a label mask (`req` AND / `forbid` NOT, DNF-expanded) + target pattern
+ optional `@arg` + optional condition (lineage-includes / after / target-scope).
Full semantics and 12 examples: `docs/taint-dsl.md`.

## Critical: the Rust↔C ABI

`collector/src/dsl/lower.rs`'s `#[repr(C)]` structs are **byte-identical** to the C
structs in `bpf/taint.h`. The blob is serialized with `from_raw_parts` and read
directly into the BPF rodata. Any change to `taint.h` MUST be mirrored in
`lower.rs` (and vice versa). The `fixed-size` test in `dsl/mod.rs` guards total
`CConfig` size against drift.

## eBPF verifier gotchas (see bpf/README.md for detail)

- Mark deep helpers `__noinline` (own stack frame); `te_check` takes ≤ 5 args.
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
3. Add a worked example + test in `dsl/mod.rs` and document it in `docs/taint-dsl.md`.

### Adding a kernel hook

1. Add a `SEC("tp/...")` handler in `process.bpf.c`.
2. Call the appropriate `te_*` propagation helper, then `te_check` / `te_connect_check`.
3. Emit only via `emit_violation()`.

## Common Issues

- **eBPF permission errors**: needs `sudo` or `CAP_BPF` + `CAP_SYS_ADMIN`.
- **No violations fire**: confirm the loader printed `ActPlane: N sources, N rules,
  ...` (rodata loaded) and that exec patterns match `comm` (basename, ≤ 15 chars),
  not the full path.
- **ABI size mismatch on load** ("config size mismatch"): `lower.rs` and `taint.h`
  drifted — re-sync the structs.
