# ActPlane Collector

The userspace half of ActPlane: a **project-policy runner + taint-DSL compiler +
reporting shim**. It discovers `actplane.yaml`, parses its embedded `policy: |`
DSL, lowers it to the kernel ABI (`struct taint_config`), runs the embedded eBPF
program, and prints each `TAINT_VIOLATION` the kernel emits with its policy
reason. The kernel does all taint propagation and matching.
Each clause starts with an action verb: `notify`, `block`, or `kill`.
For harness enforcement, `block` denies through BPF LSM when available, while
`kill` makes the action fail by terminating the violating task. If BPF LSM is
not active, tracepoint mode does not support `block`; use `notify` for reporting
or `kill` for harness termination. `actplane run` always prepares
`.actplane/last-violation.txt` and exports the hook environment.

## Build & test

```bash
cargo build --release        # produces target/release/actplane
cargo test                   # DSL compiler unit tests (E1–E12, DNF, ABI size)
```

## Usage

```bash
sudo -E ./target/release/actplane run -- codex --cd /work
sudo -E ./target/release/actplane --policy ../policies/readonly.yaml run -- claude -p "review"
./target/release/actplane compile --out cfg.bin
./target/release/actplane feedback-hook
```

See [`../docs/rule-language.md`](../docs/rule-language.md) for the policy grammar and 12
worked examples.

## Source layout

- `src/main.rs` — CLI driver. Discovers/loads `actplane.yaml`, calls
  `dsl::compile_str`, writes the config blob to a temp file, spawns the loader
  (`--config`), seeds the `AGENT` label for `run` targets, and reports each
  violation line with its reason via `report()`.
- `src/dsl/` — the compiler:
  - `ast.rs` — `Policy` / `Source` / `Rule` / `Clause` / `Expr` / `Cond` / `Xform`.
  - `parse.rs` — hand-rolled lexer + recursive-descent parser for the DSL.
  - `lower.rs` — `#[repr(C)]` mirrors of the kernel structs (`CSource`, `CRule`,
    `CXform`, `CGate`, `CConfig`) and
    `compile(Policy) -> Compiled { bytes, reasons, meta, labels }`:
    bit allocation, DNF expansion of label expressions (`dnf()`), and glob lowering
    (`lower_exec` / `lower_path` / `lower_ipv4`, mapping `**`/`*` to EXACT / PREFIX /
    SUFFIX / ANY match kinds and IPs to net+mask).
  - `mod.rs` — `compile_str()` entry point + the test suite.
- `src/binary_extractor.rs` — embeds `bpf/process` via `include_bytes!` and extracts
  it to a temp dir at runtime so the single `actplane` binary is self-contained.

## ABI contract

`lower.rs`'s `#[repr(C)]` structs are **byte-identical** to the C structs in
`bpf/taint.h`. The compiled blob is serialized with `std::slice::from_raw_parts`
and read straight into the BPF rodata by the loader (`bpf/process.c`). Any change
to `taint.h` must be mirrored here (and vice versa); the `fixed-size` test guards
the total `CConfig` size against drift.
