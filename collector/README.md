# ActPlane Collector

The userspace half of ActPlane: a **taint-DSL compiler + reporting shim**. It
parses a `.dsl` policy, lowers it to the kernel ABI (`struct taint_config`), runs
the embedded eBPF program, and prints each `TAINT_VIOLATION` the kernel emits
with its policy reason. The kernel does all taint propagation and matching.
Individual rules can request `effect audit`, `effect block`, or `effect kill`.
For harness enforcement, `block` denies through BPF LSM when available, while
`kill` makes the action fail by terminating the violating task; `--kill-on-violation`
upgrades fallback `block` hits to SIGKILL when BPF LSM is unavailable.

## Build & test

```bash
cargo build --release        # produces target/release/actplane
cargo test                   # DSL compiler unit tests (E1–E12, DNF, ABI size)
```

## Usage

```bash
sudo ./target/release/actplane policy.dsl          # compile + enforce/audit
sudo ./target/release/actplane --kill-on-violation policy.dsl
./target/release/actplane policy.dsl --out cfg.bin # compile only -> kernel blob
```

See [`../docs/taint-dsl.md`](../docs/taint-dsl.md) for the policy grammar and 12
worked examples.

## Source layout

- `src/main.rs` — CLI driver. Reads the policy, calls `dsl::compile_str`, writes
  the config blob to a temp file, spawns the loader (`--config`), and reports each
  violation line with its reason via `report()`.
- `src/dsl/` — the compiler:
  - `ast.rs` — `Policy` / `Source` / `Rule` / `Clause` / `Expr` / `Cond` / `Xform`.
  - `parse.rs` — hand-rolled lexer + recursive-descent parser for the DSL.
  - `lower.rs` — `#[repr(C)]` mirrors of the kernel structs (`CSource`, `CRule`,
    `CXform`, `CGate`, `CConfig`) and `compile(Policy) -> Compiled { bytes, reasons, meta }`:
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
