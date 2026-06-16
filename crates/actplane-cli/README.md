# ActPlane CLI

The command-line frontend for ActPlane: a **project-policy runner + runtime
control client + setup/reporting shim**. File policies are YAML (`actplane.yaml` or `.actplane/policy.yaml`)
with an embedded `policy: |` DSL block; raw DSL is only accepted through `--rule`
for one-off command-line use. The CLI calls `actplane-ifc-compiler` to lower DSL
to the kernel ABI (`struct taint_config`), calls `actplane-runtime` to run the
eBPF engine, and prints each
`TAINT_VIOLATION` the kernel emits with its policy reason. The kernel does all
taint propagation and matching.
Each clause starts with an action verb: `notify`, `block`, or `kill`.
For harness enforcement, `block` denies through BPF LSM when available, while
`kill` makes the action fail by terminating the violating task. If BPF LSM is
not active, tracepoint mode does not support `block`; use `notify` for reporting
or `kill` for harness termination. `actplane run` always prepares
`.actplane/last-violation.txt` and exports the hook environment.

## Build & test

```bash
cargo build --release -p actplane
cargo test -p actplane
../../test/policy-corpus.sh  # YAML policy corpus + release compile microbench
```

## Usage

```bash
sudo -E ./target/release/actplane run -- codex --cd /work
sudo -E ./target/release/actplane --policy ../policies/readonly.yaml run -- claude -p "review"
./target/release/actplane compile --out cfg.bin
./target/release/actplane feedback-hook
```

See [`../docs/rule-language.md`](../docs/rule-language.md) for the policy grammar and 13
worked examples.

## Source layout

- `src/main.rs` — CLI driver. Discovers/loads `actplane.yaml`, calls
  `actplane-ifc-compiler`, dispatches `run` / `watch` / `compile` / setup
  commands, and delegates runtime work to `actplane-runtime`.
- `src/doctor.rs`, `src/setup.rs`, `src/templates.rs`, `src/template_generate.rs`
  — project UX and policy template helpers.
- `../../crates/actplane-ifc-compiler/` — parser/lowerer and kernel ABI blob
  generation.
- `../../crates/actplane-runtime/` — engine loading, domains, control server,
  MCP, hooks, feedback, and reporting.
- `../../test/policies/` — YAML policy corpus; each file has a `policy: |` block that is
  parsed through the same YAML shape users write.

## ABI contract

`../actplane-ifc-compiler/src/dsl/lower.rs`'s `#[repr(C)]` structs are **byte-identical** to the C structs in
`bpf/taint.h`. The compiled blob is serialized with `std::slice::from_raw_parts`
and loaded straight into the eBPF policy maps by `bpf/src/lib.rs`. Any change to
`taint.h` must be mirrored here (and vice versa); the `fixed-size` test guards
the total `CConfig` size against drift.
