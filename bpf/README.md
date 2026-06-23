# ebpf-ifc-engine

**eBPF information-flow control engine for Linux.**

Kernel-level label propagation and policy rule matching across process,
file, and network boundaries. Loads prebuilt CO-RE eBPF programs via
[aya](https://aya-rs.dev/) — no clang or libbpf required at runtime.
[ActPlane](https://github.com/eunomia-bpf/ActPlane) uses this engine
for AI agent harness enforcement.

## How it works

Each node (process, file, network endpoint) carries a 64-bit label
bitmask. Labels propagate through fixed transfer functions at kernel
hooks:

| Hook | Propagation |
|------|------------|
| fork | child inherits parent labels |
| exec | process acquires source labels matching the binary |
| read/open | process acquires file labels |
| write | file acquires process labels |
| connect | endpoint acquires process labels |
| recv | process acquires endpoint labels |

Rules check accumulated labels at each hook. When a rule matches, the
engine emits a match event with one of three effects:

- **notify** — observe and report (operation proceeds)
- **block** — BPF-LSM returns `-EPERM` (pre-operation denial)
- **kill** — `SIGKILL` the matching task

The loader attaches hooks according to the loaded engine profile. Process
lifecycle and the argv-capable exec tracepoint are always attached. Exec scanning
is split across tail-call stages, so exact exec policies do not force the
verifier through prefix and conditioned-rule scanners in the same program.
Because argv tokens are observed after exec, argv-sensitive exec rules should
use `notify` or `kill`; they are not pre-exec `block` rules.

When BPF-LSM is active, the loader can also mark its own control pid as
protected. Runtime-domain subjects, including uid 0 subjects, cannot signal or
ptrace that protected pid, and they cannot use the `bpf()` syscall to create,
load, attach, pin, or fetch BPF programs, maps, or links. Lookup, update,
delete, and fd-info operations on already-held map fds remain available for
ActPlane's runtime control path.
Processes outside any ActPlane runtime domain
remain ordinary host administrators and can still stop or unload the engine.

## Kernel state

The engine uses separate maps for policy tables, process/domain state,
object labels, provenance, fd tracking, runtime control, and event output. The
most important maps are:

| Map | Purpose |
|-----|---------|
| `ts_updates`, `ts_rules`, `ts_counts` | Hot-reloadable compiled policy tables and active loop counts |
| `ts_proc`, `ts_proc_domains` | Global and runtime-domain process label state |
| `ts_root`, `ts_sess`, `ts_sess_zero` | Lineage roots and temporal gate/staleness epochs |
| `ts_file`, `ts_endp` | Per-domain file and IPv4 endpoint labels |
| `ts_file_prov`, `ts_endp_prov`, `ts_proc_prov` | Label provenance for corrective feedback |
| `cap_req`, `cap_state`, `cap_task`, `cap_policy` | Runtime domain and append/reload admission state |
| `ts_fd`, `ts_fileptr`, `ts_sockfd`, `ts_mmap` | Tracepoint fallback fd, socket, and mmap tracking |
| `rb` | `TAINT_VIOLATION` ring buffer |

File identities are real `(dev,inode)` when hooks can recover a `struct file`.
Tracepoint-only path references fall back to a domain-scoped FNV-1a path id.

## Usage as a library

The supported product entrypoint is the `actplane` CLI. The `ebpf-ifc-engine`
crate is the lower-level loader used by the CLI and runtime, and its API follows
the kernel ABI more closely.

Add to your `Cargo.toml`:

```toml
[dependencies]
ebpf-ifc-engine = { path = "bpf" }
```

```rust
use std::sync::atomic::AtomicBool;

use ebpf_ifc_engine::Loader;

// Load a compiled policy config
let config: Vec<u8> = std::fs::read("policy.bin")?;
let mut loader = Loader::load(&config)?;
loader.seed_label(std::process::id() as i32, 1)?;

// Read match events
let stop = AtomicBool::new(false);
loader.run(&stop, |event| {
    println!("rule {} matched on pid {}", event.rule_id, event.pid);
})?;
```

## Usage as standalone loader

```bash
cargo build -p ebpf-ifc-engine --bin actplane-loader
sudo ./target/debug/actplane-loader --config policy.bin
```

The loader attaches eBPF programs, reads the policy config into rodata,
and prints match events as NDJSON to stdout.

## Building the eBPF programs

The prebuilt CO-RE object ships in `prebuilt/process.bpf.o`. To rebuild:

```bash
# Requires: clang, llvm, libelf-dev, zlib1g-dev
cd bpf && make
```

Or via cargo:

```bash
ACTPLANE_REBUILD_BPF=1 cargo build -p ebpf-ifc-engine
```

## Binary config format

The compiler writes a fixed-size `taint_config` blob. The struct layout is
defined in `taint.h` and mirrored byte-for-byte in Rust (`lower.rs`). It
contains:

- `n_updates` plus up to 320 `taint_update` entries. Updates cover sources,
  declassify/endorse transforms, temporal gates, and `since` invalidators.
- `n_rules` plus up to 128 `taint_rule` entries. Boolean `or` clauses are
  lowered into multiple kernel rules.

The loader copies those entries into writable BPF array maps so runtime reloads
and append-only policy deltas can update the active policy without rebuilding
the eBPF object.

## Requirements

- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- Root or `CAP_BPF` + `CAP_SYS_ADMIN`
- BPF-LSM active for `block` effect (`bpf` in `/sys/kernel/security/lsm`)

## Used by

- [ActPlane](https://github.com/eunomia-bpf/ActPlane) — programmable
  OS-level policy engine for AI agent harnesses

## License

MIT
