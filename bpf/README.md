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

Rules check accumulated labels at each hook. When a rule matches, the
engine emits a match event with one of three effects:

- **notify** — observe and report (operation proceeds)
- **block** — BPF-LSM returns `-EPERM` (pre-operation denial)
- **kill** — `SIGKILL` the matching task

## Kernel state

Five BPF hash maps track label state:

| Map | Key | Value |
|-----|-----|-------|
| `ts_proc` | pid | label bitmask + lineage gates |
| `ts_root` | root pid | temporal gate state |
| `ts_sess` | session id | temporal gate state |
| `ts_file` | path hash (FNV-1a) | label bitmask |
| `ts_endp` | IPv4 address | label bitmask |

## Usage as a library

Add to your `Cargo.toml`:

```toml
[dependencies]
ebpf-ifc-engine = "0.1"
```

```rust
use ebpf_ifc_engine::{ActplaneBpf, Config};

// Load a compiled policy config
let config: Vec<u8> = std::fs::read("policy.bin")?;
let mut engine = ActplaneBpf::new()?;
engine.load(&config)?;

// Read match events
for event in engine.events() {
    println!("rule {} matched on pid {}", event.rule_id, event.pid);
}
```

(Note: the API shown above is illustrative. See the source for the
actual interface.)

## Usage as standalone loader

```bash
cargo install ebpf-ifc-engine
sudo actplane-loader --config policy.bin
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

The engine reads a `taint_config` struct as read-only BPF data. The
struct layout is defined in `taint.h` and mirrored byte-for-byte in
Rust (`lower.rs`). It contains:

- Up to 32 sources (label introduction rules)
- Up to 32 rules (label-matching deny clauses)
- Up to 16 transforms (declassify/endorse gates)
- Up to 16 temporal gates

## Requirements

- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- Root or `CAP_BPF` + `CAP_SYS_ADMIN`
- BPF-LSM active for `block` effect (`bpf` in `/sys/kernel/security/lsm`)

## Used by

- [ActPlane](https://github.com/eunomia-bpf/ActPlane) — programmable
  OS-level policy engine for AI agent harnesses

## License

MIT
