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
| `ts_updates`, `ts_rules`, `ts_counts` | Runtime-appendable compiled policy tables and active loop counts |
| `ts_proc`, `ts_proc_domains` | Global and runtime-domain process label state |
| `ts_root`, `ts_sess`, `ts_sess_zero` | Lineage roots and temporal gate/staleness epochs |
| `ts_file`, `ts_endp` | Per-domain file and IPv4 endpoint labels |
| `ts_file_prov`, `ts_endp_prov`, `ts_proc_prov` | Label provenance for corrective feedback |
| `cap_req`, `cap_state`, `cap_task`, `cap_policy` | Runtime domain and append admission state |
| `ts_fd`, `ts_fileptr`, `ts_sockfd`, `ts_mmap` | Tracepoint fallback fd, socket, and mmap tracking |
| `rb` | `TAINT_VIOLATION` ring buffer |

File identities are real `(dev,inode)` when hooks can recover a `struct file`.
Tracepoint-only path references fall back to a domain-scoped FNV-1a path id.

## Runtime model

The supported product entrypoint is the `actplane` CLI. The runtime installs or
opens one bpffs-pinned engine under `/sys/fs/bpf/actplane/v1` by default. Set
`ACTPLANE_BPF_PIN_ROOT` to use a different pin root.

The first runtime client installs and pins the maps, programs, and links. Later
clients open those pins and append domain-scoped policy deltas through pinned
control maps. Direct per-command private engine loading is not a supported
runtime model.

The daemonless runtime has a single active event reader. A `run`, `watch`, or
MCP auto-attach session holds the singleton runtime lock while it drains the
pinned ring buffer, and it clears policy/control-map state when that session
starts and exits. A second runtime session must wait or fail fast instead of
racing to consume the same ring-buffer events.

The `ebpf-ifc-engine` crate remains the low-level kernel ABI boundary used by
the runtime. Normal callers should use the CLI and runtime crate instead of
loading eBPF programs directly.

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

The committed object is what production loads: `ebpf-ifc-engine` embeds
`prebuilt/process.bpf.o` with `include_bytes!`, so it must be regenerated (and
committed) whenever the kernel C under `bpf/` changes. If it is not, the shipped
engine silently runs code that lacks the current source, which is a correctness
gap rather than a cosmetic mismatch: commit `8298d23a` added
`te_record_file_prov_mask` to `taint_engine.bpf.h` without regenerating the
object, so `master` shipped an engine missing that fix (and one whose
`trace_rename_exit` fails the Linux 6.8 verifier where a fresh build loads). CI
enforces `script/check_prebuilt_fresh.sh`, which applies two checks because no
single portable one covers both failure modes. First, it compares a
source-provenance digest (`prebuilt/source.sha256`, over the kernel C and the
`Makefile` whose flags determine codegen) against the current tree, so any edit
there, even one that only changes a function body or a compile flag, fails until
the objects and the stamp are regenerated together. Second, it rebuilds both
objects and requires the committed object to define every `__noinline` function
the source defines, which names the specific missing function when an object
predates a newly added one.
Both checks are source-derived rather than byte-based, so they do not depend on
the exact clang/LLVM version (nor on whether that compiler emits `LBB0_*`
basic-block labels as local symbols).

Because the objects are binary and every branch that touches the kernel C
regenerates them from its own base, two such branches always conflict in
`bpf/prebuilt/*.bpf.o`. Resolve by rebuilding from the merged source (`make -C
bpf` then copy `.output/*.bpf.o` over `prebuilt/`, or `ACTPLANE_REBUILD_BPF=1
cargo build -p ebpf-ifc-engine`, which also refreshes the stamp); do not pick a
side of the binary conflict.

## Summed-stack budget (the 6.8 verifier limit)

From Linux 6.8 the verifier sums the maximum stack depth across every frame in a
call chain and rejects a program whose total exceeds 512 bytes, with
`combined stack size of N calls is M. Too large`. A helper can therefore pass on
one kernel and fail here even though its own frame is small, because the limit is
on the chain. The two ways to stay under it are to inline (fewer, larger frames
usually sum lower than many small ones) and to keep `bpf_loop` contexts off the
stack entirely.

The latter matters for the scan collectors. A `bpf_loop` context argument is a
stack-typed value that stays spilled for the whole program, so a context struct
passed to `bpf_loop` raises every caller's frame. The collectors can keep their
contexts in per-CPU scratch maps (`te_*_scratch_buf()`) and pass only a
stack-resident handle, which keeps the exit handlers small enough to sum under
512.

This is not hypothetical. An object in which the collectors pass their contexts
on the stack reaches `combined stack size of 6 calls is 576. Too large` for
`trace_recvfrom_exit` and `trace_recvmsg_exit`; an object built with the contexts
in scratch maps loads all 93 programs with no rejection. Those two programs are
autoloaded only for `TE_POLICY_RECV` (or file-flow with advanced tracepoints), so
the failure is easy to miss: an exec-only or connect-only policy loads fine, but
a policy that uses `recv` together with a file source or a file rule sets both
features and the engine then fails to load entirely, even though the policy
compiles to a valid blob.

Verify with a guest boot rather than the host. Recent kernels no longer perform
the combined-stack walk that 6.8 does, so a host load can succeed where a 6.8
guest rejects. The diagnostic `vvload` loads every program and reports
`VLOAD_DONE ok=<n> fail=<n>` per config, naming the offending program where the
production loader only reports that the skeleton failed.

## Binary config format

The compiler writes a fixed-size `taint_config` blob. The struct layout is
defined in `taint.h` and mirrored byte-for-byte in Rust (`lower.rs`). Because the
blob is read straight into BPF rodata, both sides assert the exact field offsets,
not just the total size: `bpf/test_taint.c`'s `test_abi_layout` checks the C
layout and `abi_layout_matches_the_c_header` in `lower.rs` checks the Rust mirror
against the same numbers. A same-width field reorder passes a total-size check
while reinterpreting every field, so both layouts must be updated together when
either changes. The blob contains:

- `n_updates` plus up to 320 `taint_update` entries. Updates cover sources,
  declassify/endorse transforms, temporal gates, and `since` invalidators.
- `n_rules` plus up to 128 `taint_rule` entries. Boolean `or` clauses are
  lowered into multiple kernel rules.

The loader copies those entries into writable BPF array maps so admitted
runtime policy deltas can extend the active policy without rebuilding the eBPF
object.

## Requirements

- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- Root or `CAP_BPF` + `CAP_SYS_ADMIN`
- BPF-LSM active for `block` effect (`bpf` in `/sys/kernel/security/lsm`)

## Used by

- [ActPlane](https://github.com/eunomia-bpf/ActPlane) — programmable
  OS-level policy engine for AI agent harnesses

## License

MIT
