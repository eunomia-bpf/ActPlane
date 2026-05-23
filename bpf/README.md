# ActPlane eBPF programs

The kernel half of ActPlane. The **taint enforcer** is the heart of the system;
the other programs are retained capture tools.

## Build & test

```bash
make            # builds all APPS (sslsniff browsertrace stdiocap process test_taint)
make test       # runs the C unit tests (test_taint)
make debug      # AddressSanitizer build of the userspace loaders
```

eBPF programs use the CO-RE pattern with an architecture-specific `vmlinux.h` from
`vmlinux/`. Each emits JSON to stdout and debug info to stderr.

## The taint enforcer (`process`)

| File | Role |
|------|------|
| `taint.h` | The rule **ABI** + matching predicates, shared with the Rust compiler. Defines `struct taint_source / taint_rule / taint_xform / taint_gate / taint_config`, the `taint_match`/`taint_src_kind`/`taint_op`/`taint_cond` enums, and the matchers (`taint_streq`, `taint_prefix`, `taint_suffix`, `taint_match`, `taint_mask_ok`, `taint_arg_match`). |
| `taint_engine.bpf.h` | The engine state + helpers. Maps: `ts_proc` (pid → labels + lineage gates), `ts_root`, `ts_sess` (session gates), `ts_file` (fnv1a(path) → labels), `ts_endp` (IPv4 → labels). Rodata rule tables (filled by the loader). `te_*` propagation/eval functions. |
| `process.bpf.c` | The hooks: tracepoints maintain lineage/audit fallback; BPF LSM hooks (`bprm_check_security`, `file_open`, `file_permission`, `file_truncate`, `path_truncate`, `path_unlink`, `path_rename`, `socket_connect`) block with `-EPERM` when BPF LSM is active. The **only** output is `emit_violation()`. |
| `process.c` | Userspace loader. `--config <blob>` reads a `struct taint_config` into the BPF rodata, detects whether `bpf` LSM is active, disables LSM programs in audit mode, and prints each `TAINT_VIOLATION` as NDJSON (formatting `conn_ip` for connect rules). |
| `test_taint.c` | Unit tests for the matching predicates. |

### Taint model (summary)

Each node (process / file / endpoint) carries a `u64` label bitmask. Sources add
labels (`exec` comm match, `file` path match, `endpoint` IP match). Propagation:
fork → child inherits; exec → source/xform/gate applied to the process; read → file
labels flow into the process; write → process labels flow into the file; connect →
process labels flow to the endpoint. LSM hooks can deny before commit (`block`);
tracepoint fallback can still enforce the harness by terminating the violating
task (`kill`). Sinks (`deny exec/open/write/connect`) match
on a label mask (`req` AND / `forbid` NOT, DNF-expanded by the compiler) plus the
target pattern, optional `@arg` match, and an optional condition (`lineage-includes`,
`after`, target scope). Each rule carries an explicit effect (`audit`, `block`,
or `kill`). On a match the rule's `rule_id`, `effect`, `blocked`, and `killed`
flags are emitted; the compiler keeps the reason strings. Full semantics:
[`../docs/taint-dsl.md`](../docs/taint-dsl.md).

### eBPF verifier notes (why the code looks the way it does)

- **Subprograms for stack room.** `te_check` / `te_exec_update` / `te_file_src` /
  `te_endp_src_ip` / `te_connect_check` are `__noinline` so each gets its own 512 B
  frame. `te_check_labels` takes one context pointer (BPF subprogram scalar args
  are limited) and writes the matched rule effect back into that context.
- **Copy rodata before matching.** Each loop copies `struct taint_rule r =
  taint_rules[i]` into a non-volatile local; matchers take `const char *` (not
  `const volatile char *`). Direct volatile rodata reads inside the matchers
  mis-evaluate EXACT/PREFIX/SUFFIX.
- **Explicit bound guards, not index masking.** `if (idx < N)` instead of
  `idx & (N-1)` — masking lets clang fold `ptr + idx` into `ptr | idx`, which the
  verifier rejects ("bitwise operator |= on pointer prohibited").
- **Buffers ≥ pattern length.** `comm` and the IP string buffer are
  `TAINT_PAT_LEN` so matchers never read out of bounds.
- **Numeric IPv4 for connect.** The compiler lowers host/IP patterns to net+mask;
  the kernel does `(ip & mask) == net`, avoiding in-kernel string formatting (which
  triggered the pointer-OR rejection). The loader formats the IP for display.

## Retained capture programs

- `sslsniff` — hooks `SSL_read`/`SSL_write` via uprobes to capture plaintext TLS.
- `stdiocap` — captures process stdio.
- `browsertrace` — browser-side tracing.

These are kept as data sources / building blocks; the enforcer (`process`) is the
component the collector drives.
