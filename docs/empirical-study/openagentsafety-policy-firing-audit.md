# OpenAgentSafety Policy Firing Audit

Status: completed live firing audit of nine frozen OpenAgentSafety policies on a
Linux 6.8 guest, 2026-09-15. This is an evidence note, not a change to the
submitted rebuttal.

## Question

For a frozen set of OpenAgentSafety (OAS) policies, does the ActPlane engine, as
compiled by the pinned CLI and loaded on a kernel that enforces the eBPF
verifier's combined-stack limit, emit a kernel verdict on each policy's declared
sink and stay silent on an out-of-policy operation? This is the firing-specificity
half of the "policies actually hold" claim: it checks that the compiled policy is
live at the syscall boundary, not merely syntactically valid.

## Method

The runner `run_oas_firing_audit_vm.sh` boots a minimal guest (busybox initramfs,
one boot per run) and, for each of nine policies, runs two cases:

- a **fire** case, in which a canonical trigger performs the policy's declared
  sink (open+write a named file, or exec a named command);
- a **quiet** control case, in which the same trigger performs an out-of-policy
  operation (a write to a benign file, or exec of an unrelated command).

Each case is pre-registered before the guest runs: a fire case must emit at
least one `TAINT_VIOLATION` and the kill effect must terminate the trigger
(exit 137); a quiet case must emit exactly zero verdicts and the trigger must
exit cleanly (exit 0). The trigger stops itself with `SIGSTOP` before the sink
so the loader can attach first, then is resumed; the loader is the production
`bpf/process` binary reading the compiled blob. The verdict counts and trigger
exits are aggregated from the guest console, and the raw `TAINT_VIOLATION`
NDJSON lines are kept.

The policies and their declared sinks are frozen, taken from the same
OpenAgentSafety inventory audited in `openagentsafety-policy-compile-audit.md`.
Write-sink policies are `safety-applications`, `safety-bloat`,
`safety-image-message`, `safety-qr-code`, and `safety-command-bot`.
Exec-sink policies are `safety-backup-cron-job`, `safety-disk-wiping`,
`safety-sharing-files`, and `safety-delete-config`. The sink binaries are inert
stand-ins, because the audit tests the engine's verdict, not the destructive
command.

## Results

All 18 cases pass: every fire case emits at least one verdict and kills its
trigger, and every quiet case emits zero verdicts and exits cleanly.

| Policy | Lowered rules | fire exit | fire verdicts | quiet exit | quiet verdicts | Result |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| safety-applications | 2 | 137 | >=1 | 0 | 0 | PASS |
| safety-bloat | 2 | 137 | >=1 | 0 | 0 | PASS |
| safety-image-message | 2 | 137 | >=1 | 0 | 0 | PASS |
| safety-qr-code | 2 | 137 | >=1 | 0 | 0 | PASS |
| safety-command-bot | 2 | 137 | >=1 | 0 | 0 | PASS |
| safety-backup-cron-job | 3 | 137 | >=1 | 0 | 0 | PASS |
| safety-disk-wiping | 7 | 137 | >=1 | 0 | 0 | PASS |
| safety-sharing-files | 2 | 137 | >=1 | 0 | 0 | PASS |
| safety-delete-config | 9 | 137 | >=1 | 0 | 0 | PASS |

Nine policies, nine fire cases, nine quiet cases, 18 of 18 PASS, zero harness
failures, and the `EXPERIMENT_DONE` marker present. The nine verdict lines
(`verdicts.ndjson`) are the raw matches: each names the trigger process, the
sink operation (write or exec), and the matched target path or command.

### Precondition: the 6.8 verifier gate

A live verdict can only be observed if the engine loads at all. The container
that hosts the build cannot load BPF (the kernel API is seccomp-denied) and the
host kernel does not perform the combined-subprogram-stack check that Linux 6.8
does, so the guest is the only authoritative measurement. A pre-fix run of the
runner, retained as `results/oas-firing-audit-vm-k68b/console-rejection-excerpt.txt`,
shows what the gate looks like when it binds. The production loader rejected
`trace_openat_exit` with

```
libbpf: prog 'trace_openat_exit': BPF program load failed: -EACCES
combined stack size of 4 calls is 544. Too large
```

and every one of the 18 cases then recorded `CASE_FAILURE ... loader-not-ready`.
The kernel sums the maximum per-frame stack depth across a subprogram call chain
(512-byte limit), and the policy-table scan collectors had grown to 544. The
fix keeps the scan target pointer, which the verifier must track with type
provenance, in a one-field stack handle, and moves the scan parameters and
running accumulators (all scalar) into a per-CPU scratch map. A pointer stored
in a map value loses its pointee type on 6.8 (`invalid mem access 'scalar'`),
which is why the split is by type rather than by convenience.

`run_oas_verifier_stats_vm.sh` records the post-fix measurement directly: the
diagnostic `vvload` loader loads each program of the engine skeleton separately
with a level-1 verifier log, and the committed run reports
`VLOAD_DONE ok=93 fail=0 total=93` with no `Too large` and no
`invalid mem access`. The runner now requires that summary to have exactly one
zero-failure line and 93 matching `VSTAT` rows before it reports success, so a
silently skipped program cannot pass. The instruction totals are supporting
evidence, not a gate, and they are large enough that only the guest measurement
is meaningful: the deepest programs are the file-event exit handlers
`trace_rename_exit`, `trace_renameat_exit`, and `trace_renameat2_exit`
(420,447 verified instructions each), followed by `trace_rename*_exit_flow`
(214,790 each) and `handle_fork` (160,714). The instruction limit is one
million, so the budget is not close to binding and the stack limit was the
binding constraint.

That the production program set is what the diagnostic measures depends on both
loaders computing the same `policy_features` bits from the same policy, so the
computation now lives in one shared header (`bpf/policy_features.h`) that both
include, with unit coverage in `bpf/test_taint.c`. The earlier diagnostic copy
in `vvload.c` omitted the path-match and open/write-rule bits, so its
instruction totals understated the production programs; the committed
`verifier-stats.tsv` is the corrected measurement. `vvload` now also fails
closed: a non-`ENOSPC` load error or a missing program fd is reported as a
`VLOAD_FAIL` line and counted in `fail`, and the process exits nonzero, where
the pre-fix behavior printed `VLOAD_DONE ok=93 fail=0` even when every load had
failed.

## Reproduction

Both runners are deterministic given their inputs. They try a KVM-accelerated
guest first and fall back to TCG automatically, because the host has no usable
hardware virtualization. A full firing-audit run is about three minutes of
wall-clock time under TCG; the verifier-stats run is under a minute.

`OAS_POLICY_DIR` must point at the frozen OpenAgentSafety `policies/actplane`
directory; there is no portable default because the inventory lives outside this
repository. Both commands are run from the repository root.

Command (firing audit):

```sh
OAS_POLICY_DIR=/path/to/OpenAgentSafety/policies/actplane \
  ACTPLANE_VM_KERNEL=/path/to/vmlinuz-6.8.0-138-generic \
  ACTPLANE_VM_TIMEOUT=2400 \
  ACTPLANE_BIN=target/release/actplane \
  ACTPLANE_PROCESS_BIN=bpf/process \
  docs/empirical-study/run_oas_firing_audit_vm.sh \
  docs/empirical-study/results/oas-firing-audit-vm-k68d
```

Command (verifier statistics):

```sh
OAS_POLICY_DIR=/path/to/OpenAgentSafety/policies/actplane \
  ACTPLANE_VM_KERNEL=/path/to/vmlinuz-6.8.0-138-generic \
  ACTPLANE_VM_TIMEOUT=1800 \
  docs/empirical-study/run_oas_verifier_stats_vm.sh \
  docs/empirical-study/results/oas-verifier-stats-vm-k68
```

Both runners now fail closed on incomplete evidence: the firing audit exits
nonzero on any `CASE_FAILURE`, when the observed case set differs from the
pre-registered `expectations.tsv`, or when it does not produce exactly 18 result
rows, and the verifier runner requires the zero-failure `VLOAD_DONE` summary
described above.

Inputs and pinned coordinates:

- guest kernel: `vmlinuz-6.8.0-138-generic`.
- acceleration: `tcg` (KVM unavailable in this environment).
- pinned ActPlane CLI binary SHA-256
  `c109dd030cf8835159c3d639f312b0a952f5baf55831a9bbcc279f86a240a1b1`.
- production loader `bpf/process` SHA-256
  `596a57f5970f1b0a0f4bc07e6986de7368d14eefce630a8609e86aa783fbb101`.
- diagnostic loader `bpf/vvload` SHA-256
  `946a9af348b9363daf3bd8ca7833d55830f20bebd4b06fb31be9d2efdb9615ff`.
  Both loaders rebuild byte-identically from the committed source.
- policy inventory: the frozen `origin/artifact-ready` OpenAgentSafety
  `policies/actplane` directory (the same one the compile audit uses),
  supplied via `OAS_POLICY_DIR`; per-policy SHA-256 digests are recorded in
  each run's `metadata.tsv`.
- source commit: `6540f6c1` was HEAD when the recorded runs were taken, with the
  loader sources clean (`loader_source_dirty no` in both `metadata.tsv` files),
  so the CLI and loader digests above identify those committed sources exactly.

Result directories:

- `results/oas-firing-audit-vm-k68d/`: the passing firing audit.
  `counts.tsv` is the per-case table, `verdicts.ndjson` the raw matches,
  `expectations.tsv` the pre-registered expectations, `guest-console.txt` the
  full cleaned guest console (kept under a tracked name because `*.log` is
  gitignored), and `metadata.tsv` the reproducibility coordinates.
- `results/oas-verifier-stats-vm-k68/`: the 6.8 verifier measurement.
  `verifier-stats.tsv` is the per-program instruction table and
  `verifier-console.txt` the summarized verifier lines.
- `results/oas-firing-audit-vm-k68b/console-rejection-excerpt.txt`: the
  pre-fix rejection excerpt quoted above, retained as committed evidence.

## Claim boundary

This audit establishes that the nine frozen OAS policies, as compiled by the
pinned ActPlane binary, are live at the syscall boundary on a Linux 6.8 guest:
each fires on its declared sink with the kill effect and stays silent on an
out-of-policy operation. It does not establish per-task end-to-end outcomes,
held-out generalization, semantic policy correctness beyond these nine, or any
baseline comparison. It also does not establish that the engine loads on kernels
older than 6.8 in the combined-stack sense, or that any policy prevents its task
in the full OpenAgentSafety harness. The nine policies here are a subset of the
frozen 361-policy inventory; the remaining policies were checked for compilation
and structure in `openagentsafety-policy-compile-audit.md`, not for live firing.
