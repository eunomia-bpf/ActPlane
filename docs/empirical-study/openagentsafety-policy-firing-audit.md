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
does, so the guest is the only authoritative measurement. An earlier iteration
of the engine was rejected on 6.8 with

```
combined stack size of 4 calls is 544. Too large
```

because 6.8 sums the maximum per-frame stack depth across a subprogram call
chain, and the policy-table scan collectors had grown deep. The fix keeps the
scan target pointer, which the verifier must track with type provenance, in a
one-field stack handle, and moves the scan parameters and running accumulators
(all scalar) into a per-CPU scratch map. A pointer stored in a map value loses
its pointee type on 6.8 (`invalid mem access 'scalar'`), which is why the split
is by type rather than by convenience. The resulting global maximum frame chain
is 480 bytes, below the 512-byte limit.

`run_oas_verifier_stats_vm.sh` records the same measurement directly: the
diagnostic `vvload` loader loads each program of the engine skeleton separately
with a level-1 verifier log, and the run confirms all 93 programs load with no
`Too large` and no `invalid mem access`. The instruction totals are supporting
evidence, not a gate. The largest programs are `handle_fork` (160,714 verified
instructions) and the file-event exit handlers `trace_rename_exit`,
`trace_renameat_exit`, and `trace_renameat2_exit` (82,476 each). The instruction
limit is one million, so the budget is not close to binding; the stack limit was
the binding constraint.

## Reproduction

Both runners are deterministic given their inputs. They try a KVM-accelerated
guest first and fall back to TCG automatically, because the host has no usable
hardware virtualization. A full firing-audit run is about three minutes of
wall-clock time under TCG; the verifier-stats run is under a minute.

Command (firing audit, from the repository root):

```sh
ACTPLANE_VM_KERNEL=/path/to/vmlinuz-6.8.0-138-generic \
  ACTPLANE_VM_TIMEOUT=2400 \
  ACTPLANE_BIN=target/release/actplane \
  ACTPLANE_PROCESS_BIN=bpf/process \
  docs/empirical-study/run_oas_firing_audit_vm.sh \
  docs/empirical-study/results/oas-firing-audit-vm-k68d
```

Command (verifier statistics):

```sh
ACTPLANE_VM_KERNEL=/path/to/vmlinuz-6.8.0-138-generic \
  ACTPLANE_VM_TIMEOUT=1800 \
  docs/empirical-study/run_oas_verifier_stats_vm.sh \
  docs/empirical-study/results/oas-verifier-stats-vm-k68
```

Inputs and pinned coordinates:

- guest kernel: `vmlinuz-6.8.0-138-generic`.
- acceleration: `tcg` (KVM unavailable in this environment).
- pinned ActPlane CLI binary SHA-256
  `c109dd030cf8835159c3d639f312b0a952f5baf55831a9bbcc279f86a240a1b1`.
- production loader `bpf/process` SHA-256
  `2012be0c8ad550ef4777eceddbba8e1142fc60d3b149e45e0c79fdcfcee31681`.
- diagnostic loader `bpf/vvload` SHA-256
  `6350aca9fcad90868465542d769201f4b77601d4bfd13ab5c7c34d06748a4a89`.
- policy inventory: the frozen `origin/artifact-ready` OpenAgentSafety
  `policies/actplane` directory (the same one the compile audit uses); per-policy
  SHA-256 digests are recorded in each run's `metadata.tsv`.
- source commit: `73a715537314e8676b8c6e8bd3d11e19f5d69530`.

Result directories:

- `results/oas-firing-audit-vm-k68d/`: the passing firing audit.
  `counts.tsv` is the per-case table, `verdicts.ndjson` the raw matches,
  `expectations.tsv` the pre-registered expectations, and `metadata.tsv` the
  reproducibility coordinates. `console.clean.log` is the full guest console.
- `results/oas-verifier-stats-vm-k68/`: the 6.8 verifier measurement.
  `verifier-stats.tsv` is the per-program instruction table and
  `verifier-console.txt` the summarized verifier lines.

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
