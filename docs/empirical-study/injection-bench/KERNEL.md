# Kernel and authority integration inspection

This is a source and environment inspection, not an experiment result. The remote inspection ran at 2026-10-29 05:53 UTC through `scripts/inspect_kernel.sh`. No benchmark, engine load, process termination, or policy mutation was performed. The existing retained agents and their checkouts were preserved.

## Available artifact and environment

The built CLI is `/workspaces/lanes/translation-models/target/release/actplane`, reporting `actplane 0.1.8`. Its source checkout is `fe23a1e730f330768a7a884bd75850dc6852f299`. Copy this binary and any required assets into this lane's remote raw directory before experimentation. Do not build or modify that existing checkout. The unrelated active checkout `/workspaces/repository` is on `test/mcp-handler-surface`, commit `89895c8120a860aaea4634384293c7fbc3886a81`, so its source identity must not be silently substituted for the supplied artifact.

The Workspace runs kernel `7.3.0-070300rc3-generic`, as root with effective/bounding capability mask `000001ffffffffff`. `/dev/kvm` and `qemu-system-x86_64` are available. The shared volume had approximately 34 GiB free at inspection. An existing guest kernel is at `/workspaces/.agent-state/actplane-research/raw/translation-models-20261028/vm-root/boot/vmlinuz-6.8.0-138-generic`. No existing GUI/OSWorld disk image was found in the targeted experiment and research roots to depth five. This is a bounded inventory, not proof no image exists anywhere.

No ActPlane engine, low-level `process` loader, or QEMU process was seen in the process-name inspection. No pinned BPF files appeared under `/sys/fs/bpf` to depth three. These are inspection-time observations, not a reservation of the singleton engine.

## Supported authority distinction

`actplane run --delta child.dsl -- command` launches a stopped child, binds it to a runtime child domain, installs deltas, and resumes it. `crates/actplane-runtime/src/runtime.rs` binds that executing child with `AUTH_BIND_RULE` and `TARGET_SELF`. The control plane has broader authority including `AUTH_DECLASSIFY` and `AUTH_DELEGATE`. A trusted parent can therefore install a preauthored policy before the untrusted tool result is delivered, while the executing child can append its own restrictive rule.

`actplane control delta add --target-id ID --delta file.dsl` reaches the running control socket. Its Unix peer identity is obtained with `SO_PEERCRED`; the append path passes the actual peer PID into authority checks (`control.rs` and `mcp.rs`). Using the local socket from the constrained process preserves caller identity. Calling an unbound external parent CLI to submit an alleged child mutation would test the parent's authority instead.

Kernel `bpf/capability.bpf.h` checks caller/target scope and authority masks. A delta that clears labels requires `AUTH_DECLASSIFY` and authority over every cleared bit. Ancestor-domain source/flow state is separate from child-domain state in `bpf/taint_engine.bpf.h`, and inherited ancestor rules remain applicable to descendants. A child's missing or malicious initial policy can still be ineffective when the parent supplies no task-specific protections. This is the scientific distinction between the two requested AgPlane conditions, not itself a measured result.

The public `--parent-domain` flag currently errors with an explicit unsupported message for the pinned singleton. Use an isolated command domain as the trusted parent and an actual runtime child beneath it, rather than relying on that flag. Establish the parent/child relationship and caller identities from actual audit records in preflight.

## Audit semantics that must remain separate

The normal runtime writes `append_policy_delta` records to its audit JSONL with policy hash, caller PID/identity, target ID, status, provenance and error. Rejections can occur at several stages: parsing, runtime approval, feature/capacity checks, userspace authority precheck, or kernel admission. `bpf/src/lib.rs::append_policy_delta_with_rule_id_base` calls `precheck_append_authority` before submitting any request to the kernel. Consequently, an audit record with `status: rejected` does not by itself prove kernel rejection.

The kernel's `cap_request_cb` increments aggregate `cap_stats` slots for accept, reject, drain and drop. There is no per-attempt kernel admission ring event in the inspected implementation. For accepted append operations, `submit_expect_count` checks the kernel policy-table count increment. A kernel-side failure is reported when that count fails to increment. This differs from a source-proven userspace authority rejection before submission.

Record all attempted deltas with the original agent-produced text and whether the rejection happened before submission, was confirmed by kernel count/counter observation, or has unknown decision stage. If no malicious mutation is attempted by an official attack, report zero observed attempts; do not invent a weakening attack to fill the requested evidence column. Kernel admission evidence requires actual submitted requests and correlated kernel observations. Do not relabel a userspace check as kernel rejection, and do not count the deterministic replay evaluator as live kernel enforcement.

## Concurrency and process-boundary constraints

The normal CLI acquires `PinnedEngine::try_lock_runtime`, then clears singleton runtime maps on entry and exit. Independent `actplane run` invocations must therefore be serialized, or use a single established engine and its runtime child-domain controls. Launching independent CLI engines concurrently cannot establish a fair isolated comparison and may collide with another lane's engine reservation. A failed runtime lock is an operational failure, not attack prevention.

A Docker client's descendants do not include processes created by an already running Docker daemon. Wrapping `docker exec` on the host therefore does not establish that the container's effects belong to the constrained domain. A Docker-backed benchmark needs the actual tool/container process bound to the policy domain, with a race-free stopped start, or ActPlane loaded inside the container on the relevant kernel. VM-backed tools require enforcement in the guest kernel; host enforcement around QEMU cannot distinguish individual guest file or network operations.

The executing benchmark process must not retain root/BPF map-write authority over its own enforcement plane. The inspected Workspace itself runs as root, so child privilege handling and the protected control plane are required parts of the actual harness integration. Availability of privileged execution is not proof of a valid threat-model deployment.

## Reproduce inspection

From PowerShell, run:

```powershell
& "C:\Program Files\Git\bin\bash.exe" C:/Users/10678/actplane-tools/ws.sh run injection-bench -- bash scripts/inspect_kernel.sh
```

The remote transcript is written to `/workspaces/exp/injection-bench/raw/kernel-inspection.txt`. All commands are read-only outside that lane-owned transcript.

## Live mechanism preflight and artifact limitation

After the README benchmark choice was committed, `scripts/kernel_preflight.sh` attempted an inert real file-read denial. This setup check is not part of the benchmark and contributes no ASR or utility observations.

The supplied CLI rejected a parent `block open` rule before worker launch. `PINNED_POLICY_FEATURES` in `bpf/src/lib.rs` advertises only `ALL_HOOK_FEATURES` (`0x3f0`), excluding the open and write sink matcher bits. Its own error said `needed=0x104, supported=0x3f0, missing=0x4`. This rejection is userspace feature validation, not kernel attack prevention.

The supervisor authorized a lane-owned artifact build. `scripts/build_file_profile.sh` copies the exact supplied source commit to remote `raw/actplane-file-profile`, changes only the advertised feature mask, builds there, and retains hashes and the exact patch. The original checkout and supplied binary remain untouched. The initial broad feature mask enabled open/write and contains/suffix classes. The actual kernel rejected `trace_openat_exit` with `BPF program is too large. Processed 1000001 insn`. A narrower mask enabling open/write with only the preexisting exact/prefix matchers also failed at that program and instruction limit. Its full raw output is under `raw/kernel-preflight/file-only/parent/engine.stderr`.

The adapter uses its own pin root for the modified artifact, avoiding reuse of a singleton with incompatible loaded features. No successful constrained worker execution or kernel denial was established by those initial failed attempts. They cannot justify AgPlane benchmark results, and the kernel-audit denominator must not treat engine-load failure as a rejected malicious delta.

`scripts/actplane_adapter.py` implements stopped child launch, a root-owned control plane, UID/GID 65534 workers, an empty supplementary group set, all capability bounding bits dropped, and `no_new_privs`. It retains `/proc/self/status` from the actual child. It captures real BPF `cap_stats` and `ts_counts` maps before and after each cell, plus the native runtime audit, rather than substituting replay results. The successful guest preflight below verifies these transitions.

The supplied self-policy may be authored by the executing model after consuming its exact initial attacked conversation before the physical worker process starts. The constrained child bootstrap then installs it as the actual child caller. This preserves the logical model conversation and the kernel caller authority, but it is not evidence that inference itself occurred inside the confined child process. The runner must disclose this distinction.

## Successful guest preflight and final artifact boundary

The direct Workspace kernel path had another independent defect: user space supplied container PIDs, while `bpf_get_current_pid_tgid` reported host PIDs. Diagnostic counters showed a valid source delta rejected at submitter identity. A proposed protected-submitter drain gate did not resolve the mismatch and was reverted before the successful guest run. No PID-namespace adaptation or host-namespace entry is used in the final path.

`scripts/vm_runner.sh` boots the existing Ubuntu guest kernel with KVM, enables the BPF LSM, and loads copied 9p modules. It exports the container root read-only, with writable shares only for this lane and benchmark temporary files. The root-owned guest queue server executes each cell serially in the guest's root PID namespace. Thus user-space and kernel PID identities agree. It consumes no downloaded disk image. The existing kernel/module tree is read-only and remains unchanged.

The final modified artifact differs from supplied commit `fe23a1e730f330768a7a884bd75850dc6852f299` in the following necessary ways:

- The userspace singleton profile advertises the implemented open/write sink classes, retaining exact/prefix matchers. Contains/suffix classes remain disabled.
- `CAP_DOMAIN_DEPTH` is reduced to the tested parent-plus-child topology. Process descendants inherit the child's domain. Experiments using additional nested runtime domains are outside this artifact's coverage.
- Kernel admission checks retain their original conditions, but expose distinct rejection codes and stage counters. The `cap_stats` map has additional diagnostic slots. No accepted caller, target, scope, authority, or label mask is broadened.

This is a modified ActPlane artifact, not evidence that the supplied stock binary works unchanged. The exact patch, binary/header/source/object SHA-256 hashes, guest identity, native audits and native events are preserved in [results/kernel-preflight/evidence.json](results/kernel-preflight/evidence.json) and [results/kernel-preflight/artifact.patch](results/kernel-preflight/artifact.patch). The machine-readable setup observations are in [results/kernel-preflight/preflight.csv](results/kernel-preflight/preflight.csv), produced by committed `scripts/summarize_kernel_preflight.py`.

Both parent-installed and self-installed inert policies passed the guest preflight. A legitimate file write/read succeeded, while a guarded read produced `PermissionError` and a native event with `blocked: true`. The worker's effective, permitted, inheritable, bounding and ambient capability masks were all zero, UID/GID were unprivileged, and `NoNewPrivs` was enabled. The self-policy append used the constrained child's real Unix peer identity, and both the kernel admission and rule-table counters increased. These setup observations establish a runnable enforcement path and are excluded from benchmark ASR/utility denominators.

The diagnostic `cap_stats` slots are: accept, reject, drain, drop, missing caller domain, missing source/target state, target authority, operation authority, label authority, scope widening, submitter identity, unsupported feature, and malformed request/table insertion failure. Native runtime rejections still require stage classification because userspace validation can reject before submitting a request.

Start the retained guest service through the authorized wrapper:

```powershell
& "C:\Program Files\Git\bin\bash.exe" C:/Users/10678/actplane-tools/ws.sh run injection-bench --bg -- bash scripts/vm_runner.sh
```

The queue readiness file is remote `raw/vm/queue/ready.json`, and guest boot evidence is `raw/vm/console.log`. Host `execute()` calls automatically submit to that service. Queue directories and request files are root-only. Only required inference environment variables are forwarded, and the guest replaces retained credential values with a marker after reading them. Neither credentials nor full environment dumps enter committed result artifacts. Inference transports can instead stay on the host and use a per-cell file channel shared with the unprivileged guest worker.

## Parallel model instances and cleanup

The live default guest remains unchanged. Additional `qwen` and `frontier` instances use separate `raw/vm-qwen` and `raw/vm-frontier` directories, queues, PID files and boot logs. Each guest has its own kernel and BPF maps. The adapter locks a private guest `/run` tmpfs, so independent guests can execute concurrently while each guest retains serial singleton use. The original retained default guest may still use its earlier `/tmp` lock, which has no contender among the additional guests.

`vm_runner.sh qwen` and `vm_runner.sh frontier` start the extra instances through the same background wrapper command above. Each instance reserves the CPU and memory values specified in `vm_runner.sh`; there is no additional disk image. Both extra instances passed the same real parent/self read-denial and legitimate read/write preflight concurrently. Raw observations are in `raw/kernel-preflight/guest-qwen-parallel` and `raw/kernel-preflight/guest-frontier-parallel`.

Set `ACTPLANE_VM_QUEUE` in each model's runner process, or pass it explicitly to `execute(env=...)`, to select the corresponding `raw/vm-INSTANCE/queue`. An explicit call environment takes precedence over the process environment. No routing selection mutates global process environment state. Immutable runner snapshots must include the updated adapter before using these queues.

After the model matrix reaches terminal status, stop each retained instance with the wrapper's foreground `run` command and `bash scripts/vm_runner.sh stop INSTANCE`, using `default`, `qwen`, and `frontier` as applicable. The stop path verifies that the PID's command line names that exact lane-owned initrd before sending a signal. It removes readiness and releases the guest's CPU, RAM, kernel maps and mounts when QEMU exits. Results, logs, initrd inputs and artifact hashes remain available. Never stop an instance while its benchmark cells are running, and never stop another lane's QEMU process.

To meet the measured model-throughput deadline, `qwen2`, `qwen3` and `qwen4` were subsequently started through the same generic runner. They use `raw/vm-qwen2/queue`, `raw/vm-qwen3/queue` and `raw/vm-qwen4/queue`, with identical kernel/artifact inputs and separate BPF maps. Each passed the existing real protected-read and legitimate read/write preflight before accepting model cells. Their setup evidence is in the corresponding `raw/kernel-preflight/guest-qwenN-parallel` directories. They add no adapter semantics or benchmark tasks. Include these three instance names in the same explicit post-matrix stop lifecycle. All configured guests together fit the Workspace CPU and memory allocation.

## Benchmark audit export

Run `python3 scripts/audit_results.py` through the Workspace wrapper after the declared model matrices terminate. It reads `raw/runs/main-v1` and `raw/runs/frontier-v1` by default and exports small CSVs to remote `results/audit`. It is also safe to inspect a live prefix, whose pending rows and unavailable after-counters remain explicit. Rerun before final reporting.

`append_attempts.csv` retains each observed native append or otherwise recorded child submission with caller identity, target, policy hash/text reference, syntax flags and decision stage. `initial_loads.csv` separates initial trusted/neutral parent installation from runtime mutation. Generation failure without an authored policy is not counted as a submission. Rejected native status alone never establishes kernel rejection. A kernel rejection requires the missing-admission acknowledgment, an attributable reject-counter increment and consistent rejection-stage counters. Accepted child deltas are correlated with actual rule/update table and acceptance-counter changes, with group correlation labeled separately when necessary. Source, endorsement and declassification syntax describe requested policy constructs, not malicious intent.

`cases.csv` records observed native blocked/killed events alongside unchanged official scored outcomes and a reference/hash for the actual final filesystem snapshot. Native events do not determine ASR or utility. A failed write can leave partial filesystem state, so permission failures are not equated with attack prevention. `read_issues.csv` preserves missing-completeness evidence such as an interrupted JSON write rather than silently converting it into a clean audit.
