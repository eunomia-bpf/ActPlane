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
