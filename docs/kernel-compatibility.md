# Kernel Compatibility

ActPlane has two embedded CO-RE objects because the full runtime relies on
kernel interfaces that are not present in Linux 5.10.

| Kernel | Engine path | Supported commands |
| --- | --- | --- |
| Earlier than 5.10 | Rejected before load | `compile` only |
| 5.10 through 6.0 | Direct compatibility loader | `compile`, static `run` |
| 6.1 and newer | Pinned singleton loader | Full CLI, MCP, watch, attach, and runtime deltas |

## Linux 5.10 Policy Boundary

The compatibility engine is deliberately narrower than the modern engine. It
supports:

- exec sources with exact or any matching
- exec sink rules with exact or any matching
- `notify` and `kill` effects
- up to 64 lowered updates and 32 lowered rules

It rejects file and network operations, prefix/suffix/contains exec matching,
`@arg`, rule conditions, `block`, runtime domains, and policy deltas. Violation
events retain the rule reason, target, process identity, effect, and matched
label set, but omit the per-label provenance payload.

These checks happen in userspace before BPF load. Unsupported policies do not
silently run with reduced semantics.

## Compatibility Design

Linux 5.10 predates `BPF_MAP_TYPE_USER_RINGBUF` and the `bpf_loop` helper used
by the singleton engine. It also accounts BPF maps and programs against
`RLIMIT_MEMLOCK`, and it cannot pin the perf-event BPF links used by the
singleton lifecycle.

The compatibility object therefore:

- replaces `bpf_loop` with verifier-visible bounded loops
- stores static rule/update counts in loader-patched read-only globals
- replaces the capability request user ring buffer with an unused array map
- uses an exec-only, global-domain pipeline with bounded exact matching
- ignores modern hook-reservation environment variables so its attach set
  remains within the older verifier's limits
- attaches directly for the lifetime of `actplane run`, without pinned links
- raises `RLIMIT_MEMLOCK` before creating maps

The modern object and singleton behavior are unchanged on Linux 6.1 and newer.
Concurrent compatibility runs use isolated maps, but each run attaches a
separate tracepoint set and adds per-event overhead.

Raising a finite hard limit requires root or `CAP_SYS_RESOURCE`. A
capability-only deployment using `CAP_BPF` and `CAP_SYS_ADMIN` must also grant
`CAP_SYS_RESOURCE` or start ActPlane with an unlimited memlock limit.

## Reproducing The KVM Test

The validated source is the upstream stable kernel repository at tag
`v5.10.260`, commit `738ac465e4e900d4a391a27da4e20c090eaa1e75`. The validation host used
virtme-ng 1.40 and QEMU 9.2.2.

```bash
git clone --depth 1 --branch v5.10.260 \
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-5.10

script/test-kernel-5.10.sh /path/to/linux-5.10
```

If `arch/x86/boot/bzImage` is absent, the script first builds the kernel with
the required BPF, BTF, tracing, securityfs, and BPF-LSM options. It then builds
ActPlane on the host, boots the kernel with KVM, and verifies all of the
following inside the guest:

- the running release starts with `5.10.`
- `/sys/kernel/btf/vmlinux` is readable
- the `bpf` LSM is active and the compatibility LSM programs verify and attach
- a host-built ActPlane binary loads without a manual memlock adjustment
- an exec source and notify sink produce the expected violation reason
- modern hook-reservation environment variables cannot widen the compatibility
  attach set

Set `ACTPLANE_REBUILD_KERNEL=1` to force a kernel rebuild through
virtme-ng's existing configuration and build flow. Set `ACTPLANE_KVM_TIMEOUT`
to override the 120-second host-side boot and smoke-test timeout.
