# Kernel Compatibility

ActPlane has two embedded CO-RE objects because the full runtime relies on
kernel interfaces that are not present in Linux 5.10.

| Kernel | Engine path | Supported commands |
| --- | --- | --- |
| Earlier than 5.10 | Rejected before load | `compile` only |
| 5.10 through 6.0 | Direct compatibility loader | `compile`, static `run` |
| 6.1 and newer | Pinned singleton loader | Full CLI, MCP, watch, attach, and runtime deltas |

## Linux 5.10 Policy Boundary

The compatibility engine is static and global-domain, but preserves the main
policy semantics:

- exec sources, transforms, argv-token rules, glob matchers, and conditions
- path-based file sources, reads/writes, open/write sinks, rename label moves,
  freshness gates, and exact/prefix/suffix/contains matchers
- numeric IPv4 connect/recv sources, sinks, conditions, and endpoint flow
- `notify` and `kill` for exec, file, connect, and recv events
- BPF-LSM `block` for exec without `@arg`, connect, and connected IPv4 recv
- per-label provenance across process, file, and endpoint propagation
- up to 64 lowered updates and 32 lowered rules

The older-kernel path remains narrower than the modern engine. It does not
provide runtime domains, policy deltas, pinned singleton lifecycle, MCP/watch/
attach runtime integration, or advanced fd/mmap/IPC tracking. File flow is
path-hash based and committed only after a successful open or mutation, so it does
not provide modern inode/fd precision for already-open descriptors, fd passing,
sendfile/splice/copy_file_range, mmap permission changes, or Unix-socket IPC.
Unconnected recv cannot be blocked before the kernel reveals its peer, and
file `block` remains a 6.1+ feature because Linux 5.10 cannot safely resolve all
file paths in the required pre-operation LSM hooks. `block exec` with `@arg`
remains unsupported because argv is only available in the post-exec tracepoint.
Relative paths remain relative and should not be used to satisfy an absolute
exact-path policy. Compatibility-mode file matching also uses the pathname
spelling supplied to the syscall and does not canonicalize symlink aliases.

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
- uses separate verifier-bounded exec, path-based file, and numeric IPv4
  pipelines in the global domain
- ignores modern hook-reservation environment variables so its attach set
  remains within the older verifier's limits
- attaches directly for the lifetime of `actplane run`, without pinned links
- raises `RLIMIT_MEMLOCK` before creating maps

The modern object and singleton behavior are unchanged on Linux 6.1 and newer.
Concurrent compatibility runs use isolated maps, but each run attaches a
separate tracepoint set and adds per-event overhead.

On Linux 5.10, raising a finite hard limit requires root or `CAP_SYS_RESOURCE`.
A capability-only deployment must also grant `CAP_SYS_RESOURCE` or start
ActPlane with an unlimited memlock limit. Linux 5.11 and newer use memcg
accounting, so a failed best-effort memlock raise does not prevent loading.

## Reproducing The KVM Test

The validated source is the upstream stable kernel repository at tag
`v5.10.260`. The test uses virtme-ng/KVM and builds the ActPlane userspace
binary on the host.

```bash
git clone --depth 1 --branch v5.10.260 \
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-5.10

script/test-kernel-5.10.sh /path/to/linux-5.10
```

If `arch/x86/boot/bzImage` is absent, the script first builds the kernel with
the required BPF, BTF, tracing, securityfs, and BPF-LSM options. It then builds
ActPlane on the host, then boots a fresh KVM guest for every named feature case.
The matrix verifies all of the following inside the guests:

- the running release starts with `5.10.`
- `/sys/kernel/btf/vmlinux` is readable
- the `bpf` LSM is active and the compatibility LSM programs verify and attach
- a host-built ActPlane binary loads without a manual memlock adjustment
- exec, file, and network sources and transitive propagation
- argv, glob, lineage, after, target, freshness, and declassification behavior
- per-label provenance across file and endpoint hops
- `notify`, `kill`, and real `EPERM` from every supported block hook class
- truncate, unlink, rename, rename label migration, and failed-operation rollback
- explicit rejection of file `block` and unrepresentable endpoint patterns,
  plus high-numbered connected sockets, fd replacement, `FD_CLOEXEC` reuse,
  and non-socket reads

Each report must contain exactly the expected reason count and exit status.
Successful runs require `actplane_rc=0`, while rejection cases require the
documented nonzero status and error. A verifier error, missing hook, extra
match, or runner failure fails the case.

Set `ACTPLANE_REBUILD_KERNEL=1` to force a kernel rebuild through
virtme-ng's existing configuration and build flow. Set `ACTPLANE_KVM_TIMEOUT`
to override the 120-second host-side boot and smoke-test timeout.
