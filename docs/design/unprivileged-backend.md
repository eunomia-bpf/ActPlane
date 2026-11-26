# Unprivileged Enforcement Backend (Landlock + seccomp)

Status: step 1 (the static tier) is implemented in `crates/actplane-sandbox`
and exposed as `--backend unprivileged` on `actplane run` and
`actplane compile`. Steps 2 and 3 are future work and are described here so
that step 1 stays consistent with them.

## Request

The operator asked (verbatim, 2026-11-25):

> 给 actplane 看看是不是可以没有 priviledge 的情况下用 lanlock 或者 seccomp? 你想想现在这样合适吗? 具体怎么设计?

## Why a second backend

ActPlane compiles its policy language to one eBPF engine: 14 BPF-LSM hooks give
pre-operation `block`, and about 80 syscall tracepoints drive label
propagation, `kill`, and `notify` (`bpf/process.bpf.c`,
`docs/security_model.md`). Loading that engine needs root, or `CAP_BPF` +
`CAP_PERFMON` + `CAP_SYS_ADMIN`, and pre-op `block` needs a kernel booted with
`lsm=bpf`. Most laptops, containers, and CI runners have neither, so ActPlane is
unusable exactly where many agents run.

The eBPF design is still the right default. It is the only design that adopts an
already-running process (`cap_task`), tracks labels across every process and
file on the host in kernel, and enforces argv-sensitive and temporal rules
without a user-space round trip. The decision is therefore:

- Keep the BPF-LSM backend as the precise, privileged, default backend.
- Add a second backend, `unprivileged`, that shares the same parser, AST, and
  validation (`crates/actplane-ifc-compiler`), and enforces with interfaces an
  ordinary user may apply to its own children: Landlock and seccomp.
- A clause the second backend cannot enforce exactly makes the whole policy fail
  closed, with a per-clause explanation. No clause is downgraded to a weaker
  effect, and no clause is silently dropped.

## Architecture

```
actplane.yaml ─▶ parse + validate (actplane-ifc-compiler, unchanged)
                     │
                     ├─▶ bpf-lsm backend: lower ─▶ taint_config ─▶ eBPF engine
                     │
                     └─▶ unprivileged backend (actplane-sandbox)
                           analyze clauses ─▶ SandboxSpec (exact clauses only)
                           (a) static tier: Landlock + seccomp, applied by the launcher
                           (b) supervisor tier: seccomp user-notify (step 2)
```

The `unprivileged` backend has two tiers.

**(a) Static tier (step 1, this change).** The launcher builds Landlock
rulesets and a classic-BPF seccomp program before `fork`. In the child, between
`fork` and `execve`, it performs only raw system calls on that prepared memory:

1. `prctl(PR_SET_NO_NEW_PRIVS, 1)`
2. `landlock_restrict_self(fd, 0)` for each prepared ruleset (layer)
3. `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`
4. `execve` of the target command

The filters are irrevocable and inherited by every descendant. Enforcement is
done by the kernel at the operation itself, with no user-space round trip.

**(b) Supervisor tier (step 2).** The ActPlane launcher stays the parent
(`PR_SET_CHILD_SUBREAPER`) and installs a seccomp filter that returns
`SECCOMP_RET_USER_NOTIF` for a short list of system calls only: `open*`,
`creat`, `exec*`, `connect`, `sendto`/`sendmsg` with a destination,
`exit_group`, `rename*`, `unlink*`, and `link*`. The supervisor runs the same
information-flow semantics as the eBPF engine in user space and answers each
notification:

- `open` is emulated: the supervisor resolves and opens the file itself and
  installs the descriptor into the target with `SECCOMP_IOCTL_NOTIF_ADDFD`
  (with `SECCOMP_ADDFD_FLAG_SEND`). The checked file is the opened file, so
  there is no time-of-check/time-of-use gap.
- `connect` is emulated: the supervisor copies the address, decides, takes the
  socket with `pidfd_getfd`, and connects it itself with the address it
  checked, so the target cannot change the address after the check.
- `execve` can only be checked and then continued
  (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`): the kernel re-reads the path and argv
  from the target's memory, so another thread can change them after the check.
  This TOCTOU gap is inherent and is reported for every argv-sensitive clause.

## Rule mapping

| Policy construct | Unprivileged mechanism | Tier |
| --- | --- | --- |
| write / unlink / truncate confinement, read-only domains | Landlock filesystem rights: exact, kernel-enforced, no per-operation user-space cost | static |
| read / open confinement | Landlock read rights (open for reading, list directory) | static |
| exec deny by path | Landlock execute allow-list, never beneath a writable hierarchy | static |
| argv exec rules (`exec "git" "push"`) | notify on `execve`, pre-op block, checked then continued (TOCTOU caveat) | supervisor |
| deny-all network | Landlock TCP connect/bind with no allowed port (ABI >= 4) plus seccomp refusing every non-TCP IPv4/IPv6 socket | static |
| IPv4 prefix allow-lists | notify `connect` + `pidfd_getfd`, connect performed by the supervisor | supervisor |
| label sources (`source L = file/exec/endpoint`) | notify `open` with `ADDFD`; file labels keyed by `(dev, inode)`, persistable as `user.*` extended attributes | supervisor |
| propagation | fork inheritance; a labeled writer taints the files it opens for write; IPC and descriptor passing are approximated by scanning `/proc/<pid>/fd` at decision points, plus an optional sound mode that taints the whole domain | supervisor |
| temporal gates (`after exec X exits 0 since write Y`) | `execve`, `exit_group`, and open-for-write notifications | supervisor |
| lineage (`lineage-includes`) | exec ancestry recorded by the supervisor | supervisor |
| domains and deltas | `launch-child` stacks a new Landlock layer; dynamic rules update supervisor tables with the existing monotonic checks | both |
| `notify` and `kill` effects | supervisor report or `SIGKILL` | supervisor |

Deltas that would need a new Landlock restriction on an already-running process
are rejected. Landlock can only be applied by a process to itself, so this is the
same principle as the eBPF engine refusing deltas that need hook classes that
were not reserved at load time.

## Step 1: the static tier

### Accepted clause forms

A clause is `exact` when all of the following hold, and `unsupported` otherwise:

- The effect is `block`.
- The subject predicate is absent, `if true`, or `if R`, where `R` is the runner
  label that `run` seeds on the launched process (`COMMAND`, else `AGENT`, the
  same selection the eBPF runner uses) and the policy never removes `R` with
  `declassify R by exec ...`. Under `run`, every process of the launched tree
  then carries `R`, so the predicate holds on exactly the processes the
  sandbox covers.
- There is no argv token, no `unless after ...`, no `unless lineage-includes
  ...`, and no `unless target not ...`.
- The operation and target are one of:

| Clause form | Mechanism |
| --- | --- |
| `block write file ANY` | Landlock: every write right is refused (read-only domain) |
| `block write file ANY unless target "/dir/**"` | Landlock: write rights only beneath `/dir` |
| `block write file ANY unless target "/dir/file"` | Landlock: write and truncate only on that existing file |
| `block unlink file ...` | same as `write`: the compiler lowers `unlink` to the kernel write op, so both backends treat it as write confinement |
| `block read file ANY [unless target ROOT]`, `block open file ANY [unless target ROOT]` | Landlock read rights (open for reading, list directory) |
| `block exec "*"` | Landlock: execute is refused everywhere |
| `block exec "*" unless target "/dir/**"` | Landlock execute allow-list; accepted only when the policy also confines writes and no allowed exec location is writable |
| `block connect endpoint "*"` | Landlock TCP connect/bind refused on every port (ABI >= 4), and seccomp refuses every IPv4/IPv6 socket that is not a TCP stream socket and every TCP fast-open send; below ABI 4 seccomp refuses every IPv4/IPv6 socket |

`ANY` is `"/**"`, `"*"`, `"**"`, or `"**/*"`, the patterns the compiler lowers to
match every path. `ROOT` is an absolute, normalized path, either exact or
followed by `/**`.

### Rejected clause forms

- `notify` and `kill` effects (need the supervisor's report channel or a kill).
- Any label predicate other than the runner label (`if SECRET`, `if not R`,
  `if A and B`), and runner-label predicates when the policy declassifies the
  runner label.
- Argv tokens (`exec "git" "push"`).
- `unless after ...`, `unless lineage-includes ...`.
- `unless target not PAT` and any target that refuses one region while allowing
  the rest (`write file "**/.env"`, `write file "/etc/**"`): Landlock rules are
  allow-lists, so a denied region with everything else allowed is not
  expressible.
- Relative or globbed allowed roots (`unless target "src/**"`,
  `"/work/*.txt"`, `"/work/*"`).
- `exec PAT` for any pattern other than `"*"` (refusing one program while
  allowing every other one is not an allow-list).
- An execute allow-list without a write confinement clause, or whose allowed
  region overlaps the writable region.
- `connect endpoint PAT` other than `"*"`, `connect ... unless target ...`, and
  every `recv` clause.

`actplane compile --backend unprivileged` prints the status of every clause and
exits 1 when any clause is unsupported. `--explain` adds the mechanism, notes,
host support, and always-applied hardening. `--json` emits
`actplane.compile.unprivileged.v1`. `actplane run --backend unprivileged`
refuses an unsupported policy before starting the command.

### Layers

Each exact clause is an independent restriction, and restrictions intersect: an
access is allowed only where every clause of its class allows it. Landlock layers
also intersect, so the launcher packs the constraints into layers in which each
access class is handled by one constraint only, merging constraints that share a
root. A layer therefore never widens a clause. The backend stacks at most 8
layers, leaving room under Landlock's limit of 16 for sandboxes the launcher
already runs in.

### Always-applied hardening

Every launched process gets, independent of the policy:

- `no_new_privs`, so setuid and file-capability programs cannot regain
  privileges and the filters cannot be lifted;
- seccomp `EPERM` for `io_uring_setup`, `io_uring_enter`, and
  `io_uring_register` (io_uring submissions bypass seccomp, and its socket
  operation would bypass the socket filter), `ptrace`, `process_vm_writev`,
  `socket(AF_PACKET, ...)`, and `SOCK_RAW`/`SOCK_PACKET` sockets outside
  `AF_NETLINK` (netlink stays available for `getaddrinfo` and `getifaddrs`);
- system calls through a foreign ABI are refused (x32 returns `EPERM`, a
  foreign architecture such as i386 compat kills the process), so the
  per-number filter cannot be sidestepped;
- on Landlock ABI >= 6, signal and abstract Unix socket scoping, so the
  sandbox cannot signal or connect to the launcher or other processes outside
  it (best effort: reported as unavailable on older kernels);
- with any Landlock layer, Landlock's own ptrace restriction across the
  sandbox boundary;
- for an execute allow-list, no execute right beneath a writable hierarchy.

### Divergences from the bpf-lsm backend

All known divergences are in the stricter direction, or concern descriptors that
were opened before the sandbox was applied. `compile --explain` lists them per
clause.

- Landlock checks access when a file is opened, created, removed, renamed, or
  truncated. Descriptors the launcher passes in (stdin, stdout, stderr) stay
  usable, whereas the eBPF engine also checks each `write(2)` on a regular file.
- Creating directories, symlinks, sockets, and FIFOs, and removing directories,
  count as writes. The eBPF engine does not hook those operations.
- The eBPF file rules cover regular files and directories only. To match, the
  common character devices (`/dev/null`, `/dev/zero`, `/dev/full`,
  `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx`, `/dev/pts/*`) stay
  readable and writable under file rules. Other device nodes and FIFOs outside
  the allowed region are refused.
- An exact file root (`unless target "/dir/file"`) must exist at launch. It can
  be written and truncated, while creating, removing, or renaming it stays
  refused.
- Network denial also refuses IPv6, UDP, ICMP, SCTP, MPTCP, raw sockets, TCP
  bind, and TCP fast-open sends. The eBPF engine mediates IPv4 `connect`.
- The eBPF engine matches exec patterns on the command name (basename). The
  static tier matches the executable path, so `block exec "*" unless target
  "/dir/**"` has no eBPF equivalent.
- Denials return `EACCES` (Landlock) or `EPERM` (seccomp) instead of the
  eBPF engine's `EPERM`, and the static tier writes no per-event
  corrective-feedback record.

### CLI surface

| Command | Behavior |
| --- | --- |
| `actplane compile --backend unprivileged [--explain \| --json]` | per-clause `exact`/`unsupported` report; exit 1 when any clause is unsupported; `--out` is refused because there is no kernel blob |
| `actplane run --backend unprivileged -- <cmd>` | refuses an unsupported policy before launch; otherwise applies the sandbox and returns the command's exit code; no sudo |
| `actplane doctor` | reports the Landlock ABI, seccomp filter availability, and `no_new_privs` |

`--backend` defaults to `bpf-lsm`, so existing behavior is unchanged.
`run --backend unprivileged` rejects `--parent-domain`, `--child-id`,
`--scope-id`, `--delta`, `--delta-text`, and approval metadata, because the
static tier has no runtime domains. `control launch-child` keeps talking to a
running eBPF engine. An unprivileged `launch-child` needs the step 2 supervisor
as its long-running control server, and will stack one Landlock layer per child
domain.

## Step 2: seccomp user-notify supervisor (future)

- The launcher becomes the parent and subreaper of the agent tree and keeps the
  notify listener; only the system calls listed under the supervisor tier are
  notified, so ordinary reads and writes on open descriptors keep kernel speed.
- Labels and gates live in supervisor tables keyed by `(dev, inode)` for files
  and by pid lineage for processes; file labels can persist as `user.*`
  extended attributes where the filesystem supports them.
- `notify` reports through the existing feedback files; `kill` sends
  `SIGKILL` to the notified task; `block` answers the notification with an
  error.
- Monitor integrity: Landlock signal and abstract Unix scoping (ABI >= 6),
  Landlock's ptrace restriction, no write access to the supervisor state (its
  state directory stays outside every writable root), `io_uring_setup` refused
  (seccomp cannot see io_uring submissions), irrevocable filters, and
  `no_new_privs`. The static filter must also refuse
  `seccomp(SECCOMP_SET_MODE_FILTER)` with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
  inside the sandbox: a nested listener installed later would receive the
  notification first and could continue the call without the supervisor's
  check.
- Stacking with agents' own sandboxes: Landlock layers intersect, and seccomp
  takes the highest-precedence action across all filters, so an agent's own
  Landlock or seccomp sandbox only narrows what ActPlane allows.

## Step 3: differential testing and performance (future)

- Run both backends on the same policy corpus (`test/policies/`,
  `test/e2e_file_flow_cases.yaml`, `script/e2e_examples.sh`) and compare every
  decision; every disagreement must be one of the documented divergences.
- Measure per-operation overhead of both backends on the same workloads
  (Landlock path walks, seccomp filter cost, notify round trips) against the
  eBPF hooks.

## Kernel requirements

| Feature | Requirement |
| --- | --- |
| Landlock read and execute rules | ABI 1, Linux 5.13 |
| Landlock write confinement (needs truncate control) | ABI 3, Linux 6.2 |
| Landlock TCP connect/bind | ABI 4, Linux 6.7 (below it, network denial uses seccomp only) |
| Landlock signal and abstract Unix scoping | ABI 6, Linux 6.12 |
| seccomp filter mode, `no_new_privs` | Linux 3.5 |
| seccomp user notification (step 2) | Linux 5.0; `ADDFD` 5.9; `ADDFD_FLAG_SEND` 5.14; `pidfd_getfd` 5.6 |

The full feature set needs Linux 6.12 or newer (Landlock ABI 6). Linux 6.7 to
6.11 lacks scoping. Older kernels support file rules only, and write
confinement needs 6.2. The seccomp filter supports x86_64 and aarch64.
`actplane doctor` reports what the running kernel offers, and `run` refuses a
policy the kernel cannot enforce instead of applying a weaker sandbox.

## Limitations

- Only agents launched by ActPlane are covered. The unprivileged backend cannot
  adopt an already-running pid the way the eBPF backend's `cap_task` binding
  does, because Landlock and seccomp apply only to the calling process and its
  future children.
- IPC-mediated flows are approximate in the supervisor tier (descriptor scans at
  decision points, or the sound whole-domain taint mode).
- Argv-sensitive exec rules keep a TOCTOU gap in the supervisor tier.
- An execute allow-list restricts which files can be executed with `execve`;
  code run by an allowed interpreter, loaded by the dynamic loader
  (`ld.so <file>`), or executed from an anonymous memory file is not itself
  executed from a path. Bind mounts that alias an exec root and a writable
  root also defeat the static separation check.
- macOS would need a separate Seatbelt (`sandbox_init`) backend.
