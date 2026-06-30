# Kernel-Resident Singleton Engine

This is an internal lifecycle design for ActPlane's eBPF engine, not
user-facing usage guidance.

Status: normative target. Current transitional paths may still load an engine
for one foreground invocation, but they must not grow into a required
long-lived userspace owner.

Core invariant:

> A running kernel must have at most one ActPlane engine. All long-lived
> ActPlane state lives in pinned kernel objects, not in a userspace daemon.

## Required Properties

- One booted kernel has at most one active ActPlane engine instance.
- ActPlane must not require `actplaned` or any equivalent long-lived userspace
  process.
- Programs, links, maps, the policy/domain registry, and the durable event log
  are pinned in bpffs.
- Every `actplane` process is a short-lived client. It opens pinned kernel
  objects, submits one bounded operation or reads bounded state, then exits.
- Different projects, agents, MCP servers, and shells are tenants of the same
  kernel engine. They must not load separate BPF programs.
- Project policy replacement is domain-scoped. It must not globally replace
  rules for unrelated domains.
- Runtime policy mutation remains monotonic: child domains may tighten policy,
  but may not remove inherited policy or widen delegated authority.

## Pinned State

The singleton is discovered through a versioned bpffs root such as:

```text
/sys/fs/bpf/actplane/v1/
  meta
  programs/
  links/
  maps/
```

The exact object names are ABI details and should not be documented here as
implemented behavior until code and tests pin them. The required contract is
that `meta` identifies the engine schema, object/ABI identity, enabled hook
profile, and install generation, and that every durable enforcement object is
reachable from this root.

## Client Lifecycle

Every command follows the same lifecycle:

```text
open pinned meta
  compatible -> open pinned programs, links, and maps
  missing    -> install the singleton, pin it, then use it
  conflict   -> fail explicitly with upgrade/uninstall guidance
perform one bounded operation
exit
```

`run`, `attach`, `watch`, `mcp`, policy/status commands, and `feedback-hook` are
clients of the same pinned engine. A client may wait for a child process or poll
events for UX, but enforcement and policy state must not depend on that client
remaining alive.

The initial install must not let the first project choose a narrow hook profile
for the host. Supported hook classes should be reserved for the singleton, while
kernel features that are truly unavailable, such as inactive BPF-LSM hooks, can
remain unavailable.

## Domain Policy

Projects and agent sessions are kernel-admitted domains. Domain ids are
host-wide and must not rely only on Linux pid values.

The domain registry must track enough kernel-resident state to bind pids,
authority, active policy slots, and feedback/audit ownership to a domain. A
project policy update replaces only that domain's active policy. It must not
quiesce or reload policy for unrelated domains.

Legacy `--parent-domain` semantics are not automatically mapped onto the
singleton. A host-global parent domain would require an explicit host-global
replacement protocol, so transitional clients must reject that mode instead of
silently treating it as an isolated per-session domain.

Concurrent clients coordinate through admitted kernel state. Userspace files,
repo-local sockets, lock files, and process lifetime must not become durable
policy authority.

## Feedback and Events

Ring buffers are notification channels and require a live userspace reader.
They cannot be the only durable feedback surface in a daemonless design.

The engine must keep bounded kernel-resident event and reason state in pinned
maps. Short-lived clients can format that state for users and agents. Project
files such as `.actplane/last-violation.txt` are projections only; they are not
the source of truth for durable ActPlane state.

## Forbidden Designs

- Required `actplaned` or any equivalent long-lived userspace daemon.
- Per-project BPF program loads after the singleton is installed.
- Repo-local sockets, files, or processes as engine lifetime or policy
  authority.
- Global policy reloads that affect unrelated domains.
- First-project-wins hook profiles.
- Persistent policy, registry, or event state stored only in userspace.

## Implementation Boundary

Do not claim that a concrete map, transaction protocol, event-log format, or
domain operation is implemented until code and tests back it. Partial
implementations must still preserve the invariants above: no required daemon,
no second per-project engine, and no durable ActPlane authority outside pinned
kernel objects.
