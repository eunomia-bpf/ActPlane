# Runtime Capability / Delta Admission Design

This is a design sketch for making ActPlane's layered runtime configurable
without trusting the CLI, MCP server, hooks, or policy files as runtime
authority.

The key idea:

> Do not put a complex business-level capability model in eBPF. Treat
> capability as a mask-based authority to apply monotonic deltas to kernel
> effective state.

User space may submit requests. The kernel decides whether the request is an
allowed restriction delta and, if so, applies it by OR-ing masks or narrowing a
scope. User space never writes effective policy maps directly.

## Design Goal

Support dynamic layering and delegation while keeping the eBPF side simple:

- main agent can restrict a child/subagent;
- subagent can self-restrict;
- no principal can weaken parent policy;
- no principal can affect parent or sibling state unless explicitly allowed;
- CLI/MCP/hooks are untrusted request producers;
- kernel effective maps are the source of truth.

This is not a business capability system such as `reviewer` or `builder`.
Those are user-space concepts. The kernel sees only IDs and masks.

## State Model

Per-process state points to a principal:

```c
struct pid_state {
    u32 session_id;
    u32 principal_id;
    u32 layer_stack_id;
    u64 labels;
};
```

Each principal has static identity/authority and mutable effective restrictions:

```c
struct principal_state {
    u32 parent;
    u32 subtree_root;
    u32 scope_id;

    u64 labels;
    u64 update_cap_mask;      // which delta classes this principal may request
    u64 affect_scope_mask;    // self / child / subtree authority

    u64 effective_restrict;   // monotonic: only OR new restriction bits
    u64 required_gates;       // monotonic: only OR new gate requirements
    u64 allowed_label_mask;   // labels this principal may add to self/child
};
```

Policy requests are fixed-size, mask-oriented records:

```c
struct policy_request {
    u32 requester_pid;
    u32 target_principal;

    u64 required_cap_mask;
    u64 add_restrict_mask;
    u64 add_label_mask;
    u64 require_gate_mask;

    u32 new_scope_id;         // 0 means unchanged; otherwise must narrow
    u32 flags;
};
```

The important property is that the request contains no arbitrary DSL, YAML,
string policy, or business role. It contains only pre-resolved IDs and masks.

## Request Channel

Use a user-to-kernel queue such as `BPF_MAP_TYPE_USER_RINGBUF`:

```text
untrusted user space
  writes policy_request records

eBPF admission program
  drains requests
  validates masks and scope
  applies accepted deltas
```

The effective maps used by syscall enforcement are not writable by normal user
space. User space can only enqueue a request. A request is not authority.

If user ringbuf is not practical for a target kernel, the same design can use a
request map plus a kernel-side drain point. The security boundary is the same:
request state is untrusted; effective state is kernel-admitted.

## Admission Logic

Kernel admission should stay mechanical:

```text
requester = pid_state[current_pid].principal_id
src = principal_state[requester]
dst = principal_state[target_principal]

1. target is self, child, or descendant according to affect_scope_mask
2. required_cap_mask plus capability classes implied by non-empty delta fields
   is a subset of src.update_cap_mask
3. add_restrict_mask only adds restriction bits
4. add_label_mask is a subset of src.allowed_label_mask
5. require_gate_mask only adds gate requirements
6. new_scope_id is unset or is a subset of dst.scope_id
7. request never clears bits, deletes rules, downgrades effects, or widens scope
8. accepted delta is applied to dst effective state

The kernel must not trust `required_cap_mask` as the only authority
description. It should derive at least the generic capability class from the
request body itself:

```text
add_restrict_mask != 0 -> CAP_ADD_RESTRICTION
add_label_mask    != 0 -> CAP_ADD_LABEL
require_gate_mask != 0 -> CAP_REQUIRE_GATE
new_scope_id      != 0 -> CAP_NARROW_SCOPE
```

`required_cap_mask` can add more specific authority bits, but it cannot remove
the implied checks.
```

Apply is monotonic:

```c
dst.effective_restrict |= req.add_restrict_mask;
dst.labels             |= req.add_label_mask;
dst.required_gates     |= req.require_gate_mask;
if (req.new_scope_id)
    dst.scope_id = req.new_scope_id;
```

There is no user-visible operation that clears `effective_restrict`, clears
`required_gates`, removes labels, widens scope, or mutates an ancestor.

## Mask Vocabulary

The kernel should only know stable bit vocabularies.

Example update capability bits:

```text
CAP_SELF_RESTRICT
CAP_CONFIGURE_CHILD
CAP_CREATE_CHILD
CAP_ADD_LABEL
CAP_REQUIRE_GATE
CAP_NARROW_SCOPE
CAP_ADD_RESTRICTION
CAP_ENDORSE
CAP_DECLASSIFY
```

Example restriction bits:

```text
RESTRICT_NO_NETWORK
RESTRICT_READONLY_WORKSPACE
RESTRICT_WRITE_ONLY_SCOPE
RESTRICT_NO_EXEC_OUTSIDE_PROFILE
RESTRICT_NO_CONTROL_PLANE_WRITE
RESTRICT_REQUIRE_GATE_FOR_WRITE
RESTRICT_REQUIRE_GATE_FOR_CONNECT
```

The exact bit names can evolve, but the kernel operation should remain simple:
subset checks and OR.

## High-Level Lowering

User-facing concepts lower to masks before they reach the kernel.

Example:

```text
NO_NETWORK(child)
```

lowers to:

```text
target_principal = child
required_cap_mask = CAP_CONFIGURE_CHILD | CAP_ADD_RESTRICTION
add_restrict_mask = RESTRICT_NO_NETWORK
```

Example:

```text
REQUIRE_REVIEW(child, write)
```

lowers to:

```text
target_principal = child
required_cap_mask = CAP_CONFIGURE_CHILD | CAP_REQUIRE_GATE
require_gate_mask = GATE_REVIEWED_FOR_WRITE
```

Example:

```text
WRITE_ONLY_PATH(child, worktree_scope)
```

lowers to:

```text
target_principal = child
required_cap_mask = CAP_CONFIGURE_CHILD | CAP_NARROW_SCOPE
add_restrict_mask = RESTRICT_WRITE_ONLY_SCOPE
new_scope_id = worktree_scope
```

## Scope IDs

Runtime requests should not submit arbitrary path globs. Path/network/command
profiles should be installed or pre-resolved into scope IDs.

```text
scope_id 1 = project root read scope
scope_id 2 = worktrees/reviewer/**
scope_id 3 = no network
scope_id 4 = docs/**
```

The kernel admission check only needs:

```text
is_subset_scope(new_scope_id, old_scope_id)
```

The compiler/control plane can build the scope lattice ahead of time. The kernel
only stores compact IDs and a subset relation table or parent chain.

## Enforcement Fast Path

The syscall fast path should not drain requests or walk layer trees.

It should read effective state only:

```text
pid -> principal_id
principal -> effective_restrict / labels / required_gates / scope_id
object -> labels
rule/restriction table -> effect
```

Then perform normal IFC enforcement:

```text
propagate labels
check sink rules
check effective restriction bits
emit notify/block/kill
```

All expensive or low-frequency admission work happens outside the syscall hot
path.

## What This Avoids

This design avoids putting these concepts into eBPF:

- reviewer/builder/tester roles;
- arbitrary policy templates;
- YAML/DSL parsing;
- string-heavy runtime rule creation;
- business-specific delegation logic;
- complex policy layer DAG traversal in the fast path.

The kernel is a small IFC update/admission engine:

```text
check mask
check scope subset
check self/descendant
OR masks
enforce effective state
```

## Safety Properties

If implemented correctly:

- CLI can be untrusted.
- MCP/hooks can be untrusted.
- Policy files can be treated as proposals, not runtime authority.
- A principal can self-restrict but not self-unrestrict.
- A parent can restrict a child only if it has the relevant update bits.
- A child cannot mutate parent or sibling effective state.
- Effective policy state lives in kernel maps and is not directly user-writable.
- Runtime delegation is monotonic.

## Limits

This design does not support arbitrary runtime DSL submission. That is a feature,
not a bug.

Arbitrary DSL should remain an install/load-time operation, or it should lower
to pre-approved masks, scopes, labels, gates, and restriction bits.

The model also depends on the effective maps being protected from direct
userspace writes. If an attacker has unrestricted `CAP_BPF`, `CAP_SYS_ADMIN`, or
root access, they can tamper with the enforcement substrate regardless of this
admission design.

## Relationship to IFC

IFC remains the data-flow engine:

```text
labels propagate across process/file/network edges
sink rules check label flow
gates endorse/declassify or satisfy preconditions
```

Mask admission is meta-policy:

```text
who can add which restrictions, labels, gates, or narrower scopes
```

The two layers should stay separate. IFC decides whether an operation is allowed.
Admission decides whether a runtime policy delta may become part of the effective
IFC state.
