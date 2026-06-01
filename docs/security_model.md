# Security Model

ActPlane's reusable engine has two layers:

```text
IFC core:       object + label + event + rule
Runtime policy: domain + binding + delta + authority
```

Agent, subagent, MCP, hooks, prompts, and workspaces are integrations above this
model. They are not part of the engine security model.

## Core Entities

An IFC rule is pure system policy:

```text
rule = condition + effect + reason
```

It does not say whether it is mandatory for child domains. That is a runtime
domain decision.

A domain is the runtime policy boundary for a process tree:

```text
pid -> domain
domain -> effective policy
event(pid) checks only pid's domain
```

Files, sockets, and stdio are not domains. They are IFC objects that carry
labels and participate in flow rules.

A binding attaches a rule to a domain:

```text
binding = domain + rule + mode
```

Binding modes:

```text
locked   -> child domain cannot disable this binding
default  -> child domain may disable this binding for itself
```

So "locked/default" belongs to the domain binding, not to the rule definition.

## Two Logical YAMLs

It is useful to keep two logical files, even if a CLI later allows them in one
physical YAML.

Rule catalog:

```yaml
version: 1

rules:
  no-git-branch:
    ifc: |
      rule no-git-branch:
        kill exec "git" "branch"
        because "do not create git branches"

  no-network:
    ifc: |
      rule no-network:
        kill connect any
        because "network is disabled by default"

  readonly:
    ifc: |
      rule readonly:
        kill write file any
        because "this domain is read-only"
```

Domain policy:

```yaml
version: 1

domains:
  session:
    bind:
      - rule: no-git-branch
        mode: locked
      - rule: no-network
        mode: default
```

The same rule can be bound differently by different domains:

```yaml
domains:
  review:
    parent: session
    bind:
      - rule: readonly
        mode: locked

  build:
    parent: session
    bind:
      - rule: readonly
        mode: default
```

## Effective Policy

For a domain `D`:

```text
locked(D)  = locked(parent(D)) + local_locked(D)
default(D) = default(parent(D)) - disabled_defaults(D) + local_default(D)
policy(D)  = locked(D) + default(D)
```

Only locked policy is a security invariant:

```text
locked(child) >= locked(parent)
```

Here `>=` means "at least as restrictive", not "more privileges".

Default policy is a template:

```text
default(parent)
```

Child domains may keep it, disable it, or replace it with stricter local policy.

## Child Updates

A child domain may update its own domain policy if its authority allows it.

Allowed updates:

```text
add local default bindings
add local locked bindings
disable inherited default bindings
add labels
add gates
narrow scope
create child domains with no more authority than delegated
```

Rejected updates:

```text
disable inherited locked bindings
modify parent domain state
modify sibling domain state
remove inherited locked bindings
widen scope
remove labels or gates
increase delegated authority
mutate an existing locked rule definition
```

## Examples

### 1. Default Block That Child Disables

Parent domain:

```yaml
domains:
  session:
    bind:
      - rule: no-git-branch
        mode: locked
      - rule: no-network
        mode: default
```

Child domain:

```yaml
domains:
  review:
    parent: session
    disable:
      - no-network
```

Result:

```text
review still enforces no-git-branch
review does not enforce no-network
session and sibling domains are unchanged
```

Trying to disable `no-git-branch` is rejected because its inherited binding is
locked.

### 2. Child Adds a Locked Rule for Its Own Children

Child domain:

```yaml
domains:
  review:
    parent: session
    bind:
      - rule: readonly
        mode: locked
```

Grandchild domain:

```yaml
domains:
  review-helper:
    parent: review
    disable:
      - readonly
```

Result:

```text
review-helper cannot disable readonly
readonly was locked by review, so it is mandatory below review
session policy is unchanged
```

This lets a child domain define stricter policy for its descendants without
modifying the parent.

### 3. Child Adds a Default Rule for Its Own Children

Child domain:

```yaml
domains:
  build:
    parent: session
    bind:
      - rule: no-network
        mode: default
```

Grandchild domain:

```yaml
domains:
  build-fetch:
    parent: build
    disable:
      - no-network
```

Result:

```text
build enforces no-network by default
build-fetch may disable no-network
locked rules inherited from session still apply
```

### 4. Runtime Rule Addition

Rules can be added at runtime if they are submitted as compiled policy deltas.
The kernel should not parse YAML or DSL in the admission path.

CLI shape:

```bash
actplane rule compile rules/no-curl.yaml --out no-curl.ir
actplane domain bind review --rule-ir no-curl.ir --mode default
```

Semantics:

```text
userspace compiles rule DSL -> rule IR
userspace submits add-rule delta
kernel checks authority
kernel installs rule into review's effective policy
```

A domain can also bind an existing catalog rule at runtime:

```bash
actplane domain bind review --rule no-network --mode locked
```

This is allowed only if the caller has authority to update `review`.

### 5. Runtime Disable of Default Policy

CLI shape:

```bash
actplane domain disable review no-network
```

Admission checks:

```text
caller can update review
no-network is inherited as default, not locked
review's effective locked policy remains unchanged
```

Rejected case:

```bash
actplane domain disable review no-git-branch
```

Reason:

```text
no-git-branch is inherited as locked
```

## Runtime Delta Admission

User space does not directly mutate effective policy state. It submits deltas.

Useful delta classes:

```text
create_domain
bind_rule
add_rule_ir
disable_default_rule
add_label
add_gate
narrow_scope
```

A delta contains only precompiled IDs and masks:

```text
caller_pid
domain_id
required_mask
add_label_mask
add_restrict_mask
add_gate_mask
new_scope_id
bind_rule_ids
bind_modes
disable_default_rule_ids
```

The kernel admits a delta only if:

```text
caller_pid is bound to a domain
caller may affect the target domain
caller has the required authority bits
scope only narrows
labels/gates/restrictions only add
disabled rules are inherited as default
locked parent bindings remain effective
new locked bindings do not weaken inherited locked policy
```

Accepted deltas are merged into the domain's already-computed effective state.
The syscall fast path should not walk the domain tree.

## Rule Identity

Runtime-added rules should be content-addressed or versioned:

```text
rule_id = hash(compiled_rule_ir)
```

This prevents a child from changing the meaning of an inherited locked rule by
reusing its name with different contents.

Names such as `no-network` are user-facing aliases. Kernel admission should use
stable IDs or hashes.

## Current Implementation Mapping

The current low-level ABI still uses `target_id` in some structs. In this model,
that id is a domain id:

```text
cap_task[pid] -> domain id
cap_state[domain id] -> effective domain state
```

Current implemented fields:

```text
parent
scope_id
labels
authority_mask
target_mask
restrict_mask
gate_mask
label_mask
```

Implemented today:

```text
rule catalog in policy YAML
domain bindings in policy YAML
default_domain / --domain selection
locked/default binding resolution at compile time
disable inherited default bindings at compile time
user ringbuf request path
domain-like state map
pid-to-domain-like binding
mask-based authority checks
monotonic labels/restrictions/gates/scope update
```

Still needed to fully implement this model:

```text
domain naming in low-level BPF ABI
stable rule IDs / content hashes
runtime domain binding table
runtime locked/default binding metadata
runtime disabled-default rule set
delta admission for bind/disable
runtime add-rule IR maps
dynamic child-domain creation
tests for locked versus default bindings
```
