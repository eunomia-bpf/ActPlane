# Minimal eBPF IFC Engine UX/API

`ebpf-ifc-engine` is a generic OS-level information-flow engine. It should not
contain agent, subagent, reviewer, builder, MCP, hook, prompt, or workspace
concepts.

## Core Model

The enforcement core needs four concepts:

```text
object  -> process, file, endpoint, stdio channel
label   -> information tag
event   -> exec, fork, read, write, connect
rule    -> event + labels + target -> effect + reason
```

The kernel loop is:

```text
observe event
move labels
check rules
emit or block
```

## Dynamic Policy

Runtime policy updates add three concepts:

```text
delta      -> requested monotonic change
authority  -> whether caller can apply that delta
domain     -> process-tree policy boundary
```

Accepted deltas only add or narrow:

```text
add labels
add restrictions
add gates
narrow scope
create child domain
```

Rejected deltas remove or widen:

```text
clear labels
remove restrictions
remove gates
widen scope
modify unrelated domain
```

## DSL

The DSL should describe system structure, then lower to kernel tables and
deltas.

Minimum YAML shape:

```yaml
version: 1

ifc: |
  source TESTED = exec "**/pytest"

  rule test-before-commit:
    kill exec "git" "commit" unless after exec "**/pytest"
    because "run the test suite before committing"
```

Optional dynamic update shape:

```yaml
version: 1

domain:
  id: build
  parent: session
  scope:
    files: ["./src/**", "./target/**"]

authority:
  apply_to_self: true
  apply_to_child: false

ifc: |
  source BUILD_OUTPUT = file "./target/**"

  rule no-build-output-network:
    kill connect any if BUILD_OUTPUT
    because "build output cannot be sent to the network"
```

`domain` is just a name that compiles to a small id. The kernel only sees ids,
masks, and scope ids. Some low-level ABI fields still use `target_id`; in the
security model that id is a domain id.

## API

CLI:

```text
actplane compile policy.yaml --out policy.ir
actplane --domain review compile --out review.ir
actplane run --policy policy.yaml -- <cmd>
actplane apply --domain <id> --policy policy.yaml
actplane exec --domain <id> -- <cmd>
actplane events
actplane doctor
```

Library:

```rust
compile(yaml) -> Ir
load(ir) -> Engine
run(engine, command) -> Process
apply_delta(engine, domain, delta) -> Result
events(engine) -> Iterator<Event>
```

Kernel request:

```text
caller_pid
domain_id
required_mask
add_label_mask
add_restrict_mask
add_gate_mask
new_scope_id
```

That is the dynamic authority model: check mask, check domain, check monotonicity,
then OR/narrow.

## Boundary

Belongs in the engine:

```text
object + label + event + rule + domain + delta + authority
```

Everything agent-specific is a wrapper above the engine.
