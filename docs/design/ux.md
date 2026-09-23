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

policy: |
  source TESTED = exec "**/pytest"

  rule test-before-commit:
    kill exec "git" "commit" unless after exec "**/pytest"
    because "run the test suite before committing"
```

Optional dynamic update shape:

```yaml
version: 1

rules:
  no-network:
    policy: |
      rule no-network:
        kill connect endpoint "*"
        because "network is disabled by default"

  no-build-output-network:
    policy: |
      source BUILD_OUTPUT = file "./target/**"

      rule no-build-output-network:
        kill connect endpoint "*" if BUILD_OUTPUT
        because "build output cannot be sent to the network"

domains:
  session:
    bind:
      - rule: no-network
        mode: locked

  build:
    parent: session
    bind:
      - rule: no-build-output-network
        mode: locked
```

A domain is a named policy boundary that compiles to a small id. Each domain is
a key under `domains:`, with an optional `parent`, a `bind` list attaching named
rules from `rules:` (each `mode: locked` or `default`), and a `disable` list
removing rules inherited from a parent. The kernel only sees ids, masks, and
scope ids. Some low-level ABI fields still use `target_id`; in the security
model that id is a domain id.

## API

CLI:

```text
actplane init
actplane compile --json
actplane compile --domains
actplane --domain review compile --explain
actplane --domain review compile --out review.ir
sudo -E actplane --domain review run -- <cmd>
actplane control status
actplane control delta add --target-id <id> --delta policy.dsl
actplane doctor
```

On the plain-compile path, when a domain actually resolves, the CLI reports
which domain was selected (`doctor.rs`):

```text
domain: review
parent: session
policy: no-git-branch, readonly
```

The `--json` and `--explain` paths report the same choice in their own form. That
makes the runtime choice visible before anything needs privileges.

Library:

```rust
actplane_ifc_compiler::dsl::compile_str(src: &str) -> Result<Compiled, String>
PinnedEngine::load(config_blob: &[u8]) -> io::Result<PinnedEngine>
engine.run(&stop: &AtomicBool, on: impl FnMut(Violation)) -> io::Result<()>
engine.submit_delta(req: DeltaRequest) -> io::Result<()>
```

Violations are delivered through the `run` callback rather than an iterator; the
engine owns the ring-buffer drain.

Kernel request:

```text
caller_pid
target_id
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
