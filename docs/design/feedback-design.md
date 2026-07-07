# Corrective Feedback

ActPlane treats feedback as part of enforcement. The kernel engine detects a
policy match, the runtime resolves the rule metadata, and the agent integration
delivers the same reason back to the agent. Hooks and MCP transport feedback,
but they do not re-evaluate policy in userspace.

## Event Flow

```text
eBPF/BPF-LSM match
  -> TAINT_VIOLATION event with effect, process, target, and rule id
  -> actplane runtime resolves rule name and reason
  -> .actplane/last-violation.txt is updated
  -> project hook or MCP integration forwards the reason to the agent
```

The user-facing feedback file names the rule, effect, target, process, reason,
and the expected alternative. This is the corrective-feedback payload consumed
by Codex/Claude Code hooks and by humans inspecting the last violation.

## Effects

- `notify`: records the violation and forwards guidance while allowing the
  operation to complete.
- `block`: denies the operation in a BPF-LSM pre-operation hook and forwards the
  reason.
- `kill`: terminates the matching task and forwards the reason. This is useful
  for argv-sensitive exec policies whose full argument context is available
  after exec.

In all cases, the rule match originates from the OS-level ActPlane engine. The
integration layer only carries the resulting reason into the agent workflow.

## User Surfaces

`actplane run` writes `.actplane/last-violation.txt` during an enforced run.
`actplane init --with-codex` installs the project-local Codex hook. `actplane
init --with-mcp` installs the MCP auto-attach configuration. `actplane mcp
--auto-attach-parent` exposes the same engine feedback through MCP resources.
