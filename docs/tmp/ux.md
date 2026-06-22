# ActPlane UX and Product Model

This document defines the user experience ActPlane should optimize for. The
goal is not to make ActPlane feel like another agent plugin, but to make it feel
like a reliable OS-level policy plane for agent processes.

ActPlane has three layers:

```text
Kernel data plane
  eBPF / BPF-LSM observes flows, propagates labels, and enforces notify/block/kill.

ActPlane control plane
  Compiles policy, loads enforcement, attaches sessions, delegates scopes,
  explains status, and records audit/feedback.

Agent integration layer
  Hooks, MCP resources, and CLI adapters deliver feedback to agents and users.
  They do not own policy authority.
```

## UX Principles

1. The kernel is authoritative.
   Agent hooks, MCP, and CLI commands may explain or transport feedback, but they
   must not re-detect violations in userspace as the source of truth.

2. Setup should be path-stable.
   Project integrations should call `actplane` from `PATH`, not a local build
   artifact. Users should be able to run `actplane init --all`, then start
   `codex`.

3. Feedback must be actionable.
   A blocked or killed action should tell the agent what happened, which rule
   fired, why retrying unchanged is not useful, and what kind of alternative is
   expected.

4. MCP should stay resource-first.
   MCP is useful for long-lived status, policy, and feedback resources. It should
   not grow into a broad tool surface for modifying policy.

5. Policy authority must be layered and monotonic.
   Lower layers can only add restrictions or narrow scope. They cannot remove,
   weaken, or bypass parent policy.

6. Control-plane files are protected by default.
   Agents and subagents should not be able to edit `actplane.yaml`, `.actplane/`,
   `.mcp.json`, hooks, or audit/feedback channels unless a higher authority
   explicitly allows it.

## Command Model

ActPlane commands should fall into clear lifecycle categories.

### One-shot diagnostics

These commands run, print an answer, and exit.

```bash
actplane compile --explain
actplane doctor
cat .actplane/last-violation.txt
actplane control status
```

`compile --explain` validates policy without privileges. It compiles the DSL,
summarizes rules, prints a backend support matrix, and reports static warnings such as
unsupported `block` behavior without BPF-LSM, unsupported `notify/kill recv`,
argv-sensitive `block exec`, or hostname endpoint patterns that cannot match
in-kernel IPv4.

`doctor` diagnoses the local environment: policy discovery, `actplane` on
`PATH`, Codex hook setup, project MCP config, duplicate global/project MCP
config, passwordless sudo, BTF, and BPF-LSM active or reboot-pending state.

`status` should summarize active protected sessions, loaded policy hashes,
layer stacks, attached PIDs, feedback paths, and enforcement backend state.

`explain last` should render the latest violation for a human or agent: rule,
effect, target, provenance, retry guidance, and the policy layer that introduced
the rule.

### Session commands

These commands own a runtime until the protected command exits or the user stops
the process.

```bash
sudo -E actplane run -- <agent-or-command>
actplane watch
```

`run` launches a command under enforcement, seeds the process tree with the
runner label, writes feedback to the configured feedback file, and stops when
the command exits.

`watch` attaches the engine to the parent agent or shell pid and reports project
policy matches without launching a child command. It should preserve the parent
pid before passwordless sudo elevation so the protected process tree remains the
repo/session boundary.

### Long-lived integration

```bash
actplane mcp --auto-attach-parent
```

MCP is a long-lived process started by the agent client. It should keep the stdio
connection open until the session ends. With `--auto-attach-parent`, it should
try passwordless sudo, load the kernel engine, seed the parent agent process, and
keep reporting kernel feedback to the feedback file.

The MCP server should expose resources such as:

- `actplane:///policy`: current policy validation and rule summary.
- `actplane:///feedback`: latest corrective feedback.
- `actplane:///status`: active backend, layer stack, attached parent PID, policy
  hash, and feedback path.

It should avoid adding policy-modifying tools. If a write path is needed later,
prefer a CLI/supervisor command that validates authority and monotonicity.

## Layered Policy Model

The policy model should be an unbounded stack or tree of layers, not a fixed
four-level hierarchy. Fixed semantics matter more than fixed depth.

```text
Layer[0]  root / ActPlane invariants
Layer[1]  user or project policy
Layer[2]  session policy
Layer[3]  main agent task policy
Layer[4]  delegated subagent policy
Layer[5]  nested delegated helper policy
...
Layer[n]  arbitrary delegated scope
```

Each layer is a delegation boundary:

```text
PolicyLayer {
  id
  parent_id
  authority
  principal
  scope
  policy_overlay
  capabilities
  created_at
  expires_at?
}
```

The effective policy for a process is:

```text
effective_policy(process) =
  merge_monotonic(
    root_invariants,
    project_policy,
    session_policy,
    delegation_chain(process)
  )
```

Monotonic merge means a child layer may:

- add rules;
- add labels;
- add gates or preconditions;
- narrow path, process, or network scope;
- upgrade effect strength from `notify` to `block` to `kill`;
- add extra provenance requirements.

A child layer may not:

- delete parent rules;
- downgrade effects;
- widen workspace or network scope;
- remove gates or preconditions;
- introduce declassify or endorse privileges not granted by a parent;
- alter parent policy, hooks, MCP config, feedback files, or audit logs;
- escape its principal or PID subtree scope.

This makes the layer system indefinitely extensible while preserving the core
security property: delegation can restrict, not escalate.

## Subagent Delegation

Main agents should be allowed to create stricter contracts for subagents without
modifying the project root policy. Subagents should not be able to modify the
main agent's policy, workspace, feedback channel, or sibling subagent state.

A future command could look like:

```bash
actplane delegate --name reviewer --policy .actplane/delegations/reviewer.yaml -- codex exec ...
```

`delegate` should:

1. verify the caller has authority to create this child layer;
2. verify the child policy is monotonic relative to its parent layer;
3. assign the subagent a principal such as `SUBAGENT/reviewer`;
4. seed the subagent process tree with the delegated layer/principal labels;
5. restrict writable workspace scope unless explicitly granted;
6. record the delegation in status/audit output.

Example intent:

```yaml
policy: |
  source SUB_REVIEWER = delegated "reviewer"

  rule subagent-readonly-main:
    kill write file "**" if SUB_REVIEWER unless target under "worktrees/reviewer/**"
    because "reviewer subagent may only write inside its delegated workspace"

  rule subagent-cannot-edit-control-plane:
    kill write file "**/actplane.yaml" if SUB_REVIEWER
    kill write file "**/.actplane/**" if SUB_REVIEWER
    kill write file "**/.mcp.json" if SUB_REVIEWER
    kill write file "**/.codex/hooks.json" if SUB_REVIEWER
    because "subagents cannot modify the policy/control plane"
```

The exact DSL surface may change, but the UX contract should not: a main agent
can give subagents stricter scopes; subagents cannot weaken or edit parent
authority.

## Feedback UX

Feedback should be optimized for agent recovery. The agent should receive:

- the rule name;
- the target operation;
- the effect actually applied: `notify`, `block`, `kill`, or `unsupported`;
- the human reason from `because`;
- whether retrying unchanged is useful;
- taint/provenance source when available;
- a short next-step instruction.

Current channel:

```text
kernel violation -> collector report -> .actplane/last-violation.txt
                 -> feedback-hook / MCP resource -> agent context
```

The formatter should use a stable machine-readable tag so supervisors can parse
it without relying on natural language:

```json
{"actplane_rule":"no-git-branch","effect":"kill","action":"kill","retry_useful":false}
```

Human text should stay concise. A good shape is:

```text
[ActPlane] Operation stopped by rule "no-git-branch".
- Operation: exec git branch
- Reason: create branches/worktrees on the host, not via the agent
- Retry: retrying unchanged will fail
- Next: use the existing branch/worktree, or ask the user to create one
```

## Control-Plane Self-Protection

ActPlane should ship default invariants that protect its own authority surface.
These should not depend on every project author remembering to write them.

Default protected paths:

- `actplane.yaml`
- `.actplane/**`
- `.mcp.json`
- `.codex/hooks.json`
- `.claude/settings*.json`
- `AGENTS.md` / `CLAUDE.md` when used as policy instructions
- audit and feedback logs

Default protected processes:

- ActPlane supervisor/enforcer processes
- active MCP auto-attach server
- policy compiler/loader during setup

The policy should allow users to override these only from a higher authority
outside the protected agent scope.

## Roadmap

Recommended order:

1. Keep `init --all`, `doctor`, MCP auto-attach, and feedback reliable.
2. Keep `actplane control status` and `.actplane/last-violation.txt` stable.
3. Add built-in control-plane self-protection.
4. Add policy layer metadata and effective policy hashes.
5. Add `actplane delegate` for subagent contracts.
6. Add policy tests/simulation for rule authoring.
7. Add append-only audit logs and replay/export commands.
8. Consider UI only after the CLI/control plane is stable.

## Non-Goals

ActPlane should avoid:

- making tool-layer preflight checks the enforcement source of truth;
- exposing broad MCP tools that mutate policy;
- letting agents start or stop root enforcement without a higher authority;
- becoming a general EDR/SIEM product;
- adding UI before the control-plane semantics are stable.
