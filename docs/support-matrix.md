# Support Matrix and Operational Limits

This page explains what ActPlane can enforce today, what requires BPF-LSM, and
what should be reviewed with `actplane compile --explain` before use.

Always start with:

```bash
actplane compile --explain --report-out docs/actplane-review.txt
actplane doctor
```

Use `--json` for CI:

```bash
actplane compile --json > actplane-compile-report.json
```

## Effects

| Effect | What it means | Requires BPF-LSM | Use when |
| --- | --- | ---: | --- |
| `notify` | Record feedback; operation proceeds | No | Observe-first rollout, reminders, non-fatal workflow guidance |
| `block` | Pre-operation denial in a BPF-LSM hook | Yes | Security-sensitive file/network/process policy that must not commit |
| `kill` | Terminate the matching task and emit feedback | No for tracepoint-backed operations | Argv-sensitive exec rules such as `git push`, `git commit`, `git branch` |

If several clauses match one event, ActPlane chooses the strongest effect:

```text
kill > block > notify
```

## Operation Coverage

| Operation pattern | Pre-op `block` | `kill` / `notify` | Notes |
| --- | --- | --- | --- |
| `exec "git"` | Yes, with BPF-LSM | Yes | Executable identity can be denied pre-op. |
| `exec "git" "push"` | Not pre-op today | Yes | Argv-token predicates are observed after exec; use `kill`. |
| `open file PAT` | Yes, with BPF-LSM | Yes | Use for mandatory mediation and protected files. |
| `read file PAT` | Yes, with BPF-LSM | Yes | Also introduces source labels from file sources. |
| `write file PAT` | Yes, with BPF-LSM | Yes | Covers writes, creates, truncates when hooks are active. |
| `unlink file PAT` | Yes, with BPF-LSM | Yes | Use for destructive-operation policy. |
| `connect endpoint PAT` | Yes for supported endpoint forms, with BPF-LSM | Yes | Numeric IPv4 support is strongest today. |
| `recv endpoint PAT` | Yes for connected IPv4 recv, with BPF-LSM | Yes | Endpoint-source ingress support depends on hook profile. |
| Built-in control-plane guard | Yes, with BPF-LSM | Yes | Always prepended by `run`, `watch`, and MCP auto-attach. |

The last row is not an operation an operator writes. Every enforced launch
prepends one built-in rule (named `actplane-control-plane`) that blocks writes
to the loaded policy's `.actplane/` directory and to `actplane.yaml`, with only
`.actplane/runs/*` left writable for the subject's own run record. It needs no
extra hook class beyond the file-write hooks any `write file` clause selects, and
`actplane compile` omits it, so the compiled blob an operator inspects is the
policy as written rather than the running policy. The command refuses to start
rather than dropping the guard when the project path does not fit the kernel's
63-byte pattern window.

## Pattern Support

| Pattern class | Support | Notes |
| --- | --- | --- |
| Exec basename, e.g. `exec "git"` | Supported | Treated like `exec "**/git"`. |
| Exec path glob, e.g. `exec "**/pytest"` | Supported | Review lowered matchers with `compile --explain`. |
| Single argv token, e.g. `exec "git" "push"` | Supported post-exec | Use `kill` or `notify`; not pre-op `block`. |
| File exact/prefix/suffix/any globs | Supported | Real `(dev,inode)` identity in LSM mode where available. |
| Endpoint numeric IPv4, e.g. `10.0.0.` or `127.` | Supported | This is the recommended endpoint policy form today. |
| Hostname endpoint glob | Surface syntax accepted, kernel support limited | `compile --explain` reports support details. |
| IPv6 endpoint glob | Surface syntax accepted, kernel support limited | `compile --explain` reports support details. |
| Path contains/suffix in runtime deltas | Requires profile reservation | Deltas cannot introduce hook/matcher classes not reserved at load time. |

## Hook Profiles

ActPlane loads the hook classes needed by the compiled policy. Some runtime
deltas can only be accepted later if the relevant hook and matcher classes were
reserved when the engine loaded.

| Setting | Effect |
| --- | --- |
| default profile | Load the policy-selected attach set. |
| `ACTPLANE_RESERVE_FILE_FLOW=1` | Reserve file-flow hooks for later runtime deltas. |
| `ACTPLANE_ENABLE_ADVANCED_HOOKS=1` (alias `ACTPLANE_ADVANCED_TRACEPOINTS`) | Enable advanced file-flow hooks. |
| `ACTPLANE_HOOK_PROFILE=full` | Enable file flow, network, and block hook classes for future deltas. |

Use the full profile for long-running MCP/watch sessions that will accept child
domain deltas whose final policy is not known at startup.

## BPF-LSM vs Tracepoint Mode

| Capability | BPF-LSM active | Tracepoint-only mode |
| --- | --- | --- |
| Pre-op denial with `block` | Yes | No |
| Post-event `notify` | Yes | Yes |
| Post-event `kill` for supported events | Yes | Yes |
| Real file identity | Strongest | Available for many fd-backed events; fallback uses path hash |
| Argv-token exec policy | `kill`/`notify` after exec | `kill`/`notify` after exec |
| Security claim for "operation never committed" | Use `block` | Do not claim pre-op denial |
| Built-in control-plane guard | Pre-op deny | Match and feedback only |


Tracepoint-only mode is still useful for observation, corrective feedback, and
many harness-level policies. Use BPF-LSM for hard security boundaries.

Set `ACTPLANE_FORCE_TRACEPOINT=1` to force tracepoint-only mode even when
BPF-LSM is active on the host. The engine reads this flag directly
(`ebpf_ifc_engine::bpf_lsm_active`), and `compile --json` (the `host` block) and
`compile --explain` both report BPF-LSM as unavailable under it, so a `block`
clause is reported as unsupported. Use it to reproduce the tracepoint backend a
no-LSM runner uses, for example to confirm a policy still enforces its `kill`
and `notify` clauses without pre-op denial. `actplane doctor` reports the same
mode on its BPF-LSM line.

## Data-Flow Semantics

Labels propagate across:

- fork and exec lineage
- file reads and writes
- supported network receive/send paths
- supported fd duplication and IPC paths in advanced profiles

This is conservative. A process that reads a small secret value can taint later
files or processes even if some later output does not literally contain the
secret. That over-tainting is intentional: ActPlane favors preserving
provenance over silently missing a derived flow.

## Temporal Gates

`after exec G` is latching: once it has happened in a lineage, it remains true.

Use `since` for freshness:

```text
after exec "**/pytest" exits 0 since write "src/**"
```

This means the gate is valid only if `pytest` exited 0 after the latest write to
`src/**`. Any later matching write makes the gate stale.

## Runtime Deltas

Runtime deltas are append-only policy changes applied to a running engine:

```bash
actplane control delta add --target-id <domain-id> --delta policy-delta.dsl
```

Allowed delta shape:

- add local bindings
- add labels
- add gates
- add restrictions
- narrow scope
- create child domains within delegated authority

Rejected delta shape:

- remove inherited rules
- weaken parent policy
- widen scope
- remove gates (labels can be removed only through a `declassify` update, which requires `AUTH_DECLASSIFY`)
- mutate an existing rule definition
- introduce hook or matcher classes not reserved at load time

If configured, runtime-delta admission can require metadata:

```bash
actplane control delta add \
  --target-id <domain-id> \
  --delta policy-delta.dsl \
  --approved-by alice \
  --approval-ref REVIEW-123 \
  --generated-by codex
```

The current admission gate is deterministic local metadata checking. When
`verify_issued_tokens` is enabled it additionally verifies the delta's
`approval_ref` against gate tokens that the control plane has issued; the
static metadata check alone is not a cryptographic signature or external
ticket-system verifier.

## Delegation

`actplane delegate` runs one subagent under a delegated policy contract and
records a first-class `delegate` record on the run audit timeline:

```bash
sudo -E actplane delegate --name reviewer --scope readonly --template readonly-review -- sh -c 'make check'
```

The contract is optional. A bare delegation binds the subagent into a child
domain that inherits the parent policy and may only tighten it, and still
records the principal and scope. With a contract, it is exactly one of:

- a workspace confinement: the subagent's file access is confined to a
  writable path (or glob), rendered from the built-in `workspace-confinement`
  template and installed as the child-domain policy delta:

```bash
actplane delegate --name builder --workspace /work/repo/** -- cmd...
```

- a built-in template rendered into a child-domain policy delta:

- an append-only DSL fragment, from a file or inline, with the same
  admission metadata as runtime deltas:

```bash
actplane delegate --name builder --delta contract.dsl --approved-by alice -- cmd...
actplane delegate --name builder --delta-text 'source L = file "secrets/**"' -- cmd...
```

Relevant flags: `--name` (required principal), `--scope` (free-form label,
recorded only), `--workspace` (writable path confinement, enforced through
the `workspace-confinement` contract), `--template` + `--set KEY=VALUE`
(built-in contract), `--delta` / `--delta-text` (DSL-fragment contract),
`--child-id`, `--scope-id`, and the delta metadata `--approved-by`,
`--approval-ref`, `--generated-by`. The command after `--` is the subagent
argv; the
`launch_child_domain` record it is filed next to still lands on the timeline,
and the new `delegate` record carries the outcome:

```text
{"event":"delegate","status":"accepted","principal":"builder","workspace":"/work/repo/**","contract_ref":"template `workspace-confinement`", ...}
{"event":"delegate","status":"rejected","principal":"builder","error":"...", ...}
```

`actplane replay` classifies each record as a `[delegate]` step (kind
`delegate` under `--json`); a rejected contract lands on the timeline too, so
the audit history shows which subagents were admitted and which were refused.

A delegation's resource scope is the `--workspace` confinement: an actual
enforcement boundary on the subagent's file access, recorded on the `delegate`
record and rendered in the `replay` summary. The free-form `--scope` label is
recorded only and is not an enforcement boundary.

## Gate Tokens

Gate/approval tokens are the issued-token half of the admission gate. The
kernel already enforces the requirement side through `AUTH_REQUIRE_GATE`;
ActPlane manages and audits the issuance. A token is a first-class control
action, recorded on the run audit timeline as an `issue_gate_token` record:

```bash
actplane control gate issue GATE-123 --approved-by alice
actplane control gate list
```

The issued token is held in the control plane's gate-token registry. When
the runtime's `verify_issued_tokens` gate is on, a delta is admitted only if
its `approval_ref` matches a token already in that registry; an absent or
unrecognized `approval_ref` is rejected with the token reason:

```yaml
runtime:
  approval:
    append_delta:
      verify_issued_tokens: true
```

The issued-token model is opt-in and off by default. The static metadata
check (the `required` allowlist) still runs independently, so enabling
`verify_issued_tokens` layers a second, issued-reference check on top of it.

Each issuance lands on the timeline as an `issue_gate_token` record and is
classified as a `[gate_token]` step by `actplane replay`:

```text
{"event":"issue_gate_token","status":"accepted","token":"GATE-123","approved_by":"alice", ...}
```




## Attach Limits

`actplane attach --pid <pid>` is post-hoc:

```bash
sudo -E actplane attach --pid <pid>
```

It protects future events from the attached process tree, but it does not
reconstruct:

- prior file reads or writes
- prior network flows
- prior labels
- prior temporal gates
- prior ancestry outside the attached tree

For strict history from process start, use:

```bash
sudo -E actplane run -- <cmd>
```

or project MCP auto-attach:

```bash
actplane init --with-mcp
```

## Engine Pin Root

The `watch`, `mcp`, `attach`, and `run` commands all keep one engine for the
session by opening a pinned singleton engine under a single bpffs directory,
`/sys/fs/bpf/actplane/v1` (`bpf/src/lib.rs:34`). The
first process to start loads the engine and pins its maps and links there, and
later processes open the pinned objects instead of loading another engine
(`bpf/src/lib.rs:1721`). This is what lets an MCP or watch session accept child
domain deltas whose final policy is not known at startup.

Set `ACTPLANE_BPF_PIN_ROOT` to relocate that directory. The engine reads it when
it resolves the pin paths (`bpf/src/lib.rs:115`), so every process in the session
must set the same value; a process that points at a different root installs a
second engine rather than joining the first (`bpf/src/lib.rs:1988`). Use it when
bpffs is mounted somewhere other than `/sys/fs/bpf`, for example under a
container runtime that relocates it.

## Recommended Rollout

1. Generate or choose a policy.

   ```bash
   actplane init --list-templates
   actplane init --template no-git-branch --out actplane.yaml
   ```

2. Review support and limits.

   ```bash
   actplane compile --explain --report-out docs/actplane-review.txt
   actplane doctor
   ```

3. Start with `notify` or a narrow `kill` policy when possible.

4. Move to `block` only after `compile --explain` confirms BPF-LSM support for
   the relevant clauses.

5. For long-running parent/child sessions, reserve the hook profile needed by
   expected child deltas before the engine starts.

6. Keep `.actplane/last-violation.txt` with incident artifacts when a policy
   fires; it is the human-readable record of the corrective reason.
