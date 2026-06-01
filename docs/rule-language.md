# ActPlane Rule Language (Labeled Information-Flow Control) — Formal Definition & Worked Examples

> Goal: a policy language for **OS-enforced agent harnesses** whose rules are workflow, capability, and provenance policies over the agent's whole execution, not static access-control lists. Security-relevant policies are one class of policy, not the sole product framing.
>
> **Honest novelty position (see `related_work.md`)**: in-kernel cross-channel labeled information-flow *enforcement* is **not** itself new — **CamQuery (CCS'18)** already propagates a `confidential` label across process/file/network in-kernel and blocks before the action. ActPlane does **not** claim to invent that. What this DSL contributes is the combination CamQuery and the agent-guardrail tools each miss: an **agent-oriented rule model** (the source/sink/declassify classes of §3, framed around agent behaviors) on the **modern eBPF/BPF-LSM substrate** (vs CamQuery's kernel module / Linux Provenance Module), enforced **below the tool layer** so the bash/SDK escape doesn't bypass it (vs AgentSpec/Invariant), and closing the loop with **corrective semantic feedback** to a cooperative-but-forgetful agent. Tetragon gives boolean lineage + single-channel block; SLEUTH/CamFlow match-only; AgentSpec dataflow policy at the bypassable tool layer. The DSL below is the expressiveness that ties these together.

> **Status: implemented as a BPF-LSM enforcement backend with tracepoint observation.**
> - **Compiler** `collector/src/dsl/` (parse → lower to the kernel ABI `struct taint_config`): bit allocation, boolean→`req`/`forbid` masks via DNF, glob→exact/prefix/suffix/any lowering, IPv4→net/mask, gates, declassify/endorse, and the `since` staleness clause (§1.9). Unit tests cover E1–E13 compile + effect coverage.
> - **Kernel engine** `bpf/taint.h` + `taint_engine.bpf.h` + `process.bpf.c`: object+subject sources, boolean masks, declassify/endorse, lineage/after/target conditions, the `since` epoch engine (§1.9), object identity by `(dev,inode)` (§1.10), process+file+endpoint data-flow propagation (fork/exec/read/write/connect), exact/prefix/suffix/any matching, numeric IPv4 connect. It uses LSM hooks for exec, file access/mutation, and connect blocking when `bpf` LSM is active; otherwise tracepoints support `notify` reporting and explicit `kill` termination. `block` is LSM-only. Matching predicates have 30 unit tests (`test_taint.c`).
> - **Loader** `bpf/process.c` installs the compiled config, checks BPF LSM availability, and reports only `TAINT_VIOLATION` with `effect`, `blocked`, and `killed` fields.
>
> Current limitations: Positional argument predicates are handled after exec unless an argv cache is added before `bprm_check_security`; `block` on such predicates is unsupported because `block` belongs to LSM pre-op hooks, while `notify` reports and `kill` terminates the matching task after exec in tracepoint mode. Endpoint host globs require userspace DNS/SNI support because kernel connect matching is numeric IPv4. File identity uses real `(dev,inode)` in LSM mode and falls back to `(0, fnv1a(path))` in tracepoint mode (§1.10). The eager per-gate consumption set (Layer B, §1.10) is the remaining precision step and is deliberately deferred. The corrective-feedback loop is wired up through `actplane run`: rule matches the eBPF/LSM enforcer produces are formatted into `.actplane/last-violation.txt`, and the agent hook forwards that payload (see [`feedback-design.md`](feedback-design.md), [`../script/agent-feedback.md`](../script/agent-feedback.md)); the agent eval across the four conditions (C1–C4) remains.

### Enforcement Semantics

ActPlane uses **harness-level enforcement**. A matched action is enforced if it
does not complete as a useful agent action and the agent receives corrective
feedback:

- `block`: a BPF-LSM hook denies the operation before the kernel commits it
  (`-EPERM`). This is security-style pre-operation blocking. Without BPF LSM,
  `block` is unsupported and tracepoints do not evaluate it.
- `kill`: the OS immediately terminates the matching task. For exec rules that
  rely on post-exec argv observation, the new image may have started, but the
  agent action is still forced to fail.
- `notify`: report only; the action proceeds.

This distinction is intentional: ActPlane is an agent operating harness, not
only a security reference monitor. When a security claim needs pre-operation
denial, use `block` on hooks whose arguments are available before commit.

---

## 1. Model

### 1.1 Nodes (typed)
- **Process** `P(pid)` — identity attributes: `exe` (path of the executable), `comm`, `arg` (argv tokens), `uid`.
- **File** `F(path)` — identity: `path`.
- **Endpoint** `E(host, port)` — identity: `host`, `port`.

### 1.2 Labels and state
A finite set of label names `L`. The label **state** is a map
σ : Node → 2^L
i.e. every node carries a *set* of labels. Initial state: every node has ∅ unless a **source** assigns intrinsic labels (§1.4).

### 1.3 Operations (events)
The kernel observes a stream of operations; each has a process **subject** and (except fork) an **object**:

| op | subject → object | meaning |
|---|---|---|
| `fork(p, c)` | proc → proc | p creates child c |
| `exec(p, f)` | proc → file | p replaces its image with file f |
| `read(p, f)` | proc → file | p reads f |
| `write(p, f)` | proc → file | p writes/creates f |
| `unlink(p, f)` | proc → file | p deletes f |
| `connect(p, e)` | proc → endpoint | p opens a connection to e |
| `recv(p, e)` | proc → endpoint | p receives data from e |

### 1.4 Sources (label introduction)
A source gives a node *intrinsic* labels. Two forms:
- **object source**: `source L = file PAT` / `source L = endpoint PAT` — any matching file/endpoint intrinsically carries `L`. (Reading it taints the reader via propagation.)
- **subject source**: `source L = exec PAT` — a process that `exec`s a matching file acquires `L` (and passes it to descendants via fork).

### 1.5 Propagation (fixed transfer functions — the core)
Propagation is **not** policy-defined; it is the fixed semantics of flow. On each event the state updates *before* the sink check:

```
fork(p,c)    : σ(c) ∪= σ(p)                      # child inherits parent
exec(p,f)    : σ(p) ∪= σ(f) ∪ srcExec(f)         # process absorbs file + exec-source labels
read(p,f)    : σ(p) ∪= σ(f)                      # reader absorbs file labels
write(p,f)   : σ(f) ∪= σ(p)                      # written file inherits writer labels (derivation)
unlink(p,f)  : (no flow)
connect(p,e) : σ(e) ∪= σ(p)                      # egress: endpoint records writer labels
recv(p,e)    : σ(p) ∪= σ(e)                      # received data taints receiver
```

The **invariant**: `L ∈ σ(n)` iff information from some `L`-source has reached `n` through a fork/exec/read/write/recv chain — i.e. the transitive provenance closure, maintained incrementally (O(1) per event, no graph walk; this is what makes in-kernel enforcement feasible).

### 1.6 Declassification / endorsement (what makes provenance policies usable)
A blunt "tainted ⇒ deny" is unusable (everything taints, all false-positives). Two label transforms, triggered by a **gate** event:
- `declassify L by exec G` — when a process execs gate `G`, **remove** `L` from it (confidentiality release: e.g. a redactor clears `SECRET`).
- `endorse K by exec G` — when a process execs gate `G`, **add** marker `K` (integrity upgrade: e.g. human-review adds `REVIEWED`).

### 1.7 Sinks (the rules)
```
rule NAME:
  EFFECT OP TARGET-PAT [ARGS…] if Φ [unless COND]
  because "..."
```
- `EFFECT` is the action verb that starts each clause: `notify`, `block`, or `kill`.
- `OP` ∈ the operations above; `TARGET-PAT` matches the object.
- `ARGS` (optional): additional quoted strings after the target pattern are positional arguments (e.g. `exec "git" "commit"` matches git with argv containing "commit").
- `Φ` is a boolean over labels of the **subject**: `L`, `not L`, `Φ and Φ`, `Φ or Φ`, `true`.
- `COND` (optional) relaxes the rule:
  - `target PAT` — only when the object also matches PAT (positive scope), or `target not PAT` (allow-listed region).
  - `lineage-includes exec G` — **mandatory mediation**: allowed iff an ancestor (incl. self) exec'd `G`.
  - `after exec G [since EV…]` — **temporal**: allowed iff `exec G` happened earlier in this process's lineage. Plain `after` is *latching* (satisfied once `G` ever ran). The optional `since EV…` tail makes the gate go **stale** when a later invalidating event `EV` occurs (§1.9).

**Rule match**: event `op(s, o)` matches clause `EFFECT op pat if Φ unless cond` iff
`match(o, pat) ∧ Φ(σ(s)) ∧ ¬cond(s, o, history)`.
Each clause declares its own effect:

- `block` (default): deny at the BPF-LSM hook. It is unsupported in tracepoint mode.
- `notify`: report only; the operation proceeds.
- `kill`: send `SIGKILL` to the matching task. With BPF-LSM active, the hook also denies the triggering operation when the rule is evaluated before commit; from tracepoints it is harness-level termination, not pre-op blocking.

If multiple clauses/rules match the same event, the kernel chooses the strongest effect: `kill > block > notify`.

**Implicit basename matching**: if an exec target pattern contains no `/`, it is treated as a basename match. `exec "git"` is equivalent to `exec "**/git"` — it matches `/usr/bin/git`, `/opt/bin/git`, etc. Patterns containing `/` (like `exec "/usr/bin/git"` or `exec "**/deploy*"`) are used as-is.

### 1.8 Pattern matching
`PAT` is a glob over the relevant attribute: process `exe`/`comm`/`arg`, file `path`, endpoint `host`. `**` = any path span, `*` = one segment / any chars, exact otherwise. Endpoint host supports `*` suffix/prefix wildcards. For exec targets, a pattern without `/` is implicitly treated as a basename match (see §1.7).

### 1.9 Staleness (`since`): gates that re-arm when their inputs change

Plain `after exec G` is **latching**: run the gate once and it stays satisfied
forever, even after you change its inputs again. That is the trap a build system
avoids with **staleness**: `foo.o` is stale the moment `foo.c` changes after the
last build. The `since` tail gives a gate that exact behavior — it **goes stale**
when its inputs change again, and nothing more.

```
after exec "**/pytest"                       # ran pytest ever  → permanently OK
after exec "**/pytest" since write "src/**"  # ran pytest since I last edited src
```

`since Y` resets the gate whenever a `Y`-event happens later in the same lineage.
The plain-language name for it everywhere in docs and errors is **"the gate is
stale."** A `since` clause may list several invalidators
(`since write "src/**" or write "tests/**"`): any of them, occurring after the
gate, makes it stale.

**Semantics (epoch comparison, still O(1) per event).** Each gate bit is replaced
by an **epoch** (a monotonic per-lineage event counter):

```
state per process lineage:
  gate_epoch[g]   : epoch of the most recent `exec g`            (0 = never)
  inval_epoch[s]  : epoch of the most recent `since`-event s     (0 = never)

on exec(p, f):      for each gate g matching f:           gate_epoch[g]  = ++epoch
on write/read(p,f): for each since-event s matching f:    inval_epoch[s] = ++epoch
fork(p,c):          child copies both maps (same as latching gate inheritance)

condition `after exec X since Y` holds  iff
    gate_epoch[X] != 0  AND  gate_epoch[X] > inval_epoch[Y]
```

This keeps the in-kernel-enforceability argument intact: O(1) per event (no
provenance-graph walk, just counter writes and one compare at check time),
bounded state (one `u32` epoch per distinct gate and per distinct `since`-event
in the policy — a handful, not per object), and lineage-scoped (inherited at fork
exactly like labels, so "since *I* edited src" means anyone in the agent's
subtree). Engine surface: `te_sess` per-session epochs, `te_tick`/`te_stamp`,
`te_after_satisfied` in `taint_engine.bpf.h`; ABI fields
`taint_update.invals` and `taint_rule.{gate_idx,since_mask}`.
`since read PAT` bumps `inval_epoch` on **read** events as well as writes.

### 1.10 Object identity and the precision frontier

There is **one ordering primitive — the per-session monotonic epoch counter**.
You never need per-object "version numbers": the "version" of a file is just the
epoch of its last write. The real design axis is **what granularity you compare
that counter at**.

**Layer A — object identity + per-file last-write epoch (implemented).** Files
are keyed by an object identity rather than a path hash:

```
struct file_id    = { u64 ino; u32 dev; }      // real (dev,inode) in LSM mode;
                                                // (0, fnv1a(path)) fallback otherwise
struct file_state = { u64 labels; u32 last_write_epoch; }
```

In **LSM mode** the hooks carry a `struct file`/`dentry`, so we read the real
`(i_ino, s_dev)`: rename keeps provenance, overwrite is the same object, a
hardlink can't dodge a rule. In **tracepoint mode** there is no inode at
`sys_enter`, so `file_id` falls back to `(0, fnv1a(path))` — byte-for-byte the
old path-hash behavior, so nothing regresses. `last_write_epoch` is populated
only for files that already carry labels, so `ts_file` stays as sparse and
bounded as before.

**Layer B — per-gate consumption set (the precision step, deferred).** To stop
"editing `bar.py` invalidates a test that only read `foo.py`", the engine would
record which files a gate actually read and invalidate eagerly per file. The
honest catch: **precision trades against eviction-safety.** The consumed map must
be LRU-bounded; an eviction means a missed invalidation, i.e. a *false negative*
(a stale commit slips through), which is the dangerous direction. Layer A
over-approximates (any pattern-matching write invalidates) — more false
positives, never a false negative. For the cooperative-agent threat model a false
positive costs one redundant test run while a false negative ships stale code, so
Layer A's conservatism is often the correct default, and Layer B should be
**opt-in per rule** where a precision number is needed.

---

## 2. Concrete syntax (grammar)

```
policy      := decl*
decl        := source_decl | sink_decl | xform_decl
source_decl := "source" IDENT "=" node_kind PATTERN          # node_kind: file|endpoint|exec
sink_decl   := "rule" IDENT ":" clause+ ["because" STRING]
clause      := EFFECT OP target [STRING] ["if" expr] ["unless" cond]
EFFECT      := "block" | "notify" | "kill"                    # default: block
xform_decl  := ("declassify"|"endorse") IDENT "by" "exec" PATTERN
OP          := "exec"|"read"|"write"|"unlink"|"connect"|"recv"|"open"
target      := ("file"|"endpoint"|"exec") PATTERN
expr        := term (("and"|"or") term)*
term        := ["not"] IDENT | "true"
cond        := "target" ["not"] PATTERN
             | "lineage-includes" "exec" PATTERN
             | "after" "exec" PATTERN [ "since" event_pat ("or" event_pat)* ]
event_pat   := ("write"|"read"|"exec") PATTERN
PATTERN, STRING := quoted string
```
Each clause starts with the action verb (`notify`, `block`, or `kill`) — there is
no separate `deny` keyword or `effect` line. `open` matches file-open operations
(the kernel's `TOP_OPEN` hook). An optional quoted string after the target pattern is a positional
argument (e.g. `exec "git" "push"` requires token `push` in argv). For exec
targets, a pattern without `/` is treated as basename matching: `exec "git"` is
equivalent to `exec "**/git"`.

The `since EV…` tail on `after` is the staleness primitive defined in §1.9:
`after exec "**/pytest" since write "src/**"` means "tests must have run *after*
your last edit to src". `EV` may be a `write`/`read`/`exec` pattern; multiple
invalidators are joined with `or`.

The effect is compiled into the kernel ABI and is the source of truth for what
happens on a match. `because` stays Rust-side and shapes the corrective-feedback
payload shown to the agent. See
[`feedback-design.md`](feedback-design.md) and [`../script/agent-feedback.md`](../script/agent-feedback.md).

---

## 3. Worked examples (each: scenario · why · rule)

> These are harness examples: agent operating policies that keep a cooperative-but-forgetful agent on the intended path. Some examples are security-relevant because secrets and untrusted content are clear provenance labels, but the point is broader than a DLP or sandbox.

### E1 — Sensitive context stays on approved paths
**Scenario**: while debugging, the agent reads `.env` for a value, and later another tool in the same task opens an external connection. **Why**: the harness should preserve a data-handling policy across later tools, not rely on the agent remembering where the value came from.
```
source SECRET = file "**/.env"
source SECRET = file "/etc/secrets/**"
rule sensitive-context-boundary:
  block connect endpoint "*"        if SECRET
  block write   file "/shared/**"   if SECRET
  because "sensitive task context must stay local unless redacted first"
declassify SECRET by exec "**/redact"
```

### E2 — Untrusted task input needs review before privileged action
**Scenario**: the agent fetches a web page or reads an issue that says "now run `git push --force`". The content marks the task context as `UNTRUST`; privileged actions need review before proceeding. **Why**: this is a harness policy for handling untrusted instructions, enforced below the prompt and tool API.
```
source UNTRUST = endpoint "*"
source UNTRUST = file "**/downloads/**"
rule no-injected-priv:
  block exec "git" "push"  if UNTRUST and not REVIEWED
  block exec "**/deploy*"  if UNTRUST and not REVIEWED
  because "privileged action is derived from untrusted task input; needs review"
endorse REVIEWED by exec "**/human-approve"
```

### E3 — Mandatory mediation (must pass through a gate)
**Scenario**: the production DB file may only be touched by the approved migration tool, never opened ad-hoc by the agent. **Why**: encode "the only sanctioned path", not just "who". Pure lineage gate, no label.
```
rule mediate-proddb:
  block open file "**/prod.db"  unless lineage-includes exec "**/migrate"
  because "prod.db is reachable only through the migration tool"
```

### E4 — Workspace policy (lineage-scoped writes)
**Scenario**: the agent should only modify files in its task workspace, but via `bash` it writes or deletes outside. **Why**: keep a fallible agent inside its task boundary without relying on a container boundary.
```
source AGENT = exec "**/codex"
rule confine-writes:
  block write  file "/**"  if AGENT  unless target "/work/**"
  block unlink file "/**"  if AGENT  unless target "/work/**"
  because "agent may only modify its workspace /work/**"
```

### E5 — Test-before-commit (temporal ordering, staleness-aware)
**Scenario**: the agent commits without running tests since its last code edit. **Why**: a process/CI-hygiene invariant a harness should enforce, not hope for. The latching `after exec "**/pytest"` lets `edit → test → edit → commit` slip through; `since` re-arms the gate when src changes again (§1.9).
```
source AGENT = exec "**/codex"
rule test-before-commit:
  block exec "git" "commit"
    if AGENT  unless after exec "**/pytest" since write "src/**" or write "tests/**"
  because "tests are stale — you edited code after the last passing run; re-run the test suite, then commit"
```

### E6 — Read-only sub-agent capability scoping
**Scenario**: a sub-agent spawned for "research/summarize" must not write files, exec git, or open the network — its entire subtree is read-only. **Why**: least privilege scoped to a task subtree, inherited automatically over fork/exec.
```
source RESEARCH = exec "**/research-agent"
rule research-readonly:
  block write   file "/**"     if RESEARCH
  block connect endpoint "*"   if RESEARCH
  block exec    "git"          if RESEARCH
  because "research sub-agent is read-only; spawn an executor for changes"
```

### E7 — Transitive derived-data tracking (cross-process, cross-file)
**Scenario**: process A reads sensitive task context, transforms it, writes `/tmp/out.json`; later, an unrelated uploader B reads `out.json` and tries to POST it. **Why**: the data-handling policy should follow *derived* data through files and across processes, which single-event matchers cannot do.
```
# reuses E1's SECRET source + sensitive-context-boundary rule:
#   write(A,/tmp/out.json) propagates SECRET to the file;
#   read(B,/tmp/out.json)  propagates SECRET to B;
#   connect(B,*) is then a rule match even though B never touched .env.
```

### E8 — Redaction path (usability)
**Scenario**: a report legitimately needs to be sent, but only after a redactor removes sensitive fields. **Why**: shows the harness is not a blunt deny; the sanctioned path is expressible.
```
# E1 rule + `declassify SECRET by exec "**/redact"`:
#   send without running the redactor process -> blocked
#   the redactor process clears SECRET for its output path -> post-redaction connect is allowed
```

### E9 — Cross-tool / unbypassable coverage
**Scenario**: "the agent may not use git" must hold whether it calls the *git tool*, runs `bash -c 'git ...'`, or `python -c "subprocess.run(['git',...])"`. **Why**: this is the §3 claim — tool-layer guards (AgentSpec) miss the bash/SDK paths; lineage label propagation catches all three because each git lands in the agent's descendant subtree.
```
source AGENT = exec "**/codex"
rule no-git:
  block exec "git"  if AGENT
  because "this agent must not invoke git on any path"
# three traces (tool / bash / python) all produce a rule match.
```

### E10 — Provenance-scoped network allow-list
**Scenario**: a process that has handled customer records may connect only to approved internal ranges; once it carries that label, arbitrary external connections are outside the task policy. **Why**: network policy is conditioned on what data the process has handled, not just on a static process name.
```
source CUSTOMER_DATA = file "/data/customers/**"
rule customer-data-egress:
  block connect endpoint "*"               if CUSTOMER_DATA  unless target "10.0.0."
  because "customer-data task may only reach approved internal ranges"
```

### E11 — Destructive op requires a fresh confirmation gate
**Scenario**: the agent attempts `git push --force` or deletes under `/data` without a confirmation step. **Why**: gate irreversible actions behind an explicit confirmation the harness can observe. A latching `after exec "**/confirm"` would arm one confirm to authorize every later force-push; `since exec "git"` makes confirmation single-shot — any later `git` invocation makes the confirm stale again (§1.9).
```
source AGENT = exec "**/codex"
rule confirm-destructive:
  kill exec "git" "--force"  if AGENT  unless after exec "**/confirm" since exec "git"
  kill unlink file "/data/**"        if AGENT  unless after exec "**/confirm"
  because "each force-push needs a fresh confirm; a stale confirm doesn't count"
```

### E12 — Task non-interference / separation (multi-label sets)
**Scenario**: two concurrent agent tasks share a workspace; data produced under task A must not end up in task B's commit. **Why**: preserve task separation across shared tools and files; this needs label *sets*, not a single bit.
```
source TASK_A = exec "**/task-a"
source TASK_B = exec "**/task-b"
rule no-cross-task-commit:
  block exec "git" "commit"  if TASK_A and TASK_B
  because "a commit must not mix data from task A and task B"
```

### E13 — Migration-check must be fresh w.r.t. the migrations on disk
**Scenario**: the agent writes to `prod.db` after running a migration check, but edited the migrations again in between. **Why**: the check must have seen the migrations actually on disk; `since write "migrations/**"` re-arms the gate whenever migrations change (§1.9).
```
source AGENT = exec "**/codex"
rule migrate-checked:
  block write file "**/prod.db"
    if AGENT  unless after exec "**/migrate-check" since write "migrations/**"
  because "prod.db write needs a migration-check that saw the current migrations"
```

---

## 4. Why these are valuable (and where the novelty actually is)
> Caveat repeated: the *mechanism* (cross-channel taint enforced in-kernel) is CamQuery's; the novelty is the agent-oriented harness model + eBPF substrate + sub-tool-layer coverage + feedback loop. Per-example value:
- **E3, E5, E11, E13** are *mandatory-mediation / temporal* rules ("only via gate", "only after fresh tests", "only after a fresh confirm", "only after a current migration-check") that prompt instructions do not reliably preserve. The `since` staleness primitive (§1.9) is what makes "fresh" enforceable rather than latching.
- **E4, E6, E9, E12** are *lineage-scoped capability / task-boundary* rules over the fork/exec subtree.
- **E1, E7, E8, E10** are data-handling rules over **derived, cross-process, cross-channel** data. They are security-relevant, but the harness point is provenance continuity across tools.
- **E2** is an untrusted-input review rule: when task context came from outside, privileged actions require an endorsement step.
- **Declassification (E8) + endorsement (E2)** are what move this from "blunt deny" to a usable operating policy with sanctioned paths.

---

## 5. Evaluation algorithm
```
state σ : Node -> set<Label>           # proc by pid, file by path, endpoint by host:port
gates G : pid  -> set<gate-id>         # for lineage-includes / after / declassify / endorse
for ev in trace:
    apply propagation(ev) to σ          # §1.5
    apply sources(ev) to σ              # §1.4 (intrinsic labels on touched node)
    apply xforms(ev) to σ, G            # §1.6 declassify/endorse on gate exec
    for rule in policy, clause in rule:
        if clause.op == ev.op and match(ev.object, clause.target)
           and Φ(σ[ev.subject]) and not cond(ev.subject, ev.object, G, history):
              emit Violation(rule.name, ev, reason)
```
Lineage attributes (`gates`, ancestry, and the per-lineage epoch counters of §1.9) are propagated at `fork`/`exec` exactly like labels, so `lineage-includes` / `after` / `after … since` are O(1) lookups, not graph walks — preserving the in-kernel-enforceability argument.

## 6. Implementation

Two-tier (per §10.4): a userspace Rust **compiler** lowers the DSL to a flat kernel config; the **kernel** propagates taint and evaluates rules, emitting only rule matches. File policies are YAML (`actplane.yaml` / `.actplane/policy.yaml`) with an embedded `policy: |` DSL block; raw DSL is only accepted through `--rule`.

- **`collector/src/dsl/`** — `ast.rs`, `parse.rs` (DSL → AST, incl. the optional `since` tail on `after` and implicit basename matching for exec targets), `lower.rs` (AST → `struct taint_config` bytes: label/gate bit allocation, boolean→`req`/`forbid` via DNF, glob→exact/prefix/suffix/any, IPv4→net/mask, and source/xform/gate/`since` lowering into `taint_update[]`). `mod.rs::compile_str`. Tests compile E1–E13, rule effects, and the YAML corpus in `collector/test/policies/`. `main.rs` loads `actplane.yaml`, compiles its `policy: |` DSL block, spawns the loader, and prints rule matches with their reason (the feedback payload).
- **`bpf/taint.h`** — the kernel ABI (`taint_update`/`taint_rule`/`taint_config`) + libc-free matching predicates (`taint_streq`/`prefix`/`suffix`/`any`, `mask_ok`, `arg_match`), 30 unit tests in `test_taint.c`.
- **`bpf/taint_engine.bpf.h`** — label maps (proc/file/endpoint) + lineage/session gates + per-session epochs (`te_sess`, `te_tick`/`te_stamp`, `te_after_satisfied`) for §1.9 staleness + `file_id`/`file_state` object identity (§1.10) + generic update application + propagation + `te_check_labels` (bpf2bpf subprograms; pattern reads via local copies, IPv4 matched numerically — both chosen to satisfy the verifier).
- **`bpf/process.bpf.c`** — fork/exec/exit/open/mutate/connect hooks; one emitter (`emit_violation`). **`bpf/process.c`** — installs config, reports rule matches.

Engineering notes (verifier): patterns are copied rodata→local before matching (direct `volatile` reads mis-evaluate); heavy helpers are `__noinline` (stack budget); buffers are ≥ `TAINT_PAT_LEN`; argv/index access uses explicit bound guards (index masking makes clang emit a pointer-OR the verifier rejects); connect matches numeric IPv4 (no in-kernel string formatting). See the status note at the top for what is verified live and what remains.
