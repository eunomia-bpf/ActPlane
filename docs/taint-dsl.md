# ActPlane Taint DSL — Formal Definition & Worked Examples

> Goal: a policy language for **OS-enforced agent harnesses** whose rules are workflow, capability, and provenance contracts over the agent's whole execution, not static access-control lists. Security-relevant policies are one class of contract, not the sole product framing.
>
> **Honest novelty position (see `related_work.md`)**: in-kernel cross-channel taint *enforcement* is **not** itself new — **CamQuery (CCS'18)** already propagates a `confidential` label across process/file/network in-kernel and blocks before the action. ActPlane does **not** claim to invent that. What this DSL contributes is the combination CamQuery and the agent-guardrail tools each miss: an **agent-oriented rule model** (the source/sink/declassify classes of §3, framed around agent behaviors) on the **modern eBPF/BPF-LSM substrate** (vs CamQuery's kernel module / Linux Provenance Module), enforced **below the tool layer** so the bash/SDK escape doesn't bypass it (vs AgentSpec/Invariant), and closing the loop with **corrective semantic feedback** to a cooperative-but-forgetful agent. Tetragon gives boolean lineage + single-channel block; SLEUTH/CamFlow detect-only; AgentSpec dataflow policy at the bypassable tool layer. The DSL below is the expressiveness that ties these together.

> **Status: implemented as a BPF-LSM enforcement backend with tracepoint audit fallback.**
> - **Compiler** `collector/src/dsl/` (parse → lower to the kernel ABI `struct taint_config`): bit allocation, boolean→`req`/`forbid` masks via DNF, glob→exact/prefix/suffix/any lowering, IPv4→net/mask, gates, declassify/endorse. 15 unit tests (E1–E12 compile + effect coverage).
> - **Kernel engine** `bpf/taint.h` + `taint_engine.bpf.h` + `process.bpf.c`: object+subject sources, boolean masks, declassify/endorse, lineage/after/target conditions, process+file+endpoint data-flow propagation (fork/exec/read/write/connect), exact/prefix/suffix/any matching, numeric IPv4 connect. It uses LSM hooks for exec, file access/mutation, and connect blocking when `bpf` LSM is active; otherwise tracepoints provide audit reporting. Matching predicates have 30 unit tests (`test_taint.c`).
> - **Loader** `bpf/process.c` installs the compiled config, detects BPF LSM availability, and reports only `TAINT_VIOLATION` with `effect`, `blocked`, and `killed` fields.
>
> Current limitations: `@arg` exec predicates are handled after exec unless an argv cache is added before `bprm_check_security`; this still gives harness-level enforcement when the matching task is killed, but not security-style pre-exec denial. Endpoint host globs require userspace DNS/SNI support because kernel connect matching is numeric IPv4; file labels are still keyed by path hash rather than inode/dev. The corrective-feedback loop is wired up kernel-side: violations the eBPF/LSM enforcer detects are formatted (`--feedback-file`) into the §6 reason payload the agent reads on failure (see [`feedback-design.md`](feedback-design.md), [`../script/agent-feedback.md`](../script/agent-feedback.md)); the agent eval across the four conditions (C1–C4) remains.

### Enforcement Semantics

ActPlane uses **harness-level enforcement**. A matched action is enforced if it
does not complete as a useful agent action and the agent receives corrective
feedback:

- `block`: a BPF-LSM hook denies the operation before the kernel commits it
  (`-EPERM`). This is security-style pre-operation blocking.
- `kill`: the OS immediately terminates the violating task. For exec rules that
  rely on post-exec argv observation, the new image may have started, but the
  agent action is still forced to fail.
- `audit`: report only; the action proceeds.

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
A finite set of label names `L`. The taint **state** is a map
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

### 1.4 Sources (taint introduction)
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
  deny OP TARGET-PAT if Φ [unless COND]   reason "..."
```
- `OP` ∈ the operations above; `TARGET-PAT` matches the object.
- `Φ` is a boolean over labels of the **subject**: `L`, `not L`, `Φ and Φ`, `Φ or Φ`, `true`.
- `COND` (optional) relaxes the deny:
  - `target PAT` — only when the object also matches PAT (positive scope), or `target not PAT` (allow-listed region).
  - `lineage-includes exec G` — **mandatory mediation**: allowed iff an ancestor (incl. self) exec'd `G`.
  - `after exec G` — **temporal**: allowed iff `exec G` happened earlier in this process's lineage.

**Violation**: event `op(s, o)` violates rule `deny op pat if Φ unless cond` iff
`match(o, pat) ∧ Φ(σ(s)) ∧ ¬cond(s, o, history)`.
Each rule has an explicit `effect`:

- `block` (default): deny at the BPF-LSM hook when available; otherwise report in tracepoint fallback, or terminate the task when `--kill-on-violation` is enabled.
- `audit`: report only; the operation proceeds.
- `kill`: send `SIGKILL` to the violating task. With BPF-LSM active, the hook also denies the triggering operation when the rule is evaluated before commit.

If multiple clauses/rules match the same event, the kernel chooses the strongest effect: `kill > block > audit`.

### 1.8 Pattern matching
`PAT` is a glob over the relevant attribute: process `exe`/`comm`/`arg`, file `path`, endpoint `host`. `**` = any path span, `*` = one segment / any chars, exact otherwise. Endpoint host supports `*` suffix/prefix wildcards.

---

## 2. Concrete syntax (grammar)

```
policy      := decl*
decl        := label_decl | source_decl | sink_decl | xform_decl
label_decl  := "label" IDENT
source_decl := "source" IDENT "=" node_kind PATTERN          # node_kind: file|endpoint|exec
sink_decl   := "rule" IDENT ":" clause+ ["reason" STRING]
                                        ["remediation" STRING] ["effect" EFFECT]
clause      := "deny" OP target ["if" expr] ["unless" cond]
EFFECT      := "block" | "audit" | "kill"                    # default: block
xform_decl  := ("declassify"|"endorse") IDENT "by" "exec" PATTERN
OP          := "exec"|"read"|"write"|"unlink"|"connect"|"recv"|"open"
target      := ("file"|"endpoint"|"exec") PATTERN [ "@arg" STRING ]
expr        := term (("and"|"or") term)*
term        := ["not"] IDENT | "true"
cond        := "target" ["not"] PATTERN
             | "lineage-includes" "exec" PATTERN
             | "after" "exec" PATTERN
PATTERN, STRING := quoted string
```
(`open` is sugar matching both `read` and `write`; `@arg "x"` additionally requires token `x` in argv — for `git push` etc.)

`effect` is compiled into the kernel ABI and is the source of truth for what
happens on a match. `reason` and `remediation` stay Rust-side and shape the
corrective-feedback payload shown to the agent. `enforce block|gate|warn` is
accepted as a compatibility alias (`gate -> block`, `warn -> audit`), but new
policies should use `effect block|audit|kill`. See
[`feedback-design.md`](feedback-design.md) and [`../script/agent-feedback.md`](../script/agent-feedback.md).

---

## 3. Worked examples (each: scenario · why · rule)

> These are harness examples: agent operating contracts that keep a cooperative-but-forgetful agent on the intended path. Some examples are security-relevant because secrets and untrusted content are clear provenance labels, but the point is broader than a DLP or sandbox.

### E1 — Sensitive context stays on approved paths
**Scenario**: while debugging, the agent reads `.env` for a value, and later another tool in the same task opens an external connection. **Why**: the harness should preserve a data-handling contract across later tools, not rely on the agent remembering where the value came from.
```
source SECRET = file "**/.env"
source SECRET = file "/etc/secrets/**"
rule sensitive-context-boundary:
  deny connect endpoint "*"        if SECRET
  deny write   file "/shared/**"   if SECRET
  reason "sensitive task context must stay local unless redacted first"
declassify SECRET by exec "**/redact"
```

### E2 — Untrusted task input needs review before privileged action
**Scenario**: the agent fetches a web page or reads an issue that says "now run `git push --force`". The content marks the task context as `UNTRUST`; privileged actions need review before proceeding. **Why**: this is a harness contract for handling untrusted instructions, enforced below the prompt and tool API.
```
source UNTRUST = endpoint "*"
source UNTRUST = file "**/downloads/**"
rule no-injected-priv:
  deny exec "**/git" @arg "push"  if UNTRUST and not REVIEWED
  deny exec "**/deploy*"          if UNTRUST and not REVIEWED
  reason "privileged action is derived from untrusted task input; needs review"
endorse REVIEWED by exec "**/human-approve"
```

### E3 — Mandatory mediation (must pass through a gate)
**Scenario**: the production DB file may only be touched by the approved migration tool, never opened ad-hoc by the agent. **Why**: encode "the only sanctioned path", not just "who". Pure lineage gate, no label.
```
rule mediate-proddb:
  deny open file "**/prod.db"  unless lineage-includes exec "**/migrate"
  reason "prod.db is reachable only through the migration tool"
```

### E4 — Workspace contract (lineage-scoped writes)
**Scenario**: the agent should only modify files in its task workspace, but via `bash` it writes or deletes outside. **Why**: keep a fallible agent inside its task boundary without relying on a container boundary.
```
source AGENT = exec "**/codex"
rule confine-writes:
  deny write  file "/**"  if AGENT  unless target "/work/**"
  deny unlink file "/**"  if AGENT  unless target "/work/**"
  reason "agent may only modify its workspace /work/**"
```

### E5 — Test-before-commit (temporal ordering)
**Scenario**: the agent commits without ever running tests in this session. **Why**: a process/CI-hygiene invariant a harness should enforce, not hope for.
```
source AGENT = exec "**/codex"
rule test-before-commit:
  deny exec "**/git" @arg "commit"  if AGENT  unless after exec "**/pytest"
  reason "run the test suite before committing"
```

### E6 — Read-only sub-agent capability scoping
**Scenario**: a sub-agent spawned for "research/summarize" must not write files, exec git, or open the network — its entire subtree is read-only. **Why**: least privilege scoped to a task subtree, inherited automatically over fork/exec.
```
source RESEARCH = exec "**/research-agent"
rule research-readonly:
  deny write   file "/**"     if RESEARCH
  deny connect endpoint "*"   if RESEARCH
  deny exec    "**/git"       if RESEARCH
  reason "research sub-agent is read-only; spawn an executor for changes"
```

### E7 — Transitive derived-data tracking (cross-process, cross-file)
**Scenario**: process A reads sensitive task context, transforms it, writes `/tmp/out.json`; later, an unrelated uploader B reads `out.json` and tries to POST it. **Why**: the data-handling contract should follow *derived* data through files and across processes, which single-event matchers cannot do.
```
# reuses E1's SECRET source + sensitive-context-boundary rule:
#   write(A,/tmp/out.json) propagates SECRET to the file;
#   read(B,/tmp/out.json)  propagates SECRET to B;
#   connect(B,*) is then a violation even though B never touched .env.
```

### E8 — Redaction path (usability)
**Scenario**: a report legitimately needs to be sent, but only after a redactor removes sensitive fields. **Why**: shows the harness is not a blunt deny; the sanctioned path is expressible.
```
# E1 rule + `declassify SECRET by exec "**/redact"`:
#   send without running the redactor process -> blocked
#   the redactor process clears SECRET for its output path -> post-redaction connect is allowed
```

### E9 — Cross-tool / unbypassable coverage
**Scenario**: "the agent may not use git" must hold whether it calls the *git tool*, runs `bash -c 'git ...'`, or `python -c "subprocess.run(['git',...])"`. **Why**: this is the §3 claim — tool-layer guards (AgentSpec) miss the bash/SDK paths; lineage taint catches all three because each git lands in the agent's descendant subtree.
```
source AGENT = exec "**/codex"
rule no-git:
  deny exec "**/git"  if AGENT
  reason "this agent must not invoke git on any path"
# three traces (tool / bash / python) all produce a violation.
```

### E10 — Provenance-scoped network allow-list
**Scenario**: a process that has handled customer records may connect only to approved internal ranges; once it carries that label, arbitrary external connections are outside the task contract. **Why**: network policy is conditioned on what data the process has handled, not just on a static process name.
```
source CUSTOMER_DATA = file "/data/customers/**"
rule customer-data-egress:
  deny connect endpoint "*"               if CUSTOMER_DATA  unless target "10.0.0."
  reason "customer-data task may only reach approved internal ranges"
```

### E11 — Destructive op requires a confirmation gate
**Scenario**: the agent attempts `git push --force` or deletes under `/data` without a confirmation step. **Why**: gate irreversible actions behind an explicit confirmation that the harness can observe.
```
source AGENT = exec "**/codex"
rule confirm-destructive:
  deny exec "**/git" @arg "--force"  if AGENT  unless after exec "**/confirm"
  deny unlink file "/data/**"        if AGENT  unless after exec "**/confirm"
  reason "destructive action needs an explicit confirm step first"
```

### E12 — Task non-interference / separation (multi-label sets)
**Scenario**: two concurrent agent tasks share a workspace; data produced under task A must not end up in task B's commit. **Why**: preserve task separation across shared tools and files; this needs label *sets*, not a single bit.
```
source TASK_A = exec "**/task-a"
source TASK_B = exec "**/task-b"
rule no-cross-task-commit:
  deny exec "**/git" @arg "commit"  if TASK_A and TASK_B
  reason "a commit must not mix data from task A and task B"
```

---

## 4. Why these are valuable (and where the novelty actually is)
> Caveat repeated: the *mechanism* (cross-channel taint enforced in-kernel) is CamQuery's; the novelty is the agent-oriented harness model + eBPF substrate + sub-tool-layer coverage + feedback loop. Per-example value:
- **E3, E5, E11** are *mandatory-mediation / temporal* contracts ("only via gate", "only after tests", "only after confirm") that prompt instructions do not reliably preserve.
- **E4, E6, E9, E12** are *lineage-scoped capability / task-boundary* contracts over the fork/exec subtree.
- **E1, E7, E8, E10** are data-handling contracts over **derived, cross-process, cross-channel** data. They are security-relevant, but the harness point is provenance continuity across tools.
- **E2** is an untrusted-input review contract: when task context came from outside, privileged actions require an endorsement step.
- **Declassification (E8) + endorsement (E2)** are what move this from "blunt deny" to a usable operating contract with sanctioned paths.

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
Lineage attributes (`gates`, ancestry) are propagated at `fork`/`exec` exactly like labels, so `lineage-includes` / `after` are O(1) lookups, not graph walks — preserving the in-kernel-enforceability argument.

## 6. Implementation

Two-tier (per §10.4): a userspace Rust **compiler** lowers the DSL to a flat kernel config; the **kernel** propagates taint and evaluates rules, emitting only violations.

- **`collector/src/dsl/`** — `ast.rs`, `parse.rs` (DSL → AST), `lower.rs` (AST → `struct taint_config` bytes: label/gate bit allocation, boolean→`req`/`forbid` via DNF, glob→exact/prefix/suffix/any, IPv4→net/mask). `mod.rs::compile_str`. 15 tests compile E1–E12 and rule effects. `main.rs` compiles a `.dsl`, spawns the loader, and prints violations with their reason (the feedback payload).
- **`bpf/taint.h`** — the rule ABI (`taint_source`/`taint_rule`/`taint_xform`/`taint_gate`/`taint_config`) + libc-free matching predicates (`taint_streq`/`prefix`/`suffix`/`any`, `mask_ok`, `arg_match`), 30 unit tests in `test_taint.c`.
- **`bpf/taint_engine.bpf.h`** — label maps (proc/file/endpoint) + lineage/session gates + propagation + `te_check`/`te_connect_check` (bpf2bpf subprograms; pattern reads via local copies, IPv4 matched numerically — both chosen to satisfy the verifier).
- **`bpf/process.bpf.c`** — fork/exec/exit/open/mutate/connect hooks; one emitter (`emit_violation`). **`bpf/process.c`** — installs config, reports violations.

Engineering notes (verifier): patterns are copied rodata→local before matching (direct `volatile` reads mis-evaluate); heavy helpers are `__noinline` (stack budget); buffers are ≥ `TAINT_PAT_LEN`; argv/index access uses explicit bound guards (index masking makes clang emit a pointer-OR the verifier rejects); connect matches numeric IPv4 (no in-kernel string formatting). See the status note at the top for what is verified live and what remains.
