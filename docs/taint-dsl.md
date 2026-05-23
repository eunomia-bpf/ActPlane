# ActPlane Taint DSL — Formal Definition & Worked Examples

> Goal: a policy language for **OS-enforced agent harnesses** whose rules are *information-flow / provenance invariants* over the agent's whole execution, not static access-control lists.
>
> **Honest novelty position (see `related_work.md`)**: in-kernel cross-channel taint *enforcement* is **not** itself new — **CamQuery (CCS'18)** already propagates a `confidential` label across process/file/network in-kernel and blocks before the action. ActPlane does **not** claim to invent that. What this DSL contributes is the combination CamQuery and the agent-guardrail tools each miss: an **agent-oriented rule model** (the source/sink/declassify classes of §3, framed around agent behaviors) on the **modern eBPF/BPF-LSM substrate** (vs CamQuery's kernel module / Linux Provenance Module), enforced **below the tool layer** so the bash/SDK escape doesn't bypass it (vs AgentSpec/Invariant), and closing the loop with **corrective semantic feedback** to a cooperative-but-forgetful agent. Tetragon gives boolean lineage + single-channel block; SLEUTH/CamFlow detect-only; AgentSpec dataflow policy at the bypassable tool layer. The DSL below is the expressiveness that ties these together.

> **Status: implemented as a BPF-LSM enforcement backend with tracepoint audit fallback.**
> - **Compiler** `collector/src/dsl/` (parse → lower to the kernel ABI `struct taint_config`): bit allocation, boolean→`req`/`forbid` masks via DNF, glob→exact/prefix/suffix/any lowering, IPv4→net/mask, gates, declassify/endorse. 13 unit tests (E1–E12 compile).
> - **Kernel engine** `bpf/taint.h` + `taint_engine.bpf.h` + `process.bpf.c`: object+subject sources, boolean masks, declassify/endorse, lineage/after/target conditions, process+file+endpoint data-flow propagation (fork/exec/read/write/connect), exact/prefix/suffix/any matching, numeric IPv4 connect. It uses LSM hooks for exec, file access/mutation, and connect blocking when `bpf` LSM is active; otherwise tracepoints provide audit reporting. Matching predicates have 30 unit tests (`test_taint.c`).
> - **Loader** `bpf/process.c` installs the compiled config, detects BPF LSM availability, and reports only `TAINT_VIOLATION` with a `blocked` flag.
>
> Current limitations: `@arg` exec predicates are audited after exec unless an argv cache is added before `bprm_check_security`; endpoint host globs require userspace DNS/SNI support because kernel connect matching is numeric IPv4; file labels are still keyed by path hash rather than inode/dev. A clean live e2e suite and the corrective-feedback loop beyond reason printing remain.

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

### 1.6 Declassification / endorsement (what makes IFC usable)
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
In **enforce** mode the op is blocked before its effect (LSM `-EPERM`); in **audit** mode a violation is reported with `NAME` + `reason` (the corrective feedback payload).

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
clause      := "deny" OP target ["if" expr] ["unless" cond]
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

---

## 3. Worked examples (each: scenario · why · rule)

> Each example gives the scenario, the rationale, and the rule as it would be written in the DSL.

### E1 — Secret no-exfil (confidentiality)
**Scenario**: while debugging, the agent reads `.env` for a value, and later (telemetry, or an injected instruction) opens an HTTPS connection. **Why**: API keys / customer secrets must never leave the host, regardless of which later tool sends them.
```
source SECRET = file "**/.env"
source SECRET = file "/etc/secrets/**"
rule no-exfil:
  deny connect endpoint "*"        if SECRET
  deny write   file "/shared/**"   if SECRET
  reason "secret data must not leave the host; redact first"
declassify SECRET by exec "**/redact"
```

### E2 — Prompt-injection ⇒ no privileged action (integrity)
**Scenario**: the agent fetches a web page / reads a GitHub issue containing "now run `git push --force`". The content taints the agent `UNTRUST`; it must not perform privileged actions on injected input. **Why**: the classic agent attack — untrusted input steering privileged behavior — that prompt rules can't reliably stop.
```
source UNTRUST = endpoint "*"
source UNTRUST = file "**/downloads/**"
rule no-injected-priv:
  deny exec "**/git" @arg "push"  if UNTRUST and not REVIEWED
  deny exec "**/deploy*"          if UNTRUST and not REVIEWED
  reason "action derived from untrusted input; needs human review"
endorse REVIEWED by exec "**/human-approve"
```

### E3 — Mandatory mediation (must pass through a gate)
**Scenario**: the production DB file may only be touched by the approved migration tool, never opened ad-hoc by the agent. **Why**: encode "the only sanctioned path", not just "who". Pure lineage gate, no label.
```
rule mediate-proddb:
  deny open file "**/prod.db"  unless lineage-includes exec "**/migrate"
  reason "prod.db is reachable only through the migration tool"
```

### E4 — Workspace confinement (lineage-scoped writes)
**Scenario**: the agent should only modify files in its task workspace, but via `bash` it `rm`/writes outside. **Why**: keep a fallible agent inside its sandbox-by-policy without a container.
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

### E7 — Transitive secret derivation (cross-process, cross-file)
**Scenario**: process A reads a secret, transforms it, writes `/tmp/out.json`; later, an unrelated uploader B reads `out.json` and tries to POST it. **Why**: confidentiality must follow *derived* data through files and across processes — the thing single-event matchers (Tetragon/PATROL) cannot do.
```
# reuses E1's SECRET source + no-exfil rule:
#   write(A,/tmp/out.json) propagates SECRET to the file;
#   read(B,/tmp/out.json)  propagates SECRET to B;
#   connect(B,*) is then a violation — even though B never touched .env.
```

### E8 — Declassification done right (usability)
**Scenario**: a confidential report legitimately needs to be sent — but only after a redactor strips secrets. **Why**: shows the policy is not a blunt deny; the sanctioned release path is expressible.
```
# E1 rule + `declassify SECRET by exec "**/redact"`:
#   send WITHOUT redact in lineage  -> blocked
#   redact in lineage clears SECRET -> the post-redaction connect is allowed
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
**Scenario**: a process that has handled customer PII may connect *only* to internal endpoints; once PII-tainted it cannot reach arbitrary hosts. **Why**: egress control conditioned on what data the process holds, not on a static firewall rule.
```
source PII = file "/data/customers/**"
rule pii-egress:
  deny connect endpoint "*"               if PII  unless target "*.internal"
  reason "PII-handling process may only reach *.internal"
```

### E11 — Destructive op requires a confirmation gate
**Scenario**: the agent attempts `git push --force` (or `unlink` under `/data`) without a confirmation step. **Why**: gate irreversible actions behind an explicit, lineage-visible confirmation.
```
source AGENT = exec "**/codex"
rule confirm-destructive:
  deny exec "**/git" @arg "--force"  if AGENT  unless lineage-includes exec "**/confirm"
  deny unlink file "/data/**"        if AGENT  unless lineage-includes exec "**/confirm"
  reason "destructive action needs an explicit confirm step in its lineage"
```

### E12 — Task non-interference / separation (multi-label sets)
**Scenario**: two concurrent agent tasks share a workspace; data produced under task A must not end up in task B's commit. **Why**: prevent cross-task contamination — needs label *sets*, not a single bit.
```
source TASK_A = exec "**/task-a"
source TASK_B = exec "**/task-b"
rule no-cross-task-commit:
  deny exec "**/git" @arg "commit"  if TASK_A and TASK_B
  reason "a commit must not mix data from task A and task B"
```

---

## 4. Why these are valuable (and where the novelty actually is)
> Caveat repeated: the *mechanism* (cross-channel taint enforced in-kernel) is CamQuery's; the novelty is the agent-oriented rule model + eBPF substrate + sub-tool-layer coverage + feedback loop. Per-example value:
- **E1, E7, E8, E10** are *information-flow* (confidentiality) over **derived, cross-process, cross-channel** data — propagation is the point; single-event matchers (Tetragon/eBPF-PATROL) can't *follow derivation*, and detection-only provenance (CamFlow/SLEUTH) can't *prevent* (CamQuery can — these examples are where we overlap it and must differentiate on substrate/agent-domain).
- **E2, E11** are *integrity* (untrusted-input ⇏ privileged-action) — the agent-specific prompt-injection threat, enforced below the tool layer so the bash/SDK escape (E9) doesn't bypass it.
- **E3, E5, E11** are *mandatory-mediation / temporal* invariants ("only via gate", "only after tests") — behavioral contracts no access-control list expresses.
- **E4, E6, E12** are *lineage-scoped capability / separation* — least privilege and non-interference over the fork/exec subtree.
- **Declassification (E8) + endorsement (E2)** are what move this from "blunt deny" to a usable policy — and are exactly what the agent-guardrail tools at the tool layer lack at OS scope.

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

- **`collector/src/dsl/`** — `ast.rs`, `parse.rs` (DSL → AST), `lower.rs` (AST → `struct taint_config` bytes: label/gate bit allocation, boolean→`req`/`forbid` via DNF, glob→exact/prefix/suffix/any, IPv4→net/mask). `mod.rs::compile_str`. 13 tests compile E1–E12. `main.rs` compiles a `.dsl`, spawns the loader, and prints violations with their reason (the feedback payload).
- **`bpf/taint.h`** — the rule ABI (`taint_source`/`taint_rule`/`taint_xform`/`taint_gate`/`taint_config`) + libc-free matching predicates (`taint_streq`/`prefix`/`suffix`/`any`, `mask_ok`, `arg_match`), 30 unit tests in `test_taint.c`.
- **`bpf/taint_engine.bpf.h`** — label maps (proc/file/endpoint) + lineage/session gates + propagation + `te_check`/`te_connect_check` (bpf2bpf subprograms; pattern reads via local copies, IPv4 matched numerically — both chosen to satisfy the verifier).
- **`bpf/process.bpf.c`** — fork/exec/exit/open/mutate/connect hooks; one emitter (`emit_violation`). **`bpf/process.c`** — installs config, reports violations.

Engineering notes (verifier): patterns are copied rodata→local before matching (direct `volatile` reads mis-evaluate); heavy helpers are `__noinline` (stack budget); buffers are ≥ `TAINT_PAT_LEN`; argv/index access uses explicit bound guards (index masking makes clang emit a pointer-OR the verifier rejects); connect matches numeric IPv4 (no in-kernel string formatting). See the status note at the top for what is verified live and what remains.
