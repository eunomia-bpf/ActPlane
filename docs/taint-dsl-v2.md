# ActPlane Taint DSL v2 — Staleness-Aware Contracts

> **Status: implemented (Tier 1 `since` + Layer A object identity).**
> - `since` clause: parser/AST, ABI (`taint_inval`,
>   `taint_rule.{gate_idx,since_mask}`, `taint_config.invals`), epoch engine
>   (`te_sess` per-session epochs, `te_tick`/`te_stamp`, `te_inval_hits`,
>   `te_after_satisfied`).
> - Layer A (§4): `ts_file` keyed by `struct file_id` `{ino,dev}` with
>   `struct file_state {labels,last_write_epoch}`; real `(dev,inode)` in LSM
>   mode, `(0,fnv1a(path))` fallback in tracepoint mode.
>
> Both pass the kernel verifier and load live. Covered by `dsl/mod.rs`
> (E5′/E11′/E13 + reject tests) and the live `E5b … goes stale (since)` e2e
> case; all of E1–E12 still pass in tracepoint mode (no regression). Layer B
> (per-gate consumption set) is the remaining precision step — see §4, and note
> it is deliberately deferred / opt-in.

> v2 is a **superset** of v1 ([`taint-dsl.md`](taint-dsl.md)). Every v1 policy
> compiles and runs unchanged. v2 adds exactly **one new core primitive** plus
> the engine work that makes it correct. The point is not "more syntax" — it is
> closing the one gap that the related-work survey ([`related/`](related/)) leaves
> open.

## 0. Why v2 exists (the one-sentence version)

v1's `after exec X` is **latching**: run the gate once and it stays satisfied
forever, even after you change its inputs again. That is the same trap a build
system avoids with **staleness**: `foo.o` is stale the moment `foo.c` changes
after the last build. v2 gives ActPlane that one missing idea — a gate that
**goes stale** when its inputs change again — and nothing else.

```
v1:  after exec "**/pytest"              # ran pytest ever  → permanently OK
v2:  after exec "**/pytest"
       since write "src/**"              # ran pytest since I last edited src
```

`since Y` resets the gate whenever a `Y`-event happens later in the same lineage.
That is the whole feature. Plain name for it everywhere in docs and errors:
**"the gate is stale."** No "version-scoped obligation," no "contract automata."

## 1. Where this sits vs prior art (honest boundary)

From the downloaded papers in [`related/`](related/):

| System | Layer | Ordering / "must do X first" | Goes stale when input changes again? |
|---|---|---|---|
| Agent-C (`2512.23738`) | tool-call | yes (temporal LTL-style) | **no** — over tool-call sequence, not OS objects |
| AgentSpec (`2503.18666`) | tool-call | trigger/predicate | no |
| Progent (`2504.11703`) | tool-call | privilege narrowing | no |
| FIDES / CaMeL (`2505.23643`, `2503.18813`) | tool-call | IFC labels | no |
| CamQuery (`1808.06049`) | **kernel** | provenance queries | has object *versioning*, but no agent **obligation** |
| ActPlane v1 | **kernel, below tool layer** | `after` (latching) | **no** |
| **ActPlane v2** | **kernel, below tool layer** | `after … since …` | **yes** |

The unoccupied cell is the last row: *staleness-aware workflow obligations,
enforced on real OS objects, below the tool boundary.* Agent-C has ordering but
no OS objects and no staleness; CamQuery has object versions but no agent
obligation. v2 is exactly their product. Everything else in this DSL is
deliberately **not** claimed as novel.

## 2. New grammar (diff against v1 §2)

Only the `after` condition changes; one optional `since` tail is added.

```
cond        := "target" ["not"] PATTERN
             | "lineage-includes" "exec" PATTERN
             | "after" "exec" PATTERN [ since_clause ]      # ← since_clause is new
since_clause := "since" event_pat ("or" event_pat)*
event_pat    := ("write" | "read" | "exec") PATTERN
```

- `since` is optional. `after exec X` with no `since` keeps v1's latching
  semantics byte-for-byte.
- `since` may list several invalidators (`since write "src/**" or write "tests/**"`):
  any of them, occurring after the gate, makes it stale.

No other production changes. `source`, `rule`, `declassify`, `endorse`,
`effect`, `reason`, `remediation`, `@arg`, `target`, `lineage-includes` are all
unchanged.

## 3. Semantics (epoch comparison, still O(1) per event)

v1 tracks gates as **latching bits** propagated at fork/exec. v2 replaces the
bit with an **epoch** (a monotonic per-lineage event counter):

```
state per process lineage:
  gate_epoch[g]   : epoch of the most recent `exec g`            (0 = never)
  inval_epoch[s]  : epoch of the most recent `since`-event s     (0 = never)

on exec(p, f):     for each gate g matching f:  gate_epoch[g]  = ++epoch
on write/read(p,f):for each since-event s matching f: inval_epoch[s] = ++epoch
fork(p,c):         child copies both maps (same as v1 gate inheritance)

condition `after exec X since Y` holds  iff
    gate_epoch[X] != 0  AND  gate_epoch[X] > inval_epoch[Y]
```

Properties that keep the in-kernel-enforceability argument from v1 §5 intact:

- **O(1) per event** — no provenance-graph walk; just counter writes and one
  compare at check time.
- **Bounded state** — one `u32` epoch per distinct gate and per distinct
  `since`-event in the policy (a handful), not per object. Replaces the v1 gate
  bitmask; net per-proc state grows from bits to a small `u32[]`.
- **Lineage-scoped** — inherited at fork exactly like v1 gates, so "since *I*
  edited src" means anyone in the agent's subtree, which is the threat model.

### 3.1 ABI impact (read before touching `taint.h`)

This is the only place v2 is not free:

- `taint_gate` / the per-proc gate field in `taint_engine.bpf.h` change from a
  **bitmask** to a small **epoch array**. That is an ABI change → `lower.rs`
  `#[repr(C)]` mirrors must move in lockstep, and the `fixed-size` test in
  `dsl/mod.rs` must be updated (see CLAUDE.md "Critical: the Rust↔C ABI").
- The global/per-lineage `epoch` counter is new engine state; a `u32` is enough
  for any realistic agent run and wraps harmlessly (compares are relative).
- `since read PAT` requires the engine to bump `inval_epoch` on **read** events,
  which today only propagate labels — a one-line addition to the read hook.

## 4. Object identity & the precision frontier (honest version)

There is **one ordering primitive — the per-session monotonic `epoch` counter**.
You never need per-object "version numbers": the "version" of a file is just the
epoch of its last write. The real design axis is **what granularity you compare
that counter at**, and each step has a clear cost.

### Layer A — object identity + per-file last-write epoch (implemented)

v1 keyed files by `fnv1a(path)`. That lies under rename / overwrite / hardlink.
Layer A keys `ts_file` by an object identity instead:

```
struct file_id  = { u64 ino; u32 dev; }        // real (dev,inode) when the hook
                                                // has an inode (LSM mode);
                                                // (0, fnv1a(path)) as fallback
struct file_state = { u64 labels; u32 last_write_epoch; }
```

- In **LSM mode** the hooks carry a `struct file`/`dentry`, so we read the real
  `(i_ino, s_dev)` — fixing the path-hash limitation: rename keeps provenance,
  overwrite is the same object, a hardlink can't dodge a rule.
- In **tracepoint mode** there is no inode at `sys_enter`, so `file_id` falls
  back to `(0, fnv1a(path))` — **byte-for-byte the old behavior**, so nothing
  regresses (verified: all E1–E12 + E5b still pass live in tracepoint mode).
- `last_write_epoch` is populated only for files that already carry labels (so
  `ts_file` stays exactly as sparse/bounded as before). It is infrastructure for
  Layer B; nothing reads it yet.

Layer A on its own does **not** change `since` precision — the sink (commit)
still can't enumerate which files a gate read. It is the prerequisite + an
independent bug fix.

### Layer B — per-gate consumption set (the precision step, NOT built)

To stop "editing `bar.py` invalidates the test that only read `foo.py`", you must
record **which files the gate actually read** and invalidate eagerly:

- gate read of a file matching the `since` pattern → record `consumed[(root,
  file_id)] = {gate_mask, epoch}` (an LRU map; this is the only state that scales
  with files).
- any later write to that `file_id` with a newer epoch → set a per-session
  `stale_gates` bit for those gates.
- sink check → just test the gate's `stale_gates` bit (still O(1), no scan).

The honest catch: **precision trades against eviction-safety.** The consumed map
must be LRU-bounded; an eviction → a missed invalidation → a *false negative*
(a stale commit slips through), which is the dangerous direction. Tier-1 / Layer
A `since` over-approximates (any pattern-matching write invalidates) — more false
positives, but **never** a false negative.

For the cooperative-agent threat model a false positive costs one redundant test
run; a false negative ships stale code. So Layer A's conservatism is often the
*correct* tradeoff, and Layer B should be **opt-in per rule**, used where the
precision eval needs the number — not the default. This frontier (precision vs
eviction-safety) is itself a result worth plotting, not a detail to hide.

## 5. Examples that v2 fixes (diff against v1 §3)

### E5′ — test-before-commit, now staleness-aware
```
source AGENT = exec "**/codex"
rule test-before-commit:
  deny exec "**/git" @arg "commit"
    if AGENT
    unless after exec "**/pytest" since write "src/**" or write "tests/**"
  effect block
  reason "tests are stale — you edited code after the last passing run"
  remediation "re-run the test suite, then commit"
```
v1 let `edit → test → edit → commit` through. v2 blocks it: the second edit
bumps `inval_epoch` past `gate_epoch[pytest]`.

### E11′ — confirm-destructive, re-armed per attempt
```
source AGENT = exec "**/codex"
rule confirm-destructive:
  deny exec "**/git" @arg "--force"
    if AGENT
    unless after exec "**/confirm" since exec "**/git"
  effect kill
  reason "each force-push needs a fresh confirm; a stale confirm doesn't count"
```
v1's `after exec confirm` armed one confirm to authorize every later force-push.
v2 makes confirmation **single-shot**: any later `git` invocation makes the
confirm stale again.

### E13 — migration-check before touching prod (new in v2)
```
source AGENT = exec "**/codex"
rule migrate-checked:
  deny write file "**/prod.db"
    if AGENT
    unless after exec "**/migrate-check" since write "migrations/**"
  effect block
  reason "prod.db write needs a migration-check that saw the current migrations"
```
Pure v2: the check must be fresh w.r.t. the migrations actually on disk.

## 6. What v2 does *not* add (scope discipline)

Deliberately left out, to keep the novelty claim narrow and defensible:

- **No automata keyword, no LTL surface.** `after … since` is the only ordering
  primitive; multi-step chains compose from it. Calling it "automata" invites the
  Agent-C / Agent-Behavioral-Contracts (`2602.22302`) comparison we lose.
- **No denial-as-channel feedback model.** ARM (`2604.04035`) owns
  "denial feedback is a causal leak." v2's `reason`/`remediation` stay as v1's
  cooperative-agent payload; a leakage-aware feedback class is a *separate*
  future track, not bundled here.
- **No NL→DSL synthesis.** Keep the core system valid without an LLM in the loop.

## 7. Implementation checklist (when you greenlight it)

1. `dsl/parse.rs` — extend `cond` parser with the optional `since` tail
   (`event_pat` reuses the existing op + pattern parsers).
2. `dsl/ast.rs` — add `since: Vec<(Op, Pattern)>` to the `After` condition.
3. `dsl/lower.rs` — lower gate+since to epoch-slot indices; update the
   `#[repr(C)]` gate struct and the `fixed-size` test.
4. `bpf/taint.h` — gate bitmask → epoch array (ABI, mirror in `lower.rs`).
5. `bpf/taint_engine.bpf.h` — epoch counter; bump on exec/write/read; compare in
   `te_check`. Watch the verifier (bounded loop over the small epoch array,
   explicit `if (idx < N)` guards — see CLAUDE.md gotchas).
6. `process.bpf.c` — `since read` needs the read hook to bump `inval_epoch`.
7. Tests: add E5′/E11′/E13 compile+effect cases to `dsl/mod.rs`; add the
   `edit→test→edit→commit` trace to `test/e2e_examples.sh`.
8. (Tier 2, later) switch file identity to `(dev,inode,gen)` and per-version
   gate-consumption tracking.

## 8. Eval the v2 primitive earns (ties back to the OSDI pitch)

- **Staleness correctness:** the `edit→test→edit→commit` and
  `confirm→force→force` traces that v1 wrongly allows and v2 blocks — direct,
  reproducible, one number.
- **Precision (Tier 1 vs Tier 2):** false-positive rate when "edit README" or
  "edit unrelated module" should *not* invalidate "tests for src". This is the
  number that justifies the per-object-version cost and separates v2 from a
  coarse session flag.
- **Cost:** added per-event work (two counter writes), per-proc state delta
  (bits → small `u32[]`), and BPF verifier loadability with the epoch array.
