# RQ2: Does the Current Compiler Still Exhibit the Historical Path-Lowering Over-Match?

Status: completed host-side compiler evaluation, one live 6.8 guest probe
(2026-09-15) and its post-fix re-run (2026-09-17), and both compiler-only
lowering fixes: the `**/<name>` bare-root regression (2026-09-16) and the
`**/dir/**` first-segment-relative miss (2026-09-17). This is an evidence note
for the reviewer response. It does not modify `docs/papers` and it does not
re-derive the frozen end-to-end 18/26/28 counts.

## Question

`rq2-fp-attribution.md` attributes the 18 ActPlane false positives to four stages
and leaves an explicit boundary: "The current implementation must be evaluated
separately before claiming that any historical lowering defect remains." This note
performs that evaluation. The hypothesis is that some of the historical path
lowering (at the 2026-06-07 compiler lineage, `cc3a9b11`) has since been tightened,
and that what remains is a mix of resolved lowerings and genuinely broad
translated patterns.

## Method

Two independent checks, both reproducible from committed code:

1. **Compiler replay** (`docs/empirical-study/replay_fp_lowering.py`). For each of
   the 18 frozen FP rows, compile the frozen `rule.yaml` with the pinned `actplane`
   binary into the kernel ABI blob (`struct taint_config`, see `bpf/taint.h`),
   parse the lowered matchers out of the blob, and replay the recorded event
   through a faithful port of the kernel matcher predicates. The script also ports
   `lower_path`/`lower_exec` at both `cc3a9b11` and HEAD, asserts the HEAD port
   reproduces the compiled blob exactly (0 mismatches across all frozen rules), and
   replays the historical lowering on the same event. Host-only, no kernel.
2. **Live guest probe** (`docs/empirical-study/run_rq2_except_probe_vm.sh`). Runs
   frozen policy shapes against an `exec python3`/`claude`-labelled trigger in a
   6.8 KVM/TCG guest with BPF: an exception form (`notify write file "**/*.js" if
   AGENT unless target "**/dist/**"`), a sink form (`notify write file "**/dist/**"
   if AGENT`), a file-source form (`source CLI = file "**/src/lib/**"`), and the
   `**/.env` dotfile form. Each path family is exercised with a relative, nested,
   and absolute destination, so the probe measures both the `**/dir/**` relative
   mis-match and the `**/<name>` bare-root case (now fixed, so the bare `.env` is
   expected to fire). TCG is used because the host has no usable hardware
   virtualization.

The recorded event string is the string the kernel matched: in tracepoint mode
file events are resolved from the userspace path argument (`TE_REF_USER_PATH`) and
recorded verbatim, so a tool that passed a relative path yields a relative target.

## Result: current-compiler replay

Classes over the 18 FP rows: **16 still fire**, **1 lowering defect is resolved**,
**1 never fired**.

| FP-audit primary cause | Rows | Current matcher |
| --- | ---: | --- |
| translation over-approximation | 9 | still fires |
| harness-tool interaction | 4 | still fires |
| historical path lowering | 4 | 3 still fire, 1 resolved |
| trajectory protocol/judge | 1 | never fired (consistent with the note: no setup intervention) |

One historical over-match is gone: the NemoClaw lookalike fixture
`test/fixtures/src-lib-new-command.js.txt`. Historically `**/*.js` lowered to
`CONTAINS(".js")`, which matched that `.js.txt` file; today it lowers to
`SUFFIX(".js")`, which does not. The same tightening changed `**/*.sh` and `**/*.py`
from `CONTAINS` to `SUFFIX`; those events (harness-generated `/tmp/...tool.py`
paths) still fire, but now via a correct extension match rather than a substring.

No row newly fires, and no row's classification depends on an unvalidated port:
the HEAD lowering port agrees with the compiled blob for every rule.


## Fixed (2026-09-16): the `**/<name>` bare-root regression

The tightening that removed the `.js.txt` false positive (row above) changed the
lowering of `**/<name>` patterns from `CONTAINS("<name>")` to `SUFFIX("/<name>")`.
Before the fix, the suffix form required a slash before the name, so it no longer
matched a **bare relative** path whose parent is the search root: `/work/.env` and
`sub/.env` matched, but a top-level `.env` written from the repository root did
not.

Which frozen policies this affected is decidable from the artifact:

| Frozen row | Pattern | Historical | Pre-fix current | Frozen evidence |
| --- | --- | --- | --- | --- |
| `Alishahryar1/free-claude-code` `6` | `**/.env` | `contains(.env)` | `suffix(/.env)` | three TP rows whose recorded target is bare `write .env` |
| `NousResearch/hermes-agent` `s02_keep_credentials_out_of_repo` | `**/.env` | `contains(.env)` | `suffix(/.env)` | rule text only |
| `yusufkaraaslan/Skill_Seekers` `68` | `**/.env`, `**/.env.local` | `contains(...)` | `suffix(/...)` | rule text only |

The first row was decisive because the frozen artifact records the kernel matching
exactly the bare relative string: `setup_fired: true` with feedback
``Operation `write .env```, judged TP in three traces. The pre-fix compiler
compiled that rule to `suffix("/.env")`, which cannot match `.env`; the 2026-09-15
probe confirmed it live (bare `.env` predicted/observed 0 verdicts, nested
`sub/.env` 1).

**Fix.** The compiler pairs the suffix form with a companion `exact` matcher, so
both halves of the pattern are covered by existing kernel matchers and the
engine is byte-identical to `master`. A repo-relative `**/<name>` (a globstar, a
slash, and a wildcard-free basename) still lowers to `suffix("/"+name)`, which
fires on `sub/.env` and `/work/.env`; a second entry, `exact("<name>")`, fires on
the bare root-level name (`.env`) and on nothing else (`foo.env` is not equal to
`.env`, and the suffix form rejects it too because it needs the leading slash).
The two are mutually exclusive, so no event double-fires. Sources emit the pair
as two `taint_update`s and sinks as two `taint_rule`s.

Emitting an extra table entry is verifier-free because the update and rule scans
run in `bpf_loop` callbacks, which the verifier checks once rather than per entry.
This matters because the file-event hooks have almost no verifier headroom. Two
earlier attempts were rejected on the CI kernel's 1,000,000-instruction budget
(12/12 e2e cases had passed before either): a new `TAINT_MATCH_BASENAME` kind
(0x5) added a branch to the inlined `te_path_match` and doubled its explored
state, and folding the bare case into `taint_suffix` added ~26,000 instructions
on the 6.8 guest (`trace_openat_exit` 491,049 -> 517,041), which the CI kernel's
~2x state exploration pushed past the limit. The companion-entry form leaves
`trace_openat_exit` at exactly `master`'s 491,049 on the 6.8 guest, and the set
of programs that fail to load is identical to `master`'s (the three
`trace_rename*_exit` handlers at the 1M limit; `trace_recvfrom_exit`/
`trace_recvmsg_exit` are `-EACCES`), none autoloaded by these policies.

This is not a Rust↔C ABI change and edits no kernel code: only
`crates/actplane-ifc-compiler/src/dsl/lower.rs` changes, and both committed
prebuilt objects stay at `master`. The wildcard form remains `suffix`
(`**/*.js` -> `suffix(".js")`, so the `.js.txt` false positive stays fixed). The
new match is a strict superset of the pre-fix form (everything `suffix("/"+name)`
matched still matches, plus the bare name) and a strict subset of the historical
`contains(name)` (no substring match inside a longer name). The static
divergence scan (`audit_path_lowering_divergence.py`) reports zero *target-role*
findings, because current and historical agree on all three probe forms for every
frozen pattern. Its `condition_findings` list records the exception-role residue
separately: for `NVIDIA__NemoClaw/s02` (`unless target "**/dist/**"`) and
`NousResearch__hermes-agent/29` (`unless target "**/scripts/**"`), the single
condition stores only `contains("/dist/")`/`contains("/scripts/")`, so it misses
the first-segment-relative form (`dist/x.js`, `scripts/x.js`) that the target
matcher covers and the negated exception over-fires there. That residue is the
open exception half, described below.

Legacy (Linux 5.10) note: the legacy engine already implements `exact`, so the
companion entry works there too. A `**/<name>` policy gains the bare-root match
on both engines; nothing that matched before stops matching, so there is no
compatibility narrowing.

The regression shipped without a test failure because every case in
`test/e2e_cases.yaml` and `test/e2e_file_flow_cases.yaml` accesses guarded files by
absolute `${D}/...` path, so the suite never exercised a bare root-level relative
path and structurally could not detect this class. A bare-relative file-source
case (`F9`) is now added to `test/e2e_file_flow_cases.yaml` so CI exercises it.

The `**/dir/**` miss in the next section shared that blind spot, since that class
also needs a relative path. A first-segment-relative file-*source* case (`F10`) is
now added to `test/e2e_file_flow_cases.yaml` alongside the bare-name `F9`, so CI
exercises both relative-path regressions.

## Fixed (2026-09-17): the `**/dir/**` first-segment-relative miss

The persisted miss below is that a repo-relative `**/dir/**` (or `**/dir/*`)
pattern lowers to `contains("/dir/")`, whose literal needs a slash before the
directory. In tracepoint mode the kernel matches the recorded userspace path, so a
path that begins at the directory (`dist/x.js`) does not match. The earlier
analysis concluded that an `unless target` exception "cannot be expressed with the
current single `cond_kind`/`cond_pat` ABI", which is true of the exception role,
but the **source**, **sink**, **gate**, and **invalidator** roles use plain
`taint_update`/`taint_rule` table entries that can carry an extra matcher.

**Fix.** For a repo-relative `**/<dir>/**` or `**/<dir>/*`, the compiler now pairs
the existing `contains("/dir/")` primary with a companion `prefix("dir/")` entry
(an existing match kind). The prefix covers exactly the first-segment-relative
form (a leading segment equal to the directory) and nothing else: a nested
`sub/dir/...` and an absolute `/w/dir/...` still match via the primary, and a
longer first segment `dirx/...` matches neither. The companion is emitted for the
file source, the sink target, the `after` gate, and the `since` invalidator, all
through one `lower_path_companions` helper, so the compiler stays internally
consistent. The `unless target` exception keeps its single `cond_kind`/`cond_pat`
pair and therefore still over-fires on the first-segment-relative form; that half
still needs an ABI-level disjunction and is recorded as open.

Like the `**/<name>` fix, this is compiler-only: it edits no kernel code and only
`crates/actplane-ifc-compiler/src/dsl/lower.rs`; both committed prebuilt objects
stay at `master`. An extra table entry is verifier-free because the update and
rule scans run in `bpf_loop` callbacks (verified once). The engine's rule scan
keeps a single best-effect match (`te_record_best`), so a companion that co-matches
the same event costs no duplicate verdict.

Evidence: the `--selftest` pins the companion and matcher semantics; the replay
now models the primary-plus-companion lowering and still reproduces the compiled
blob for every frozen rule (0 port mismatches) with the FP classifications
unchanged; the divergence scan reports the five frozen `**/dir/**` patterns as
first-segment *expansions*; and the live 6.8 guest probe flips the source,
sink, and frozen-FN rows to fire on the first-segment-relative path. The
exception row (`except_dist_relative`) is not measurable on this host: like
every suffix write-rule shape it exceeds the guest's instruction budget and is
reported `skip(engine-budget)` (see the post-fix evidence below), so its
remaining over-fire is established by the pre-fix probe and the unchanged
lowering, not by a new verdict.

## Pre-fix diagnosis: the `**/dir/**` relative-path miss

The NemoClaw `s02_no_new_javascript_sources` rule is

```
notify write file "**/*.js" if AGENT or AGENT_ALT unless target "**/dist/**"
```

The historical compiler and the pre-fix current compiler both lowered the
repo-relative `**/dist/**` to `CONTAINS("/dist/")`. That literal requires a slash
before `dist`, so it matches an absolute `.../dist/...` path but not a relative
`dist/...` path.
Because tracepoint mode matches the recorded (possibly relative) path, the
lowering is wrong in both directions for relative paths. The live guest probe
confirms this with the same trigger and destination, changing only the path form
and the policy, and adds a third policy shape that uses the same
`**/dir/**` family for a file **source**:

This table is the **pre-fix** record: it is what the 2026-09-15 probe observed
before the fix described above. Every operation executed (trigger exit 0), so the
counts are verdicts, not lost operations.

| Case (by one shared trigger) | Predicted | Observed |
| --- | ---: | ---: |
| exception policy, `dist/agent-health/x.js` (relative) | 1 | 1 |
| exception policy, `/w/dist/agent-health/y.js` (absolute) | 0 | 0 |
| exception policy, `src/x.js` (relative, outside exception) | 1 | 1 |
| sink policy `**/dist/**`, `dist/agent-health/x.js` (relative) | 0 | 0 |
| sink policy `**/dist/**`, `/w/dist/agent-health/y.js` (absolute) | 1 | 1 |
| sink policy `**/dist/**`, `sub/dist/x.js` (relative, nested) | 1 | 1 |
| source policy `**/src/lib/**`, read `src/lib/cli.rs` (relative) | 0 | 0 |
| source policy `**/src/lib/**`, read `nemoclaw/src/lib/cli.rs` (relative, nested) | 1 | 1 |
| source policy `**/src/lib/**`, read `/work/src/lib/cli.rs` (absolute) | 1 | 1 |

The rows show three consequences of the same lowering, and two rows bound it:

- the `unless target` **exception over-fires** on a relative path (row 1) while
  correctly excluding the absolute twin (row 2);
- a `**/dist/**` **sink under-fires** on the same relative path (row 4) while
  correctly firing on the absolute twin (row 5);
- a `**/src/lib/**` **file source silently fails to label** a relative read
  (row 7), because the source never matches, so any downstream sink that depends
  on the label stays silent; the absolute twin labels and fires (row 9).

The miss is specific, not general, to relative paths: it needs the relative path
to *start* with the pattern's first segment. A preceding directory supplies the
slash the `contains` literal expects, so a nested relative path matches and
behaves like the absolute case (rows 6 and 8). The defect therefore bites
exactly when a tool addresses a guarded directory from the repository root,
e.g. `dist/...` or `src/lib/...`, and not when it is invoked deeper.

Rows 4, 7, and 8 are the enforcement-relevant direction, since rows 4 and 7 are
where a guarded action proceeds and row 8 shows the same relative read working
once a parent directory restores the slash. Row 7 is the most consequential: a
repo-relative source that reads a first-segment-relative path never taints the
process, so completeness (catching the violating action) is lost without any
verdict, while no over-report marks the gap.

The 2026-09-18 post-fix re-run measures the rows the fix targets, with the
remaining suffix write-rule rows unmeasurable on this host (engine budget, see
the evidence list):

| Case (same trigger) | Pre-fix | Post-fix |
| --- | ---: | ---: |
| source `**/src/lib/**`, read `src/lib/cli.rs` (first-segment) | 0 | 1 |
| source `**/src/lib/**`, read `nemoclaw/src/lib/cli.rs` (nested) | 1 | 1 |
| source `**/src/lib/**`, read `/work/src/lib/cli.rs` (absolute) | 1 | 1 |
| sink `**/dist/**`, write `dist/agent-health/x.js` (first-segment) | 0 | 1 |
| sink `**/dist/**`, write `/w/dist/agent-health/y.js` (absolute) | 1 | 1 |
| sink `**/dist/**`, write `sub/dist/x.js` (nested) | 1 | 1 |
| exception, `except_*` (suffix write rule) | 1/0/1 | skip |
| dotfile `env_*` (suffix write rule) | 0/1/0 | skip |

Every measured row now matches its prediction: the first-segment source and sink
flip to 1 while the nested and absolute controls stay 1, so the fix adds exactly
the missing form.

Root cause: the compiler's repo-relative lowering assumes the runtime path is
absolute. Its unit test is literally named
`repo_relative_paths_match_absolute_runtime_paths`, and the `contains` lowering is
chosen to match an absolute path (`**/dist/**` -> `CONTAINS("/dist/")`,
`**/src/lib/**` -> `CONTAINS("/src/lib/")`). In **tracepoint mode** the file hooks
resolve `TE_REF_USER_PATH` from the userspace path argument, which is relative
when the caller passed a relative path, so the assumption does not hold for that
hook. The probe measures tracepoint mode; the LSM path hooks use different strings
(e.g. `file_permission` matches the dentry basename), and their interaction with
these lowerings is not measured here. The `**/<name>` half of this root cause and
the `**/dir/**` **source**, **sink**, **gate**, and **invalidator** halves are
now fixed (the two fix sections above), and only the `unless target` exception
half remains open, because its single `cond_kind`/`cond_pat` cannot hold the
disjunction the companion needs.

## Interpretation

The historical-lowering part of the 18-FP attribution is only partly obsolescent.
One of the four historical-lowering FPs no longer reproduces, and the `.js`
extension family was tightened from substring to suffix matching. The other three
historical-lowering FPs persist, and the dominant remaining cause is genuinely
broad translated patterns (9 translation rows still fire on their recorded event),
not a stale compiler defect. This supports the paper's end-to-end framing: the
false positives are mostly translation- and harness-stage effects. Two distinct
relative-path completeness defects were found in the current compiler. The
`**/<name>` bare-root regression (the recent `contains` -> `suffix` tightening) is
fixed: the compiler lowers it to `suffix("/<name>")` paired with `exact("<name>")`,
which matches a bare root-level file and still rejects a longer name like
`foo.env`. The inherited `**/dir/**` lowering mis-matched a first-segment-relative
directory in three enforcement roles (an exception over-fired, a sink
under-fired, and a file source silently failed to label); its source, sink, gate,
and invalidator roles are now fixed by the companion `prefix("<dir>/")`, while the
`unless target` exception still over-fires because it needs an ABI-level
disjunction. The source case was the completeness half of Reviewer D's concern and
dropped enforcement without emitting any verdict; the live post-fix probe now fires
it.

### Does it explain frozen false negatives?

The same lowering also appears in the frozen false-negative set. A role-aware
static exposure audit (`audit_fn_lowering_exposure.py`) checks each of the 28
ActPlane false negatives: does its frozen rule use a repo-relative `**/dir/**`
file pattern, and does the recorded tool log show a first-segment-relative path
for an action of the matching operation (a `file` source is materialized on any
open, read or write; a `file` sink matches only its own op)? One row qualifies:

| Frozen FN row | Role | Frozen pattern | Lowered | Recorded relative path |
| --- | --- | --- | --- | --- |
| `rohitg00/agentmemory` `6`, direct | source | `**/src/functions/**` | `contains(/src/functions/)` | `src/functions/archive.ts` (Write) |

The rule gates on that file source (`source AUDIT_CHANGE = file
"**/src/functions/**"`), so if the source misses, the dependent rule never fires:
exactly the enforcement-losing direction the live probe demonstrates for
`**/src/lib/**`. An earlier, op-blind version of the audit also flagged
`alibaba/OpenSandbox` `7`, but that row's violating write happens inside a Bash
script, so the only recorded path there was a `Read` against a write sink; the
role-aware audit drops it. That is why the count moved from two candidates to
one confirmed exposure.

The guest probe then runs the **exact frozen policy** of the `rohitg00/agentmemory`
row (`source AGENT = exec "claude"`, `source AUDIT_CHANGE = file
"**/src/functions/**"`, `notify exec "git" "commit" if AGENT and AUDIT_CHANGE`)
against a read-then-`git commit` trigger, with the recorded relative path and a
nested control:

| Live case (frozen FN policy) | Predicted (pre-fix) | Observed (pre-fix) |
| --- | ---: | ---: |
| read `src/functions/archive.ts` (the recorded relative path), then commit | 0 | 0 |
| read `a/src/functions/archive.ts` (nested relative control), then commit | 1 | 1 |

Those are the pre-fix rows. The commit runs in both cases (trigger exits 0). On
the recorded relative path the file source never labelled the process, so the
`git commit` rule stayed silent: the frozen false negative reproduced with the
current compiler on Linux 6.8. The nested path supplied the slash the
`CONTAINS("/src/functions/")` literal needs, so it labelled and fired, which
isolated the path form as the cause. After the companion fix, the post-fix guest
probe measures both rows at 1: the recorded relative read now labels, and the
`git commit` rule fires, so the frozen false-negative shape no longer reproduces.

What remains attribution, not demonstration: the frozen 2026-06-07 run may have
reached the engine through a different hook path string, and the artifact does not
retain the kernel's per-task matched path, so this shows the current compiler
reproduces the observed silence rather than proving the historical cause. The
audit sees only paths recorded as tool arguments; a violating path written inside
a Bash script (as in the `alibaba/OpenSandbox` row) is not visible to it.

### Remediation decided: the compiler-side companion entry

Two options were considered for the `**/dir/**` miss, both compiler-side rather
than engine-side:

1. **Normalize in the kernel.** Resolve `TE_REF_USER_PATH` against the caller's
   cwd before matching, so the recorded string is absolute as the lowering
   assumes. This needs the tracepoint hooks to compute the absolute path, which
   the current hooks deliberately avoid (they read the raw user argument because
   `bpf_d_path` on the syscall path is not always available); it also changes the
   reported `target` string in every verdict.
2. **Lower both forms.** Emit, per repo-relative `**/dir/**` pattern, matchers
   that also match the first-segment-relative form (an anchored `prefix` on
   `dir/` as well as `/dir/`).

Option 2 was chosen and implemented. It keeps the kernel unchanged, needs no
Rust↔C ABI change (it pairs the existing `contains` with the existing `prefix`,
exactly as the `**/<name>` fix paired `suffix` with `exact`), and edits only
`crates/actplane-ifc-compiler/src/dsl/lower.rs`. The only role it cannot cover is
the `unless target` exception, whose single `cond_kind`/`cond_pat` pair cannot
hold the `contains`/`prefix` disjunction; that half remains open and, unlike the
source/sink/gate roles, needs an ABI-level disjunction. The committed probe gives
the fix a ready regression test: the `**/dir/**` rows (`except_*`, `sink_*`,
`source_*`) and the two `frozen_fn_*` rows are exact pass/fail conditions, and a
first-segment-relative file-source case (`F10`) is added to the CI e2e suite.

Because the exception half is a genuine ABI limitation, the compiler now makes it
**discoverable** rather than silent. `repo_relative_condition_is_partial` is the
single predicate for "this condition pattern carries a companion the condition
role cannot express", and `compile --explain`/`--json` emit a
`repo_relative_target_condition_partial` warning naming the over-firing form. The
`condition_findings` list in the divergence scan names the two frozen rules it
affects. An absolute exception (`unless target "/work/dist/**"`) has no companion
and does not warn.


## Reproduction

```sh
# host-only compiler replay (writes the committed evidence)
python3 docs/empirical-study/replay_fp_lowering.py \
  /path/to/corpus-test /path/to/fp_rows.json target/release/actplane \
  --out docs/empirical-study/results/rq2-fp-current-lowering/replay.json

# static historical-vs-current lowering divergence over the frozen rules (its
# `condition_findings` list records the exception-role over-fire residue)
python3 docs/empirical-study/audit_path_lowering_divergence.py \
  /path/to/corpus-test \
  --out docs/empirical-study/results/rq2-path-lowering-divergence/divergence.json

# static exposure of the defect in the frozen false-negative set
python3 docs/empirical-study/audit_fn_lowering_exposure.py \
  /path/to/corpus-test /path/to/artifact/rq2-qwen-primary /path/to/fp_rows.json \
  --out docs/empirical-study/results/rq2-fn-lowering-exposure/exposure.json

# ported-lowering and kernel-matcher self-checks
python3 docs/empirical-study/replay_fp_lowering.py --selftest

# live guest probe (requires a 6.8 vmlinuz and qemu, like the firing audit; the
# probe compiles its own inline policy, so no OAS_POLICY_DIR is needed). KVM is
# unavailable in this environment (nested virt denied), so the guest runs under
# TCG and the run needs a generous timeout.
ACTPLANE_VM_KERNEL=/path/to/vmlinuz-6.8.0-138-generic ACTPLANE_VM_TIMEOUT=3000 \
  docs/empirical-study/run_rq2_except_probe_vm.sh \
  docs/empirical-study/results/rq2-except-probe-vm-postfix

`fp_rows.json` is the `rows` array emitted by
`node docs/empirical-study/audit_rq2_verdicts.js ARTIFACT_ROOT` on the frozen
`origin/artifact-ready` export; the corpus root is the extracted
`docs/corpus-test`. Raw evidence:

- `results/rq2-fp-current-lowering/replay.json`: per-row classification, the
  historical-vs-current lowering of each offending glob, the port-vs-blob checks,
  and the per-rule replay detail.
- `results/rq2-path-lowering-divergence/divergence.json`: the static
  historical-vs-current lowering divergences over the frozen rules (the five
  `**/dir/**` first-segment expansions and the `**/<name>` narrowing).
- `results/rq2-except-probe-vm/`: the **pre-fix** live record, taken at
  `0e248945` (2026-09-15). `summary.tsv` (predicted vs observed),
  `expectations.tsv`, `counts.tsv`, `guest-console.txt` (full cleaned console),
  `metadata.tsv` (kernel, acceleration, per-policy hashes), and the five policy
  blobs. Its `**/dir/**` source/sink rows (0 verdicts where the action
  proceeded) and its `env_bare_relative` row (0 verdicts) are the pre-fix
  diagnosis.
- `results/rq2-except-probe-vm-postfix/`: the **post-fix** live re-run at the
  fix commit (2026-09-18), same probe, expectations updated to the fixed
  behavior. The rows the fix targets all move to fire on the first-segment
  relative form: `source_rel_read` 0 -> 1, `sink_dist_relative` 0 -> 1, and the
  exact frozen-FN row `frozen_fn_rel_read` 0 -> 1, with the nested/absolute
  controls unchanged at 1. Six rows are reported `skip(engine-budget)`: the
  suffix **write-rule** shapes (`except_*` = `notify write file "**/*.js" ...`,
  `env_*` = `notify write file "**/.env"`). Those autoload the full file
  evaluator, whose `trace_openat_exit` exceeds this guest's 1,000,000-instruction
  limit under this host's engine build (clang 19); the guest reports `-E2BIG`,
  the probe records the case as unmeasurable, and it is excluded from the
  pass/fail comparison. That budget condition is pre-existing and unrelated to
  this compiler-only change: an engine built from the **pristine pre-fix**
  source (`0e248945`) also rejects the **committed pre-fix** `except`/`env`
  blobs on this host, and both engine sources are byte-identical to `master`.
  The skipped rows are the sole exception/suffix shapes; every `contains`/
  `prefix` row the fix changes loads and fires.

  The fix was additionally re-validated live in a 6.8 guest in this environment.
  A local verifier oracle (guest `vmlinuz-6.8.0-138-generic`, qemu/TCG, the
  diagnostic loader) loads every engine program: `master` and both fixed engines
  have the **same** failure set (the three `trace_rename*_exit` handlers at the
  1M limit, `trace_recvfrom_exit`/`trace_recvmsg_exit` `-EACCES`), none autoloaded
  by these policies. A `source SECRET = file "**/.env"` policy plus a connect sink
  run through the **production** loader (`bpf/process` built from the fixed
  source) emits exactly one verdict for a bare `.env` read then `connect 1.1.1.2`
  (`"target":"1.1.1.2"`, `provenance.target:".env"`, `effect":"kill"`), and none
  for a `foo.env` control read; the pre-fix `master` engine emits none for the
  bare `.env` case, reproducing the regression. The companion-entry fix keeps
  `trace_openat_exit` at exactly `master`'s 491,049 instructions on the 6.8
  guest; the two rejected attempts (the `TAINT_MATCH_BASENAME` kind and the
  `taint_suffix` fold) each pushed it over the CI limit.
- `results/rq2-fn-lowering-exposure/exposure.json`: the static FN exposure audit
  output (candidate rows and their lowered patterns).

## Claim boundary

The replay is host-side matcher evaluation on the recorded event strings, not a
live verdict for all 18 rows. The live probe covers the exception, sink, source,
and bare-dotfile shapes plus the exact `rohitg00/agentmemory` FN policy and the
`Alishahryar1/free-claude-code` TP policy in tracepoint mode on Linux 6.8; it does
not establish LSM-mode behavior, other policies, or per-task outcomes. It
reproduces the `rohitg00/agentmemory` FN silence (pre-fix) and the
free-claude-code TP regression on their recorded paths, but does not prove the
frozen 2026-06-07 run's kernel path string; that FN row is the only confirmed
static exposure, and paths written inside Bash scripts are outside the audit's
view. The miss is bounded to first-segment-relative and bare root-level relative
paths. It does not re-derive the 78/28 or 18/26/28 counts, and it does not
establish semantic policy correctness beyond the probe. Both lowerings are now
fixed compiler-only, so the engine is byte-identical to `master`: the
`**/<name>` bare-root form pairs the existing `suffix("/<name>")` with
`exact("<name>")`, and the `**/dir/**` first-segment form pairs the existing
`contains("/<dir>/")` with `prefix("<dir>/")`. Evidence for both: `--selftest`,
blob-port agreement (0 mismatches), the divergence scan, the C unit tests, the
local 6.8 verifier oracle, the live firing proof, and the post-fix guest probe.
Only the `unless target` exception half of the `**/dir/**` miss remains open,
because it needs an ABI-level disjunction the current single `cond_kind`/`cond_pat`
cannot express. That half is no longer silent: the compiler flags it in
`compile --explain`/`--json` and the divergence scan names the affected frozen
rules, so the approximation is discoverable before rollout.
