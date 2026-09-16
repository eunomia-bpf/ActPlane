# RQ2: Does the Current Compiler Still Exhibit the Historical Path-Lowering Over-Match?

Status: completed host-side compiler evaluation, one live 6.8 guest probe
(2026-09-15), and the `**/<name>` bare-root lowering fix (2026-09-16). This is an
evidence note for the reviewer response. It does not modify `docs/papers` and it
does not re-derive the frozen end-to-end 18/26/28 counts.

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
The suffix form needs a slash before the name, so it no longer matched a **bare
relative** path whose parent is the search root: `/work/.env` and `sub/.env`
matched, but a top-level `.env` written from the repository root did not.

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

**Fix.** The compiler now lowers a repo-relative `**/<name>` (a globstar, a slash,
and a wildcard-free basename) to a new kernel matcher kind, `TAINT_MATCH_BASENAME`
(value 5), carrying the bare literal `<name>` instead of `/<name>`. A new kernel
helper `taint_basename` returns true when the text equals the literal (a bare
root-level name) or ends with `"/" + literal` at a component boundary, so it
matches a bare `.env`, `sub/.env`, and `/work/.env` but still rejects `foo.env`
and `a/.env.bak`. It is `taint_suffix` plus one boundary byte (the extra work is a
single clamped read and one zero test), so it keeps the verifier-friendly shape.
The new kind is routed through `taint_match`, `te_path_match` (gated on
`TE_POLICY_PATH_SUFFIX`, which the Rust side sets for `M_BASENAME`), and
`cap_path_match_supported`. The wildcard form remains `suffix`: `**/*.js` is still
`suffix(".js")`, so the `.js.txt` false positive stays fixed. This is a
Rust↔C ABI addition (`bpf/taint.h` + `crates/actplane-ifc-compiler/src/dsl/lower.rs`
together, verified by the fixed-size blob test), and both committed prebuilt
objects are regenerated from the modified engine.

After the fix, a repo-relative `**/<name>` is a strict superset of the pre-fix
match (everything `suffix("/"+name)` matched still matches, plus the bare name),
and a strict subset of the historical `contains(name)` (no substring match inside
a longer name). The nine `**/*.js`-family patterns keep their suffix behavior, so
the historical over-match is not reintroduced. The static divergence scan
(`audit_path_lowering_divergence.py`) now reports zero findings, because current
and historical agree on all three probe forms for every frozen pattern.

Legacy (Linux 5.10) note: `validate_legacy_config` rejects `M_BASENAME`, as it
already did for `M_CONTAINS`, because the compatibility engine does not implement
the basename matcher. A `**/<name>` policy that the pre-fix legacy loader accepted
(as a length-limited `suffix`) now fails closed with an explicit error rather than
mismatching; this is a compatibility narrowing, not silent misbehavior, and the
modern engine (the evaluated configuration) is unaffected.

The regression shipped without a test failure because every case in
`test/e2e_cases.yaml` and `test/e2e_file_flow_cases.yaml` accesses guarded files by
absolute `${D}/...` path, so the suite never exercised a bare root-level relative
path and structurally could not detect this class. A bare-relative file-sink case
is now added to `test/e2e_file_flow_cases.yaml` so CI exercises it.

The `**/dir/**` miss in the next section shares that blind spot, since that class
also needs a relative path. Adding one relative-path case per family gives both
regressions a home in CI; this fix adds the bare-name case, and the
`**/dir/**` case remains open (below).

## Result: persisted relative-path matching miss

The NemoClaw `s02_no_new_javascript_sources` rule is

```
notify write file "**/*.js" if AGENT or AGENT_ALT unless target "**/dist/**"
```

Both the historical and the current compiler lower the repo-relative
`**/dist/**` to `CONTAINS("/dist/")`. That literal requires a slash before `dist`,
so it matches an absolute `.../dist/...` path but not a relative `dist/...` path.
Because tracepoint mode matches the recorded (possibly relative) path, the
lowering is wrong in both directions for relative paths. The live guest probe
confirms this with the same trigger and destination, changing only the path form
and the policy, and adds a third policy shape that uses the same
`**/dir/**` family for a file **source**:

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

Every operation executed (trigger exit 0), so the counts are verdicts, not lost
operations. The rows show three consequences of the same lowering, and two rows
bound it:

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

Root cause: the compiler's repo-relative lowering assumes the runtime path is
absolute. Its unit test is literally named
`repo_relative_paths_match_absolute_runtime_paths`, and the `contains` lowering is
chosen to match an absolute path (`**/dist/**` -> `CONTAINS("/dist/")`,
`**/src/lib/**` -> `CONTAINS("/src/lib/")`). In **tracepoint mode** the file hooks
resolve `TE_REF_USER_PATH` from the userspace path argument, which is relative
when the caller passed a relative path, so the assumption does not hold for that
hook. The probe measures tracepoint mode; the LSM path hooks use different strings
(e.g. `file_permission` matches the dentry basename), and their interaction with
these lowerings is not measured here. The `**/<name>` half of this root cause is
now fixed (above); the `**/dir/**` half remains, because the fix must reach the
`unless target` exception as well as the sink, which the current single
`cond_kind`/`cond_pat` ABI cannot express as a disjunction.

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
now fixed: the compiler lowers it to the new basename matcher, which matches a
bare root-level file and still rejects a longer name like `foo.env`. The inherited
`**/dir/**` lowering still mis-matches a first-segment-relative directory (an
exception over-fires, a sink under-fires, and a file source silently fails to
label); that one remains open because a fix touches the exception ABI (see the
remediation section). The source case is the completeness half of Reviewer D's
concern and still drops enforcement without emitting any verdict.

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

| Live case (frozen FN policy) | Predicted | Observed |
| --- | ---: | ---: |
| read `src/functions/archive.ts` (the recorded relative path), then commit | 0 | 0 |
| read `a/src/functions/archive.ts` (nested relative control), then commit | 1 | 1 |

The commit runs in both cases (trigger exits 0). On the recorded relative path the
file source never labels the process, so the `git commit` rule stays silent: the
frozen false negative reproduces with the current compiler on Linux 6.8. The
nested path supplies the slash the `CONTAINS("/src/functions/")` literal needs, so
it labels and fires, which isolates the path form as the cause.

What remains attribution, not demonstration: the frozen 2026-06-07 run may have
reached the engine through a different hook path string, and the artifact does not
retain the kernel's per-task matched path, so this shows the current compiler
reproduces the observed silence rather than proving the historical cause. The
audit sees only paths recorded as tool arguments; a violating path written inside
a Bash script (as in the `alibaba/OpenSandbox` row) is not visible to it.

### Remediation shape for the `**/dir/**` miss (not fixed here)

This one is compiler-side, not engine-side, and a fix must decide where paths are
normalized. Two options, with their costs:

1. **Normalize in the kernel.** Resolve `TE_REF_USER_PATH` against the caller's
   cwd before matching, so the recorded string is absolute as the lowering
   assumes. This needs the tracepoint hooks to compute the absolute path, which
   the current hooks deliberately avoid (they read the raw user argument because
   `bpf_d_path` on the syscall path is not always available); it also changes the
   reported `target` string in every verdict.
2. **Lower both forms.** Emit, per repo-relative `**/dir/**` pattern, matchers that
   also match the first-segment-relative form (an anchored `prefix`/`contains` on
   `dir/` as well as `/dir/`). This keeps the kernel unchanged for a plain sink but
   doubles the matcher per clause and, for an `unless target` exception, cannot be
   expressed with the current single `cond_kind`/`cond_pat` ABI, because the
   exception now needs a disjunction. Option 2 therefore also implies an ABI
   change.

Either option touches the Rust↔C ABI (`taint.h` and `lower.rs` together) and the
kernel matcher set. The `**/<name>` fix above shows the pattern for such an ABI
addition (a new `TAINT_MATCH_BASENAME` kind threaded through the matcher, the
feature gate, and the blob); the `**/dir/**` fix additionally needs the
disjunction, so it is larger. The committed probe gives that fix a ready
regression test: the `**/dir/**` rows (`except_*`, `sink_*`, `source_*`) and the
two `frozen_fn_*` rows are exact pass/fail conditions.

## Reproduction

```sh
# host-only compiler replay (writes the committed evidence)
python3 docs/empirical-study/replay_fp_lowering.py \
  /path/to/corpus-test /path/to/fp_rows.json target/release/actplane \
  --out docs/empirical-study/results/rq2-fp-current-lowering/replay.json

# static historical-vs-current lowering divergence over the frozen rules
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
# probe compiles its own inline policy, so no OAS_POLICY_DIR is needed)
ACTPLANE_VM_KERNEL=/path/to/vmlinuz-6.8.0-138-generic ACTPLANE_VM_TIMEOUT=900 \
  docs/empirical-study/run_rq2_except_probe_vm.sh \
  docs/empirical-study/results/rq2-except-probe-vm
```

`fp_rows.json` is the `rows` array emitted by
`node docs/empirical-study/audit_rq2_verdicts.js ARTIFACT_ROOT` on the frozen
`origin/artifact-ready` export; the corpus root is the extracted
`docs/corpus-test`. Raw evidence:

- `results/rq2-fp-current-lowering/replay.json`: per-row classification, the
  historical-vs-current lowering of each offending glob, the port-vs-blob checks,
  and the per-rule replay detail.
- `results/rq2-path-lowering-divergence/divergence.json`: the static
  historical-vs-current lowering divergences over the frozen rules.
- `results/rq2-except-probe-vm/`: the **pre-fix** live record, taken at
  `0e248945` (2026-09-15) before this fix. `summary.tsv` (predicted vs observed),
  `expectations.tsv`, `counts.tsv`, `guest-console.txt` (full cleaned console),
  `metadata.tsv` (kernel, acceleration, per-policy hashes), and the five policy
  blobs. Its `env_bare_relative` row (0 verdicts) is the pre-fix behavior and is
  retained as the diagnosis of the regression; the current probe prints the fixed
  expectations (bare `.env` fires, `foo.env` does not). It was not re-run after
  the fix: the guest 6.8 verifier in this environment now rejects every engine
  program at the instruction limit (`BPF program is too large. Processed 1000001
  insn` on `trace_openat_exit`), including the verbatim committed prebuilt object
  and pristine `master` source, so the failure is a pre-existing environment
  toolchain drift, not this fix (see the session report).
- `results/rq2-fn-lowering-exposure/exposure.json`: the static FN exposure audit
  output (candidate rows and their lowered patterns).

## Claim boundary

The replay is host-side matcher evaluation on the recorded event strings, not a
live verdict for all 18 rows. The live probe covers the exception, sink, source,
and bare-dotfile shapes plus the exact `rohitg00/agentmemory` FN policy and the
`Alishahryar1/free-claude-code` TP policy in tracepoint mode on Linux 6.8; it does
not establish LSM-mode behavior, other policies, or per-task outcomes. It
reproduces the `rohitg00/agentmemory` FN silence and the free-claude-code TP
regression on their recorded paths, but does not prove the frozen 2026-06-07 run's
kernel path string; that FN row is the only confirmed static exposure, and paths
written inside Bash scripts are outside the audit's view. The miss is bounded to
first-segment-relative and bare root-level relative paths. It does not re-derive
the 78/28 or 18/26/28 counts, and it does not establish semantic policy
correctness beyond the probe. The `**/<name>` bare-root lowering is fixed here
(compiler + kernel matcher, host-side evidence: `--selftest`, blob-port agreement,
zero divergence findings, and the C unit tests); the `**/dir/**` first-segment
relative miss is reported but not fixed, because it needs a `unless target`
disjunction the current ABI cannot express.
