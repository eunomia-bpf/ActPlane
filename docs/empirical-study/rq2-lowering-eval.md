# RQ2: Does the Current Compiler Still Exhibit the Historical Path-Lowering Over-Match?

Status: completed host-side compiler evaluation plus one live 6.8 guest probe,
2026-09-15. This is an evidence note for the reviewer response. It does not modify
`docs/papers` and it does not re-derive the frozen end-to-end 18/26/28 counts.

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
   two frozen policy shapes against an `exec python3`-labelled trigger in a 6.8
   KVM/TCG guest with BPF: the exception form `notify write file "**/*.js" if
   AGENT unless target "**/dist/**"`, and the sink form `notify write file
   "**/dist/**" if AGENT`. Each is exercised with a relative and an absolute
   destination, so the probe measures both the exception over-fire and the sink
   under-fire for the same lowering. TCG is used because the host has no usable
   hardware virtualization.

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
these lowerings is not measured here. This note does not change the compiler; it
isolates the mode-dependent input the lowering depends on.

## Interpretation

The historical-lowering part of the 18-FP attribution is only partly obsolescent.
One of the four historical-lowering FPs no longer reproduces, and the `.js`
extension family was tightened from substring to suffix matching. The other three
historical-lowering FPs persist, and the dominant remaining cause is genuinely
broad translated patterns (9 translation rows still fire on their recorded event),
not a stale compiler defect. This supports the paper's end-to-end framing: the
false positives are mostly translation- and harness-stage effects, and the one
durable path-semantics issue is the repo-relative `**/dir/**` lowering, which is
reproducible on demand and cuts three ways on a relative path: an exception
over-fires, a sink under-fires, and a file source silently fails to label (so
downstream enforcement is lost). The source case is the completeness half of the
same defect and is the strongest form of Reviewer D's concern, because it drops
enforcement without emitting any verdict.

### Does it explain frozen false negatives?

The same lowering also appears in the frozen false-negative set. A static
exposure audit (`audit_fn_lowering_exposure.py`) checks each of the 28 ActPlane
false negatives: does its frozen rule use a repo-relative `**/dir/**` file
pattern, and does the recorded tool log show a first-segment-relative action path
that the lowered `CONTAINS("/dir/")` would miss? Two rows qualify:

| Frozen FN row | Frozen pattern | Lowered | Recorded relative path |
| --- | --- | --- | --- |
| `rohitg00/agentmemory` `6`, direct | `**/src/functions/**` | `contains(/src/functions/)` | `src/functions/archive.ts` |
| `alibaba/OpenSandbox` `7`, script | `**/server/**` | `contains(/server/)` | `server/opensandbox_server/api/eval_pause_script.py` |

Both rules gate on a `file` **source** (`source AUDIT_CHANGE = file
"**/src/functions/**"` and `source SPEC_CONTEXT = file "**/server/**"`), so if the
source misses, the dependent rule never fires: exactly the enforcement-losing
direction the live probe demonstrates for `**/src/lib/**`.

This is **static exposure, not proven causation**. The frozen artifact does not
retain the kernel's per-task matched path, so the audit cannot confirm what string
the frozen engine actually matched, and each frozen run used the 2026-06-07
compiler whose exact `TE_REF_USER_PATH` handling is not re-run here. The audit
identifies two candidates consistent with the defect and is deliberately reported
as such.

## Reproduction

```sh
# host-only compiler replay (writes the committed evidence)
python3 docs/empirical-study/replay_fp_lowering.py \
  /path/to/corpus-test /path/to/fp_rows.json target/release/actplane \
  --out docs/empirical-study/results/rq2-fp-current-lowering/replay.json

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
- `results/rq2-except-probe-vm/`: `summary.tsv` (predicted vs observed),
  `expectations.tsv` (pre-registered predictions), `counts.tsv`,
  `guest-console.txt` (full cleaned console), `metadata.tsv` (kernel,
  acceleration, per-policy hashes), and the three policy blobs.
- `results/rq2-fn-lowering-exposure/exposure.json`: the static FN exposure audit
  output (candidate rows and their lowered patterns).

## Claim boundary

The replay is host-side matcher evaluation on the recorded event strings, not a
live verdict for all 18 rows. The live probe covers three policy shapes
(exception, sink, and file source) in tracepoint mode on Linux 6.8; it does not
establish LSM-mode behavior, other policies, or per-task outcomes, and it does
not establish that a specific frozen RQ2 false negative was caused by this
lowering. The FN audit is static exposure over the recorded tool logs, not proof
of causation; the artifact does not retain the kernel's per-task matched path.
The miss is bounded to first-segment-relative paths. It does not re-derive the
78/28 or 18/26/28 counts, and it does not establish semantic policy correctness
beyond the probe. The compiler is unchanged; the relative-path lowering is
reported as a reproducible finding, not fixed here.
