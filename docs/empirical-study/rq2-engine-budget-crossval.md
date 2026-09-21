# The 1M complexity limit, cross-validated against PR44's object

The RQ2 probe and the OAS runs both carry a caveat: several cases are
unmeasurable on this host because the engine's file-event handlers exceed the
Linux 6.8 verifier's 1M-instruction processing limit (`-E2BIG`, "BPF program is
too large"). Those rows are recorded as `skip(engine-budget)` rather than
pass/fail. This note records what was measured about that limit, and in
particular an independent check of the claim that PR44's engine object does not
hit it.

## The two limits are different, and this one is state explosion

Linux 6.8 enforces two independent verifier budgets that are easy to conflate:

- the summed-stack limit (512 bytes along a call chain), fixed on this branch by
  keeping `fileptr_ref` off the stack (`f315e600`; see `bpf/README.md`); and
- the instruction-processing limit (1,000,000, `BPF_MAXINSNS`), which is about
  **verifier work**, not program size.

The failing handlers hold a few thousand instructions and still exhaust the
second budget, because the verifier explores too many states through them. That
is why the naive fix does not work: shrinking instruction count does nothing, and
the lever is where the verifier can bound each loop cheaply.

## Independent check: PR44's object loads 93/93

The claim that PR44's engine restructure clears the limit was measured here
rather than taken from PR44's own committed log. The per-program diagnostic
loader was built from PR44's `vvload.c` against PR44's committed
`prebuilt/process.bpf.o` (sha256 in `metadata.tsv`) and run in a 6.8 guest with
the same policy blob as the branch measurements:

```
VLOAD_DONE ok=93 fail=0 total=93
```

with `trace_openat_exit` verified at `processed 315323 insns`. No rejection of
either kind appears in that run. Raw per-program lines:
`pr44verify-guest-console.txt`, summarized in `pr44verify-summary.tsv`.

For comparison, the same policy on this branch (`079e1247`, object
`56de86c9...`) is `ok=85 fail=8`: the eight failures are the open/creat/truncate/
rename exit handlers, all "BPF program is too large". `branch-baseline-guest-console.txt`
and `branch-baseline-summary.tsv` record that run, whose failing programs are
listed per row in `branch-baseline-failures.tsv`. The three objects are compared
on identical inputs, so PR44's object is a genuine improvement under this budget
rather than a difference in reporting.

## A partial port was measured and rejected

Applying only part of PR44's treatment (`te_handle_file_event` made `__noinline`
with the label accumulators folded into scratch, plus `te_read` and
`te_write_flow` made `__noinline`) was measured and **regressed** the program set:

```
VLOAD_DONE ok=82 fail=11 total=93
```

`p44style-guest-console.txt` and `p44style-summary.tsv` record it, with the eleven
failing programs and their two rejection kinds in `p44style-failures.tsv`. The
tradeoff is the point: making those three helpers `__noinline` gives the handlers
a shared subprogram, which does remove the complexity rejection for the
open/creat/truncate exit handlers, but each helper's own frame is then added to
every chain that reaches it, and on this source those frames are still too large.
So the failure moves from the complexity budget to the summed-stack limit
(`trace_openat_exit` goes from "too large" to `7 calls is 544`) and the treatment
adds new failures to `trace_read`, `trace_recvfrom`, and `trace_recvmsg`, which
the baseline loads.

PR44 avoids this because its restructure also moves the scan collectors'
`bpf_loop` contexts into per-CPU scratch, shrinking `te_read` to a 0x50-byte
frame and `te_write_flow` to 0x28, where the same treatment on this source leaves
them at 0x90 and 0x70. The two budgets are coupled through any helper that is on
both a deep exit chain and a read/recv chain, so the fix has to shrink the frames
and unshare the body together. That is PR44's change, and this branch does not
reproduce it; the partial port is recorded here as a rejected approach so it is
not retried.

## What this means for the branch

The complexity limit is not fixed on `experiments/rq2-lowering-eval-20260915`,
and the bounded attempts to fix it locally do not hold. It affects:

- the static C loader with policies that pull in file sink rules and path
  matchers (all eight failing handlers above); and
- the RQ2 probe's six `skip(engine-budget)` rows, which stay unmeasurable on this
  engine build.

The remedy is PR44's engine restructure (or an equivalent that shrinks the same
frames), not a local edit here. This does not affect the rows that *are* measured:
the probe's `skip(engine-budget)` rows are excluded from its count comparison, and
the replay's rows are host-side matcher evaluation with no kernel involvement.

## Evidence format, and a guard against the malformation found here

These files are parsed by row, so a row whose field count differs from its
header has no defined meaning. The first revision of this directory's summaries
had exactly that defect: `ok`/`fail`/`total` were two-field rows beside
three-field `failed` rows, and the file had no header, so `awk -F '\t' '$2 ==
"..."'` would read the wrong thing depending on the row. It is fixed here by
splitting the two shapes (`*-summary.tsv` is `metric`/`value`,
`*-failures.tsv` is `program`/`load_error`/`reason`, each with a header).

The same class appeared in review on PR44, where an `expectations.tsv` had a
four-field header and three-field rows from a `printf` placeholder/argument
mismatch. Because it is a recurring shape and the files are machine-read,
`script/check_evidence_tsv.sh` now fails when a committed evidence TSV has a row
whose field count differs from its header, or when the directory holds no TSV at
all. It runs in CI's Build and Test job and as `make check-evidence`. Both
shapes above were confirmed to fail it, and the corrected files pass.
