# Independent final result review

Reviewers: baseline_docs and effect_oracle subagents. Read-only reviews after
the repaired complete matrix, without supplying a requested verdict.

Run status: **valid for persistent-effect and prohibited-invocation measurements**.
Tested hypothesis: **supported within the frozen RQ2 corpus**.
Research value: **supporting**.
Paper impact: **additional RQ2 evidence and a mechanism/workload boundary**.
Next paper decision: report uneven default resource-boundary coverage together
with collateral denial; do not claim general sandbox failure or agent confusion.

The baseline reviewer independently recomputed the complete per-trace CSV,
aggregate counts and denial trace keys. The oracle reviewer independently read
all policy families, payloads and completed violation outcomes. Both obtained:

| System | Prevented | New compliant access denial |
| --- | --- | --- |
| Codex workspace-write | 15/111 | 6/76 |
| Standalone SRT defaults | 93/111 | 72/76 |
| SRT cwd-write analogue | 33/111 | 1/76 |
| Docker defaults | 0/111 | 0/76 |

Every baseline/control record completed. Denial regex extraction from the exact
tool error CSV reproduces the same compliant trace key sets. All original-worker
fidelity rows match tool inputs, return codes and Read byte counts. The only
effect exclusions are the public-disclosure safety-shim traces, identically
excluded across configurations. No prohibited target mismatch, scaffolding
false positive, restored output or executable-identity gap was found.

Interpretation requires the documented boundaries. Codex prevention concerns
protected Git metadata. SRT cwd-write prevention occurs only in script traces
because the fixed outside-cwd log path is denied before the payload. Standalone
SRT denies most compliant writes. Its no-config policy is distinct from the
enabled Claude Code harness. File checks establish persistent final changes,
and command checks establish invocation rather than downstream success.

AgPlane rows are imported notification detections under a different guest
environment, with their own denominators. New sandbox compliant triggers are
tool-visible access denials, not directly observed internal decisions. The
corpus is author-generated and does not establish general injection resistance
or agent confusion. The additional filesystem fidelity diagnostic is
supplementary and does not change the independently verified outcome metrics.

Supplementary addendum: after excluding Git object filenames, persistent
changed-path sets agree on all but the documented compliant OpenSandbox
generator trace. Its original private-network execution cannot download the
generator, while the new unrestricted control can. The reviewer found no
blocker for the scoped claims because all eligible violation effects remain
observable. Missing-command/module signals and this network difference must
not be interpreted as full toolchain compatibility or task utility.

No scientific blocker remains for reporting these scoped results. Numerical
source files are results/comparison.csv, results/per-trace.csv,
results/errors.csv, results/exclusions.csv and results/fidelity.csv. The
read-only oracle audit script also recomputes the actual raw violation effects.
