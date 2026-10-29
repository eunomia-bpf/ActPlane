# Benign-utility results

Official Terminal-Bench comparisons and all fixed public replays completed. Final adjudication retains unknown cases; task success and intervention verification are distinct endpoints. [README.md](README.md) gives methods, exclusions, the paper-ready paragraph and scope limits. [headline.csv](results/headline.csv) is produced by [report.py](report.py).

| Cohort | No defense | Broad sources | Narrowed sources |
| --- | ---: | ---: | ---: |
| Initial official task success | 4/6 | 6/6 | 4/6 |
| Natural-network official task success | 2/3 | 2/3 | 2/3 |
| Network false calls / covered calls | 0/80 | 12/51 | 1/67 |
| Replay false-call bounds | 0% | 2.77–2.92% | 0% |
| Replay covered calls | 1,335 | 1,335 | 1,335 |

The initial cohort had no tracked IPv4 connects, so its score differences cannot establish an enforcement benefit. The network cohort produced 44 broad and 5 narrowed actual denials: 41/1 false events and 3/4 true events. Fixed replay completed 40 trajectories per condition, with 614 broad events: 584 false, 12 true repository-runtime violations, and 18 unknown. False-call bounds include unresolved calls in the upper bound. These figures come from the headline CSV; replay has no official task-success score.

Paired total-time changes were −15.7%/−8.0% for initial broad/narrowed, +16.7%/−5.6% for network tasks, and +18.8%/+13.8% for disk-backed replay. Timing is descriptive, affected by tracing, model/order/cache variability, contention and timeout censoring. The replay timing medians use 39 disk-backed pairs and exclude the trajectory using bounded private cache tmpfs; that trajectory remains in intervention results.

A separate native Codex authentication-source control changed official reward from 1 to 0 with 252 actual native denials before any model tool. Those are true strict-policy violations during benign authentication, not false interventions. This boundary case is separate from the headline population and overhead calculations.

Key files:

- [Official initial trials](benchmark/results/trials.csv), [network trials](benchmark/network/results/trials.csv), and [network adjudications](benchmark/network/results/intervention-adjudications.csv).
- [Replay runs](replay/results/runs.csv), [interventions](replay/results/interventions.csv), [adjudication evidence](replay/results/adjudication_evidence.csv), and [separate forensic verification](replay/results/open-audit-summary.csv).
- [Position rates](results/position.csv), [chronological event bins](results/chronological-bins.csv), and [PDF figure](results/benign-utility.pdf).
- [Cleanup receipt](results/runtime-cleanup.csv), [annotation method](annotation.md), [review record](plan-review.md), and [remaining gaps](BLOCKED.md).

The full requested trusted-declassification condition remains incomplete: these official workloads provide no established trusted gate. Condition (c) measures source narrowing only. The task-shell boundary excludes the Terminus controller/model context and can end before outer-shell recovery. New AF_INET connect denial excludes existing socket writes, accepted responses, IPv6 and unconnected UDP sends. Compiled substring overmatching, renamed aliases and a positively observed new private key outside narrowed sources prevent security-equivalence claims. These results do not resolve session-wide retained-secret propagation. No paper source was changed; raw evidence remains remote. Only this lane is committed, with no push or PR.
