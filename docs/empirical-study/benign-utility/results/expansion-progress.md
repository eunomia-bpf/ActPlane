Expansion snapshot from `results/headline.csv`; pending cells are not failures.

| Cohort | Condition | Completed / planned | Official successes / completed | Matched successes / common tasks |
| --- | --- | ---: | ---: | ---: |
| Added | No AgPlane | 5/18 | 4/5 | 3/4 |
| Added | Broad sources | 4/18 | 2/4 | 2/4 |
| Added | Narrowed sources | 4/18 | 3/4 | 3/4 |
| Combined | No AgPlane | 11/24 | 8/11 | 7/10 |
| Combined | Broad sources | 10/24 | 8/10 | 8/10 |
| Combined | Narrowed sources | 10/24 | 7/10 | 7/10 |

Combined tasks with valid outcomes in all three conditions: `adaptive-rejection-sampler`, `cancel-async-tasks`, `fix-code-vulnerability`, `git-leak-recovery`, `hf-model-inference`, `log-summary-date-ranges`, `modernize-scientific-stack`, `openssl-selfsigned-cert`, `sanitize-git-repo`, `vulnerable-secret`.

Additional completed cells outside that matched set: No AgPlane: `nginx-request-logging`.

Available-condition scores can have different task mixes. The matched column uses the same tasks completed in every condition.

| Cohort | Condition | Covered calls | False calls | Unknown calls | Unassigned events | False-call bounds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Added | No AgPlane | 33 | 0 | 0 | 0 | 0.00–0.00% |
| Added | Broad sources | 70 | 0 | 0 | 108 | 0.00% lower; upper unavailable |
| Added | Narrowed sources | 58 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | No AgPlane | 101 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | Broad sources | 130 | 0 | 0 | 108 | 0.00% lower; upper unavailable |
| Combined | Narrowed sources | 111 | 0 | 0 | 0 | 0.00–0.00% |

The added/combined matrices are complete only when every frozen task has valid outcomes in every condition. Security coverage and adjudication completeness remain separate fields.
