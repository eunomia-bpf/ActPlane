Expansion snapshot from `results/headline.csv`; pending cells are not failures.

| Cohort | Condition | Completed / planned | Official successes / completed | Matched successes / common tasks |
| --- | --- | ---: | ---: | ---: |
| Added | No AgPlane | 6/18 | 5/6 | 4/5 |
| Added | Broad sources | 5/18 | 3/5 | 3/5 |
| Added | Narrowed sources | 6/18 | 4/6 | 4/5 |
| Combined | No AgPlane | 12/24 | 9/12 | 8/11 |
| Combined | Broad sources | 11/24 | 9/11 | 9/11 |
| Combined | Narrowed sources | 12/24 | 8/12 | 8/11 |

Combined tasks with valid outcomes in all three conditions: `adaptive-rejection-sampler`, `cancel-async-tasks`, `fix-code-vulnerability`, `git-leak-recovery`, `hf-model-inference`, `log-summary-date-ranges`, `modernize-scientific-stack`, `nginx-request-logging`, `openssl-selfsigned-cert`, `sanitize-git-repo`, `vulnerable-secret`.

Additional completed cells outside that matched set: No AgPlane: `pytorch-model-cli`; Narrowed sources: `pytorch-model-cli`.

Available-condition scores can have different task mixes. The matched column uses the same tasks completed in every condition.

| Cohort | Condition | Covered calls | False calls | Unknown calls | Unassigned events | False-call bounds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Added | No AgPlane | 58 | 0 | 0 | 0 | 0.00–0.00% |
| Added | Broad sources | 71 | 0 | 0 | 108 | 0.00% lower; upper unavailable |
| Added | Narrowed sources | 95 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | No AgPlane | 126 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | Broad sources | 131 | 0 | 0 | 108 | 0.00% lower; upper unavailable |
| Combined | Narrowed sources | 148 | 0 | 0 | 0 | 0.00–0.00% |

The added/combined matrices are complete only when every frozen task has valid outcomes in every condition. Security coverage and adjudication completeness remain separate fields.
