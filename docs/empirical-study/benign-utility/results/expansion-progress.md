Expansion snapshot from `results/headline.csv`; pending cells are not failures.

| Cohort | Condition | Completed / planned | Official successes / completed | Matched successes / common tasks |
| --- | --- | ---: | ---: | ---: |
| Added | No AgPlane | 7/18 | 6/7 | 5/6 |
| Added | Broad sources | 6/18 | 4/6 | 4/6 |
| Added | Narrowed sources | 6/18 | 4/6 | 4/6 |
| Combined | No AgPlane | 13/24 | 10/13 | 9/12 |
| Combined | Broad sources | 12/24 | 10/12 | 10/12 |
| Combined | Narrowed sources | 12/24 | 8/12 | 8/12 |

Combined tasks with valid outcomes in all three conditions: `adaptive-rejection-sampler`, `cancel-async-tasks`, `fix-code-vulnerability`, `git-leak-recovery`, `hf-model-inference`, `log-summary-date-ranges`, `modernize-scientific-stack`, `nginx-request-logging`, `openssl-selfsigned-cert`, `pytorch-model-cli`, `sanitize-git-repo`, `vulnerable-secret`.

Additional completed cells outside that matched set: No AgPlane: `write-compressor`.

Available-condition scores can have different task mixes. The matched column uses the same tasks completed in every condition.

| Cohort | Condition | Covered calls | False calls | Unknown calls | Unassigned events | False-call bounds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Added | No AgPlane | 72 | 0 | 0 | 0 | 0.00–0.00% |
| Added | Broad sources | 100 | 14 | 0 | 0 | 14.00–14.00% |
| Added | Narrowed sources | 95 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | No AgPlane | 140 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | Broad sources | 160 | 14 | 0 | 0 | 8.75–8.75% |
| Combined | Narrowed sources | 148 | 0 | 0 | 0 | 0.00–0.00% |

The added/combined matrices are complete only when every frozen task has valid outcomes in every condition. Security coverage and adjudication completeness remain separate fields.
