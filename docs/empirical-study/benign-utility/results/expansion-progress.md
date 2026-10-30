Expansion snapshot from `results/headline.csv`; pending cells are not failures.

| Cohort | Condition | Completed / planned | Official successes / completed | Matched successes / common tasks |
| --- | --- | ---: | ---: | ---: |
| Added | No AgPlane | 8/18 | 7/8 | 7/8 |
| Added | Broad sources | 8/18 | 6/8 | 6/8 |
| Added | Narrowed sources | 9/18 | 5/9 | 5/8 |
| Combined | No AgPlane | 14/24 | 11/14 | 11/14 |
| Combined | Broad sources | 14/24 | 12/14 | 12/14 |
| Combined | Narrowed sources | 15/24 | 9/15 | 9/14 |

Combined tasks with valid outcomes in all three conditions: `adaptive-rejection-sampler`, `cancel-async-tasks`, `fix-code-vulnerability`, `fix-git`, `git-leak-recovery`, `hf-model-inference`, `log-summary-date-ranges`, `modernize-scientific-stack`, `nginx-request-logging`, `openssl-selfsigned-cert`, `pytorch-model-cli`, `sanitize-git-repo`, `vulnerable-secret`, `write-compressor`.

Additional completed cells outside that matched set: Narrowed sources: `extract-elf`.

Available-condition scores can have different task mixes. The matched column uses the same tasks completed in every condition.

| Cohort | Condition | Covered calls | False calls | Unknown calls | Unassigned events | False-call bounds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Added | No AgPlane | 91 | 0 | 0 | 0 | 0.00–0.00% |
| Added | Broad sources | 143 | 14 | 0 | 0 | 9.79–9.79% |
| Added | Narrowed sources | 180 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | No AgPlane | 159 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | Broad sources | 203 | 14 | 0 | 0 | 6.90–6.90% |
| Combined | Narrowed sources | 233 | 0 | 0 | 0 | 0.00–0.00% |

The added/combined matrices are complete only when every frozen task has valid outcomes in every condition. Security coverage and adjudication completeness remain separate fields.
