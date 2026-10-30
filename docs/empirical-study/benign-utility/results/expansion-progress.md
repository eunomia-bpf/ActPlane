Expansion snapshot from `results/headline.csv`; pending cells are not failures.

| Cohort | Condition | Completed / planned | Official successes / completed | Matched successes / common tasks |
| --- | --- | ---: | ---: | ---: |
| Added | No AgPlane | 10/18 | 8/10 | 8/9 |
| Added | Broad sources | 10/18 | 7/10 | 7/9 |
| Added | Narrowed sources | 9/18 | 5/9 | 5/9 |
| Combined | No AgPlane | 16/24 | 12/16 | 12/15 |
| Combined | Broad sources | 16/24 | 13/16 | 13/15 |
| Combined | Narrowed sources | 15/24 | 9/15 | 9/15 |

Combined tasks with valid outcomes in all three conditions: `adaptive-rejection-sampler`, `cancel-async-tasks`, `extract-elf`, `fix-code-vulnerability`, `fix-git`, `git-leak-recovery`, `hf-model-inference`, `log-summary-date-ranges`, `modernize-scientific-stack`, `nginx-request-logging`, `openssl-selfsigned-cert`, `pytorch-model-cli`, `sanitize-git-repo`, `vulnerable-secret`, `write-compressor`.

Additional completed cells outside that matched set: No AgPlane: `caffe-cifar-10`; Broad sources: `caffe-cifar-10`.

Available-condition scores can have different task mixes. The matched column uses the same tasks completed in every condition.

| Cohort | Condition | Covered calls | False calls | Unknown calls | Unassigned events | False-call bounds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Added | No AgPlane | 157 | 0 | 0 | 0 | 0.00–0.00% |
| Added | Broad sources | 194 | 14 | 0 | 0 | 7.22–7.22% |
| Added | Narrowed sources | 180 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | No AgPlane | 225 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | Broad sources | 254 | 14 | 0 | 0 | 5.51–5.51% |
| Combined | Narrowed sources | 233 | 0 | 0 | 0 | 0.00–0.00% |

The added/combined matrices are complete only when every frozen task has valid outcomes in every condition. Security coverage and adjudication completeness remain separate fields.
