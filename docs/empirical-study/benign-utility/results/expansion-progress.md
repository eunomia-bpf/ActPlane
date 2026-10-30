Expansion snapshot from `results/headline.csv`; pending cells are not failures.

| Cohort | Condition | Completed / planned | Official successes / completed | Matched successes / common tasks |
| --- | --- | ---: | ---: | ---: |
| Added | No AgPlane | 11/18 | 9/11 | 8/10 |
| Added | Broad sources | 11/18 | 7/11 | 7/10 |
| Added | Narrowed sources | 10/18 | 5/10 | 5/10 |
| Combined | No AgPlane | 17/24 | 13/17 | 12/16 |
| Combined | Broad sources | 17/24 | 13/17 | 13/16 |
| Combined | Narrowed sources | 16/24 | 9/16 | 9/16 |

Combined tasks with valid outcomes in all three conditions: `adaptive-rejection-sampler`, `caffe-cifar-10`, `cancel-async-tasks`, `extract-elf`, `fix-code-vulnerability`, `fix-git`, `git-leak-recovery`, `hf-model-inference`, `log-summary-date-ranges`, `modernize-scientific-stack`, `nginx-request-logging`, `openssl-selfsigned-cert`, `pytorch-model-cli`, `sanitize-git-repo`, `vulnerable-secret`, `write-compressor`.

Additional completed cells outside that matched set: No AgPlane: `protein-assembly`; Broad sources: `protein-assembly`.

Available-condition scores can have different task mixes. The matched column uses the same tasks completed in every condition.

| Cohort | Condition | Covered calls | False calls | Unknown calls | Unassigned events | False-call bounds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Added | No AgPlane | 215 | 0 | 0 | 0 | 0.00–0.00% |
| Added | Broad sources | 235 | 14 | 0 | 1558 | 5.96% lower; upper unavailable |
| Added | Narrowed sources | 218 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | No AgPlane | 283 | 0 | 0 | 0 | 0.00–0.00% |
| Combined | Broad sources | 295 | 14 | 0 | 1558 | 4.75% lower; upper unavailable |
| Combined | Narrowed sources | 271 | 0 | 0 | 0 | 0.00–0.00% |

The added/combined matrices are complete only when every frozen task has valid outcomes in every condition. Security coverage and adjudication completeness remain separate fields.
