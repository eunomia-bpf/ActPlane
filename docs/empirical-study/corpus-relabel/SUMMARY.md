# Reviewed merged study

DO NOT ACCEPT the merged reviewed labels as method-consistent. Original-reference failures: procedure1, procedure2, procedure3. Best relative agreement: procedure2. All three procedures deviate from the original reference. Recommend re-running all affected shards with procedure2 only after its remaining original-reference failures are resolved and independently revalidated. Its relative ranking is not a pass. No shard was re-run.

Added-sample pairwise exact matches are 67.3–74.7%, with context kappas 0.610–0.710. Original-reference exact matches are 53.3–58.3%; enforcement kappas are 0.556–0.571 and context kappas 0.349–0.478. Original-reference enforcement raw agreement (67.3–68.2%) also falls below the roughly 92–95% agreement implied by the historical estimated 5–8% error band. The outcome is the same under that recorded bar. Procedure 2 ranks first by mean original-reference kappa, 0.6880, and still fails type, enforcement and context. All three shards are affected.

Independent first-party claude-opus-5-5 reviewed 100/100 rows. Its exact four-label agreement is 79%, with kappas 0.944 (type), 0.924 (topic), 0.874 (enforcement) and 0.803 (context). The 21 statements with at least one disagreement and their label-level rationales are retained in disagreements.csv. No label was changed from this check.

Validated 27,601 added statements exactly once across 298 repositories. The requested merge has 29,717 statements in 362 repositories, retaining all 2,116 original labels from 64 repositories (including the 27 overlaps). Original reference: origin/artifact-ready = 63db86945c9b8618a46aa68c8de214bc4b8343d9.

Method identity cannot be certified. Historical sections name Claude Opus 4.6, temperature 0 and a fixed seed; the three review runners use Codex gpt-5.6-sol with their configured reasoning/default sampling and different examples/output instructions. The added corpus also has broader discovery, eligibility, eight file families, automated segmentation, and different first-pass annotators (documented in corpus-merge/README.md). These differences predate this task. Counts below describe the requested frozen merge and must not be presented as a validated same-method replication if the consistency gate fails.

## Recomputed numbers

These are the requested reviewed-label results even when the consistency gate rejects their adoption. Numerators, denominators, unrounded values and 95% intervals are in numbers.csv. Calculations call corpus-merge/analyze_merge.py metrics unchanged, including its 10,000 whole-repository bootstrap draws and seed 20261029. Original plot script is copied byte-for-byte from corpus-merge; four PDFs and PNG previews are under figures/, with Type 42 settings and pdffonts evidence.

| Measure | Paper | Current | Reviewed |
|---|---|---|---|
| 1. Repositories | 64 | 362 | 362 |
| 1. Instruction files (inventory) | 84 | 775 | 775 |
| 1. Files with statement labels | unavailable | 755 | 755 |
| 1. Statements | 2,116 | 29,717 | 29,717 |
| 1. Median GitHub stars | 20K | 34,881.5 | 34,881.5 |
| 2. Policies / statements | 64% | 53.8% | 57.3% |
| 2. Descriptions / statements | 36% | 46.2% | 42.7% |
| 2. Repositories with more policy than description | 70.1% | 61.0% | 67.7% |
| 2. Minimum repository policy share | 0% | 0.0% | 0.0% |
| 2. Maximum repository policy share | 97% | 100.0% | 100.0% |
| 3. Policy share: Development Process | 87% | 71.6% | 73.2% |
| 3. Policy share: Implementation Details | 85% | 66.3% | 68.9% |
| 3. Policy share: Architecture | 23% | 15.7% | 19.1% |
| 3. Policy share: Build and Run | unavailable | 54.9% | 56.6% |
| 3. Policy share: AI Integration | unavailable | 62.9% | 66.8% |
| 3. Policy share: Testing | unavailable | 68.5% | 69.7% |
| 3. Policy share: System Overview | unavailable | 1.7% | 3.5% |
| 3. Policy share: Documentation | unavailable | 47.9% | 54.4% |
| 3. Policy share: Configuration & Environment | unavailable | 37.8% | 43.0% |
| 3. Policy share: Security | unavailable | 66.8% | 71.3% |
| 3. Policy share: DevOps | unavailable | 49.7% | 56.6% |
| 3. Policy share: Maintenance | unavailable | 74.0% | 76.7% |
| 4. Policies | 1,361 | 15,985 | 17,041 |
| 4. semantic_only / policies | 17% | 23.1% | 13.1% |
| 4. content / policies | 38% | 34.3% | 33.0% |
| 4. per_event / policies | 29% | 26.0% | 24.5% |
| 4. cross_event / policies | 16% | 16.6% | 29.4% |
| 4. System-observable / policies | 83% | 76.9% | 86.9% |
| 5. Development Process / all cross-event policies | 39.5% | 23.9% | 22.0% |
| 5. Repositories with at least one cross-event policy | 81% | 85.1% | 92.3% |
| 5. Repositories spanning all four tiers | 43% | 69.3% | 66.0% |
| 6. System-observable policies | 1,127 | 12,295 | 14,812 |
| 6. Self-contained / system-observable | 26.4% | 20.7% | 39.3% |
| 6. Project context / system-observable | 64.2% | 72.8% | 41.9% |
| 6. Task context / system-observable | 9.4% | 6.5% | 18.8% |
| 6. Not self-contained / system-observable | 73.6% | 79.3% | 60.7% |
| 7. Context-dependent / cross-event | 95% | 97.8% | 82.5% |
| 7. Project context / cross-event | 77% | 90.4% | 57.3% |
| 7. Task context / cross-event | 19% | 7.4% | 25.1% |
| 7. Context-dependent / content | 58% | 61.5% | 45.8% |
| 7. Self-contained / content | 42% | 38.5% | 54.2% |
| 8. OS-enforceable policy candidates | 607 | 6,810 | 9,192 |
| 8. (Per-event + cross-event) / policies | 45% | 42.6% | 53.9% |
| 8. Largest per-repository policy count (all tiers) | unavailable | 216 | 229 |
| 8. Largest per-repository OS-tier policy count | 66 | 122 | 141 |

## First-pass changes

| shard | label | changed | total | rate |
|---|---|---|---|---|
| 1 | type | 494 | 9201 | 0.05368981632431258 |
| 1 | topic | 330 | 9201 | 0.0358656667753505 |
| 1 | enforceability | 1775 | 9201 | 0.19291381371590044 |
| 1 | context_required | 2498 | 9201 | 0.271492229105532 |
| 1 | any | 2999 | 9201 | 0.32594283230083687 |
| 1 | boundary | 2153 | 9201 | 0.23399630474948374 |
| 2 | type | 432 | 9200 | 0.04695652173913043 |
| 2 | topic | 400 | 9200 | 0.043478260869565216 |
| 2 | enforceability | 1705 | 9200 | 0.18532608695652175 |
| 2 | context_required | 2374 | 9200 | 0.25804347826086954 |
| 2 | any | 3000 | 9200 | 0.32608695652173914 |
| 2 | boundary | 2167 | 9200 | 0.23554347826086958 |
| 3 | type | 418 | 9200 | 0.04543478260869565 |
| 3 | topic | 212 | 9200 | 0.023043478260869565 |
| 3 | enforceability | 1741 | 9200 | 0.1892391304347826 |
| 3 | context_required | 2405 | 9200 | 0.2614130434782609 |
| 3 | any | 2940 | 9200 | 0.31956521739130433 |
| 3 | boundary | 974 | 9200 | 0.1058695652173913 |
| all | type | 1344 | 27601 | 0.0487 |
| all | topic | 942 | 27601 | 0.0341 |
| all | enforceability | 5221 | 27601 | 0.1892 |
| all | context_required | 7277 | 27601 | 0.2636 |
| all | any | 8939 | 27601 | 0.3239 |
| all | boundary | 5294 | 27601 | 0.1918 |

## Independent Claude cross-check

| label | n | agreement | kappa | change_rate |
|---|---|---|---|---|
| type | 100 | 0.9800 | 0.9436 | 0.0200 |
| topic | 100 | 0.9300 | 0.9235 | 0.0700 |
| enforceability | 76 | 0.9079 | 0.8739 | 0.0921 |
| context_required | 64 | 0.8750 | 0.8033 | 0.1250 |

See CHECK.md, agreement.csv, exact_match.csv and disagreements.csv for the complete procedure results and individual Claude disagreements. Claude labels never replace the reviewed labels. review_sample.csv contains a separate 100-statement author sample with empty verdicts.

## Reproduction and evidence

Run prepare_study.py and report_checks.py through ws.sh run corpus-relabel with the existing corpus-merge virtualenv. Run run_checks.py locally for model calls. The model adapter retains every original runner and prompt, changes only output paths, and uses 150 statements per batch. Sampling seeds, allocation and example exclusions are retained in sampling.json and excluded_worked_examples.csv. All samplings use equal allocation across populated type/tier/topic strata with repository round robin within strata, without replacement. This deliberately emphasizes uncommon categories. Original sample excludes all embedded worked-example text. The two 100-statement samples use reviewed-label strata.

Inputs for offline reproduction are the unchanged corpus-merge/.inputs staged snapshot (copy to .inputs here), verified against source_hashes.csv, plus the retained shard inputs/outputs. Source input payloads are already versioned in corpus-scale and original YAML snapshots are retained in the shard directories. Large raw CLI logs are excluded; structured batch inputs, outputs, runners, schemas and instructions remain versioned. No paper repository edits, full-shard reruns, pull, rebase or PR.

Final checks: all 45 current-merge values match baseline_numbers.csv exactly; original runner and reviewed.csv hashes are unchanged; the plot script differs from the original only in the documented output directory and Type 42 settings. Source text comparisons across the first-pass export normalize CRLF/LF only, while each shard input versus reviewed output requires exact field equality. Figure previews were visually inspected: original legend overlays and the long-label clipping in figure 3 are retained. Workspace timestamps are approximately 10 minutes ahead of the local host, so cross-host file times are not used as elapsed-time evidence.
