# Final reviewed 362-repository study

All 29,717 statements have reviewed labels: 2,116 statements from the original 64 repositories reviewed with unchanged procedure 2, plus 27,601 previously reviewed statements from 298 added repositories. Final `type`, `topic`, `enforceability`, and `context_required` columns contain reviewed labels; `_first` columns preserve prior labels. Source IDs, text and spans are preserved.

The operator's 2026-10-29 decision prioritizes label accuracy over historical method matching. Procedure 2 retains its historical examples and prompt wording (including its shard-2/added-repositories wording). Some historical examples come from the original 64 repositories. This full-corpus correction pass is not an independent held-out accuracy evaluation. Boundary flags preserve the existing segmentation. The human-review verdicts are blank and remain pending.

The table's paper values are the historical values embedded in unchanged `corpus-merge/analyze_merge.py`; unavailable paper values are literal `unavailable`. Current paper values are recomputed on the original first-pass merged 362-repository labels and exactly match all existing primary metrics. Final values use reviewed labels for every repository. Supplemental metrics use the same bootstrap draws and denominator definitions. Counts and extrema have no bootstrap intervals in the unchanged metric code. Fractions show percentages and 95% percentile intervals in percentage points, using 10,000 draws of whole repositories with seed 20261029.

Cross-event policies' top three topic shares (denominator: all cross-event policies): Development Process: 1,174/5,251 (22.4%), Testing: 975/5,251 (18.6%), AI Integration: 729/5,251 (13.9%).

| Measure | Paper value | Current paper value (first-pass merged) | Final reviewed value (95% CI) |
|---|---:|---:|---:|
| 1. Repositories | 64 | 362 | 362 |
| 1. Instruction files (inventory) | 84 | 775 | 775 |
| 1. Files with statement labels | unavailable | 755 | 755 |
| 1. Statements | 2,116 | 29,717 | 29,717 |
| 1. Median GitHub stars | 20K | 34,881.5 | 34,881.5 |
| 2. Policies / statements | 64% | 53.8% [51.5, 56.0] | 57.8% [55.4, 59.9] |
| 2. Descriptions / statements | 36% | 46.2% [44.0, 48.5] | 42.2% [40.1, 44.6] |
| 2. Repositories with more policy than description | 70.1% | 61.0% [56.1, 66.0] | 68.8% [63.8, 73.5] |
| 2. Minimum repository policy share | 0% | 0.0% | 0.0% |
| 2. Maximum repository policy share | 97% | 100.0% | 100.0% |
| 3. Policy share: Development Process | 87% | 71.6% [69.4, 73.8] | 73.3% [71.1, 75.3] |
| 3. Policy share: Implementation Details | 85% | 66.3% [61.9, 70.2] | 69.1% [64.9, 73.0] |
| 3. Policy share: Architecture | 23% | 15.7% [12.4, 19.3] | 20.0% [16.3, 23.8] |
| 3. Policy share: Build and Run | unavailable | 54.9% [50.4, 59.3] | 56.8% [52.4, 61.1] |
| 3. Policy share: AI Integration | unavailable | 62.9% [59.6, 66.2] | 67.2% [63.9, 70.5] |
| 3. Policy share: Testing | unavailable | 68.5% [65.2, 71.6] | 70.2% [67.0, 73.3] |
| 3. Policy share: System Overview | unavailable | 1.7% [0.6, 3.0] | 3.5% [1.2, 7.0] |
| 3. Policy share: Documentation | unavailable | 47.9% [43.8, 52.0] | 54.7% [50.0, 59.2] |
| 3. Policy share: Configuration & Environment | unavailable | 37.8% [32.5, 43.5] | 43.5% [37.8, 49.3] |
| 3. Policy share: Security | unavailable | 66.8% [61.9, 71.7] | 72.0% [67.2, 76.6] |
| 3. Policy share: DevOps | unavailable | 49.7% [43.7, 55.4] | 57.4% [50.7, 63.6] |
| 3. Policy share: Maintenance | unavailable | 74.0% [68.5, 79.1] | 77.4% [71.6, 82.4] |
| 4. Policies | 1,361 | 15,985 | 17,163 |
| 4. semantic_only / policies | 17% | 23.1% [21.3, 25.0] | 12.1% [10.8, 13.6] |
| 4. content / policies | 38% | 34.3% [31.5, 37.1] | 32.9% [30.1, 35.7] |
| 4. per_event / policies | 29% | 26.0% [23.9, 28.3] | 24.4% [22.5, 26.3] |
| 4. cross_event / policies | 16% | 16.6% [15.4, 17.9] | 30.6% [28.7, 32.6] |
| 4. System-observable / policies | 83% | 76.9% [75.0, 78.7] | 87.9% [86.4, 89.2] |
| 5. Development Process / all cross-event policies | 39.5% | 23.9% [20.8, 27.2] | 22.4% [19.5, 25.4] |
| 5. Repositories with at least one cross-event policy | 81% | 85.1% [81.5, 88.7] | 93.6% [90.9, 96.1] |
| 5. Repositories spanning all four tiers | 43% | 69.3% [64.6, 74.0] | 65.7% [60.8, 70.4] |
| 6. System-observable policies | 1,127 | 12,295 | 15,080 |
| 6. Self-contained / system-observable | 26.4% | 20.7% [18.2, 23.5] | 40.9% [38.4, 43.5] |
| 6. Project context / system-observable | 64.2% | 72.8% [70.0, 75.3] | 39.7% [37.4, 42.1] |
| 6. Task context / system-observable | 9.4% | 6.5% [5.5, 7.6] | 19.3% [17.5, 21.2] |
| 6. Not self-contained / system-observable | 73.6% | 79.3% [76.5, 81.8] | 59.1% [56.5, 61.6] |
| 7. Context-dependent / cross-event | 95% | 97.8% [96.7, 98.7] | 81.4% [79.3, 83.4] |
| 7. Project context / cross-event | 77% | 90.4% [88.3, 92.3] | 56.0% [53.1, 58.7] |
| 7. Task context / cross-event | 19% | 7.4% [5.7, 9.3] | 25.4% [22.9, 27.9] |
| 7. Context-dependent / content | 58% | 61.5% [56.6, 66.0] | 44.3% [40.4, 48.3] |
| 7. Self-contained / content | 42% | 38.5% [34.0, 43.4] | 55.7% [51.7, 59.6] |
| 8. OS-enforceable policy candidates | 607 | 6,810 | 9,434 |
| 8. (Per-event + cross-event) / policies | 45% | 42.6% [40.0, 45.3] | 55.0% [52.2, 57.8] |
| 8. Largest per-repository policy count (all tiers) | unavailable | 216 | 229 |
| 8. Largest per-repository OS-tier policy count | 66 | 122 | 141 |
| Cross-event policies in Implementation Details | unavailable | 6.7% [5.3, 8.3] | 8.3% [6.8, 9.9] |
| Cross-event policies in Architecture | unavailable | 2.3% [1.5, 3.3] | 2.2% [1.6, 2.8] |
| Cross-event policies in Build and Run | unavailable | 6.9% [5.5, 8.5] | 7.4% [6.2, 8.8] |
| Cross-event policies in AI Integration | unavailable | 7.6% [5.8, 9.5] | 13.9% [11.6, 16.4] |
| Cross-event policies in Testing | unavailable | 25.2% [22.7, 27.8] | 18.6% [16.7, 20.5] |
| Cross-event policies in System Overview | unavailable | 0.0% [0.0, 0.0] | 0.1% [0.0, 0.2] |
| Cross-event policies in Documentation | unavailable | 12.4% [10.5, 14.4] | 10.5% [9.0, 12.1] |
| Cross-event policies in Configuration & Environment | unavailable | 3.1% [2.1, 4.1] | 3.6% [2.8, 4.4] |
| Cross-event policies in Security | unavailable | 2.5% [1.4, 4.1] | 4.9% [3.7, 6.3] |
| Cross-event policies in DevOps | unavailable | 6.0% [4.4, 7.9] | 4.9% [3.6, 6.4] |
| Cross-event policies in Maintenance | unavailable | 3.3% [2.3, 4.3] | 3.4% [2.6, 4.3] |
| content: project context / tier | unavailable | 60.3% [55.4, 64.7] | 37.6% [33.6, 41.7] |
| content: task context / tier | unavailable | 1.3% [0.9, 1.7] | 6.7% [5.5, 8.0] |
| per_event: none context / tier | unavailable | 9.2% [7.3, 11.2] | 49.1% [46.2, 52.0] |
| per_event: project context / tier | unavailable | 78.1% [75.3, 80.8] | 22.2% [20.0, 24.4] |
| per_event: task context / tier | unavailable | 12.7% [10.7, 14.9] | 28.7% [25.7, 32.0] |
| per_event: project_task context / tier | unavailable | 90.8% [88.8, 92.7] | 50.9% [48.0, 53.8] |
| cross_event: none context / tier | unavailable | 2.2% [1.3, 3.3] | 18.6% [16.6, 20.7] |

`final_review_sample.csv` samples 100 distinct statements from the full 362-repository frame, covering 88 repositories and both original/added cohorts ({'original64': 11, 'added298': 89}). It uses equal allocation across populated final type/tier/topic strata, with repository round robin within strata, seed 20261033. A 100-statement sample cannot include all 362 repositories. It is intended for qualitative human review, not prevalence estimation.

Four figures in `final_figures/` use the unchanged merge plotting source, with only its output directory redirected. Loaded repository, statement, topic, tier and context counts reconcile with final metrics. All four PDFs have embedded TrueType fonts (Type 42 setting), and `pdffonts` confirms no Type 3 fonts. PNG previews accompany the PDFs. Existing plot style and legend placement are preserved.

Reproduce from the repository root: `python -u docs/empirical-study/corpus-relabel/run_original64.py`, then `python -u docs/empirical-study/corpus-relabel/finalize_study.py`. Procedure-2 validated batch caches allow resumption. Python dependencies and hashes are recorded in `final_provenance.json`. No paper repository files are edited.
