# Merged repository empirical study

Data-analysis-only handoff, 2026-10-29. The paper repository and the two data-free waterfall diagrams are unchanged.
All computation and figure production run in the existing actplane-dev Workspace. No extraction, inference, relabeling, or prevalence correction is performed.

## Sources and repository merge

- Original: `../corpus-scale/paper_labels.csv` (2,116 statements), `paper_files.csv`, and `paper_provenance.csv`, recovered by `recover.py` from immutable ActPlane commit `63db86945c9b8618a46aa68c8de214bc4b8343d9`, snapshot 2026-05-23. Every recovered statement's text, range, and four labels is checked against that commit's `docs/corpus/<repo>/statements.yaml`. All files in the historical provenance manifest are SHA-256 verified, including raw instructions and star metadata.
- Corpus-scale: `../corpus-scale/labels.csv` is the **final accepted deployed label table**. Type/topic are frozen decisions from the Qwen3.8-27B (`qwen3.8-27b-nvfp4`) and GLM-5.3 (`zai/glm-5.3`) pipeline. Enforcement/context are the accepted rescue `r1` labels deployed by `rescue/deploy.py`. Their values are checked against `rescue/source-adjudicated.csv` and its deployment-manifest hash. The frozen type/topic fingerprint is checked against `rescue/retained_axes.csv`.
- `analysis_statements.csv` supplies repository/file membership and is checked row by row against `labels.csv` for all four axes and against `statements.csv` for source fields. All 30,846 statement IDs and accepted labels are present, covering all 325 repositories and all 761 included repository/content pairs. The five headline values in `summary.csv` are reproduced exactly before any merge; see `source_headline_check.csv`: 53.0053%, 76.4098%, 80.1009%, 86.4615%, and 7,118. Misclassification-corrected estimates and pre-rescue failed labels are not used.
- `corpus_manifest.csv` supplies the byte-deduplicated included file inventory. `repositories.csv` supplies stars at the 2026-10-28 snapshot. Historical stars come from the selected May metadata. Stars follow the retained repository version in each merge, with no live refresh.
- Primary: keep **all original statements and labels for all 64 original repositories**, including the 27 overlaps; append the 298 new-only corpus-scale repositories. Alternative: retain 37 original-only repositories and all 325 corpus-scale repositories. Each has exactly 362 repository identities. Case-insensitive `owner/name` comparison matches `snapshot_overlap.csv`; repository renames are not inferred. No repository is included twice. `repository_membership.csv` records every selection.

## Definitions and denominators

`directive` means policy and `description` means descriptive statement. The exact `COLLAPSE` map and 12-topic order are read from the copied original plot script: Debugging and Project Management become Development Process; Performance and UI/UX become Implementation Details. No other topic remapping occurs.

The four tiers are `semantic_only`, `content`, `per_event`, and `cross_event`. System-observable = content + per_event + cross_event. OS-enforceable candidates = per_event + cross_event. These taxonomy counts do not establish that the current engine implements every predicate. Enforcement percentages divide by policies. Context percentages divide by system-observable policies, except the explicitly named tier-specific rows. `none` is self-contained, `project` and `task` are context-dependent. Repository prevalence uses all repositories, including repositories with no policies. Majority is strictly more policies than descriptions. The Development Process cross-event row divides by **all cross-event policies**, matching the paper's statement that this topic accounts for 39.5% of them.

Instruction-file inventory follows each source's historical convention: within a repository identical bytes count once, and the May inventory additionally excludes pure `@AGENTS.md` / `@CLAUDE.md` redirect files. The October inventory retains selected redirects. **The original 84 inventory files have labels for only 64 primary files.** The `Files with statement labels` row makes this coverage difference explicit. File counts are additive across selected repository identities; identical templates in different repositories remain separate.

## Recomputed paper numbers

Every percentage is recomputed from its numerator and denominator, without averaging repository percentages. Brackets give 95% repository-bootstrap intervals, expressed as percentages. Counts and extrema have no interval. Paper values are the operator-provided current-paper values, retained verbatim, rather than treated as exact recomputed historical values. `unavailable` means that no current-paper value was supplied for that row. `numbers.csv` contains unrounded fractions, integer numerators and denominators, both interval endpoints, and the four cohorts.

| Measure | Paper value | Merged primary | Merged alternative | 64-only | 298-only |
|---|---:|---:|---:|---:|---:|
| 1. Repositories | 64 | 362 | 362 | 64 | 298 |
| 1. Instruction files (inventory) | 84 | 775 | 811 | 84 | 691 |
| 1. Files with statement labels | unavailable | 755 | 798 | 64 | 691 |
| 1. Statements | 2,116 | 29,717 | 31,987 | 2,116 | 27,601 |
| 1. Median GitHub stars | 20K | 34,881.5 | 36,502.5 | 19,999 | 40,021.5 |
| 2. Policies / statements | 64% | 53.8% [51.5, 56.0] | 53.4% [51.2, 55.5] | 64.3% [56.6, 71.6] | 53.0% [50.6, 55.3] |
| 2. Descriptions / statements | 36% | 46.2% [44.0, 48.5] | 46.6% [44.5, 48.8] | 35.7% [28.4, 43.4] | 47.0% [44.7, 49.4] |
| 2. Repositories with more policy than description | 70.1% | 61.0% [56.1, 66.0] | 60.5% [55.5, 65.5] | 73.4% [62.5, 84.4] | 58.4% [52.7, 64.1] |
| 2. Minimum repository policy share | 0% | 0.0% | 0.0% | 0.0% | 0.0% |
| 2. Maximum repository policy share | 97% | 100.0% | 100.0% | 100.0% | 100.0% |
| 3. Policy share: Development Process | 87% | 71.6% [69.4, 73.8] | 70.5% [68.4, 72.6] | 88.1% [79.3, 94.8] | 69.6% [67.4, 71.7] |
| 3. Policy share: Implementation Details | 85% | 66.3% [61.9, 70.2] | 66.0% [61.8, 69.8] | 86.9% [79.0, 93.8] | 64.6% [60.0, 68.8] |
| 3. Policy share: Architecture | 23% | 15.7% [12.4, 19.3] | 15.3% [12.2, 18.6] | 23.5% [12.0, 37.2] | 14.7% [11.4, 18.4] |
| 3. Policy share: Build and Run | unavailable | 54.9% [50.4, 59.3] | 54.6% [50.4, 58.8] | 60.1% [46.8, 72.6] | 54.3% [49.6, 58.8] |
| 3. Policy share: AI Integration | unavailable | 62.9% [59.6, 66.2] | 61.1% [57.9, 64.4] | 78.3% [66.9, 89.9] | 62.0% [58.6, 65.4] |
| 3. Policy share: Testing | unavailable | 68.5% [65.2, 71.6] | 68.8% [65.5, 71.9] | 74.3% [62.3, 83.9] | 68.0% [64.5, 71.3] |
| 3. Policy share: System Overview | unavailable | 1.7% [0.6, 3.0] | 1.5% [0.5, 2.9] | 0.0% [0.0, 0.0] | 1.8% [0.6, 3.2] |
| 3. Policy share: Documentation | unavailable | 47.9% [43.8, 52.0] | 47.8% [43.7, 51.7] | 62.3% [44.3, 77.1] | 47.6% [43.3, 51.6] |
| 3. Policy share: Configuration & Environment | unavailable | 37.8% [32.5, 43.5] | 38.0% [32.9, 43.4] | 32.8% [17.3, 52.0] | 38.1% [32.5, 43.9] |
| 3. Policy share: Security | unavailable | 66.8% [61.9, 71.7] | 66.1% [61.2, 70.9] | 67.3% [49.3, 84.7] | 66.8% [61.6, 72.0] |
| 3. Policy share: DevOps | unavailable | 49.7% [43.7, 55.4] | 49.2% [43.6, 54.8] | 33.3% [11.8, 52.8] | 50.5% [44.5, 56.4] |
| 3. Policy share: Maintenance | unavailable | 74.0% [68.5, 79.1] | 73.9% [68.6, 78.9] | 82.9% [67.5, 95.0] | 73.2% [67.5, 78.6] |
| 4. Policies | 1,361 | 15,985 | 17,071 | 1,361 | 14,624 |
| 4. semantic_only / policies | 17% | 23.1% [21.3, 25.0] | 23.4% [21.6, 25.2] | 17.2% [12.6, 22.6] | 23.6% [21.7, 25.7] |
| 4. content / policies | 38% | 34.3% [31.5, 37.1] | 33.0% [30.3, 35.8] | 38.2% [31.1, 45.6] | 34.0% [31.0, 37.0] |
| 4. per_event / policies | 29% | 26.0% [23.9, 28.3] | 26.6% [24.5, 28.9] | 28.8% [23.4, 33.9] | 25.7% [23.4, 28.1] |
| 4. cross_event / policies | 16% | 16.6% [15.4, 17.9] | 17.0% [15.8, 18.2] | 15.8% [13.1, 18.9] | 16.7% [15.4, 18.0] |
| 4. System-observable / policies | 83% | 76.9% [75.0, 78.7] | 76.6% [74.8, 78.4] | 82.8% [77.4, 87.4] | 76.4% [74.3, 78.3] |
| 5. Development Process / all cross-event policies | 39.5% | 23.9% [20.8, 27.2] | 23.3% [20.3, 26.3] | 39.5% [30.2, 49.5] | 22.6% [19.3, 26.1] |
| 5. Repositories with at least one cross-event policy | 81% | 85.1% [81.5, 88.7] | 85.6% [82.0, 89.2] | 79.7% [70.3, 89.1] | 86.2% [82.2, 89.9] |
| 5. Repositories spanning all four tiers | 43% | 69.3% [64.6, 74.0] | 72.7% [68.0, 77.1] | 42.2% [29.7, 54.7] | 75.2% [70.1, 79.9] |
| 6. System-observable policies | 1,127 | 12,295 | 13,082 | 1,127 | 11,168 |
| 6. Self-contained / system-observable | 26.4% | 20.7% [18.2, 23.5] | 20.1% [17.6, 22.8] | 26.4% [21.1, 32.0] | 20.2% [17.5, 23.3] |
| 6. Project context / system-observable | 64.2% | 72.8% [70.0, 75.3] | 73.5% [70.8, 76.0] | 64.2% [58.4, 69.5] | 73.6% [70.6, 76.4] |
| 6. Task context / system-observable | 9.4% | 6.5% [5.5, 7.6] | 6.4% [5.4, 7.5] | 9.4% [6.4, 12.8] | 6.2% [5.1, 7.4] |
| 6. Not self-contained / system-observable | 73.6% | 79.3% [76.5, 81.8] | 79.9% [77.2, 82.4] | 73.6% [68.0, 78.9] | 79.8% [76.7, 82.5] |
| 7. Context-dependent / cross-event | 95% | 97.8% [96.7, 98.7] | 97.8% [96.9, 98.7] | 95.3% [90.3, 98.8] | 98.0% [96.9, 98.9] |
| 7. Project context / cross-event | 77% | 90.4% [88.3, 92.3] | 90.6% [88.6, 92.4] | 76.7% [69.8, 83.2] | 91.6% [89.4, 93.6] |
| 7. Task context / cross-event | 19% | 7.4% [5.7, 9.3] | 7.3% [5.7, 9.0] | 18.6% [12.3, 25.1] | 6.4% [4.7, 8.3] |
| 7. Context-dependent / content | 58% | 61.5% [56.6, 66.0] | 61.4% [56.7, 65.9] | 57.5% [48.3, 65.8] | 62.0% [56.6, 66.8] |
| 7. Self-contained / content | 42% | 38.5% [34.0, 43.4] | 38.6% [34.1, 43.3] | 42.5% [34.2, 51.7] | 38.0% [33.2, 43.4] |
| 8. OS-enforceable policy candidates | 607 | 6,810 | 7,443 | 607 | 6,203 |
| 8. (Per-event + cross-event) / policies | 45% | 42.6% [40.0, 45.3] | 43.6% [41.0, 46.3] | 44.6% [39.2, 49.6] | 42.4% [39.6, 45.2] |
| 8. Largest per-repository policy count (all tiers) | unavailable | 216 | 216 | 131 | 216 |
| 8. Largest per-repository OS-tier policy count | 66 | 122 | 138 | 66 | 122 |

## Bootstrap method

For each cohort independently, sample N whole repositories uniformly with replacement N times per replicate, retaining every statement of each selected repository with multiplicity. Use 10,000 replicates, NumPy `default_rng(20261029)`, sorted case-folded repository identities, multinomial multiplicity vectors, and central percentile endpoints (2.5%, 97.5%, NumPy linear quantiles). Within each replicate recompute pooled ratios of sums. The repository-share rows instead average repository indicators. Intervals are supplied for all ratio rows, including all headline shares in items 2, 4, 6 and both repository shares in item 5. Undefined zero-denominator replicates are omitted from percentile calculation. Counts, median stars and per-repository extrema are descriptive point values.

This is an ordinary, unstratified repository cluster bootstrap of each merged convenience sample. Unlike the earlier corpus-scale summary's 2,000 discovery-stratified draws, it applies the same method to all four requested cohorts. It does not estimate uncertainty from model error, human error, segmentation, eligibility, snapshot mixing, selection bias, or correlated templates. The primary and alternative share repository identities; their intervals are marginal, not a paired test of differences.

## Annotation checks and limitations

The paper reports an LLM-agent extraction/labeling pipeline, span/coverage checks, independent Claude and Codex cross-checking, and a stratified **100-statement human check**. This analysis retains those historical labels unchanged. The exact historical invocation prompts and human-check sample were not recovered, so that human check cannot be re-audited here. The original source-fidelity audit found 417 exact-formatting differences but zero whitespace-normalized mismatches; this merge preserves the annotated text rather than re-extracting it.

For the corpus-scale final type/topic pipeline, `format_calibration_summary.csv` reports adjudicated Cohen's kappa **0.830704 / 0.679778**, with 2,116/2,116 reference statements evaluated. Individual Qwen kappas are 0.814768 / 0.692569, and GLM kappas are 0.803433 / 0.661046. These are agreement with the historical reference, not human ground truth for the expanded corpus.

The original full-guide enforcement/context calibration failed (adjudicated kappa 0.594 / 0.191). Those failed-axis predictions are not the final labels used here. The rescue split uses 21 development repositories (505 statements) and 43 test repositories (1,611 statements). Revision r1's adjudicated test kappas are **0.694233 enforcement** (1,017 applicable historical directives) and **0.679333 context** (865 applicable system-observable directives), at 100% coverage. Individual test kappas are Qwen 0.662778 / 0.646199 and GLM 0.681311 / 0.720348. The split is held out from rescue revision/selection only: all historical labels had earlier aggregate diagnostic exposure. Context calibration conditions on original directives, while deployment conditions on the frozen automated directive set. Qwen rereads disagreements, so adjudication is correlated with a primary model. No new human audit validates segmentation, additional instruction families or noncoding files.

The May snapshot uses CLAUDE.md/AGENTS.md and coding-focused eligibility. The October snapshot uses eight families (CLAUDE.md, AGENTS.md, GEMINI.md, copilot-instructions.md, .cursor/rules/*, .cursorrules, .windsurfrules, SKILL.md), broader discovery/eligibility, capped family selection and automated segmentation. Labels, snapshot dates, file coverage, file inventory conventions and labelers therefore differ. These are merged descriptive counts, not a longitudinal effect or population estimate. In particular more observed files can increase repository cross-event prevalence.

Several supplied paper values do not match recomputation of the original labels: majority-policy repositories 73.4% versus 70.1%, maximum policy share 100% versus 97%, Development Process and Implementation Details policy shares 88.1% / 86.9% versus 87% / 85%, cross-event repositories 79.7% versus 81%, and repositories spanning all tiers 42.2% versus 43%. The 64-only column deliberately exposes these discrepancies; it is not adjusted to reproduce prose numbers. The supplied largest-per-repository count of 66 is reproduced for **OS-tier** policies: the original openclaw/openclaw repository has 131 total policies, including 45 per-event and 21 cross-event policies. Both maxima are reported explicitly to avoid confusing these scopes. `repository_counts.csv` records both snapshots' per-repository counts for inspection. Rounded context subcategories may not sum to the separately rounded context-dependent percentage.

## Figures and reproduction

The four primary-merge figures preserve the original script's style, sizes, colors, sorting, order and labels. `plot_empirical.diff` contains only the output-directory change and `pdf.fonttype = 42` / `ps.fonttype = 42`. The script still reads `<repo>/statements.yaml` from its working directory; `analyze_merge.py` creates the ignored primary `layout/`. `verify_figures.py` checks the original plot's actual loaded repository, topic, enforcement and context counts against the primary numerical table. The original coloring of exactly-50% repositories (`>=50`) is retained, while the numerical majority metric uses the paper's strict `>50%` definition. The unchanged legend locations overlay portions of some bars and labels, as visible in the previews; no layout redesign is made. No waterfall is copied or regenerated. PDFs, PNG previews and `pdffonts` output are under `figures/`.

From this repository root in Windows PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File docs/empirical-study/corpus-merge/stage_inputs.ps1
& "C:\Program Files\Git\bin\bash.exe" C:/Users/10678/actplane-tools/ws.sh run corpus-merge -- bash setup.sh
& "C:\Program Files\Git\bin\bash.exe" C:/Users/10678/actplane-tools/ws.sh run corpus-merge -- bash run.sh
& "C:\Program Files\Git\bin\bash.exe" C:/Users/10678/actplane-tools/ws.sh pull corpus-merge src/README.md src/numbers.csv src/source_hashes.csv src/source_headline_check.csv src/repository_membership.csv src/repository_counts.csv src/environment.txt src/plot_empirical.diff src/figures
```

`stage_inputs.ps1` only copies inputs and exports the immutable historical corpus subtree without checking out another branch. It requires the sibling paper checkout as specified by the operator. `.inputs/` is ignored to avoid duplicating already committed datasets. `ws.sh run` performs sync after local edits. The helper's pull places files under a nested local `src/`; move those returned artifacts into this lane directory. All Python analysis, bootstrapping, plotting, font checks and rendering occur inside actplane-dev. Python/library versions are in `environment.txt`; setup pins the three direct Python dependencies. Data inputs below must match before interpreting a rerun.

The source-label checks, merged-count checks, plot-loaded-data checks, and four `pdffonts` checks passed in the Workspace. PNG previews were visually inspected. Branch-wide CI on the initial data commit failed in an unrelated, unchanged libbpf build: GCC reports discarded const qualifiers as errors in `libbpf.c` (`kallsyms_cb`, `avail_kallsyms_cb`, `resolve_full_path`). See [CI run 40949503058](https://github.com/eunomia-bpf/ActPlane/actions/runs/40949503058). No kernel, vendored library, build configuration, or workflow repair is included in this data-only lane. No PR was opened.

## Input hashes

The `scale/` paths are byte copies of the corresponding sibling `../corpus-scale/` files. `original.tar` is the deterministic archive of the immutable historical corpus subtree. `plot_empirical.original.py` and `02-motivation.tex` are read-only snapshots from the paper repository. The latter is documentation context, not an input to counting or labeling. Per-historical-file hashes are additionally checked against `paper_provenance.csv`. Full hashes are also machine-readable in `source_hashes.csv`.

| Input (relative to staged `.inputs/`) | Bytes | SHA-256 |
|---|---:|---|
| `02-motivation.tex` | 39216 | `7a1980856b932ff49f4097f7991e9741ed408f1506d6e234dcbfaaa865a1a577` |
| `original.tar` | 2836480 | `64a3ba57320fa599dd000c03c5d175fedb2dd45372ec5ba23439313045860a3b` |
| `plot_empirical.original.py` | 8846 | `db4c6d407e75781ca05ddcbbce2e167655537b001fa27a8e25510826e15b15ef` |
| `scale/README.md` | 36312 | `5ddb2cff585a4efc6e6a55ffcd29c44e9be35a162d26c5bb86850da20f187dbb` |
| `scale/analysis_statements.csv` | 7903128 | `81f23bcc61265fe5a5c377ae2333816a7841f79dfffc3d2fe864b907336bf2d2` |
| `scale/calibration_summary.csv` | 2546 | `101c46e5554aaaea1e63b1ab57258e266b244d4796040d879ba5d9b2e0523875` |
| `scale/corpus_manifest.csv` | 4932253 | `15e3f806683d2330db85bd137de4f34f75eb297c08537d508c7aa1d2330f117f` |
| `scale/format_calibration_summary.csv` | 1235 | `1a754ba68da35ae55164f8f7cc526139e6cbd18dae81711be83a248001f5356d` |
| `scale/labels.csv` | 6570686 | `933409ce48f469bc3b4ebb883f0ff8c06dc5936281e20a9ce8940a70bf529368` |
| `scale/paper_audit.csv` | 271 | `b7a78b74ce9710a06d3788882aa42b794626b4665619a3aed1262dbec2f8dab8` |
| `scale/paper_files.csv` | 6576 | `d96e2e24be36193ea518cb1ecc731923d9f69d5f10dd654612c16074a97949dd` |
| `scale/paper_labels.csv` | 845398 | `5ab50a993f2a22fed4098d3365d999fd9bb017df0267e163f3497d7855f7d09b` |
| `scale/paper_provenance.csv` | 38449 | `3086ada55e97a504fbeb9b3b45c13d5330787ae04b021609fc9d66060a621f9a` |
| `scale/recover.py` | 6171 | `868edb8eba89fac3f8d0584298489f4403b900fb56888b79559fd6fc100ce892` |
| `scale/repositories.csv` | 132771 | `056cc92eccbce8e32a53d34bbc017f5323ad294e254b41bdc5e36d6c26389727` |
| `scale/rescue/deploy.py` | 2297 | `e9607ded566b1558ca0b100f334deccd940c0652150c2222b65d8420afc23eb4` |
| `scale/rescue/deployment_gates.csv` | 164 | `fcb339858882ddeb30e62317c2600f02a55b9aa08d52b6a9d014aa52ded0b563` |
| `scale/rescue/deployment_manifest.csv` | 330 | `86f85e380384d9cd7035bbbf4ae6a7a113ef18b8e830a442cc36cbc3f227af0e` |
| `scale/rescue/frozen_selection.json` | 1249 | `697a672ee7b018671c27ca98af64fde81cd293fc23181e7490a5e8dbe41dcf1d` |
| `scale/rescue/retained_axes.csv` | 290 | `b79ef3dc131d2990135646fbc5d491552ac78a799bec1ac2263ceee636bbdb6f` |
| `scale/rescue/source-adjudicated.csv` | 3637116 | `d3547f70841481ba33dd02e57d7c469b8ae26304599631cc74f4b3b77aa377fc` |
| `scale/rescue/test-r1-scores.csv` | 1178 | `1bbe0c8882a49d265e5bfc5a0cf375f037123b47eb68008d70cd81f2a79e98e1` |
| `scale/snapshot_overlap.csv` | 143 | `a81aefb93ad8da12434c19278f8fad6fd35f627b5729228dd95e33f62eb85cc4` |
| `scale/statements.csv` | 12918463 | `3a0bc42cb676b7e020cc9849f60b9b10bf8f59ce1211300fb1dcec7d0d661939` |
| `scale/summary.csv` | 11357 | `92dcaf8e375fc321f35ba9470795c807a9b252d7688481612d5ef498fe6cbafe` |
