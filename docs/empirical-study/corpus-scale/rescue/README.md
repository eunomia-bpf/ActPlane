# Enforcement and context rescue

The initial codebook was withheld because enforcement agreement fell below its gate and context agreement was poor. The recovered written guide explicitly treats a fully named project pattern as self-contained, whereas development annotations also mark named project assets/build commands as requiring project binding. The rescue tests explicit boundary rules against that reference convention. It does not assume that the prose and labels are mutually consistent.

**Holdout limitation:** every original label had already participated in earlier calibration, and aggregate confusions were previously inspected. This repository split is held out from rescue codebook revision and selection only. It is not an untouched external test set. No test-driven revision is permitted.

| Split | Repositories | Statements |
|---|---:|---:|
| dev | 21 | 505 |
| test | 43 | 1611 |

Few-shot examples and error inspection use development repositories only. The protocol and split were committed before development inference. Codebook selection stops at the prespecified dev criterion or revision cap, then the guide, examples, contextual inputs and inference configuration are frozen before a single test evaluation. Original type/topic labels remain fixed. Calibration conditions on known historical directives, while deployment uses the frozen automated directive set. Definitions, supplied context and axis conditioning all change, so gains cannot be attributed to the codebook alone. See `rescue/PROTOCOL.md`, `rescue/repository_split.csv`, and the versioned codebooks/examples.

| Revision | Dimension | Dev kappa | Test kappa | Test status |
|---|---|---:|---:|---|
| r1 | enforceability | 0.772 | 0.694 | evaluated_once |
| r1 | context_required | 0.654 | 0.679 | evaluated_once |

Selected revision: `r1`. Frozen artifacts and hashes are recorded in `rescue/frozen_selection.json`.

| Frozen test gate | Kappa | Coverage | Passed |
|---|---:|---:|---|
| enforceability | 0.694 | 100.0% | True |
| context_required | 0.679 | 100.0% | True |

| Test model | Dimension | Applicable N | Raw agreement | Kappa |
|---|---|---:|---:|---:|
| qwen | enforceability | 1017 | 0.761 | 0.663 |
| qwen | context_required | 865 | 0.821 | 0.646 |
| glm | enforceability | 1017 | 0.775 | 0.681 |
| glm | context_required | 865 | 0.857 | 0.720 |
| adjudicated | enforceability | 1017 | 0.784 | 0.694 |
| adjudicated | context_required | 865 | 0.835 | 0.679 |

Predicted inapplicable context counts as disagreement on applicable-gold evaluation. Full confusion cells and missing predictions remain in the test CSVs. Earlier revisions have no test scores. Raw context headlines additionally require the enforcement gate because their denominator is system-observable policies.

| Deployed axis | Passed | Evidence |
|---|---|---|
| enforceability | True | passed_test_gate |
| context_required | True | passed_test_gate |

Passing axes supersede the initial failed gates only through `rescue/deployment_gates.csv`. The initial calibration CSVs remain unchanged. Versioned source sidecars preserve named-model predictions and guide/context hashes. Original type/topic primary predictions are preserved, and `labels.csv` carries separate rescue provenance for the new axes.

### Misclassification-corrected estimates

These estimates use the frozen test confusion matrix and a constrained multinomial mixture fit. Repository bootstraps resample the test reference and the new corpus independently, preserving new discovery strata. They include confusion-matrix uncertainty but assume class-conditional error transfers to a different sample, additional file families and noncoding tasks. That assumption is unverified. A failed gate makes the corresponding correction exploratory. Corrections do not replace raw automatically labeled counts. They are conditional on the frozen directive set and do not correct segmentation or type-label errors.

| Corrected overall metric | Estimate | Bootstrap interval | Status | Point diagnostic | Identifiable draws |
|---|---:|---:|---|---|---:|
| system_state_fraction | 73.6% | [66.4%, 80.0%] | corrected_estimate | ok | 2000/2000 |
| os_enforceable_count | 7,062 | [5,858, 8,500] | corrected_estimate | ok | 2000/2000 |
| context_required_fraction | 78.8% | [73.9%, 84.3%] | corrected_estimate | ok | 2000/2000 |
| cross_event_project_share | 92.5% | [74.6%, 100.0%] | corrected_estimate | project_size_transport_unverified | 2000/2000 |

[Corrected-prevalence PDF](figures/corrected-prevalence.pdf). All overall, file-family, repository-category and file-scope corrected estimates are in `rescue/corrected_summary.csv`. Project-share correction is limited to whole-project groups. Its sensitivity/specificity can change with the number of directives per repository, so project-size transport is especially uncertain. Matrix ranks, condition numbers, boundary solutions and missing classes are retained in the correction diagnostics. The committed bootstrap audit aggregates every status/reason, and the retained raw `rescue-correction-bootstrap.csv` records individual replicate outcomes including every failure. Intervals with insufficient identifiable fits are withheld. Independent enforcement and applicability/context matrices can imply different corrected system-observable denominators.

### Recompute accepted results

From the corpus-scale directory, with the pinned Python requirements installed, the following commands recompute the accepted rescue outputs without model requests. Source-fidelity checks require the immutable raw files and contextual inputs. The frozen selection and single test-evaluation lock must be retained. Do not rerun development selection or inference to obtain a more favorable test score.

```bash
python rescue/deploy.py
python analyze.py
python figures.py
python rescue/correct_prevalence.py
python rescue/plot_corrected.py
python rescue/validate_rescue.py
python validate.py --require-complete
python validate_figures.py --previews
python audit_runs.py
python report.py
```

The paper figures depict raw accepted automated labels. `figure_intervals.csv` supplies repository-bootstrap intervals for every cell in the rescued enforcement/context figures. Corrected estimates use a separate, explicitly labeled PDF and CSV, rather than replacing raw counts.

Source context is deterministic and unannotated: target statement, repository-relative path, section-heading chain and bounded enclosing paragraph when it adds information. All source/context hashes are in `rescue/context_audit.csv`. Context helps resolve referents without promoting neighboring requirements into the target. The original reference does not provide an independent reliability check for new families or noncoding domains.

No paper source, model deployment, gateway configuration or PR is changed.
