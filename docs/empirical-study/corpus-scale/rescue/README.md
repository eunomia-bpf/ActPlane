# Enforcement and context rescue

The initial codebook was withheld because enforcement agreement fell below its gate and context agreement was poor. The recovered written guide explicitly treats a fully named project pattern as self-contained, whereas development annotations also mark named project assets/build commands as requiring project binding. The rescue tests explicit boundary rules against that reference convention. It does not assume that the prose and labels are mutually consistent.

**Holdout limitation:** every original label had already participated in earlier calibration, and aggregate confusions were previously inspected. This repository split is held out from rescue codebook revision and selection only. It is not an untouched external test set. No test-driven revision is permitted.

| Split | Repositories | Statements |
|---|---:|---:|
| dev | 21 | 505 |
| test | 43 | 1611 |

Few-shot examples and error inspection use development repositories only. The protocol and split were committed before development inference. Codebook selection stops at the prespecified dev criterion or revision cap, then the guide, examples, contextual inputs and inference configuration are frozen before a single test evaluation. Original type/topic labels remain fixed. See `rescue/PROTOCOL.md`, `rescue/repository_split.csv`, and the versioned codebooks/examples.

| Revision | Dimension | Dev kappa | Test kappa | Test status |
|---|---|---:|---:|---|
| r1 | enforceability | 0.772 | not evaluated | not_evaluated |
| r1 | context_required | 0.654 | not evaluated | not_evaluated |

Selected revision: `r1`. Frozen artifacts and hashes are recorded in `rescue/frozen_selection.json`.

Source context is deterministic and unannotated: target statement, repository-relative path, section-heading chain and bounded enclosing paragraph when it adds information. All source/context hashes are in `rescue/context_audit.csv`. Context helps resolve referents without promoting neighboring requirements into the target. The original reference does not provide an independent reliability check for new families or noncoding domains.

No paper source, model deployment, gateway configuration or PR is changed.
