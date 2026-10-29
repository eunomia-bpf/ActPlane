#!/usr/bin/env python3
"""Render rescue evidence and corrected estimates solely from generated CSVs."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,read_csv,write_csv
OUT=HERE/'rescue'

def number(row,key='value'):
 if not row or row.get(key,'')=='':return 'unavailable'
 x=float(row[key]);return f'{x:,.0f}' if row['metric'].endswith('_count') else f'{100*x:.1f}%'

def render():
 lines=['## Enforcement and context rescue', '',
 'The initial codebook was withheld because enforcement agreement fell below its gate and context agreement was poor. The recovered written guide explicitly treats a fully named project pattern as self-contained, whereas development annotations also mark named project assets/build commands as requiring project binding. The rescue tests explicit boundary rules against that reference convention. It does not assume that the prose and labels are mutually consistent.', '',
 '**Holdout limitation:** every original label had already participated in earlier calibration, and aggregate confusions were previously inspected. This repository split is held out from rescue codebook revision and selection only. It is not an untouched external test set. No test-driven revision is permitted.', '',
 '| Split | Repositories | Statements |', '|---|---:|---:|']
 for r in read_csv(OUT/'split_overview.csv'):lines.append(f'| {r["split"]} | {r["repositories"]} | {r["statements"]} |')
 lines+=['', 'Few-shot examples and error inspection use development repositories only. The protocol and split were committed before development inference. Codebook selection stops at the prespecified dev criterion or revision cap, then the guide, examples, contextual inputs and inference configuration are frozen before a single test evaluation. Original type/topic labels remain fixed. Calibration conditions on known historical directives, while deployment uses the frozen automated directive set. Definitions, supplied context and axis conditioning all change, so gains cannot be attributed to the codebook alone. See `rescue/PROTOCOL.md`, `rescue/repository_split.csv`, and the versioned codebooks/examples.', '']
 ledger=OUT/'iteration_ledger.csv'
 if ledger.exists():
  lines+=['| Revision | Dimension | Dev kappa | Test kappa | Test status |','|---|---|---:|---:|---|']
  for r in read_csv(ledger):lines.append(f'| {r["revision"]} | {r["dimension"]} | {float(r["dev_kappa"]):.3f} | {float(r["test_kappa"]):.3f} | {r["test_status"]} |' if r['test_kappa'] else f'| {r["revision"]} | {r["dimension"]} | {float(r["dev_kappa"]):.3f} | not evaluated | {r["test_status"]} |')
 else:lines+=['Development inference is in progress. No rescue test scores are available.']
 selection=OUT/'selection.csv'
 if selection.exists():
  chosen=read_csv(selection)[0]
  lines+=['',f'Selected revision: `{chosen["revision"]}`. Frozen artifacts and hashes are recorded in `rescue/frozen_selection.json`.']
 tests=OUT/'test_gates.csv'
 if tests.exists():
  lines+=['', '| Frozen test gate | Kappa | Coverage | Passed |', '|---|---:|---:|---|']
  for r in read_csv(tests):lines.append(f'| {r["dimension"]} | {float(r["test_kappa"]):.3f} | {100*float(r["coverage"]):.1f}% | {r["passed"]} |')
  selected=read_csv(selection)[0]['revision']
  lines+=['', '| Test model | Dimension | Applicable N | Raw agreement | Kappa |', '|---|---|---:|---:|---:|']
  for r in read_csv(OUT/f'test-{selected}-scores.csv'):
   if r['scope']=='applicable_gold':lines.append(f'| {r["model"]} | {r["dimension"]} | {r["expected"]} | {float(r["agreement"]):.3f} | {float(r["kappa"]):.3f} |')
  lines+=['', 'Predicted inapplicable context counts as disagreement on applicable-gold evaluation. Full confusion cells and missing predictions remain in the test CSVs. Earlier revisions have no test scores. Raw context headlines additionally require the enforcement gate because their denominator is system-observable policies.']
 deployment=OUT/'deployment_gates.csv'
 if deployment.exists():
  lines+=['', '| Deployed axis | Passed | Evidence |', '|---|---|---|']
  for r in read_csv(deployment):lines.append(f'| {r["dimension"]} | {r["passed"]} | {r["reason"]} |')
  lines+=['', 'Passing axes supersede the initial failed gates only through `rescue/deployment_gates.csv`. The initial calibration CSVs remain unchanged. Versioned source sidecars preserve named-model predictions and guide/context hashes. Original type/topic primary predictions are preserved, and `labels.csv` carries separate rescue provenance for the new axes.']
 corrected=OUT/'corrected_summary.csv'
 if corrected.exists():
  lines+=['', '### Misclassification-corrected estimates', '',
   'These estimates use the frozen test confusion matrix and a constrained multinomial mixture fit. Repository bootstraps resample the test reference and the new corpus independently, preserving new discovery strata. They include confusion-matrix uncertainty but assume class-conditional error transfers to a different sample, additional file families and noncoding tasks. That assumption is unverified. A failed gate makes the corresponding correction exploratory. Corrections do not replace raw automatically labeled counts. They are conditional on the frozen directive set and do not correct segmentation or type-label errors.', '',
   '| Corrected overall metric | Estimate | Bootstrap interval | Status | Identifiable draws |', '|---|---:|---:|---|---:|']
  wanted=['system_state_fraction','context_required_fraction','os_enforceable_count','cross_event_project_share']
  for r in read_csv(corrected):
   if r['group_type']=='overall' and r['metric'] in wanted:
    lines.append(f'| {r["metric"]} | {number(r)} | [{number(r,"ci_low")}, {number(r,"ci_high")}] | {r["status"]} | {r["successful_bootstraps"]}/{r["bootstrap_replicates"]} |')
  lines+=['', 'All overall, file-family, repository-category and file-scope corrected estimates are in `rescue/corrected_summary.csv`. Project-share correction is limited to whole-project groups. Its sensitivity/specificity can change with the number of directives per repository, so project-size transport is especially uncertain. Matrix ranks, condition numbers, boundary solutions and missing classes are retained in the correction diagnostics. The committed bootstrap audit aggregates every status/reason, and the retained raw `rescue-correction-bootstrap.csv` records individual replicate outcomes including every failure. Intervals with insufficient identifiable fits are withheld. Independent enforcement and applicability/context matrices can imply different corrected system-observable denominators.']
 lines+=['', 'Source context is deterministic and unannotated: target statement, repository-relative path, section-heading chain and bounded enclosing paragraph when it adds information. All source/context hashes are in `rescue/context_audit.csv`. Context helps resolve referents without promoting neighboring requirements into the target. The original reference does not provide an independent reliability check for new families or noncoding domains.', '',
  'No paper source, model deployment, gateway configuration or PR is changed.']
 (OUT/'README.md').write_text('\n'.join(lines).replace('## Enforcement and context rescue','# Enforcement and context rescue',1)+'\n')
 return lines
if __name__=='__main__':render()
