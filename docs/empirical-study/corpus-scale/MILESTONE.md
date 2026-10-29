# Completed-file milestone

**Interim process snapshot. Do not substitute these for complete-snapshot paper results.**

As of 2026-10-28T18:03:15+00:00, 298 complete files contain 11,862 labeled statements from 211 repositories. 57 repositories have every selected source labeled. 463 unfinished files are excluded from this separate snapshot.

| Metric | Estimate | Repository-bootstrap interval | Status |
|---|---:|---:|---|
| policy_fraction | 53.7% | 50.4%–57.3% | ok |
| system_state_fraction | withheld | withheld | withheld_calibration_failed |
| context_required_fraction | withheld | withheld | withheld_calibration_failed |
| cross_event_project_share | withheld | withheld | withheld_calibration_failed |
| os_enforceable_count | withheld | withheld | withheld_calibration_failed |

The main `summary.csv` requires complete repository coverage. This separate milestone includes finished files from partially covered repositories, so timing-dependent file selection differs from the final analysis. Intervals describe resampling repositories in this observed subset. They do not account for unfinished-file selection or model error. `interim_file_coverage.csv`, `interim_file_inclusions.csv`, and `interim_file_summary.csv` retain the exact included files, denominators, and exclusions. Run `python interim_files.py --replay` to reproduce the frozen scope. See README.md for calibration and the selection protocol.
