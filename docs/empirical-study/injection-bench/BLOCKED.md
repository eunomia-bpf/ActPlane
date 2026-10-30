# Final closeout boundary

The Codex service flagged generated content as a possible cybersecurity risk and ended the session. The supervisor explicitly instructed this lane to close out from locally retained result tables, without attempting to get past that filter. This is the controlling stop condition, superseding earlier plans to resume experiments.

No new injection payloads, attack text, exploit text, inference calls, benchmark cells, or remote runs were generated during closeout. Payload and trace files were not opened. Only working-tree status and result-table metrics were inspected. No remote process status was checked or changed, so the state of previously detached workers is unknown.

The completed GLM no-defense and official D3 comparisons are reported in [SUMMARY.md](SUMMARY.md). Other model-by-defense conditions remain incomplete in the locally retained snapshots. They must not be described as completed experiments, assigned zero utility because they are pending, or used to claim an AgPlane ASR advantage. Partial terminal counts include failed records.

Completed-condition rates come from the primary metric table. The later audit snapshot supplies partial terminal counts only. No refreshed full-matrix metrics or final kernel delta-rejection analysis are available locally. User-space admission errors must not be reported as kernel rejections.

Additional unresolved limitations remain: broad adoption of the selected published RepoGuardBench fallback was not established; the preferred OS-Harm VM route exceeded available storage under the shared workspace ceiling; the kernel artifact required lane-owned compatibility changes. The original standard-benchmark brief has not been fully satisfied.

Closeout changes are to be pushed only to `experiments/mlsys27`. No pull, rebase, branch switch, PR, or additional experiment is part of this closeout.
