# Injection-bench closeout

Closed on the supervisor's instruction after the Codex service content filter interrupted the session. This closeout inspected only working-tree status and locally retained result tables. No new inference, cells, remote commands, payload inspection, or trace inspection was performed. Remote process state was not checked; this document does not certify that previously detached jobs have stopped.

The completed comparison is the RepoGuardBench subset for `zai/glm-5.3`, with no defense and the official D3 action gate. Each condition has fifty clean and fifty attacked tasks. Failures remain in the denominators.

| Model | Defense | Terminal / planned | Pending | ASR | Clean utility | Attacked utility | Failures |
|---|---|---:|---:|---:|---:|---:|---:|
| zai/glm-5.3 | D0_none | 100 / 100 | 0 | 0 / 50 (0%) | 48 / 50 (96%) | 44 / 50 (88%) | 0 |
| zai/glm-5.3 | D3_action_gate | 100 / 100 | 0 | 0 / 50 (0%) | 45 / 50 (90%) | 40 / 50 (80%) | 0 |
| zai/glm-5.3 | agplane_pre | 2 / 100 | 98 | pending | pending | pending | not finalized |
| zai/glm-5.3 | agplane_self | 2 / 100 | 98 | pending | pending | pending | not finalized |
| qwen3.8-27b-nvfp4 | D0_none | 19 / 100 | 81 | pending | pending | pending | not finalized |
| qwen3.8-27b-nvfp4 | D3_action_gate | 18 / 100 | 82 | pending | pending | pending | not finalized |
| qwen3.8-27b-nvfp4 | agplane_pre | 4 / 100 | 96 | pending | pending | pending | not finalized |
| qwen3.8-27b-nvfp4 | agplane_self | 0 / 100 | 100 | pending | pending | pending | not finalized |
| claude-cli:opus | D0_none | 88 / 100 | 12 | pending | pending | pending | not finalized |
| claude-cli:opus | D3_action_gate | 88 / 100 | 12 | pending | pending | pending | not finalized |
| claude-cli:opus | agplane_pre | 9 / 100 | 91 | pending | pending | pending | not finalized |
| claude-cli:opus | agplane_self | 8 / 100 | 92 | pending | pending | pending | not finalized |

Sources: [closeout.csv](results/closeout.csv), produced by the metric-only aggregation in [closeout_results.ps1](scripts/closeout_results.ps1). Completed-condition numbers come from [summary.csv](results/summary.csv). Partial terminal counts come from the later [audit/summary.csv](results/audit/summary.csv), using the frozen manifests for denominators. These are different snapshots: the older primary table contains fewer partial results. The audit table is not a final ASR/utility aggregation. Terminal records include failures: the partial Qwen parent-policy records are failed records in the audit case-status table. Pending counts mean planned records without a retained terminal audit record, not verified live queue states.

The remaining conditions are unfinalized because the service content filter interrupted the session and the supervisor prohibited further cells, remote runs, and payload/trace access. No partial rate is presented as a completed result. The supplemental CLI manifest is included even though no final CLI metric table was retained locally.

## Interpretation and caveats

The completed no-defense ASR is already zero, so this snapshot establishes no ASR improvement for D3 or AgPlane. Zero completed attacks does not establish that no unsafe action was proposed or landed; these are distinct official metrics. Neither AgPlane condition has a completed model-by-defense comparison. The preliminary audit does not establish a final kernel delta-rejection result or a causal defense benefit. User-space admission failures must be separated from confirmed kernel rejections.

RepoGuardBench is a published workshop benchmark with OS-backed tasks; broad adoption was not established. It therefore does not fully satisfy the requested widely-used-benchmark criterion. The preferred OS-Harm route was blocked by archive/extracted-image storage requirements and the shared workspace disk ceiling. The kernel artifact uses documented lane-owned compatibility changes. Earlier README/table/figure files are checkpoint artifacts, not a completed full-matrix claim.

## Reproduction from retained artifacts

These commands reproduce completed-cell metrics from existing artifacts. No remote command was executed during closeout; these commands do not start fresh inference.

Display the committed completed-condition numbers locally:

```powershell
Import-Csv docs/empirical-study/injection-bench/results/summary.csv |
  Where-Object status -eq 'complete' |
  Select-Object model,system,finished,failed,attack_successes,attack_n,clean_successes,clean_n,attacked_successes,asr_lower,clean_utility,attacked_utility
```

When separately authorized, reaggregate the retained remote main run with the committed report entrypoint:

```powershell
& 'C:\Program Files\Git\bin\bash.exe' C:/Users/10678/actplane-tools/ws.sh run injection-bench -- /workspaces/exp/injection-bench/raw/venv/bin/python scripts/report.py --manifest /workspaces/exp/injection-bench/raw/runs/main-v1/planned.csv --runs /workspaces/exp/injection-bench/raw/runs/main-v1 --out /workspaces/exp/injection-bench/results
```

The frozen assignments are in [planned.csv](results/planned.csv) and [frontier-planned.csv](results/frontier-planned.csv). Runner and immutable launch helper sources remain committed under `scripts/`. A fresh-inference replay command was not re-inspected or validated under the closeout read restriction; the command above reproduces metrics from retained completed cells, not a new experiment. Raw artifacts remain remote and are required for reaggregation. Remote artifacts may have progressed beyond the local snapshots.

Other retained outputs: [table.md](results/table.md), [comparison.pdf](results/comparison.pdf), and [audit/summary.csv](results/audit/summary.csv). See [BLOCKED.md](BLOCKED.md) for the final stop boundary.
