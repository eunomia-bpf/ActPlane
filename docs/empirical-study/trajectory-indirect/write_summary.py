#!/usr/bin/env python3
"""Write the operator handoff from final committed CSVs and the current Git head."""
import argparse
import csv
from pathlib import Path
import subprocess

from analyze import HERE


def read(name):return list(csv.DictReader((HERE/name).open()))


def summarize(state,raw):
    summaries=read('dynamic_summary.csv');replays=read('dynamic_replays.csv')
    overall=next(r for r in summaries if (r['framework'],r['model'],r['classification'])==('ALL','ALL','ALL'))
    assert len(replays)==len(read('dynamic_plan.csv')),'Finish the fixed sample first'
    assert all(r['observer_errors']=='0' for r in replays),'Resolve observer errors before final handoff'
    assert all(r['passed']=='1' for r in read('dynamic_verification.csv')),'Evidence verification must pass'
    branch=subprocess.check_output(['git','branch','--show-current'],cwd=HERE,text=True).strip()
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=HERE,text=True).strip()
    metrics={r['metric']:r['value'] for r in read('dynamic_report_metrics.csv')}
    methods={r['metric']:r['value'] for r in read('method_metrics.csv')}
    confusion=next(r for r in read('dynamic_confusion.csv') if r['scope']=='all_recorded_calls')
    attempts=read('dynamic_attempts.csv')
    resource=read('resources.csv')[0]
    tracked=next(r for r in read('dynamic_tracked_scope_summary.csv') if r['framework']=='ALL' and r['path_scope']=='base_tracked_project')
    def pct(v):return f'{float(v):.2f}%'
    table='| Framework / recorded model | Traj. | Recorded calls | Attempted | Exit zero | Unnamed writes | Unnamed execs |\n|---|---:|---:|---:|---:|---:|---:|\n'
    for r in summaries:
        if r['framework']=='ALL' or r['classification']!='ALL':continue
        table+=f"| {r['framework']} / {r['model']} | {r['trajectories']} | {r['recorded_calls']} | {r['executed_calls']} | {r['successful_calls']} | {pct(r['unnamed_write_pct'])} | {pct(r['unnamed_exec_pct'])} |\n"
    scope_counts={scope:sum(r['scope']==scope for r in attempts) for scope in sorted({r['scope'] for r in attempts})}
    text=f"""# Trajectory indirect-execution study completed

Branch: `{branch}`
Final commit: `{commit}`
No PR action was taken during this follow-up.

Static analysis covers {int(methods['total_trajectories']):,} public trajectories and {int(methods['total_calls']):,} recorded calls/action slots. Dynamic validation replays the unchanged fixed sample of {len(replays)} trajectories on exact base commits, with captured OS regular-file writes and successful execs attributed to their initiating tool-call arguments.

{table}
Pooled observed effects: {int(overall['write_events']):,} positive-byte regular-file write operations, {pct(overall['unnamed_write_pct'])} unnamed, and {int(overall['exec_events']):,} successful execs, {pct(overall['unnamed_exec_pct'])} unnamed. Distinct call-path fractions are {pct(overall['unnamed_write_object_pct'])} for writes and {pct(overall['unnamed_exec_object_pct'])} for execs. For paths tracked in the root repository at the exact base commit, {tracked['unnamed_events']} of {tracked['events']} captured write operations ({pct(tracked['unnamed_pct'])}) and {tracked['unnamed_call_file_pairs']} of {tracked['call_file_pairs']} distinct call-file pairs ({pct(tracked['unnamed_call_file_pct'])}) were unnamed. This membership does not identify intended edits, and writes to temporary paths later renamed over tracked files can fall outside that row.

The post-hoc sensitivity excluding exec basenames id and run-parts yields {pct(metrics['without_profile_helpers_unnamed_exec_pct'])} unnamed execs. These helpers occur in the replay host's login-shell profile. Primary metrics retain them. The filename filter can remove genuine project executions and is not a causal origin attribution.

The static indirect label has call-level physical precision {100*float(confusion['precision']):.2f}% and recall {100*float(confusion['recall']):.2f}% across all recorded primary calls. The truth is any captured unnamed write or exec. Inline-code labels remain separate and count as negative predictions. The companion sensitivity and per-model confusion tables preserve alternate denominators without retuning static labels.

Replay fidelity: {overall['executed_calls']} of {overall['recorded_calls']} calls attempted, {overall['successful_calls']} exit-zero, {overall['failed_calls']} nonzero, and {overall['timed_out_calls']} timeouts. Exit zero is command completion, not original test/task outcome agreement. There are {metrics['setup_failed_steps']} failed setup steps, including initial steps later recovered by a fallback, {metrics['fatal_replays']} fatal primary receipts, and {metrics['observer_errors']} primary observer errors. Attempt ledger counts: {scope_counts}. Every earlier diagnostic, environment, and instrumentation attempt remains recorded. No task was resampled based on success.

Outputs: `docs/empirical-study/trajectory-indirect/` on this branch, including README, scripts, pinned source/task manifests, per-call and summary CSVs, calibration and verification CSVs, embedded-TrueType PDF figures, and a {methods['paper_paragraph_words']}-word paper paragraph. The paper source was not edited. Raw evidence and logs: `{raw}`. Last raw size is {int(resource['raw_bytes'])/1e9:.3f} GB and workspace disk use is {float(resource['workspace_used_pct']):.2f}%. Sampled disk maxima and their limitations are in dynamic_resource_samples.csv and dynamic_report_metrics.csv.

Open caveats: These are best-effort local replays, not original OS telemetry. Runtime versions, shallow-history version labels, missing dependencies, source normalization, timeouts, and substitute edit/read tools limit fidelity. The observer covers successful synchronous VFS byte-changing operations and successful exec syscalls, and omits empty creations, rename/unlink, mapped dirtying, some async/offloaded writes, forks without exec, and interpreter loading without another exec syscall. Cache and dependency installs can dominate pooled writes, so the report includes path scopes, distinct call-path counts, and equal-trajectory medians. Literal-basename/glob matching is deliberately permissive and can match same-named objects. Unresolved paths stay in denominators with explicit bounds. Existing-project-code and author-then-execute findings remain static proxies, not causal OS-effect attribution. Source license caveats and every exclusion/failure are documented. Unnamed effects are not policy violations or demonstrated guardrail bypasses.
"""
    state.mkdir(parents=True,exist_ok=True)
    (state/'SUMMARY.md').write_text(text)
    print('Final handoff written for',branch,commit)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--state',type=Path,required=True);p.add_argument('--raw',type=Path,required=True)
    args=p.parse_args();summarize(args.state,args.raw)
