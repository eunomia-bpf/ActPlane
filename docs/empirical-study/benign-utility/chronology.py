"""Derive chronological event windows without replacing verified action origins.

Replay receipts lack dispatch/end timestamps. Its independent tagged EXEC starts
therefore define observed execution intervals, including intervening idle time.
Live receipts supply submission start/end; association is never causal proof.
"""
import argparse
import bisect
from collections import defaultdict
import json
from pathlib import Path

from report import benchmark_inputs, number, read, write


def replay_starts(directory, dynamic_id):
    prefix = 'apti6e' + dynamic_id[1:]
    starts = {}
    for line in (directory / 'sources.jsonl').open():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        data = record.get('data', '')
        if not isinstance(data, str):
            continue
        fields = data.strip().split('|', 4)
        if len(fields) != 5 or fields[0] != 'EXEC' or not fields[2].startswith(prefix):
            continue
        try:
            index, timestamp = int(fields[2][len(prefix):]), int(fields[1])
        except ValueError:
            continue
        starts[index] = min(starts.get(index, timestamp), timestamp)
    return starts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--benchmark', type=Path, required=True)
    parser.add_argument('--network', type=Path, required=True)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--raw-replay', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    datasets = []
    for name, path, cohort in [('Terminal-Bench', args.benchmark, 'native_denial_primary'),
                              ('Terminal-Bench network stratum', args.network, 'network_exposure_followup')]:
        runs, calls, events, _ = benchmark_inputs(path, cohort)
        datasets.append((name, True, runs, calls, events))
    runs = [r for r in read(args.replay / 'runs.csv') if r['coverage'] == 'complete'
            and not r['fatal'] and r['recorded_calls'] == r['executed_calls']]
    datasets.append(('Public replay', False, runs, read(args.replay / 'calls.csv'),
                     read(args.replay / 'interventions.csv')))
    output, totals = [], []
    for dataset, live, runs, calls, events in datasets:
        identity = 'trial_id' if live else 'dynamic_id'
        selected = {(r[identity], r['condition']): r for r in runs}
        windows = defaultdict(list)
        for call in calls:
            key = call[identity], call['condition']
            if key in selected:
                windows[key].append(call)
        actual = [e for e in events if (e[identity], e['condition']) in selected and
                  (any(str(e.get(k, '')).lower() in ('true', '1') for k in ('blocked', 'killed'))
                   if live else number(e, 'intervened') > 0)]
        event_count = 0
        for key, run in selected.items():
            group = windows[key]
            replay_positions = {str(c['call_index']): c['position'] for c in group} if not live else {}
            if live:
                intervals = sorted((int(c['start_ns']), int(c['call_index']), c) for c in group)
            else:
                directory = args.raw_replay / run['raw_condition'] / 'dynamic/runs' / run['dynamic_id']
                starts = replay_starts(directory, run['dynamic_id'])
                if any(int(c['call_index']) not in starts for c in group):
                    raise ValueError(f'Missing independent execution start: {key}')
                intervals = sorted((starts[int(c['call_index'])], int(c['position']), c) for c in group)
            starts = [item[0] for item in intervals]
            if len(starts) != len(set(starts)):
                raise ValueError(f'Ambiguous chronological starts: {key}')
            cutoff = int(run.get('security_coverage_end_call') or 0) if live else 0
            cutoff_end = next((int(c.get('end_ns') or 0) for c in group if int(c['call_index']) == cutoff), 0)
            for event in (e for e in actual if (e[identity], e['condition']) == key):
                timestamp = int(event['timestamp_ns'])
                slot = bisect.bisect_right(starts, timestamp) - 1
                position, current, end, kind = 0, {}, '', 'before_first_observed_call'
                if slot >= 0:
                    start, position, current = intervals[slot]
                    if live:
                        end = current.get('end_ns') or ''
                        kind = current.get('action_kind', 'unknown')
                        if end and timestamp > int(end):
                            kind = 'idle_after_submission'
                        if cutoff and (position > cutoff or cutoff_end and timestamp > cutoff_end):
                            kind = 'post_root_exit'
                        elif current.get('coverage') != 'complete':
                            kind = 'submission_scope_unverified'
                    else:
                        end = intervals[slot+1][0] if slot+1 < len(intervals) else ''
                        kind = 'observed_execution_interval_including_idle'
                origin = event.get('call_index', '')
                origin_position = replay_positions.get(str(origin), '') if not live else origin
                output.append(dict(dataset=dataset, condition=key[1], session_id=key[0],
                    timestamp_ns=timestamp, verified_origin_index=origin,
                    origin_position=origin_position, observed_session_position=position,
                    window_kind=kind, window_start_ns=starts[slot] if slot >= 0 else '',
                    window_end_ns=end, current_call_coverage=current.get('coverage', 'unavailable'),
                    current_dispatch_status=current.get('dispatch_status', 'not_recorded_in_replay_receipt'),
                    adjudication=event['adjudication'],
                    boundary_note='audited cutoff submission end bounds root exit; not an exact exit timestamp' if live else 'next tagged EXEC bounds interval; final end unknown and may include tail idle',
                    temporal_evidence='submission_start_end_receipts' if live else 'independent_tagged_EXEC_starts; end/idle not recorded'))
                event_count += 1
        if event_count != len(actual):
            raise ValueError(f'Chronological event reconciliation failed: {dataset}')
        for condition in sorted({r['condition'] for r in runs}):
            totals.append(dict(dataset=dataset, condition=condition,
                actual_intervention_events=sum(e['condition'] == condition for e in actual),
                chronological_events=sum(e['dataset'] == dataset and e['condition'] == condition for e in output)))
    bins = defaultdict(list)
    for event in output:
        position = int(event['observed_session_position'])
        start = ((position - 1) // 10) * 10 + 1 if position else 0
        bins[event['dataset'], event['condition'], start, event['window_kind']].append(event)
    summary = [dict(dataset=dataset, condition=condition, bin_start=start,
        bin_end=start+9 if start else 0, window_kind=kind, intervention_events=len(group),
        confirmed_false_events=sum(e['adjudication'] == 'false_intervention' for e in group),
        confirmed_true_events=sum(e['adjudication'] == 'true_violation' for e in group),
        unknown_events=sum(e['adjudication'] == 'unknown' for e in group),
        definition='chronological event counts; not causal action counts or rates')
        for (dataset, condition, start, kind), group in sorted(bins.items())]
    write(args.out / 'chronological-events.csv', output)
    write(args.out / 'chronological-bins.csv', summary)
    write(args.out / 'chronological-reconciliation.csv', totals)
    print(f'Reconciled {len(output)} actual events into chronological windows')


if __name__ == '__main__':
    main()
