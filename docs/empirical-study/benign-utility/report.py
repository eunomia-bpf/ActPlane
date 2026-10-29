"""Aggregate native trial/replay CSV exports and render the paper figure in Linux."""
import argparse
import csv
from collections import defaultdict
from pathlib import Path
from statistics import median


def read(path):
    return list(csv.DictReader(path.open())) if path.exists() else []


def number(row, key):
    return float(row.get(key) or 0)


def write(path, rows):
    if not rows:
        raise ValueError(f'No rows for {path}')
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--benchmark', type=Path, default=Path('benchmark/results'))
    parser.add_argument('--replay', type=Path, default=Path('replay/results'))
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    all_trials = read(args.benchmark / 'trials.csv')
    if all_trials and ('selected_for_comparison' not in all_trials[0] or 'comparison_cohort' not in all_trials[0]):
        raise ValueError('Verifier availability audit is required before utility aggregation')
    trials = [r for r in all_trials if r['main_matrix'] == '1' and r['selected_for_comparison'] == '1'
              and r['comparison_cohort'] == 'native_denial_primary']
    if any(r.get('outcome_valid') != '1' for r in trials):
        raise ValueError('An unestablished native outcome was selected for comparison')
    benchmark_calls = [r for r in read(args.benchmark / 'calls.csv') if r['main_matrix'] == '1']
    replay_runs = read(args.replay / 'runs.csv')
    replay_calls = read(args.replay / 'calls.csv')
    event_data = {
        'Terminal-Bench': [r for r in read(args.benchmark / 'interventions.csv') if r['main_matrix'] == '1'],
        'Public replay': read(args.replay / 'interventions.csv'),
    }
    task_count = len(read(args.benchmark / 'tasks.csv'))
    cohort_count = len(read(args.replay / 'cohort.csv'))
    if not task_count or not cohort_count:
        raise ValueError('Both frozen benchmark and replay manifests are required')
    rows, positions = [], []
    for dataset, conditions, runs, calls, planned in [
        ('Terminal-Bench', ['a', 'b', 'c'], trials, benchmark_calls, task_count),
        ('Public replay', ['none', 'broad', 'scoped'], replay_runs, replay_calls, cohort_count),
    ]:
        benchmark = dataset == 'Terminal-Bench'
        identity = 'task' if benchmark else 'dynamic_id'
        call_identity = 'trial_id' if benchmark else identity
        valid_runs = []
        for run in runs:
            if benchmark:
                valid = run.get('outcome_valid') == '1'
            else:
                valid = (run.get('coverage') == 'complete' and not run.get('fatal')
                         and number(run, 'executed_calls') == number(run, 'recorded_calls'))
            if valid:
                valid_runs.append(run)
        keys = [(r[identity], r['condition']) for r in valid_runs]
        if len(keys) != len(set(keys)):
            raise ValueError(f'Duplicate valid main comparisons in {dataset}')
        valid_keys = {(r[call_identity], r['condition']) for r in valid_runs}
        valid_calls = [r for r in calls if (r[call_identity], r['condition']) in valid_keys
                       and r.get('coverage') == 'complete']
        baseline = {r[identity]: r for r in valid_runs if r['condition'] == conditions[0]}
        for condition in conditions:
            selected = [r for r in valid_runs if r['condition'] == condition]
            selected_calls = [r for r in valid_calls if r['condition'] == condition]
            false_calls = sum(number(r, 'confirmed_false' if benchmark else 'fp_count') > 0 for r in selected_calls)
            unknown_calls = sum(number(r, 'unknown' if benchmark else 'unknown_count') > 0 for r in selected_calls)
            potential_false_calls = sum(number(r, 'confirmed_false' if benchmark else 'fp_count') > 0 or number(r, 'unknown' if benchmark else 'unknown_count') > 0 for r in selected_calls)
            intervened_calls = sum(number(r, 'intervened') > 0 if benchmark else number(r, 'intervention_count') > 0 for r in selected_calls)
            lengths = [sum(c[call_identity] == r[call_identity] for c in selected_calls) for r in selected]
            selected_events = [r for r in event_data[dataset]
                if r['condition'] == condition and (r[call_identity], condition) in valid_keys
                and (any(str(r.get(k, '')).lower() in ('true', '1') for k in ('killed', 'blocked'))
                     if benchmark else number(r, 'intervened') > 0)]
            attributed = sum(number(r, 'intervention_events' if benchmark else 'intervention_count') for r in selected_calls)
            if attributed > len(selected_events):
                raise ValueError(f'Call counts exceed actual intervention events: {dataset}/{condition}')
            scored = [r for r in selected if r.get('outcome_success', '') != ''] if benchmark else []
            timing = []
            total_timing = []
            success_differences = []
            for run in selected:
                control = baseline.get(run[identity])
                if benchmark and control and run.get('outcome_success', '') != '' and control.get('outcome_success', '') != '':
                    success_differences.append(number(control, 'outcome_success') - number(run, 'outcome_success'))
                execution_key = 'agent_execution_s' if benchmark else 'elapsed_s'
                total_key = 'wall_s' if benchmark else 'elapsed_s'
                if control and number(control, execution_key) > 0 and number(run, execution_key) > 0:
                    timing.append(number(run, execution_key) / number(control, execution_key))
                if control and number(control, total_key) > 0 and number(run, total_key) > 0:
                    total_timing.append(number(run, total_key) / number(control, total_key))
            grouped = defaultdict(list)
            for call in selected_calls:
                i = int(call['call_index'] if benchmark else call['position'])
                start = ((i - 1) // 10) * 10 + 1
                grouped[start].append(call)
            for start, group in sorted(grouped.items()):
                positions.append(dict(dataset=dataset, condition=condition, bin_start=start,
                    bin_end=start + 9, calls=len(group),
                    intervened_calls=sum(number(r, 'intervened') > 0 if benchmark else number(r, 'intervention_count') > 0 for r in group),
                    confirmed_false_calls=sum(number(r, 'confirmed_false' if benchmark else 'fp_count') > 0 for r in group),
                    unknown_calls=sum(number(r, 'unknown' if benchmark else 'unknown_count') > 0 for r in group),
                    potential_false_calls=sum(number(r, 'confirmed_false' if benchmark else 'fp_count') > 0 or number(r, 'unknown' if benchmark else 'unknown_count') > 0 for r in group),
                    source_read_accesses=sum(number(r, 'source_read_accesses') for r in group)))
            rows.append(dict(dataset=dataset, condition=condition, planned_sessions=planned,
                coverage_complete_sessions=sum(r.get('coverage') == 'complete' for r in selected),
                outcome_valid_sessions=len(selected), official_scored_trials=len(scored) if benchmark else '',
                verifier_executed_trials=sum(r.get('verifier_valid') == '1' for r in selected) if benchmark else '',
                official_default_agent_error_trials=sum(r.get('outcome_source') == 'official_default_mean_agent_error' for r in selected) if benchmark else '',
                official_successes=sum(number(r, 'outcome_success') for r in scored) if benchmark else '',
                official_success_pct=100 * sum(number(r, 'outcome_success') for r in scored) / len(scored) if scored else '',
                paired_success_trials=len(success_differences) if benchmark else '',
                success_drop_percentage_points=100 * sum(success_differences) / len(success_differences) if success_differences else '',
                calls=len(selected_calls),
                intervention_events=len(selected_events),
                unattributed_intervention_events=len(selected_events) - int(attributed),
                intervened_calls=intervened_calls, confirmed_false_calls=false_calls, unknown_calls=unknown_calls,
                potential_false_calls=potential_false_calls,
                intervention_rate_pct=100 * intervened_calls / len(selected_calls) if selected_calls else '',
                confirmed_false_rate_pct=100 * false_calls / len(selected_calls) if selected_calls else '',
                false_rate_upper_pct=100 * potential_false_calls / len(selected_calls)
                    if selected_calls and len(selected_events) == int(attributed) else '',
                false_rate_point_pct=100 * false_calls / len(selected_calls)
                    if selected_calls and not unknown_calls and len(selected_events) == int(attributed) else '',
                intervention_adjudication_complete=int(bool(selected_calls) and not unknown_calls and len(selected_events) == int(attributed)),
                unknown_rate_pct=100 * unknown_calls / len(selected_calls) if selected_calls else '',
                min_covered_calls_per_session=min(lengths) if lengths else '',
                median_covered_calls_per_session=median(lengths) if lengths else '',
                max_covered_calls_per_session=max(lengths) if lengths else '',
                source_read_accesses=sum(number(r, 'source_read_accesses') for r in selected_calls),
                ipv4_connect_attempts=sum(number(r, 'inet4_connect_attempts') for r in selected)
                    if benchmark else sum(number(r, 'ipv4_connect_attempts') for r in selected_calls),
                paired_sessions=len(timing),
                median_paired_execution_difference_pct=100 * (median(timing) - 1) if timing else '',
                median_paired_total_difference_pct=100 * (median(total_timing) - 1) if total_timing else '',
                matrix_complete=int(len(selected) == planned and (not benchmark or len(scored) == planned))))
    write(args.out / 'headline.csv', rows)
    if positions:
        write(args.out / 'position.csv', positions)
    render(rows, positions, args.out)


def render(rows, positions, out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'pdf.fonttype': 42, 'ps.fonttype': 42, 'font.size': 9})
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.1))
    bench = [r for r in rows if r['dataset'] == 'Terminal-Bench']
    values = [r['official_success_pct'] if r['official_success_pct'] != '' else 0 for r in bench]
    bars = axes[0].bar(['No AgPlane', 'Broad', 'Scoped'], values, color=['#777777', '#ca6828', '#2577a2'])
    for bar, row in zip(bars, bench):
        n = row['official_scored_trials']
        label = f"{int(row['official_successes'])}/{n}" if n else 'pending'
        if not row['matrix_complete']:
            label += '\npartial'
            bar.set_hatch('//')
        axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, label, ha='center')
    axes[0].set(ylim=(0, 120), yticks=range(0, 101, 20), ylabel='Official task success (%)', title='Terminal-Bench subset')
    for condition, color, label in [('none', '#777777', 'No AgPlane'), ('broad', '#ca6828', 'Broad'), ('scoped', '#2577a2', 'Scoped')]:
        data = [r for r in positions if r['dataset'] == 'Public replay' and r['condition'] == condition]
        if data:
            x = [r['bin_start'] + 4.5 for r in data]
            axes[1].plot(x, [100*r['confirmed_false_calls']/r['calls'] for r in data], marker='.', color=color, label=label+' confirmed')
            if any(r['unknown_calls'] for r in data):
                axes[1].plot(x, [100*r['potential_false_calls']/r['calls'] for r in data], ls=':', color=color, label=label+' incl. unresolved')
    replay_complete = all(r['matrix_complete'] for r in rows if r['dataset'] == 'Public replay')
    replay_title = 'Public replay' if replay_complete else 'Public replay (partial)'
    axes[1].set(xlabel='Within-session call position (bins of ten)', ylabel='False-intervention rate bounds (%)', title=replay_title)
    axes[1].set_ylim(bottom=0)
    if axes[1].lines:
        if not any(any(y > 0 for y in line.get_ydata()) for line in axes[1].lines):
            axes[1].set_ylim(0, 1)
        axes[1].legend(fontsize=7)
    else:
        axes[1].text(.5, .5, 'Replay results pending', transform=axes[1].transAxes, ha='center')
    fig.text(.5, .01, 'Process-subtree scope. Scoped condition measures source narrowing; trusted declassification is unmeasured.', ha='center', fontsize=7)
    fig.tight_layout(rect=(0, .05, 1, 1))
    fig.savefig(out / 'benign-utility.pdf')
    fig.savefig(out / 'benign-utility.png', dpi=180)
    plt.close(fig)


if __name__ == '__main__':
    main()
