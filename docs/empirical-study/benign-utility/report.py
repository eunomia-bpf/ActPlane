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
    trials = [r for r in read(args.benchmark / 'trials.csv') if r['main_matrix'] == '1']
    benchmark_calls = [r for r in read(args.benchmark / 'calls.csv') if r['main_matrix'] == '1']
    replay_runs = read(args.replay / 'runs.csv')
    replay_calls = read(args.replay / 'calls.csv')
    task_count = len(read(args.benchmark / 'tasks.csv'))
    cohort_count = len(read(args.replay / 'cohort.csv'))
    rows, positions = [], []
    for dataset, conditions, runs, calls, planned in [
        ('Terminal-Bench', ['a', 'b', 'c'], trials, benchmark_calls, task_count),
        ('Public replay', ['none', 'broad', 'scoped'], replay_runs, replay_calls, cohort_count),
    ]:
        benchmark = dataset == 'Terminal-Bench'
        identity = 'task' if benchmark else 'dynamic_id'
        valid_runs = []
        for run in runs:
            if run.get('coverage') != 'complete':
                continue
            if benchmark:
                valid = run['run_status'] in ('complete', 'official_timeout')
            else:
                valid = not run.get('fatal') and number(run, 'executed_calls') == number(run, 'recorded_calls')
            if valid:
                valid_runs.append(run)
        keys = [(r[identity], r['condition']) for r in valid_runs]
        if len(keys) != len(set(keys)):
            raise ValueError(f'Duplicate valid main comparisons in {dataset}')
        valid_keys = set(keys)
        valid_calls = [r for r in calls if (r[identity], r['condition']) in valid_keys]
        baseline = {r[identity]: r for r in valid_runs if r['condition'] == conditions[0]}
        for condition in conditions:
            selected = [r for r in valid_runs if r['condition'] == condition]
            selected_calls = [r for r in valid_calls if r['condition'] == condition]
            scored = [r for r in selected if r.get('official_success', '') != ''] if benchmark else []
            timing = []
            total_timing = []
            for run in selected:
                control = baseline.get(run[identity])
                execution_key = 'agent_execution_s' if benchmark else 'elapsed_s'
                total_key = 'wall_s' if benchmark else 'elapsed_s'
                if control and number(control, execution_key) > 0 and number(run, execution_key) > 0:
                    timing.append(number(run, execution_key) / number(control, execution_key))
                if control and number(control, total_key) > 0 and number(run, total_key) > 0:
                    total_timing.append(number(run, total_key) / number(control, total_key))
            grouped = defaultdict(list)
            for call in selected_calls:
                i = int(call['call_index'])
                start = int(call['bin_start']) if 'bin_start' in call else (i // 10) * 10
                grouped[start].append(call)
            for start, group in sorted(grouped.items()):
                positions.append(dict(dataset=dataset, condition=condition, bin_start=start,
                    bin_end=start + 9, calls=len(group),
                    intervened_calls=sum(number(r, 'intervened') > 0 if benchmark else number(r, 'intervention_count') > 0 for r in group),
                    confirmed_false_calls=sum(number(r, 'confirmed_false' if benchmark else 'fp_count') > 0 for r in group),
                    unknown_calls=sum(number(r, 'unknown' if benchmark else 'unknown_count') > 0 for r in group),
                    source_read_accesses=sum(number(r, 'source_read_accesses') for r in group)))
            rows.append(dict(dataset=dataset, condition=condition, planned_sessions=planned,
                coverage_complete_sessions=len(selected), official_scored_trials=len(scored) if benchmark else '',
                official_successes=sum(number(r, 'official_success') for r in scored) if benchmark else '',
                official_success_pct=100 * sum(number(r, 'official_success') for r in scored) / len(scored) if scored else '',
                calls=len(selected_calls),
                intervened_calls=sum(number(r, 'intervened') > 0 if benchmark else number(r, 'intervention_count') > 0 for r in selected_calls),
                confirmed_false_calls=sum(number(r, 'confirmed_false' if benchmark else 'fp_count') > 0 for r in selected_calls),
                unknown_calls=sum(number(r, 'unknown' if benchmark else 'unknown_count') > 0 for r in selected_calls),
                source_read_accesses=sum(number(r, 'source_read_accesses') for r in selected_calls),
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
    axes[0].set(ylim=(0, 110), ylabel='Official task success (%)', title='Terminal-Bench subset')
    for condition, color, label in [('none', '#777777', 'No AgPlane'), ('broad', '#ca6828', 'Broad'), ('scoped', '#2577a2', 'Scoped')]:
        data = [r for r in positions if r['dataset'] == 'Public replay' and r['condition'] == condition]
        if data:
            x = [r['bin_start'] + 4.5 for r in data]
            axes[1].plot(x, [100*r['confirmed_false_calls']/r['calls'] for r in data], marker='.', color=color, label=label)
            if any(r['unknown_calls'] for r in data):
                axes[1].plot(x, [100*(r['confirmed_false_calls']+r['unknown_calls'])/r['calls'] for r in data], ls=':', color=color, label=label+' incl. unresolved')
    axes[1].set(xlabel='Original public-trajectory call index (bins of ten)', ylabel='Confirmed false interventions / calls (%)', title='Recorded-call replay; completed sessions only')
    axes[1].set_ylim(bottom=0)
    if axes[1].lines:
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
