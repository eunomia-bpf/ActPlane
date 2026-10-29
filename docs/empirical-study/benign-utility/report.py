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


def benchmark_inputs(path, cohort):
    trials = read(path / 'trials.csv')
    if trials and not {'selected_for_comparison', 'comparison_cohort', 'outcome_valid'} <= trials[0].keys():
        raise ValueError(f'Native outcome audit is required: {path}')
    selected = [r for r in trials if r['selected_for_comparison'] == '1' and r['comparison_cohort'] == cohort]
    if any(r.get('outcome_valid') != '1' for r in selected):
        raise ValueError(f'An unestablished native outcome was selected: {path}')
    if any(r.get('outcome_score') in ('', None) or r.get('outcome_success') in ('', None) for r in selected):
        raise ValueError(f'A selected native outcome has no official score: {path}')
    count = len(read(path / 'tasks.csv'))
    if not count:
        raise ValueError(f'Frozen task manifest is required: {path}')
    return selected, read(path / 'calls.csv'), read(path / 'interventions.csv'), count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--benchmark', type=Path, default=Path('benchmark/results'))
    parser.add_argument('--replay', type=Path, default=Path('replay/results'))
    parser.add_argument('--network', type=Path, help='Separately frozen natural-network follow-up results')
    parser.add_argument('--expanded', type=Path, help='Predeclared additional official tasks; also report their union with the original subset')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    trials, benchmark_calls, benchmark_events, task_count = benchmark_inputs(args.benchmark, 'native_denial_primary')
    replay_runs = read(args.replay / 'runs.csv')
    replay_calls = read(args.replay / 'calls.csv')
    event_data = {
        'Terminal-Bench': benchmark_events,
        'Public replay': read(args.replay / 'interventions.csv'),
    }
    cohort_count = len(read(args.replay / 'cohort.csv'))
    if not task_count or not cohort_count:
        raise ValueError('Both frozen benchmark and replay manifests are required')
    rows, positions = [], []
    datasets = [
        ('Terminal-Bench', ['a', 'b', 'c'], trials, benchmark_calls, task_count),
        ('Public replay', ['none', 'broad', 'scoped'], replay_runs, replay_calls, cohort_count),
    ]
    task_names = {'Terminal-Bench': {r['task'] for r in read(args.benchmark / 'tasks.csv')}}
    if args.network:
        network_runs, network_calls, network_events, network_count = benchmark_inputs(args.network, 'network_exposure_followup')
        datasets.insert(1, ('Terminal-Bench network stratum', ['a', 'b', 'c'], network_runs, network_calls, network_count))
        event_data['Terminal-Bench network stratum'] = network_events
        task_names['Terminal-Bench network stratum'] = {r['task'] for r in read(args.network / 'tasks.csv')}
    if args.expanded:
        added_runs, added_calls, added_events, added_count = benchmark_inputs(args.expanded, 'expanded_20261029')
        added_names = {r['task'] for r in read(args.expanded / 'tasks.csv')}
        if added_names & task_names['Terminal-Bench']:
            raise ValueError('The added cohort overlaps the frozen original subset')
        datasets[1:1] = [
            ('Terminal-Bench added cohort', ['a', 'b', 'c'], added_runs, added_calls, added_count),
            ('Terminal-Bench combined', ['a', 'b', 'c'], trials + added_runs,
             benchmark_calls + added_calls, task_count + added_count),
        ]
        event_data['Terminal-Bench added cohort'] = added_events
        event_data['Terminal-Bench combined'] = benchmark_events + added_events
        task_names['Terminal-Bench added cohort'] = added_names
        task_names['Terminal-Bench combined'] = task_names['Terminal-Bench'] | added_names
    for dataset, conditions, runs, calls, planned in datasets:
        benchmark = dataset != 'Public replay'
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
        covered_calls = [r for r in calls if (r[call_identity], r['condition']) in valid_keys
                         and r.get('coverage') == 'complete']
        valid_calls = [r for r in covered_calls if not benchmark or r.get('action_kind') in ('command', 'interrupt')]
        baseline = {r[identity]: r for r in valid_runs if r['condition'] == conditions[0]}
        complete_triplets = set.intersection(*[
            {r[identity] for r in valid_runs if r['condition'] == condition}
            for condition in conditions])
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
            if any(r.get('adjudication') not in ('false_intervention', 'true_violation', 'unknown') for r in selected_events):
                raise ValueError(f'Unrecognized intervention adjudication: {dataset}/{condition}')
            attributed = sum(number(r, 'intervention_events' if benchmark else 'intervention_count') for r in selected_calls)
            if attributed > len(selected_events):
                raise ValueError(f'Call counts exceed actual intervention events: {dataset}/{condition}')
            scored = [r for r in selected if r.get('outcome_success', '') != ''] if benchmark else []
            matched_scored = [r for r in scored if r[identity] in complete_triplets]
            timing = []
            total_timing = []
            timing_excluded_storage = 0
            timing_excluded_backing_mismatch = 0
            success_differences = []
            for run in selected:
                control = baseline.get(run[identity])
                if benchmark and control and run.get('outcome_success', '') != '' and control.get('outcome_success', '') != '':
                    success_differences.append(number(control, 'outcome_score') - number(run, 'outcome_score'))
                execution_key = 'agent_execution_s' if benchmark else 'elapsed_s'
                total_key = 'wall_s' if benchmark else 'elapsed_s'
                if not benchmark and control and (run.get('cache_backing') == 'tmpfs' or control.get('cache_backing') == 'tmpfs'):
                    timing_excluded_storage += 1
                    continue
                if benchmark and control and run.get('runtime_storage_backing') and control.get('runtime_storage_backing') and run['runtime_storage_backing'] != control['runtime_storage_backing']:
                    timing_excluded_backing_mismatch += 1
                    continue
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
                    attribution_complete=int(len(selected_events) == int(attributed)),
                    unassigned_intervention_events_in_condition=len(selected_events) - int(attributed),
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
                official_mean_reward=sum(number(r, 'outcome_score') for r in scored) / len(scored) if scored else '',
                official_success_pct=100 * sum(number(r, 'outcome_score') for r in scored) / len(scored) if scored else '',
                completed_task_ids=';'.join(sorted(r[identity] for r in selected)) if benchmark else '',
                pending_task_ids=';'.join(sorted(task_names[dataset] - {r[identity] for r in selected})) if benchmark else '',
                complete_triplet_tasks=len(complete_triplets) if benchmark else '',
                complete_triplet_task_ids=';'.join(sorted(complete_triplets)) if benchmark else '',
                complete_triplet_successes=sum(number(r, 'outcome_success') for r in matched_scored) if benchmark else '',
                complete_triplet_mean_reward=sum(number(r, 'outcome_score') for r in matched_scored) / len(matched_scored) if matched_scored else '',
                paired_success_trials=len(success_differences) if benchmark else '',
                success_drop_percentage_points=100 * sum(success_differences) / len(success_differences) if success_differences else '',
                calls=len(selected_calls),
                covered_terminal_submissions=sum(r['condition'] == condition for r in covered_calls) if benchmark else '',
                covered_empty_wait_submissions=sum(r['condition'] == condition and r.get('action_kind') == 'wait' for r in covered_calls) if benchmark else '',
                intervention_events=len(selected_events),
                confirmed_false_events=sum(r.get('adjudication') == 'false_intervention' for r in selected_events),
                confirmed_true_events=sum(r.get('adjudication') == 'true_violation' for r in selected_events),
                runtime_rule_violation_events=sum(r.get('project_verdict') == 'runtime_version_noncompliance' for r in selected_events),
                unknown_events=sum(r.get('adjudication') == 'unknown' for r in selected_events),
                unattributed_intervention_events=len(selected_events) - int(attributed),
                intervened_calls=intervened_calls, confirmed_false_calls=false_calls, unknown_calls=unknown_calls,
                potential_false_calls=potential_false_calls,
                attributed_intervention_rate_lower_pct=100 * intervened_calls / len(selected_calls) if selected_calls else '',
                intervention_rate_pct=100 * intervened_calls / len(selected_calls)
                    if selected_calls and len(selected_events) == int(attributed) else '',
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
                paired_sessions_excluded_cache_tmpfs=timing_excluded_storage,
                paired_sessions_excluded_storage_backing_mismatch=timing_excluded_backing_mismatch,
                runtime_storage_backings=';'.join(sorted({r.get('runtime_storage_backing') or 'not_recorded' for r in selected})) if benchmark else '',
                median_paired_execution_difference_pct=100 * (median(timing) - 1) if timing else '',
                median_paired_total_difference_pct=100 * (median(total_timing) - 1) if total_timing else '',
                security_matrix_complete=int(sum(r.get('coverage') == 'complete' for r in selected) == planned),
                matrix_complete=int(len(selected) == planned and (not benchmark or len(scored) == planned))))
    write(args.out / 'headline.csv', rows)
    if positions:
        write(args.out / 'position.csv', positions)
    expansion_progress(rows, args.out)
    paper_paragraph(rows, args.out)
    render(rows, positions, args.out)


def expansion_progress(rows, out):
    selected = [r for r in rows if r['dataset'] in ('Terminal-Bench added cohort', 'Terminal-Bench combined')]
    if not selected:
        return
    names = {'a': 'No AgPlane', 'b': 'Broad sources', 'c': 'Narrowed sources'}
    lines = ['Expansion snapshot from `results/headline.csv`; pending cells are not failures.', '',
             '| Cohort | Condition | Completed / planned | Official successes / completed | Matched successes / common tasks |',
             '| --- | --- | ---: | ---: | ---: |']
    for row in selected:
        cohort = 'Added' if row['dataset'].endswith('added cohort') else 'Combined'
        n, common = row['official_scored_trials'], row['complete_triplet_tasks']
        official = f"{int(row['official_successes'])}/{n}" if n else 'pending'
        matched = f"{int(row['complete_triplet_successes'])}/{common}" if common else 'pending'
        lines.append(f"| {cohort} | {names[row['condition']]} | {row['outcome_valid_sessions']}/{row['planned_sessions']} | {official} | {matched} |")
    combined = next(r for r in selected if r['dataset'] == 'Terminal-Bench combined' and r['condition'] == 'a')
    common = set(filter(None, combined['complete_triplet_task_ids'].split(';')))
    names_list = ', '.join(f'`{name}`' for name in sorted(common)) or 'none yet'
    lines += ['', 'Combined tasks with valid outcomes in all three conditions: ' + names_list + '.']
    extra = []
    for row in selected:
        if row['dataset'] != 'Terminal-Bench combined':
            continue
        remaining = set(filter(None, row['completed_task_ids'].split(';'))) - common
        if remaining:
            extra.append(names[row['condition']] + ': ' + ', '.join(f'`{name}`' for name in sorted(remaining)))
    if extra:
        lines += ['', 'Additional completed cells outside that matched set: ' + '; '.join(extra) + '.']
    lines += ['', 'Available-condition scores can have different task mixes. The matched column uses the same tasks completed in every condition.', '',
              '| Cohort | Condition | Covered calls | False calls | Unknown calls | Unassigned events | False-call bounds |',
              '| --- | --- | ---: | ---: | ---: | ---: | ---: |']
    for row in selected:
        cohort = 'Added' if row['dataset'].endswith('added cohort') else 'Combined'
        lower, upper = row['confirmed_false_rate_pct'], row['false_rate_upper_pct']
        bounds = 'pending' if lower == '' else f'{lower:.2f}% lower; upper unavailable' if upper == '' else f'{lower:.2f}–{upper:.2f}%'
        lines.append(f"| {cohort} | {names[row['condition']]} | {row['calls']} | {row['confirmed_false_calls']} | {row['unknown_calls']} | {row['unattributed_intervention_events']} | {bounds} |")
    lines += ['', 'The added/combined matrices are complete only when every frozen task has valid outcomes in every condition. Security coverage and adjudication completeness remain separate fields.', '']
    (out / 'expansion-progress.md').write_text('\n'.join(lines))


def paper_paragraph(rows, out):
    combined = {r['condition']: r for r in rows if r['dataset'] == 'Terminal-Bench combined'}
    if not combined:
        return
    def scores(group):
        return ', '.join(f"{int(group[c]['complete_triplet_successes'])}/{group[c]['complete_triplet_tasks']}" for c in ('a', 'b', 'c'))
    original = {r['condition']: r for r in rows if r['dataset'] == 'Terminal-Bench'}
    status = 'completed' if all(r['matrix_complete'] for r in combined.values()) else 'partial'
    text = (f"Using GLM-5.3 and official Terminal-Bench 2.0 rewards, we planned {combined['a']['planned_sessions']} tasks. "
            f"The {status} matched snapshot covers {combined['a']['complete_triplet_tasks']} tasks, with successes of {scores(combined)} "
            f"without defense, with broad sources and with narrowed sources. Original-subset results remain {scores(original)}. ")
    added = {r['condition']: r for r in rows if r['dataset'] == 'Terminal-Bench added cohort'}
    if any(not r['intervention_adjudication_complete'] for r in added.values()):
        text += 'Added-cohort intervention adjudication remains incomplete. '
    elif any(r['intervention_events'] for r in added.values()):
        text += (f"Added broad/narrowed false calls were {added['b']['confirmed_false_calls']}/{added['b']['calls']} "
                 f"and {added['c']['confirmed_false_calls']}/{added['c']['calls']}. ")
    network = {r['condition']: r for r in rows if r['dataset'] == 'Terminal-Bench network stratum'}
    if network:
        text += (f"The separate network subset achieved {scores(network)}; broad/narrowed false calls were "
                 f"{network['b']['confirmed_false_calls']}/{network['b']['calls']} and {network['c']['confirmed_false_calls']}/{network['c']['calls']}. ")
    replay = {r['condition']: r for r in rows if r['dataset'] == 'Public replay'}
    if replay and replay['broad']['false_rate_upper_pct'] != '':
        text += (f"Across {replay['broad']['outcome_valid_sessions']} public replay trajectories, broad false-call bounds were "
                 f"{replay['broad']['confirmed_false_rate_pct']:.2f}-{replay['broad']['false_rate_upper_pct']:.2f}%, "
                 f"versus {replay['scoped']['confirmed_false_rate_pct']:.2f}% with narrowed sources. ")
    text += ("Single-attempt success differences and timings are descriptive. Process-subtree coverage and source/socket gaps limit protection; "
             "trusted declassification and retained model-context recovery remain unmeasured.")
    assert len(text.split()) <= 150
    (out / 'paper-paragraph.md').write_text(text + '\n')


def render(rows, positions, out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'pdf.fonttype': 42, 'ps.fonttype': 42, 'font.size': 9})
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6))
    cohorts = [('Terminal-Bench', 'Initial\nsubset')]
    if any(r['dataset'] == 'Terminal-Bench combined' for r in rows):
        planned = next(r['planned_sessions'] for r in rows if r['dataset'] == 'Terminal-Bench combined')
        cohorts.append(('Terminal-Bench combined', f'Combined\n({planned} planned)'))
    if any(r['dataset'] == 'Terminal-Bench network stratum' for r in rows):
        cohorts.append(('Terminal-Bench network stratum', 'Network\nstratum'))
    for i, (condition, color, name) in enumerate([('a', '#777777', 'No AgPlane'), ('b', '#ca6828', 'Broad'), ('c', '#2577a2', 'Scoped')]):
        bench = [next(r for r in rows if r['dataset'] == dataset and r['condition'] == condition) for dataset, _ in cohorts]
        values = [100*r['complete_triplet_mean_reward'] if r['complete_triplet_mean_reward'] != '' else 0 for r in bench]
        x = [j + (i-1)*.24 for j in range(len(cohorts))]
        bars = axes[0].bar(x, values, width=.23, color=color, label=name)
        for bar, row in zip(bars, bench):
            n = row['complete_triplet_tasks']
            label = f"{int(row['complete_triplet_successes'])}/{n}" if n else 'pending'
            if not row['matrix_complete']:
                label += '\npartial'
                bar.set_hatch('//')
            axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, label, ha='center', fontsize=8)
    axes[0].set_xticks(range(len(cohorts)), [label for _, label in cohorts])
    axes[0].legend(loc='upper center', ncol=3, fontsize=7, frameon=False)
    axes[0].set(ylim=(0, 140), yticks=range(0, 101, 20), ylabel='Official task success (%)', title='Terminal-Bench matched task success')
    for condition, color, label in [('none', '#777777', 'None'), ('broad', '#ca6828', 'Broad'), ('scoped', '#2577a2', 'Scoped')]:
        data = [r for r in positions if r['dataset'] == 'Public replay' and r['condition'] == condition]
        if data:
            x = [r['bin_start'] + 4.5 for r in data]
            axes[1].plot(x, [100*r['confirmed_false_calls']/r['calls'] for r in data], marker='.', color=color, label=label+' lower')
            if any(r['unknown_calls'] for r in data):
                axes[1].plot(x, [100*r['potential_false_calls']/r['calls'] for r in data], ls=':', color=color, label=label+' upper')
    replay_complete = all(r['matrix_complete'] for r in rows if r['dataset'] == 'Public replay')
    replay_title = 'Public replay' if replay_complete else 'Public replay (partial)'
    axes[1].set(xlabel='Originating tool-call position (bins of ten)', ylabel='False-intervention rate bounds (%)', title=replay_title)
    axes[1].set_ylim(bottom=0)
    if axes[1].lines:
        if not any(any(y > 0 for y in line.get_ydata()) for line in axes[1].lines):
            axes[1].set_ylim(0, 1)
        axes[1].legend(fontsize=7)
    else:
        axes[1].text(.5, .5, 'Replay results pending', transform=axes[1].transAxes, ha='center')
    initial = [r for r in rows if r['dataset'] == 'Terminal-Bench']
    context = 'Initial subset: no tracked IPv4 connects. ' if all(r['ipv4_connect_attempts'] == 0 for r in initial) else ''
    partial = any(not r['matrix_complete'] for r in rows if r['dataset'] != 'Public replay')
    footer = context+'Process-subtree scope; scoped narrows sources; trusted declassification unmeasured.'
    if partial:
        footer = 'Hatching marks partial matrices; bars use tasks completed in all conditions.\n' + footer
    fig.text(.5, .01, footer, ha='center', fontsize=7)
    fig.tight_layout(rect=(0, .1 if partial else .05, 1, 1))
    fig.savefig(out / 'benign-utility.pdf')
    fig.savefig(out / 'benign-utility.png', dpi=180)
    plt.close(fig)


if __name__ == '__main__':
    main()
