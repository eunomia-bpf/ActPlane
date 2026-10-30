"""Validate all reviewed labels, reuse merge metrics, and regenerate final artifacts."""
import ast
from collections import Counter, defaultdict
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import matplotlib
import numpy as np
import yaml

HERE = Path(__file__).resolve().parent
MERGE = HERE.parent / 'corpus-merge'
AXES = ['type', 'topic', 'enforceability', 'context_required']


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read(path):
    with path.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def write(path, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def extras(rows, repos, topics, m):
    """Supplementary ratios use the identical repository bootstrap draws."""
    grouped = defaultdict(list)
    for r in rows:
        if r['type'] == 'directive':
            grouped[r['key']].append(r)
    groups = [grouped[k] for k in sorted(repos)]
    weights = np.random.default_rng(m.SEED).multinomial(
        len(repos), np.full(len(repos), 1/len(repos)), size=m.REPLICATES)
    result = []

    def ratio(key, label, predicate, denominator, paper='unavailable'):
        n = np.array([sum(predicate(r) for r in g) for g in groups])
        d = np.array([sum(denominator(r) for r in g) for g in groups])
        nums, dens = weights @ n, weights @ d
        draws = np.divide(nums, dens, out=np.full(nums.shape, np.nan), where=dens > 0)
        low, high = np.nanquantile(draws, [.025, .975])
        result.append(dict(metric=key, label=label, unit='fraction', paper_value=paper,
                           numerator=int(n.sum()), denominator=int(d.sum()),
                           value=float(n.sum()/d.sum()), ci_low=low, ci_high=high))

    for topic in topics:
        if topic != 'Development Process':  # Already included by unchanged metrics().
            ratio('cross_event_topic_share:' + topic, 'Cross-event policies in ' + topic,
                  lambda r, t=topic: r['enforceability'] == 'cross_event' and r['topic'] == t,
                  lambda r: r['enforceability'] == 'cross_event')
    existing = {('content', 'none'), ('content', 'project_task'),
                ('cross_event', 'project'), ('cross_event', 'task'), ('cross_event', 'project_task')}
    for tier in ['content', 'per_event', 'cross_event']:
        for context, keys in [('none', ['none']), ('project', ['project']), ('task', ['task']),
                              ('project_task', ['project', 'task'])]:
            if (tier, context) in existing:
                continue
            ratio(tier + '_context_' + context, f'{tier}: {context} context / tier',
                  lambda r, t=tier, ks=keys: r['enforceability'] == t and r['context_required'] in ks,
                  lambda r, t=tier: r['enforceability'] == t)
    return result


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    m = load_module('merge_metrics', MERGE / 'analyze_merge.py')
    m.INPUT = HERE / '.inputs'
    m.SCALE = m.INPUT / 'scale'
    tree = ast.parse((MERGE / 'plot_empirical.py').read_text(encoding='utf-8'))
    cfg = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
           if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
           and n.targets[0].id in ['COLLAPSE', 'TOPIC_ORDER', 'ENF_LEVELS', 'CTX_LEVELS']}
    old, om, new, nm, shared = m.load_inputs(cfg['COLLAPSE'])
    source_index = {r['statement_id']: r for r in read(m.SCALE / 'statements.csv')}
    for r in new:
        for k, v in source_index[r['statement_id']].items():
            r.setdefault(k, v)
    first = old + [r for r in new if r['key'] not in om]
    for r in first:
        r['topic'] = cfg['COLLAPSE'].get(r['topic'], r['topic'])
    first_index = {r['statement_id']: r for r in first}
    metadata = {**nm, **om}
    reviewed = read(HERE / 'original64/reviewed.csv') + read(HERE / 'reviewed_all.csv')
    assert len(reviewed) == len(first_index) == 29717
    assert len({r['statement_id'] for r in reviewed}) == 29717
    assert {r['statement_id'] for r in reviewed} == set(first_index)
    original_input = read(HERE / 'shards/original64.csv')
    assert len(original_input) == 2116
    for a, b in zip(original_input, reviewed[:2116]):
        assert all(a[k] == b[k] for k in a)
    final = []
    for r in reviewed:
        ref = first_index[r['statement_id']]
        assert all(r[k] == ref[k] for k in ['repo', 'file_path', 'start_line', 'end_line'] + AXES)
        assert r['text'].replace('\r\n', '\n') == ref['text'].replace('\r\n', '\n')
        t, p, e, c = [r[k + '_r'] for k in AXES]
        assert p in cfg['TOPIC_ORDER']
        assert (t == 'description' and e == c == '') or (t == 'directive' and e in cfg['ENF_LEVELS'] and
               ((e == 'semantic_only' and c == '') or (e != 'semantic_only' and c in cfg['CTX_LEVELS'])))
        changed = any(r[k] != r[k + '_r'] for k in AXES)
        assert r['changed'] == str(changed).lower()
        assert not changed or r['reason'].strip()
        final.append({**{k: r[k] for k in ['statement_id', 'repo', 'file_path', 'start_line', 'end_line', 'text']},
                      **{k: r[k + '_r'] for k in AXES},
                      **{k + '_first': r[k] for k in AXES}, 'changed': r['changed'], 'reason': r['reason'],
                      'review_cohort': 'original64' if ref['key'] in om else 'added298'})
    write(HERE / 'final_labels.csv', final)
    merged = [dict(r, key=r['repo'].casefold()) for r in final]
    assert len({r['key'] for r in merged}) == len(metadata) == 362
    current = m.metrics(first, metadata, cfg['TOPIC_ORDER']) + extras(first, metadata, cfg['TOPIC_ORDER'], m)
    result = m.metrics(merged, metadata, cfg['TOPIC_ORDER']) + extras(merged, metadata, cfg['TOPIC_ORDER'], m)
    baseline = {r['metric']: r for r in read(MERGE / 'numbers.csv') if r['cohort'] == 'primary'}
    for r in current:
        if r['metric'] in baseline:
            assert np.isclose(r['value'], float(baseline[r['metric']]['value']), rtol=0, atol=1e-14)
            for bound in ['ci_low', 'ci_high']:
                if r[bound] != '':
                    assert np.isclose(r[bound], float(baseline[r['metric']][bound]), rtol=0, atol=1e-14)
    numbers = []
    for a, b in zip(current, result):
        assert a['metric'] == b['metric']
        numbers.append(dict(metric=b['metric'], label=b['label'], unit=b['unit'], paper_value=b['paper_value'],
                            current_paper_value=a['value'], current_ci_low=a['ci_low'], current_ci_high=a['ci_high'],
                            final_value=b['value'], numerator=b['numerator'], denominator=b['denominator'],
                            ci_low=b['ci_low'], ci_high=b['ci_high']))
    write(HERE / 'final_numbers.csv', numbers)
    # Same equal-populated-strata sampling design, now applied to the full reviewed union.
    sampler = load_module('existing_sampling', HERE / 'prepare_study.py')
    human = sampler.sample(final, 100, m.SEED + 4)
    assert len({r['statement_id'] for r in human}) == 100
    assert {r['review_cohort'] for r in human} == {'original64', 'added298'}
    write(HERE / 'final_review_sample.csv', [{**r, 'verdict': ''} for r in human])
    layout = HERE / 'layout/final'
    layout.mkdir(parents=True, exist_ok=True)
    grouped = defaultdict(list)
    for r in merged:
        grouped[r['key']].append({k: r[k] for k in AXES})
    assert not ({p.name for p in layout.iterdir() if p.is_dir()} - {k.replace('/', '__') for k in grouped})
    for key, rows in grouped.items():
        dest = layout / key.replace('/', '__')
        dest.mkdir(exist_ok=True)
        (dest / 'statements.yaml').write_text(yaml.safe_dump(dict(statements=rows), sort_keys=False), encoding='utf-8')
    figures = HERE / 'final_figures'
    figures.mkdir(exist_ok=True)
    # Execute the original plot source, changing only the output-directory binding.
    plot_text = (MERGE / 'plot_empirical.py').read_text(encoding='utf-8')
    original_binding = "OUTDIR = os.path.join(os.path.dirname(__file__), 'figures')"
    assert plot_text.count(original_binding) == 1
    plot_text = plot_text.replace(original_binding, 'OUTDIR = ' + repr(str(figures)))
    previous = Path.cwd()
    os.chdir(layout)
    try:
        plot = {'__file__': str(MERGE / 'plot_empirical.py'), '__name__': '__main__'}
        exec(compile(plot_text, str(MERGE / 'plot_empirical.py'), 'exec'), plot)
    finally:
        os.chdir(previous)
    index = {r['metric']: r for r in result}
    assert len(plot['repo_stats']) == 362
    assert sum(r['total'] for r in plot['repo_stats']) == 29717
    assert sum(plot['dir_by'].values()) == index['policies']['value']
    for topic in cfg['TOPIC_ORDER']:
        assert plot['dir_by'][topic] == index['topic_policy:' + topic]['numerator']
        assert plot['dir_by'][topic] + plot['desc_by'][topic] == index['topic_policy:' + topic]['denominator']
    for tier in cfg['ENF_LEVELS']:
        assert plot['enf_total'][tier] == index[tier + '_fraction']['numerator']
    for c in cfg['CTX_LEVELS']:
        assert plot['ctx_total'][c] == index['context_' + c + '_fraction']['numerator']
    assert len(list(figures.glob('*.pdf'))) == 4
    for pdf in sorted(figures.glob('*.pdf')):
        fonts = subprocess.check_output(['pdffonts', pdf.name], text=True, cwd=figures)
        assert 'Type 3' not in fonts and 'TrueType' in fonts
        pdf.with_suffix('.pdffonts.txt').write_text(fonts, encoding='utf-8')
        subprocess.run(['pdftoppm', '-png', '-singlefile', '-r', '100', pdf.name, pdf.stem], check=True,
                       cwd=figures, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    cross = Counter(r['topic'] for r in merged if r['type'] == 'directive' and r['enforceability'] == 'cross_event')
    top3 = ', '.join(f'{topic}: {count:,}/{sum(cross.values()):,} ({100*count/sum(cross.values()):.1f}%)'
                     for topic, count in cross.most_common(3))
    table = ['| Measure | Paper value | Current paper value (first-pass merged) | Final reviewed value (95% CI) |',
             '|---|---:|---:|---:|']
    for a, b in zip(current, result):
        table.append(f"| {b['label']} | {b['paper_value']} | {m.display(a)} | {m.display(b)} |")
    provenance_paths = [HERE / 'shards/original64.csv', HERE / 'original64/reviewed.csv', HERE / 'reviewed_all.csv',
                        HERE / 'final_labels.csv', MERGE / 'analyze_merge.py', MERGE / 'plot_empirical.py',
                        HERE / 'shard2/run_review.py', HERE / 'shard2/shared_codebook.txt', HERE / 'shard2/response_schema.json']
    provenance = dict(bootstrap_seed=m.SEED, bootstrap_replicates=m.REPLICATES,
                      bootstrap_unit='whole repositories uniformly with replacement; percentile 95% CI',
                      python=platform.python_version(), numpy=np.__version__, matplotlib=matplotlib.__version__, pyyaml=yaml.__version__,
                      sample_seed=m.SEED+4, sample_design='equal populated type/tier/topic strata; round-robin repositories within strata; without replacement',
                      sample_repositories=len({r['repo'] for r in human}), sample_cohorts=dict(Counter(r['review_cohort'] for r in human)),
                      validation='all 29,717 exact IDs, source text/spans/first labels, label applicability, correction reasons, baseline metrics, plot-loaded counts and PDF fonts passed',
                      sha256={str(p.relative_to(HERE.parent)): hashlib.sha256(p.read_bytes()).hexdigest() for p in provenance_paths})
    (HERE / 'final_provenance.json').write_text(json.dumps(provenance, indent=2), encoding='utf-8')
    report = f'''# Final reviewed 362-repository study

All 29,717 statements have reviewed labels: 2,116 statements from the original 64 repositories reviewed with unchanged procedure 2, plus 27,601 previously reviewed statements from 298 added repositories. Final `type`, `topic`, `enforceability`, and `context_required` columns contain reviewed labels; `_first` columns preserve prior labels. Source IDs, text and spans are preserved.

The operator's 2026-10-29 decision prioritizes label accuracy over historical method matching. Procedure 2 retains its historical examples and prompt wording (including its shard-2/added-repositories wording). Some historical examples come from the original 64 repositories. This full-corpus correction pass is not an independent held-out accuracy evaluation. Boundary flags preserve the existing segmentation. The human-review verdicts are blank and remain pending.

The table's paper values are the historical values embedded in unchanged `corpus-merge/analyze_merge.py`; unavailable paper values are literal `unavailable`. Current paper values are recomputed on the original first-pass merged 362-repository labels and exactly match all existing primary metrics. Final values use reviewed labels for every repository. Supplemental metrics use the same bootstrap draws and denominator definitions. Counts and extrema have no bootstrap intervals in the unchanged metric code. Fractions show percentages and 95% percentile intervals in percentage points, using {m.REPLICATES:,} draws of whole repositories with seed {m.SEED}.

Cross-event policies' top three topic shares (denominator: all cross-event policies): {top3}.

{chr(10).join(table)}

`final_review_sample.csv` samples 100 distinct statements from the full 362-repository frame, covering {provenance['sample_repositories']} repositories and both original/added cohorts ({provenance['sample_cohorts']}). It uses equal allocation across populated final type/tier/topic strata, with repository round robin within strata, seed {m.SEED+4}. A 100-statement sample cannot include all 362 repositories. It is intended for qualitative human review, not prevalence estimation.

Four figures in `final_figures/` use the unchanged merge plotting source, with only its output directory redirected. Loaded repository, statement, topic, tier and context counts reconcile with final metrics. All four PDFs have embedded TrueType fonts (Type 42 setting), and `pdffonts` confirms no Type 3 fonts. PNG previews accompany the PDFs. Existing plot style and legend placement are preserved.

Reproduce from the repository root: `python -u docs/empirical-study/corpus-relabel/run_original64.py`, then `python -u docs/empirical-study/corpus-relabel/finalize_study.py`. Procedure-2 validated batch caches allow resumption. Python dependencies and hashes are recorded in `final_provenance.json`. No paper repository files are edited.
'''
    (HERE / 'FINAL.md').write_text(report, encoding='utf-8')
    print(json.dumps(dict(statements=len(final), repositories=len(metadata), metrics=len(numbers),
                          policies=index['policies']['value'], os_enforceable=index['os_enforceable']['value'],
                          sample_repositories=provenance['sample_repositories'], figures=4)), flush=True)


if __name__ == '__main__':
    main()
