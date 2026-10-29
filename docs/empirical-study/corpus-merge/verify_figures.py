#!/usr/bin/env python3
"""Run the minimally adapted original plot and check the data it actually loaded."""
import csv
import runpy
from pathlib import Path

root = Path(__file__).resolve().parent
plot = runpy.run_path(str(root / 'plot_empirical.py'))
with (root / 'numbers.csv').open() as f:
    numbers = {r['metric']: r for r in csv.DictReader(f) if r['cohort'] == 'primary'}
assert len(plot['repo_stats']) == int(numbers['repositories']['value'])
assert sum(r['total'] for r in plot['repo_stats']) == int(numbers['statements']['value'])
assert sum(plot['dir_by'].values()) == int(numbers['policies']['value'])
assert sum(plot['ctx_total'].values()) == int(numbers['system_observable']['value'])
for topic in plot['TOPIC_ORDER']:
    row = numbers['topic_policy:' + topic]
    assert plot['dir_by'][topic] == int(row['numerator'])
    assert plot['dir_by'][topic] + plot['desc_by'][topic] == int(row['denominator'])
for tier in plot['ENF_LEVELS']:
    assert plot['enf_total'][tier] == int(numbers[tier + '_fraction']['numerator'])
for context in plot['CTX_LEVELS']:
    assert plot['ctx_total'][context] == int(numbers['context_' + context + '_fraction']['numerator'])
print('PASS: plot-loaded repository, topic, enforcement, and context counts equal primary numbers.csv')
