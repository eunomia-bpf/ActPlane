#!/usr/bin/env python3
"""Reproduce the six motivation plots from CSVs, withholding failed dimensions."""
from collections import Counter, defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np

from common import HERE, read_csv, write_csv
from label import TOPICS

plt.rcParams.update({'pdf.fonttype': 42, 'ps.fonttype': 42, 'font.size': 10,
                     'font.family': 'DejaVu Sans', 'axes.spines.top': False,
                     'axes.spines.right': False})
LEVELS = ['semantic_only', 'content', 'per_event', 'cross_event']
CONTEXT = ['none', 'project', 'task']
COLORS = ['#bdbdbd', '#67a9cf', '#2166ac', '#b2182b']
CTX_COLORS = ['#bdbdbd', '#4393c3', '#d6604d']
DATA = []
OUT = HERE / 'figures'


def save(fig, name):
    OUT.mkdir(exist_ok=True)
    fig.savefig(OUT / (name + '.pdf'), bbox_inches='tight')
    # PNG previews stay in the raw directory when generated for inspection.
    plt.close(fig)


def withheld(name, dimensions, gates):
    failed = [d for d in dimensions if not gates.get(d, False)]
    if not failed:
        return False
    fig, ax = plt.subplots(figsize=(6.4, 2.3))
    ax.axis('off')
    ax.text(.5, .55, 'Result withheld', ha='center', fontsize=16)
    ax.text(.5, .30, 'Calibration gate did not pass: ' + ', '.join(failed), ha='center', fontsize=9)
    save(fig, name)
    DATA.append(dict(figure=name, group='withheld', label=','.join(failed), value='', denominator=''))
    return True


def waterfall(name, counts, labels, colors, title):
    fig, ax = plt.subplots(figsize=(7.4, 2.6))
    ax.set_xlim(-.2, len(labels) * 2.3)
    ax.set_ylim(-.2, 2.1)
    ax.axis('off')
    total = sum(counts)
    remaining = total
    for i, (count, label, color) in enumerate(zip(counts, labels, colors)):
        x = i * 2.3
        ax.add_patch(FancyBboxPatch((x, .5), 1.9, .9, boxstyle='round,pad=.08',
                                   facecolor=color, edgecolor='white', alpha=.85))
        ax.text(x + .95, .95, f'{label}\n{count:,} ({100*count/total:.1f}%)',
                ha='center', va='center', fontsize=9,
                color='white' if i > 1 else '#111111')
        ax.text(x + .95, 1.65, f'{remaining:,} remaining', ha='center', fontsize=8)
        if i < len(labels) - 1:
            ax.annotate('', xy=(x + 2.18, .95), xytext=(x + 1.99, .95),
                        arrowprops=dict(arrowstyle='->', color='#444444'))
        remaining -= count
        DATA.append(dict(figure=name, group='all', label=label, value=count, denominator=total))
    ax.set_title(title, fontsize=11)
    save(fig, name)


def main():
    rows = read_csv(HERE / 'analysis_statements.csv')
    gates = {r['dimension']: r['passed'] == 'True' for r in read_csv(HERE / 'calibration_gates.csv')}
    policies = [r for r in rows if r['type'] == 'directive']
    system = [r for r in policies if r['enforceability'] in LEVELS[1:]]
    repos = defaultdict(list)
    for r in rows:
        repos[r['repo']].append(r)
    name = 'empirical_rq1_policy_fraction'
    if not withheld(name, ['type'], gates):
        ratios = sorted((sum(r['type'] == 'directive' for r in rs) / len(rs), repo, len(rs))
                        for repo, rs in repos.items())
        fig, ax = plt.subplots(figsize=(6.4, 2.6))
        ax.bar(np.arange(len(ratios)), [100*r[0] for r in ratios], color='#2166ac', width=1)
        ax.axhline(50, color='#555555', linewidth=.8, linestyle='--')
        ax.set(xlabel='Repositories sorted by policy fraction', ylabel='Policy statements (%)', ylim=(0, 103))
        ax.set_title(f'{len(repos):,} repositories, {len(rows):,} statements', fontsize=10)
        ax.set_xticks([])
        for value, repo, n in ratios:
            DATA.append(dict(figure=name, group=repo, label='policy_fraction', value=value, denominator=n))
        save(fig, name)
    name = 'empirical_rq2_policy_ratio'
    if not withheld(name, ['type', 'topic'], gates):
        values = []
        for topic in TOPICS:
            rs = [r for r in rows if r['topic'] == topic]
            n = sum(r['type'] == 'directive' for r in rs)
            values.append(100*n/len(rs) if rs else 0)
            DATA.append(dict(figure=name, group=topic, label='policy', value=n, denominator=len(rs)))
        fig, ax = plt.subplots(figsize=(6.4, 4))
        ax.barh(TOPICS, values, color='#2166ac')
        ax.invert_yaxis()
        ax.set(xlabel='Policy statements (%)', xlim=(0, 100))
        save(fig, name)
    name = 'empirical-waterfall-enforcement-horizontal'
    if not withheld(name, ['type', 'enforceability'], gates):
        counts = Counter(r['enforceability'] for r in policies)
        waterfall(name, [counts[x] for x in LEVELS], ['Semantic only', 'Content', 'Per event', 'Cross event'],
                  COLORS, f'Enforcement-level waterfall ({len(policies):,} policies)')
    name = 'empirical_rq3_enforcement_by_topic'
    if not withheld(name, ['type', 'topic', 'enforceability'], gates):
        fig, ax = plt.subplots(figsize=(6.4, 4))
        left = np.zeros(len(TOPICS))
        for level, color in zip(LEVELS, COLORS):
            widths = []
            for topic in TOPICS:
                rs = [r for r in policies if r['topic'] == topic]
                n = sum(r['enforceability'] == level for r in rs)
                widths.append(100*n/len(rs) if rs else 0)
                DATA.append(dict(figure=name, group=topic, label=level, value=n, denominator=len(rs)))
            ax.barh(TOPICS, widths, left=left, label=level.replace('_', ' '), color=color)
            left += widths
        ax.invert_yaxis()
        ax.set(xlabel='Policy statements (%)', xlim=(0, 100))
        ax.legend(loc='upper center', bbox_to_anchor=(.5, -.15), ncol=2, frameon=False)
        save(fig, name)
    name = 'empirical-waterfall-context-horizontal'
    if not withheld(name, ['type', 'enforceability', 'context_required'], gates):
        counts = Counter(r['context_required'] for r in system)
        waterfall(name, [counts[x] for x in CONTEXT], ['Self-contained', 'Project', 'Task'],
                  CTX_COLORS, f'Context waterfall ({len(system):,} system-observable policies)')
    name = 'empirical_rq4_context_by_enforcement'
    if not withheld(name, ['type', 'enforceability', 'context_required'], gates):
        fig, ax = plt.subplots(figsize=(6.4, 2.6))
        left = np.zeros(3)
        for ctx, color in zip(CONTEXT, CTX_COLORS):
            widths = []
            for level in LEVELS[1:]:
                rs = [r for r in system if r['enforceability'] == level]
                n = sum(r['context_required'] == ctx for r in rs)
                widths.append(100*n/len(rs) if rs else 0)
                DATA.append(dict(figure=name, group=level, label=ctx, value=n, denominator=len(rs)))
            ax.barh([x.replace('_', ' ') for x in LEVELS[1:]], widths, left=left, label=ctx, color=color)
            left += widths
        ax.invert_yaxis()
        ax.set(xlabel='System-observable policies (%)', xlim=(0, 100))
        ax.legend(loc='upper center', bbox_to_anchor=(.5, -.25), ncol=3, frameon=False)
        save(fig, name)
    write_csv(HERE / 'figure_data.csv', DATA)


if __name__ == '__main__':
    main()
