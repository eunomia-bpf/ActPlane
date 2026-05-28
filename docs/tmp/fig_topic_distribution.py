#!/usr/bin/env python3
"""Generate Figure: Topic distribution (12 categories).

Usage: cd docs/corpus && python3 ../tmp/fig_topic_distribution.py
Output: docs/tmp/fig_topic_distribution.png
"""
import yaml, os, collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

COLLAPSE = {
    'Debugging': 'Development Process',
    'Project Management': 'Development Process',
    'Performance': 'Implementation Details',
    'UI/UX': 'Implementation Details',
}

TOPIC_ORDER = [
    'Development Process', 'Implementation Details', 'Architecture',
    'Build and Run', 'AI Integration', 'Testing',
    'System Overview', 'Documentation', 'Configuration & Environment',
    'Security', 'DevOps', 'Maintenance',
]

SHORT = {
    'Configuration & Environment': 'Config & Env',
    'Implementation Details': 'Impl. Details',
    'Development Process': 'Dev. Process',
}

desc_by = collections.Counter()
dir_by = collections.Counter()
lines_by = collections.Counter()

for d in sorted(os.listdir('.')):
    yf = os.path.join(d, 'statements.yaml')
    if not os.path.isfile(yf):
        continue
    with open(yf) as f:
        data = yaml.safe_load(f)
    if not data or 'statements' not in data:
        continue
    for s in data['statements']:
        topic = COLLAPSE.get(s.get('topic', ''), s.get('topic', ''))
        span = s['lines'][1] - s['lines'][0] if len(s.get('lines', [])) == 2 else 0
        if s.get('type') == 'description':
            desc_by[topic] += 1
        else:
            dir_by[topic] += 1
        lines_by[topic] += span

topics = TOPIC_ORDER
labels = [SHORT.get(t, t) for t in topics]
desc = np.array([desc_by[t] for t in topics])
dire = np.array([dir_by[t] for t in topics])
lines = np.array([lines_by[t] for t in topics])
total = desc + dire

fig, axes = plt.subplots(1, 3, figsize=(18, 6))
y = np.arange(len(topics))

# (a) Stacked bar
ax = axes[0]
ax.barh(y, desc[::-1], label='Description', color='#4ECDC4', edgecolor='white', linewidth=0.5)
ax.barh(y, dire[::-1], left=desc[::-1], label='Directive', color='#FF6B6B', edgecolor='white', linewidth=0.5)
ax.set_yticks(y)
ax.set_yticklabels(labels[::-1], fontsize=9)
ax.set_xlabel('Statement Count')
ax.set_title('(a) Statements by Topic')
ax.legend(loc='lower right', fontsize=9)

# (b) Directive ratio
ax = axes[1]
dir_pct = np.array([100 * d / t if t > 0 else 0 for d, t in zip(dire, total)])
colors = ['#FF6B6B' if p > 70 else '#FFD93D' if p > 40 else '#4ECDC4' for p in dir_pct[::-1]]
ax.barh(y, dir_pct[::-1], color=colors, edgecolor='white', linewidth=0.5)
ax.axvline(x=100 * dire.sum() / total.sum(), color='black', linestyle='--', linewidth=1, alpha=0.5,
           label=f'Overall ({100*dire.sum()/total.sum():.1f}%)')
ax.set_yticks(y)
ax.set_yticklabels(labels[::-1], fontsize=9)
ax.set_xlabel('Directive %')
ax.set_title('(b) Directive Ratio by Topic')
ax.legend(fontsize=8)

# (c) Statement % vs Line %
ax = axes[2]
stmt_pct = 100 * total / total.sum()
line_pct = 100 * lines / lines.sum()
w = 0.35
ax.barh(y + w / 2, stmt_pct[::-1], w, label='% Statements', color='#FF6B6B', alpha=0.8)
ax.barh(y - w / 2, line_pct[::-1], w, label='% Lines', color='#6C5CE7', alpha=0.8)
ax.set_yticks(y)
ax.set_yticklabels(labels[::-1], fontsize=9)
ax.set_xlabel('Percentage (%)')
ax.set_title('(c) Statement vs Line Share')
ax.legend(fontsize=8)

plt.tight_layout()
outpath = os.path.join(os.path.dirname(__file__), 'fig_topic_distribution.png')
plt.savefig(outpath, dpi=150, bbox_inches='tight')
print(f'Saved {outpath}')
