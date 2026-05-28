#!/usr/bin/env python3
"""Generate all RQ figures (6 separate PNGs).

Usage: cd docs/corpus && python3 ../tmp/fig_all_rqs.py
Output: docs/tmp/fig{1..6}_*.png
"""
import yaml, os, collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

COLLAPSE = {
    'Debugging': 'Development Process', 'Project Management': 'Development Process',
    'Performance': 'Implementation Details', 'UI/UX': 'Implementation Details',
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
repo_stats = []

for d in sorted(os.listdir('.')):
    yf = os.path.join(d, 'statements.yaml')
    if not os.path.isfile(yf): continue
    with open(yf) as f:
        data = yaml.safe_load(f)
    if not data or 'statements' not in data: continue
    stmts = data['statements']
    r_desc = r_dir = 0
    for s in stmts:
        topic = COLLAPSE.get(s.get('topic', ''), s.get('topic', ''))
        span = s['lines'][1] - s['lines'][0] if len(s.get('lines', [])) == 2 else 0
        if s.get('type') == 'description':
            desc_by[topic] += 1; r_desc += 1
        else:
            dir_by[topic] += 1; r_dir += 1
        lines_by[topic] += span
    repo_stats.append({'repo': d.replace('__', '/'), 'desc': r_desc, 'dir': r_dir,
                       'total': len(stmts), 'dir_pct': 100 * r_dir / len(stmts) if stmts else 0})

topics = TOPIC_ORDER
labels = [SHORT.get(t, t) for t in topics]
desc = np.array([desc_by[t] for t in topics])
dire = np.array([dir_by[t] for t in topics])
lines_arr = np.array([lines_by[t] for t in topics])
total = desc + dire
outdir = os.path.join(os.path.dirname(os.path.abspath('.')), 'tmp')

# ===== Fig 1: RQ1 - Per-repo directive fraction =====
fig, ax = plt.subplots(figsize=(8, 5))
dir_pcts = sorted([r['dir_pct'] for r in repo_stats])
colors = ['#FF6B6B' if p >= 50 else '#4ECDC4' for p in dir_pcts]
ax.bar(range(len(dir_pcts)), dir_pcts, color=colors, width=1.0, edgecolor='none')
ax.axhline(y=np.median(dir_pcts), color='black', linestyle='--', linewidth=1.5,
           label=f'Median = {np.median(dir_pcts):.1f}%')
ax.axhline(y=50, color='gray', linestyle=':', linewidth=1, alpha=0.5)
p_dir = mpatches.Patch(color='#FF6B6B', label='Majority directive (>50%)')
p_desc = mpatches.Patch(color='#4ECDC4', label='Majority description (<50%)')
ax.legend(handles=[p_dir, p_desc, ax.get_lines()[0]], fontsize=9, loc='upper left')
ax.set_xlabel('Repositories (sorted by directive fraction)', fontsize=11)
ax.set_ylabel('Directive Fraction (%)', fontsize=11)
ax.set_title('RQ1: What fraction of instruction-file content is directive?', fontsize=12, fontweight='bold')
ax.set_ylim(0, 105)
ax.text(len(dir_pcts) * 0.55, 8,
        f'n = {len(dir_pcts)} repos\n{sum(dire)}/{sum(total)} stmts = {100 * sum(dire) / sum(total):.1f}% directive',
        fontsize=9, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
plt.tight_layout()
plt.savefig(os.path.join(outdir, 'fig1_rq1_directive_fraction.png'), dpi=150, bbox_inches='tight')
plt.close(); print('Fig 1')

# ===== Fig 2: RQ2a - Topic prevalence =====
fig, ax = plt.subplots(figsize=(8, 5))
y = np.arange(len(topics))
ax.barh(y, total[::-1], color='#6C5CE7', edgecolor='white', linewidth=0.5, label='Statements')
for i, v in enumerate(total[::-1]):
    ax.text(v + 5, i, f'{v} ({100 * v / sum(total):.1f}%)', va='center', fontsize=8)
ax.set_yticks(y); ax.set_yticklabels(labels[::-1], fontsize=10)
ax.set_xlabel('Statement Count', fontsize=11)
ax.set_title('RQ2a: Which topics dominate instruction files?', fontsize=12, fontweight='bold')
ax.legend(fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(outdir, 'fig2_rq2a_topic_prevalence.png'), dpi=150, bbox_inches='tight')
plt.close(); print('Fig 2')

# ===== Fig 3: RQ2b - Directive ratio by topic =====
fig, ax = plt.subplots(figsize=(8, 5))
dir_ratio = np.array([100 * d / t if t > 0 else 0 for d, t in zip(dire, total)])
si = np.argsort(dir_ratio)
sr = dir_ratio[si]; sl = [labels[i] for i in si]
colors3 = ['#FF6B6B' if p > 70 else '#FFD93D' if p > 40 else '#4ECDC4' for p in sr]
ax.barh(y, sr, color=colors3, edgecolor='white', linewidth=0.5)
avg_line = ax.axvline(x=100 * sum(dire) / sum(total), color='black', linestyle='--', linewidth=1.5)
for i, (v, t) in enumerate(zip(sr, [total[j] for j in si])):
    ax.text(v + 1, i, f'{v:.0f}% (n={t})', va='center', fontsize=8)
p_high = mpatches.Patch(color='#FF6B6B', label='Directive-dominant (>70%)')
p_mid = mpatches.Patch(color='#FFD93D', label='Mixed (40-70%)')
p_low = mpatches.Patch(color='#4ECDC4', label='Description-dominant (<40%)')
ax.legend(handles=[p_high, p_mid, p_low, avg_line], labels=[
    'Directive-dominant (>70%)', 'Mixed (40-70%)', 'Description-dominant (<40%)',
    f'Overall avg ({100 * sum(dire) / sum(total):.1f}%)'], fontsize=8, loc='lower right')
ax.set_yticks(y); ax.set_yticklabels(sl, fontsize=10)
ax.set_xlabel('Directive Ratio (%)', fontsize=11)
ax.set_title('RQ2b: How does the directive ratio vary across topics?', fontsize=12, fontweight='bold')
ax.set_xlim(0, 105)
plt.tight_layout()
plt.savefig(os.path.join(outdir, 'fig3_rq2b_directive_ratio.png'), dpi=150, bbox_inches='tight')
plt.close(); print('Fig 3')

# ===== Fig 4: RQ2c - Statement-level vs file-level =====
chat_file_pct = {
    'Build and Run': 77.1, 'Implementation Details': 71.9, 'Architecture': 64.8,
    'Testing': 55.0, 'Development Process': 50.0, 'AI Integration': 40.0,
    'System Overview': 35.0, 'Documentation': 30.0, 'Configuration & Environment': 25.0,
    'Security': 14.5, 'DevOps': 10.0, 'Maintenance': 8.0,
}
fig, ax = plt.subplots(figsize=(8, 5))
stmt_pct = 100 * total / total.sum()
file_pct = np.array([chat_file_pct.get(t, 0) for t in topics])
w = 0.35
ax.barh(y + w / 2, stmt_pct[::-1], w, label='This study (% of statements)', color='#FF6B6B', alpha=0.85)
ax.barh(y - w / 2, file_pct[::-1], w, label='Chatlatanagulchai et al. (% of files)', color='#4ECDC4', alpha=0.85)
ax.set_yticks(y); ax.set_yticklabels(labels[::-1], fontsize=10)
ax.set_xlabel('Percentage (%)', fontsize=11)
ax.set_title('RQ2c: Does analysis granularity change topic ranking?', fontsize=12, fontweight='bold')
ax.legend(fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(outdir, 'fig4_rq2c_granularity_comparison.png'), dpi=150, bbox_inches='tight')
plt.close(); print('Fig 4')

# ===== Fig 5: RQ2d - Statement share vs line share =====
fig, ax = plt.subplots(figsize=(8, 5))
stmt_share = 100 * total / total.sum()
line_share = 100 * lines_arr / lines_arr.sum()
diff = stmt_share - line_share
s5 = np.argsort(diff); sd = diff[s5]; sl5 = [labels[i] for i in s5]
colors5 = ['#FF6B6B' if d > 0 else '#4ECDC4' for d in sd]
ax.barh(np.arange(len(sd)), sd, color=colors5, edgecolor='white')
ax.axvline(x=0, color='black', linewidth=1)
for i, (v, ss, ll) in enumerate(zip(sd, [stmt_share[j] for j in s5], [line_share[j] for j in s5])):
    side = 'left' if v < 0 else 'right'
    ax.text(v + (0.3 if v >= 0 else -0.3), i,
            f'{ss:.1f}% stmts / {ll:.1f}% lines', va='center', ha=side, fontsize=7.5)
p_terse = mpatches.Patch(color='#FF6B6B', label='Terse (more stmts per line)')
p_verbose = mpatches.Patch(color='#4ECDC4', label='Verbose (fewer stmts per line)')
ax.legend(handles=[p_terse, p_verbose], fontsize=9, loc='lower right')
ax.set_yticks(np.arange(len(sd))); ax.set_yticklabels(sl5, fontsize=10)
ax.set_xlabel('Statement share minus line share (percentage points)', fontsize=10)
ax.set_title('RQ2d: Which topics consist of terse directives vs. verbose descriptions?', fontsize=11, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(outdir, 'fig5_rq2d_stmt_vs_line.png'), dpi=150, bbox_inches='tight')
plt.close(); print('Fig 5')

# ===== Fig 6: RQ3 - Directives per repo =====
fig, ax = plt.subplots(figsize=(8, 5))
repo_stats.sort(key=lambda r: r['dir'], reverse=True)
dc = [r['dir'] for r in repo_stats]
ax.bar(range(15), dc[:15], color='#FF6B6B', edgecolor='white', label='Top 15 repos')
ax.bar(range(15, len(dc)), dc[15:], color='#CCCCCC', edgecolor='white', label='Remaining repos')
ax.axhline(y=np.median(dc), color='black', linestyle='--', linewidth=1.5,
           label=f'Median = {np.median(dc):.0f}')
top10 = sum(dc[:10]) / sum(dc) * 100
ax.text(len(dc) * 0.5, max(dc) * 0.85,
        f'Top 10 repos = {top10:.1f}% of all directives\nMedian = {np.median(dc):.0f}, Max = {max(dc)}',
        fontsize=9, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
ax.set_xlabel('Repositories (sorted by directive count)', fontsize=11)
ax.set_ylabel('Number of Directives', fontsize=11)
ax.set_title('RQ3: How are directives distributed across repositories?', fontsize=12, fontweight='bold')
ax.legend(fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(outdir, 'fig6_rq3_directive_density.png'), dpi=150, bbox_inches='tight')
plt.close(); print('Fig 6')

print('All 6 figures saved to docs/tmp/')
