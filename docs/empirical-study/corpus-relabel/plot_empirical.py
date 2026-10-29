#!/usr/bin/env python3
"""Generate all empirical-study figures as PDF for the paper.

Usage:
    cd docs/corpus && python3 ../papers/scripts/plot_empirical.py

Output: docs/papers/figures/empirical_*.pdf, cumulative_coverage.pdf,
        repo_requirements.pdf
"""
import yaml, os, collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ---------- global style ----------
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': 13,
    'axes.titlesize': 14,
    'axes.labelsize': 13,
    'xtick.labelsize': 12,
    'ytick.labelsize': 12,
    'legend.fontsize': 11,
    'figure.dpi': 300,
    'pdf.fonttype': 42,
    'ps.fonttype': 42,
})

OUTDIR = os.path.join(os.path.dirname(__file__), 'figures')

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

ENF_LEVELS = ['semantic_only', 'content', 'per_event', 'cross_event']
ENF_LABELS = ['Semantic-only', 'Content', 'Per-event', 'Cross-event']
ENF_COLORS = ['#95A5A6', '#3498DB', '#2ECC71', '#E74C3C']

CTX_LEVELS = ['none', 'project', 'task']
CTX_LABELS = ['None', 'Project', 'Task']
CTX_COLORS = ['#2ECC71', '#3498DB', '#E74C3C']

# ---------- collect data ----------
desc_by = collections.Counter()
dir_by = collections.Counter()
repo_stats = []
enf_total = collections.Counter()
enf_by_topic = {t: collections.Counter() for t in TOPIC_ORDER}
repo_enf = []
ctx_total = collections.Counter()
ctx_by_enf = {e: collections.Counter() for e in ['content', 'per_event', 'cross_event']}

for d in sorted(os.listdir('.')):
    yf = os.path.join(d, 'statements.yaml')
    if not os.path.isfile(yf):
        continue
    with open(yf) as f:
        data = yaml.safe_load(f)
    if not data or 'statements' not in data:
        continue
    stmts = data['statements']
    r_desc = r_dir = 0
    r_enf = collections.Counter()
    for s in stmts:
        topic = COLLAPSE.get(s.get('topic', ''), s.get('topic', ''))
        if s.get('type') == 'description':
            desc_by[topic] += 1
            r_desc += 1
        else:
            dir_by[topic] += 1
            r_dir += 1
            e = s.get('enforceability')
            if e in ENF_LEVELS:
                enf_by_topic[topic][e] += 1
                enf_total[e] += 1
                r_enf[e] += 1
            if e in ('content', 'per_event', 'cross_event'):
                cr = s.get('context_required', '')
                if cr in CTX_LEVELS:
                    ctx_total[cr] += 1
                    ctx_by_enf[e][cr] += 1
    repo_stats.append({
        'repo': d.replace('__', '/'),
        'desc': r_desc, 'dir': r_dir,
        'total': len(stmts),
        'dir_pct': 100 * r_dir / len(stmts) if stmts else 0,
    })
    r_dir_total = sum(r_enf.values())
    repo_enf.append({
        'repo': d.replace('__', '/'),
        'total': r_dir_total,
        **{e: r_enf[e] for e in ENF_LEVELS},
    })

topics = TOPIC_ORDER
labels = [SHORT.get(t, t) for t in topics]
desc = np.array([desc_by[t] for t in topics])
dire = np.array([dir_by[t] for t in topics])
total = desc + dire
total_dir = sum(enf_total.values())
total_sys = sum(ctx_total.values())

# ===== Fig: E-RQ1 — Per-repo policy fraction =====
fig, ax = plt.subplots(figsize=(7, 4))
dir_pcts = sorted([r['dir_pct'] for r in repo_stats])
colors = ['#FF6B6B' if p >= 50 else '#4ECDC4' for p in dir_pcts]
ax.bar(range(len(dir_pcts)), dir_pcts, color=colors, width=1.0, edgecolor='none')
ax.axhline(y=np.median(dir_pcts), color='black', linestyle='--', linewidth=1.5,
           label=f'Median = {np.median(dir_pcts):.1f}%')
ax.axhline(y=50, color='gray', linestyle=':', linewidth=1, alpha=0.5)
p_dir = mpatches.Patch(color='#FF6B6B', label='Majority policy (>50%)')
p_desc = mpatches.Patch(color='#4ECDC4', label='Majority description (<50%)')
ax.legend(handles=[p_dir, p_desc, ax.get_lines()[0]], loc='upper left')
ax.set_xlabel('Repositories (sorted by policy fraction)')
ax.set_ylabel('Policy Fraction (%)')
ax.set_ylim(0, 105)
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR, 'empirical_rq1_policy_fraction.pdf'),
            bbox_inches='tight')
plt.close()
print('E-RQ1: policy fraction')

# ===== Fig: E-RQ2 — Policy ratio by topic =====
fig, ax = plt.subplots(figsize=(7, 4.5))
y = np.arange(len(topics))
dir_ratio = np.array([100 * d / t if t > 0 else 0 for d, t in zip(dire, total)])
si = np.argsort(dir_ratio)
sr = dir_ratio[si]
sl = [labels[i] for i in si]
colors3 = ['#FF6B6B' if p > 70 else '#FFD93D' if p > 40 else '#4ECDC4' for p in sr]
ax.barh(y, sr, color=colors3, edgecolor='white', linewidth=0.5)
avg_line = ax.axvline(x=100 * sum(dire) / sum(total), color='black',
                      linestyle='--', linewidth=1.5)
for i, (v, t) in enumerate(zip(sr, [total[j] for j in si])):
    ax.text(v + 1, i, f'{v:.0f}% (n={t})', va='center', fontsize=11)
p_high = mpatches.Patch(color='#FF6B6B', label='Policy-dominant (>70%)')
p_mid = mpatches.Patch(color='#FFD93D', label='Mixed (40–70%)')
p_low = mpatches.Patch(color='#4ECDC4', label='Description-dominant (<40%)')
ax.legend(handles=[p_high, p_mid, p_low, avg_line], labels=[
    'Policy-dominant (>70%)', 'Mixed (40–70%)', 'Description-dominant (<40%)',
    f'Overall avg ({100 * sum(dire) / sum(total):.1f}%)'],
    loc='lower right')
ax.set_yticks(y)
ax.set_yticklabels(sl)
ax.set_xlabel('Policy Ratio (%)')
ax.set_xlim(0, 105)
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR, 'empirical_rq2_policy_ratio.pdf'),
            bbox_inches='tight')
plt.close()
print('E-RQ2: policy ratio by topic')

# ===== Fig: E-RQ3 — Enforcement profile by topic (normalized) =====
fig, ax = plt.subplots(figsize=(7, 4.5))
y3 = np.arange(len(topics))
# Sort topics by cross-event fraction descending
totals_topic = np.array([sum(enf_by_topic[t].values()) for t in topics])
cross_frac = np.array([
    100 * enf_by_topic[t]['cross_event'] / sum(enf_by_topic[t].values())
    if sum(enf_by_topic[t].values()) > 0 else 0
    for t in topics
])
si = np.argsort(cross_frac)
sorted_topics = [topics[i] for i in si]
sorted_labels = [SHORT.get(t, t) for t in sorted_topics]
left3 = np.zeros(len(topics))
for ei, e in enumerate(ENF_LEVELS):
    vals = np.array([enf_by_topic[t][e] for t in sorted_topics])
    tots = np.array([sum(enf_by_topic[t].values()) for t in sorted_topics])
    pct_vals = np.where(tots > 0, 100 * vals / tots, 0)
    ax.barh(y3, pct_vals, left=left3, color=ENF_COLORS[ei],
            label=ENF_LABELS[ei], edgecolor='white', linewidth=0.5)
    left3 += pct_vals
ax.set_yticks(y3)
ax.set_yticklabels(sorted_labels)
ax.set_xlabel('Percentage (%)')
ax.set_xlim(0, 105)
ax.legend(loc='lower right')
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR, 'empirical_rq3_enforcement_by_topic.pdf'),
            bbox_inches='tight')
plt.close()
print('E-RQ3: enforcement profile by topic')

# ===== Fig: E-RQ4 — Context requirement by enforcement level =====
fig, ax = plt.subplots(figsize=(6, 3.5))
enf_keys = ['content', 'per_event', 'cross_event']
enf_labels_short = ['Content', 'Per-event', 'Cross-event']
y4 = np.arange(len(enf_keys))
left4 = np.zeros(len(enf_keys))
for ci, c in enumerate(CTX_LEVELS):
    vals = np.array([ctx_by_enf[e][c] for e in enf_keys])
    totals_enf = np.array([sum(ctx_by_enf[e].values()) for e in enf_keys])
    pct_vals = np.where(totals_enf > 0, 100 * vals / totals_enf, 0)
    bars = ax.barh(y4, pct_vals, left=left4, color=CTX_COLORS[ci],
                   label=CTX_LABELS[ci], edgecolor='white', linewidth=0.5)
    for i, (pv, lf) in enumerate(zip(pct_vals, left4)):
        if pv > 8:
            ax.text(lf + pv / 2, i, f'{pv:.0f}%', ha='center', va='center',
                    fontsize=11, fontweight='bold', color='white')
    left4 += pct_vals
ax.set_yticks(y4)
ax.set_yticklabels(enf_labels_short)
ax.set_xlabel('Percentage (%)')
ax.set_xlim(0, 105)
ax.legend(loc='lower right')
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR, 'empirical_rq4_context_by_enforcement.pdf'),
            bbox_inches='tight')
plt.close()
print('E-RQ4: context by enforcement level')

print(f'\nAll figures saved to {os.path.abspath(OUTDIR)}/')
