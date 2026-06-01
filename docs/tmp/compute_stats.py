#!/usr/bin/env python3
"""Compute all empirical study statistics from corpus YAML files.

Usage: cd docs/corpus && python3 ../tmp/compute_stats.py
"""
import yaml, glob, collections

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
ENF_LEVELS = ['semantic_only', 'content', 'per_event', 'cross_event']
CTX_LEVELS = ['none', 'project', 'task']

all_stmts = []
repo_stats = []

for d in sorted(glob.glob('*/statements.yaml')):
    repo = d.split('/')[0]
    data = yaml.safe_load(open(d))
    if not data or 'statements' not in data: continue
    stmts = data['statements']
    for s in stmts:
        s['_repo'] = repo
        s['_topic'] = COLLAPSE.get(s.get('topic',''), s.get('topic',''))
        s['_span'] = s['lines'][1] - s['lines'][0] if len(s.get('lines',[])) == 2 else 0
    all_stmts.extend(stmts)
    r_desc = sum(1 for s in stmts if s.get('type') == 'description')
    r_dir = sum(1 for s in stmts if s.get('type') == 'directive')
    dl = sum(s['_span'] for s in stmts if s.get('type') == 'directive')
    sl = sum(s['_span'] for s in stmts if s.get('type') == 'description')
    repo_stats.append({
        'repo': repo.replace('__','/'), 'desc': r_desc, 'dir': r_dir,
        'total': len(stmts), 'dir_pct': 100*r_dir/len(stmts) if stmts else 0,
        'dir_lines': dl, 'desc_lines': sl, 'total_lines': dl+sl,
    })

total_stmts = len(all_stmts)
descs = [s for s in all_stmts if s.get('type') == 'description']
dirs = [s for s in all_stmts if s.get('type') == 'directive']
n_desc = len(descs)
n_dir = len(dirs)

print("=" * 60)
print("EMPIRICAL STUDY — ALL COMPUTED VALUES")
print("=" * 60)

print(f"\n### RQ1: Content Types")
print(f"Total statements: {total_stmts}")
print(f"Description: {n_desc} ({100*n_desc/total_stmts:.1f}%)")
print(f"Directive: {n_dir} ({100*n_dir/total_stmts:.1f}%)")
dir_pcts = sorted([r['dir_pct'] for r in repo_stats])
print(f"Per-repo directive fraction (median): {dir_pcts[len(dir_pcts)//2]:.1f}%")
print(f"Directives per repo (median/mean): {sorted([r['dir'] for r in repo_stats])[len(repo_stats)//2]} / {sum(r['dir'] for r in repo_stats)/len(repo_stats):.1f}")
print(f"Stmts per repo (median/mean): {sorted([r['total'] for r in repo_stats])[len(repo_stats)//2]} / {sum(r['total'] for r in repo_stats)/len(repo_stats):.1f}")

total_lines = sum(r['total_lines'] for r in repo_stats)
dir_lines = sum(r['dir_lines'] for r in repo_stats)
desc_lines = sum(r['desc_lines'] for r in repo_stats)
print(f"By lines: dir={dir_lines} ({100*dir_lines/total_lines:.1f}%), desc={desc_lines} ({100*desc_lines/total_lines:.1f}%)")
print(f"Avg lines: dir={dir_lines/n_dir:.1f}, desc={desc_lines/n_desc:.1f}")

print(f"\n### RQ4: Enforcement Level")
enf_counts = collections.Counter(s.get('enforceability') for s in dirs if s.get('enforceability') in ENF_LEVELS)
sys_total = sum(enf_counts[e] for e in ['content','per_event','cross_event'])
for e in ENF_LEVELS:
    print(f"  {e}: {enf_counts[e]} ({100*enf_counts[e]/n_dir:.1f}%)")
print(f"  System-enforceable: {sys_total} ({100*sys_total/n_dir:.1f}%)")

print(f"\n### RQ6: Context Requirement")
sys_dirs = [s for s in dirs if s.get('enforceability') in ('content','per_event','cross_event')]
ctx_counts = collections.Counter(s.get('context_required') for s in sys_dirs)
sys_n = len(sys_dirs)
print(f"System-level: {sys_n}")
for c in CTX_LEVELS:
    print(f"  {c}: {ctx_counts[c]} ({100*ctx_counts[c]/sys_n:.1f}%)")
print(f"  Needs context: {ctx_counts['project']+ctx_counts['task']} ({100*(ctx_counts['project']+ctx_counts['task'])/sys_n:.1f}%)")

print(f"\nContext x Enforcement:")
for e in ['content','per_event','cross_event']:
    e_dirs = [s for s in sys_dirs if s.get('enforceability') == e]
    et = len(e_dirs)
    nn = sum(1 for s in e_dirs if s.get('context_required') == 'none')
    pp = sum(1 for s in e_dirs if s.get('context_required') == 'project')
    tt = sum(1 for s in e_dirs if s.get('context_required') == 'task')
    print(f"  {e:15s} none={nn}({100*nn/et:.1f}%) project={pp}({100*pp/et:.1f}%) task={tt}({100*tt/et:.1f}%) total={et}")
