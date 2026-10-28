#!/usr/bin/env python3
"""Export historical labels without checking out or modifying another branch."""
import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path

import yaml

from common import DEFAULT_RAW, HERE, digest, write_csv

COLLAPSE = {'Debugging': 'Development Process', 'Project Management': 'Development Process',
            'Performance': 'Implementation Details', 'UI/UX': 'Implementation Details'}


def git(*args):
    return subprocess.check_output(['git', *args])


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    p.add_argument('--ref', default='origin/artifact-ready')
    a = p.parse_args()
    dest = a.raw / 'original'
    dest.mkdir(parents=True, exist_ok=True)
    commit = git('rev-parse', a.ref).decode().strip()
    paths = git('ls-tree', '-r', '--name-only', a.ref, 'docs/corpus').decode().splitlines()
    rows, files, provenance = [], [], []
    for path in paths:
        if not (path.endswith('statements.yaml') or path.endswith('meta.json') or
                path.endswith('CLAUDE.md') or path.endswith('AGENTS.md')):
            continue
        content = git('show', f'{a.ref}:{path}')
        target = dest / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        provenance.append(dict(ref=a.ref, commit=commit, path=path, sha256=digest(content)))
    for path in sorted((dest / 'docs/corpus').glob('*/statements.yaml')):
        obj = yaml.safe_load(path.read_text())
        repo = path.parent.name.replace('__', '/')
        meta = json.loads((path.parent / 'meta.json').read_text())
        source = obj.get('file', '')
        files.append(dict(repo=repo, file=source, statements=len(obj['statements']),
                          stars=meta.get('stars', ''), artifact_commit=commit))
        for s in obj['statements']:
            start, end = s['lines']
            rows.append(dict(statement_id=f'paper:{repo}:{s["id"]}', repo=repo,
                file_path=source, family='AGENTS.md' if 'AGENTS.md' in source else 'CLAUDE.md',
                start_line=start, end_line=end, text=s['text'],
                type=s['type'], topic=COLLAPSE.get(s['topic'], s['topic']),
                enforceability=s.get('enforceability') or '',
                context_required=s.get('context_required') or ''))
    write_csv(HERE / 'paper_labels.csv', rows)
    write_csv(HERE / 'paper_files.csv', files)
    write_csv(HERE / 'paper_provenance.csv', provenance)
    # Rounded claims are retained independently from recomputed artifact counts.
    claims = [('repositories', 64, ''), ('instruction_files', 84, ''),
              ('statements', 2116, ''), ('median_stars', 20000, 'rounded'),
              ('policy_fraction', .64, 'rounded'), ('system_state_fraction', .83, 'rounded'),
              ('context_required_fraction', .74, 'rounded'),
              ('cross_event_project_share', .81, 'rounded'), ('os_enforceable_count', 607, '')]
    write_csv(HERE / 'paper_claims.csv', [dict(metric=k, value=v, note=n,
        source='actplane-atc/main:sections/02-motivation.tex (retrieved 2026-10-28); operator brief for OS count')
        for k, v, n in claims])
    substantive = []
    redirects = 0
    for r in files:
        seen = set()
        for path in (dest / 'docs/corpus' / r['repo'].replace('/', '__')).glob('*.md'):
            content = path.read_bytes()
            if content.strip() in (b'@AGENTS.md', b'@CLAUDE.md'):
                redirects += 1
                continue
            if content not in seen:
                seen.add(content)
                substantive.append(content)
    audit = dict(label_files=len(files), labeled_statements=len(rows),
        referenced_source_files=len({r['file_path'] for r in rows}),
        labeled_span_lines=sum(int(r['end_line']) - int(r['start_line']) for r in rows),
        pure_at_redirect_files=redirects, unique_non_redirect_files=len(substantive),
        unique_non_redirect_lines=sum(len(b.splitlines()) for b in substantive),
        unique_non_redirect_bytes=sum(map(len, substantive)),
        raw_instruction_files=sum(len(list((dest / 'docs/corpus' / r['repo'].replace('/', '__')).glob('*.md'))) for r in files),
        raw_unique_contents_within_repo=sum(len({p.read_bytes() for p in
            (dest / 'docs/corpus' / r['repo'].replace('/', '__')).glob('*.md')}) for r in files))
    write_csv(HERE / 'paper_audit.csv', [audit])
    print(dict(repositories=len(files), statements=len(rows), types=dict(Counter(r['type'] for r in rows))))


if __name__ == '__main__':
    main()
