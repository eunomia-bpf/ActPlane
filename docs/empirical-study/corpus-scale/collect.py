#!/usr/bin/env python3
"""Dated, resumable repository snapshot. API requests are sequential and cached.

Sampling: union of listed searches (top 100 each), >=100 stars, pushed since
2025-01-01, non-fork, non-archived. Visit each discovery stratum in descending
stars/name order. Stop at its quota of repositories with an instruction file.
Search strata are discovery aids, not validated repository categories.
"""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import quote

import requests

from common import DEFAULT_RAW, HERE, GitHub, digest, log, now, write_csv

QUERIES = {
    'general': ['stars:>=100', 'topic:developer-tools stars:>=100',
                'topic:webapp stars:>=100', 'topic:database stars:>=100',
                'topic:devops stars:>=100', 'topic:machine-learning stars:>=100'],
    'agent': ['topic:ai-agent stars:>=100', 'topic:ai-agents stars:>=100',
              'topic:agent-framework stars:>=100', 'topic:coding-agent stars:>=100',
              'topic:llm-agent stars:>=100', 'topic:mcp stars:>=100'],
    'noncoding_discovery': ['personal assistant agent stars:>=100',
        'email agent stars:>=100', 'calendar assistant stars:>=100',
        'office agent stars:>=100', 'agent skills stars:>=100',
        'topic:browser-automation stars:>=100', 'research agent stars:>=100'],
}
QUOTAS = {'general': 200, 'agent': 75, 'noncoding_discovery': 50}


def family(path):
    name = path.rsplit('/', 1)[-1]
    if name in ('CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'SKILL.md', '.cursorrules', '.windsurfrules'):
        return name
    if path.endswith('.github/copilot-instructions.md'):
        return 'copilot-instructions.md'
    if re.search(r'(^|/)\.cursor/rules/[^/]+\.(md|mdc)$', path):
        return '.cursor/rules/*'
    return None


def priority(path):
    return (path.count('/'), len(path), path)


def run(a):
    a.raw.mkdir(parents=True, exist_ok=True)
    gh = GitHub(a.raw)
    candidates, searches = {}, []
    for stratum, queries in QUERIES.items():
        candidates[stratum] = {}
        for base in queries:
            q = base + ' pushed:>=2025-01-01 archived:false fork:false'
            data = gh.get('search/repositories', dict(q=q, sort='stars', order='desc', per_page=100))
            searches.append(dict(stratum=stratum, query=q, returned=len(data['items']),
                total_count=data['total_count'], incomplete_results=data.get('incomplete_results'),
                response_sha256=digest(json.dumps(data, sort_keys=True))))
            for item in data['items']:
                candidates[stratum][item['full_name']] = item
        print('candidates', stratum, len(candidates[stratum]), flush=True)
    write_csv(HERE / 'searches.csv', searches)
    manifest, repos, attempts, seen = [], [], [], set()
    for stratum, items in candidates.items():
        hits = 0
        quota = QUOTAS[stratum]
        for item in sorted(items.values(), key=lambda x: (-x['stargazers_count'], x['full_name'])):
            repo = item['full_name']
            if repo in seen:
                attempts.append(dict(repo=repo, stratum=stratum, status='overlap_previous_stratum'))
                continue
            seen.add(repo)
            record_path = a.raw / 'repositories' / (repo.replace('/', '__') + '.json')
            if record_path.exists():
                record = json.loads(record_path.read_text())
            else:
                record = dict(repo=repo, stratum=stratum, stars=item['stargazers_count'],
                    pushed_at=item['pushed_at'], language=item.get('language') or '',
                    description=item.get('description') or '', topics='|'.join(item.get('topics', [])),
                    default_branch=item['default_branch'], snapshot_at=now())
                try:
                    commit = gh.get(f'repos/{repo}/commits/{quote(item["default_branch"], safe="")}')
                    if not commit:
                        raise ValueError('no_head_commit')
                    record['commit'] = commit['sha']
                    tree = gh.get(f'repos/{repo}/git/trees/{commit["sha"]}', {'recursive': 1})
                    record['tree_truncated'] = tree.get('truncated', False)
                    found = [x for x in tree['tree'] if x['type'] == 'blob' and family(x['path'])]
                    record['discovered_files'] = len(found)
                    record['files'] = []
                    per_family = {}
                    for blob in sorted(found, key=lambda x: priority(x['path'])):
                        fam = family(blob['path'])
                        status = 'included'
                        # One representative path per family per repository, specified before labeling.
                        if per_family.get(fam, 0) >= a.paths_per_family:
                            status = 'path_sampling_cap'
                        elif blob.get('size', 0) > a.max_bytes:
                            status = 'file_over_size_cap'
                        else:
                            per_family[fam] = per_family.get(fam, 0) + 1
                        f = dict(repo=repo, commit=commit['sha'], file_path=blob['path'], family=fam,
                            blob_sha=blob['sha'], bytes=blob.get('size', ''), stars=record['stars'],
                            snapshot_at=record['snapshot_at'], status=status, content_sha256='',
                            duplicate_of='', raw_relpath='', stratum=stratum)
                        if status == 'included':
                            url = f'https://raw.githubusercontent.com/{repo}/{commit["sha"]}/{quote(blob["path"])}'
                            try:
                                response = requests.get(url, timeout=60)
                                response.raise_for_status()
                                content = response.content
                                sha = digest(content)
                                target = a.raw / 'files' / sha
                                target.parent.mkdir(parents=True, exist_ok=True)
                                target.write_bytes(content)
                                f.update(content_sha256=sha, raw_relpath=str(target.relative_to(a.raw)))
                                if b'\0' in content or not content.strip():
                                    f['status'] = 'empty_or_binary'
                            except requests.RequestException as e:
                                f.update(status='download_failed', error=type(e).__name__)
                            log(a.raw / 'downloads.jsonl', dict(at=now(), url=url, status=f['status']))
                        record['files'].append(f)
                    record['status'] = 'included' if any(f['status'] == 'included' for f in record['files']) else 'no_usable_instruction_file'
                except Exception as e:
                    record.update(status='repository_failed', error=type(e).__name__ + ':' + str(e)[:160], files=[])
                record_path.parent.mkdir(parents=True, exist_ok=True)
                record_path.write_text(json.dumps(record, ensure_ascii=False))
            attempts.append({k: v for k, v in record.items() if k not in ('files', 'description', 'topics')})
            if record['status'] == 'included':
                repos.append({k: v for k, v in record.items() if k != 'files'})
                manifest.extend(record['files'])
                hits += 1
            write_csv(HERE / 'repositories.csv', repos)
            write_csv(HERE / 'corpus_manifest.csv', manifest)
            write_csv(HERE / 'collection_attempts.csv', attempts)
            print(stratum, hits, '/', quota, repo, record['status'], flush=True)
            if hits >= quota:
                break
        print('stratum_finished', stratum, hits, flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    p.add_argument('--paths-per-family', type=int, default=1)
    p.add_argument('--max-bytes', type=int, default=128000)
    run(p.parse_args())
