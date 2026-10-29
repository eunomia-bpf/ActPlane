#!/usr/bin/env python3
"""Compare both supplied historical references without checking either out."""
import subprocess

import yaml

from common import HERE, digest, write_csv


def git(*args):
    return subprocess.check_output(['git', *args])


def main():
    output = []
    for ref in ['origin/artifact-ready', 'origin/backup/2026-06-14-master']:
        paths = git('ls-tree', '-r', '--name-only', ref, 'docs/corpus').decode().splitlines()
        paths = sorted(p for p in paths if p.endswith('/statements.yaml'))
        rows, identity = [], bytearray()
        for path in paths:
            content = git('show', ref + ':' + path)
            identity.extend(path.encode() + b'\0' + content + b'\0')
            data = yaml.safe_load(content)
            rows.extend(dict(r, _repo=path.split('/')[2]) for r in data['statements'])
        policies = [r for r in rows if r['type'] == 'directive']
        system = [r for r in policies if r.get('enforceability') in ['content', 'per_event', 'cross_event']]
        output.append(dict(ref=ref, commit=git('rev-parse', ref).decode().strip(),
            annotation_sha256=digest(bytes(identity)), repositories=len(paths), statements=len(rows),
            policies=len(policies), system_observable=len(system),
            context_required=sum(r.get('context_required') in ['project', 'task'] for r in system),
            os_tier=sum(r.get('enforceability') in ['per_event', 'cross_event'] for r in policies),
            cross_event_repositories=len({r['_repo'] for r in policies if r.get('enforceability') == 'cross_event'})))
    write_csv(HERE / 'historical_reference_comparison.csv', output)
    print(output)


if __name__ == '__main__':
    main()
