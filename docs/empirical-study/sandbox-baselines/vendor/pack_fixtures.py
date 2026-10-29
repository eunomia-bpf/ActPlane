#!/usr/bin/env python3
"""Pack the exact selected fixture snapshots for fast guest-local extraction."""
import json
import subprocess
from prepare import DEFAULT_RAW, HERE, csv_write, sha


def archive_path(source, raw=DEFAULT_RAW):
    return raw / 'fixture-packs' / (sha(str(source.resolve()).encode()) + '.tar.gz')


def main():
    rows = []
    for link in sorted((DEFAULT_RAW / 'selected-rule-fixtures').glob('*/*')):
        source = link.resolve()
        archive = archive_path(source)
        archive.parent.mkdir(exist_ok=True)
        if not archive.exists():
            subprocess.run(['tar', '--sort=name', '-czf', str(archive), '-C', str(source), '.'], check=True)
        rows.append(dict(repo=link.parent.name, statement_id=link.name,
                         fixture_commit=(source / '.fixture-ready').read_text().strip(),
                         archive=archive.name, archive_sha256=sha(archive.read_bytes()),
                         archive_bytes=archive.stat().st_size))
    csv_write(HERE / 'fixture-packs.csv', rows)
    print('Packed selected fixture snapshots', flush=True)


if __name__ == '__main__':
    main()
