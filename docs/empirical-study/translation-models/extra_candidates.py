#!/usr/bin/env python3
"""Recover extra source candidates for unresolved literal Edit preconditions."""
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

from prepare import DEFAULT_RAW, HERE, csv_write, sha


def main():
    raw = DEFAULT_RAW
    candidates = [
        ('yusufkaraaslan__Skill_Seekers', '4cd5140b56b44a42cc3c5be0a0c1ba81e20a4af1',
         'v3.6.0 release commit, matching the version literal in trace Edit inputs'),
        ('openclaw__openclaw', 'ecc5601b2a4cd4f3e32d862c2ae9aa7097f77bb8',
         'last upstream commit before 2026-05-30, intermediate source candidate'),
    ]
    rows = []
    for name, commit, basis in candidates:
        repo = name.replace('__', '/')
        url = f'https://codeload.github.com/{repo}/tar.gz/{commit}'
        archive = raw / 'downloads' / (name + '__' + commit + '.tar.gz')
        if not archive.exists():
            urllib.request.urlretrieve(url, archive)
        dest = raw / 'repository-candidates' / name / commit
        if not (dest / '.fixture-ready').exists():
            dest.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive) as t:
                for member in t.getmembers():
                    parts = Path(member.name).parts
                    if len(parts) < 2:
                        continue
                    member.name = str(Path(*parts[1:]))
                    t.extract(member, dest, filter='data')
            for cmd in [('git', 'init', '-q'), ('git', 'config', 'user.name', 'Eval'),
                        ('git', 'config', 'user.email', 'eval@example.invalid'),
                        ('git', 'config', 'commit.gpgsign', 'false'), ('git', 'add', '-A'),
                        ('git', 'commit', '-q', '--allow-empty', '-m', 'fixture snapshot')]:
                subprocess.run(cmd, cwd=dest, check=True, capture_output=True)
            (dest / '.fixture-ready').write_text(commit + '\n')
        rows.append(dict(repo=name, commit=commit, basis=basis, url=url, archive_sha256=sha(archive.read_bytes())))
    csv_write(HERE / 'extra-fixture-candidates.csv', rows)


if __name__ == '__main__':
    main()
