#!/usr/bin/env python3
"""Export frozen inputs and recover repository fixtures without changing a checkout."""
import argparse
import concurrent.futures
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import os
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEFAULT_RAW = Path('/workspaces/.agent-state/actplane-research/raw/translation-models-20261028')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def csv_write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', newline='', dir=path.parent, delete=False, suffix='.csv.tmp') as f:
        temporary = f.name
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        w.writeheader()
        w.writerows(rows)
    os.replace(temporary, path)


def export(raw, ref):
    dest = raw / 'artifact'
    dest.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(['git', 'rev-parse', ref], cwd=ROOT, text=True).strip()
    paths = ['docs/corpus-test', 'docs/corpus', 'docs/corpus-raw-full',
             'docs/eval_scripts', 'docs/artifact/rq2-qwen-primary',
             'docs/eval_runs/rq1-expressiveness/full-607-subagents',
             'docs/rq1-expressiveness/run_study.py']
    archive = subprocess.check_output(['git', 'archive', commit, *paths], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive)) as t:
        t.extractall(dest, filter='data')
    dsl = subprocess.check_output(['git', 'show', 'origin/master:docs/rule-language.md'], cwd=ROOT)
    (raw / 'dsl-reference.md').write_bytes(dsl)
    metadata = dict(artifact_commit=commit,
                    compiler_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    dsl_ref='origin/master:docs/rule-language.md', dsl_sha256=sha(dsl),
                    artifact_dsl_sha256=sha(subprocess.check_output(['git', 'show', commit + ':docs/rule-language.md'], cwd=ROOT)))
    (raw / 'provenance.json').write_text(json.dumps(metadata, indent=2) + '\n')
    return dest


def recover_repo(item):
    raw, docs, name, as_of = item
    meta_path = docs / 'corpus' / name / 'meta.json'
    if not meta_path.exists():
        meta_path = docs / 'corpus-raw-full' / name / 'meta.json'
    meta = json.loads(meta_path.read_text())
    # The original evaluated repo/ directories were not committed. Choose the
    # newest *recorded* instruction-file commit, never a moving default branch.
    evidence = max(meta['files'], key=lambda f: f.get('last_commit_date', ''))
    commit = evidence['last_commit_sha']
    basis = 'latest recorded instruction-file commit'
    if as_of:
        query = f"https://api.github.com/repos/{meta['repo']}/commits?until={as_of}&per_page=1"
        req = urllib.request.Request(query, headers={'User-Agent': 'ActPlane-translation-study'})
        with urllib.request.urlopen(req, timeout=60) as r:
            history = json.load(r)
        commit = history[0]['sha']
        basis = f'last upstream commit before {as_of}; original evaluated SHA unavailable'
        (raw / 'downloads').mkdir(exist_ok=True)
        (raw / 'downloads' / (name + '-commit.json')).write_text(json.dumps(history, indent=2) + '\n')
    url = f"https://codeload.github.com/{meta['repo']}/tar.gz/{commit}"
    archive = raw / 'downloads' / (name + ('__' + commit if as_of else '') + '.tar.gz')
    dest = raw / 'repos' / name
    result = dict(repo=name, commit=commit, commit_basis=basis,
                  url=url, archive_sha256='', archive_bytes='', status='ok', error='')
    try:
        archive.parent.mkdir(parents=True, exist_ok=True)
        if (dest / '.fixture-ready').exists() and (dest / '.fixture-ready').read_text().strip() != commit:
            previous = (dest / '.fixture-ready').read_text().strip()
            saved = raw / 'previous-fixtures' / name / previous
            saved.parent.mkdir(parents=True, exist_ok=True)
            dest.rename(saved)
        if not archive.exists():
            req = urllib.request.Request(url, headers={'User-Agent': 'ActPlane-translation-study'})
            with urllib.request.urlopen(req, timeout=240) as r:
                data = r.read()
            archive.write_bytes(data)
        result.update(archive_sha256=sha(archive.read_bytes()), archive_bytes=archive.stat().st_size)
        if not (dest / '.fixture-ready').exists():
            dest.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    parts = Path(m.name).parts
                    if len(parts) < 2:
                        continue
                    m.name = str(Path(*parts[1:]))
                    t.extract(m, dest, filter='data')
            # Isolated Git metadata supports trace-local add/commit/diff. No
            # upstream remotes or hooks are installed.
            for cmd in [('git', 'init', '-q'), ('git', 'config', 'user.name', 'Eval'),
                        ('git', 'config', 'user.email', 'eval@example.invalid'),
                        ('git', 'config', 'commit.gpgsign', 'false'),
                        ('git', 'add', '-A'), ('git', 'commit', '-q', '--allow-empty', '-m', 'fixture snapshot')]:
                run(*cmd, cwd=dest, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            (dest / '.fixture-ready').write_text(commit + '\n')
    except Exception as e:
        result.update(status='error', error=f'{type(e).__name__}: {e}')
    print(name, result['status'], flush=True)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    ap.add_argument('--ref', default='origin/artifact-ready')
    ap.add_argument('--export-only', action='store_true')
    ap.add_argument('--as-of', help='Recover the last source commit before a fixed UTC timestamp')
    args = ap.parse_args()
    docs = export(args.raw, args.ref) / 'docs'
    if args.export_only:
        return
    names = sorted({p.parent.parent.name for p in (docs / 'corpus-test').glob('*/*/statement.json')})
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(recover_repo, [(args.raw, docs, n, args.as_of) for n in names]))
    csv_write(HERE / 'repository-fixtures.csv', rows)


if __name__ == '__main__':
    main()
