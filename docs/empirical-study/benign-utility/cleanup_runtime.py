"""Reclaim closed dependency payloads while preserving cited evidence bytes."""
import csv
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('--restore-cited-source', action='store_true')
parser.add_argument('--replay-archives', action='store_true')
args = parser.parse_args()

root = Path('/workspaces/exp/benign-utility')
if args.replay_archives:
    subprocess.run([sys.executable, 'replay/preserve_audit_sources.py', '--verify-only'], check=True)
    rows = []
    out = root / 'results/replay-runtime-cleanup.csv'
    for archive in sorted((root / 'raw/replay/open-audit-block-broad/dynamic/runs').glob('t*/runtime*.tar.gz')):
        run = archive.parent
        assert archive.resolve().is_relative_to(root / 'raw/replay/open-audit-block-broad/dynamic/runs')
        assert (run / 'done.json').exists() and (run / 'retained-audit-source-manifest.json').exists()
        digest = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
        row = dict(utc=datetime.now(timezone.utc).isoformat(), path=str(archive),
                   bytes=archive.stat().st_size, sha256=digest, archive_retained_now=True,
                   reason='Closed recreated dependency/repository/cache payload; cited candidate bytes preserved in path-hash manifests and verified by preserve_audit_sources.py --verify-only',
                   retained_manifest=str(run / 'retained-audit-source-manifest.json'),
                   disk_free_before=shutil.disk_usage(root).free, disk_free_after='')
        rows.append(row)
        with out.open('w', newline='') as stream:
            writer=csv.DictWriter(stream, fieldnames=list(row)); writer.writeheader(); writer.writerows(rows)
        archive.unlink()
        row.update(archive_retained_now=False, disk_free_after=shutil.disk_usage(root).free)
        with out.open('w', newline='') as stream:
            writer=csv.DictWriter(stream, fieldnames=list(row)); writer.writeheader(); writer.writerows(rows)
        print(json.dumps(row), flush=True)
    raise SystemExit
target = root / 'raw/benchmark/venv'
assert target.resolve() == target
source_relative = 'lib/python3.13/site-packages/harbor/metrics/base.py'
source_path = target / source_relative
expected = '373de596'
audit_rows = list(csv.DictReader((root / 'benchmark/results/error-audit.csv').open()))
# The exact full hash is recorded beside the original native metric-source path.
hashes = [value for row in audit_rows for value in row.values()
          if value.startswith(expected) and len(value) == 64]
assert len(set(hashes)) == 1, hashes
expected = hashes[0]
if source_path.exists():
    source_bytes = source_path.read_bytes()
else:
    release = json.load(urllib.request.urlopen('https://pypi.org/pypi/harbor/0.25.0/json'))
    wheel = next(item for item in release['urls'] if item['packagetype'] == 'bdist_wheel')
    payload = urllib.request.urlopen(wheel['url']).read()
    assert hashlib.sha256(payload).hexdigest() == wheel['digests']['sha256']
    source_bytes = zipfile.ZipFile(io.BytesIO(payload)).read('harbor/metrics/base.py')
assert hashlib.sha256(source_bytes).hexdigest() == expected
if args.restore_cited_source:
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(source_bytes)
    audit = root / 'results/runtime-cleanup.json'
    receipt = json.loads(audit.read_text())
    receipt.update(preserved_cited_source=str(source_path), preserved_cited_source_sha256=expected,
                   source_restored_utc=datetime.now(timezone.utc).isoformat())
    audit.write_text(json.dumps(receipt, indent=2))
    with (root / 'results/runtime-cleanup.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(receipt))
        writer.writeheader()
        writer.writerow(receipt)
    print(json.dumps(dict(restored_path=str(source_path), sha256=expected,
                         verification='matches original error-audit.csv metric source hash')))
    raise SystemExit
before = shutil.disk_usage(root)
files = sum(1 for p in target.rglob('*') if p.is_file())
size = sum(p.stat().st_size for p in target.rglob('*') if p.is_file())
reason = ('Completed benchmark Python dependency environment; reinstall with benchmark/setup.sh. '
          'No job directories, task outputs, engine binaries, logs or result exports removed.')
receipt = dict(utc=datetime.now(timezone.utc).isoformat(), path=str(target),
               logical_bytes=size, files=files, reason=reason,
               disk_free_before=before.free, status='planned')
out = root / 'results'
out.mkdir(exist_ok=True)
audit = out / 'runtime-cleanup.json'
audit.write_text(json.dumps(receipt, indent=2))
shutil.rmtree(target)
source_path.parent.mkdir(parents=True, exist_ok=True)
source_path.write_bytes(source_bytes)
receipt.update(status='removed', disk_free_after=shutil.disk_usage(root).free)
receipt.update(preserved_cited_source=str(source_path), preserved_cited_source_sha256=expected)
audit.write_text(json.dumps(receipt, indent=2))
with (out / 'runtime-cleanup.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(receipt))
    writer.writeheader()
    writer.writerow(receipt)
print(json.dumps(receipt))
