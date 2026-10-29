"""Remove only the completed benchmark's reinstallable Python environment."""
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

root = Path('/workspaces/exp/benign-utility')
target = root / 'raw/benchmark/venv'
assert target.resolve() == target and target.is_dir()
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
receipt.update(status='removed', disk_free_after=shutil.disk_usage(root).free)
audit.write_text(json.dumps(receipt, indent=2))
with (out / 'runtime-cleanup.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(receipt))
    writer.writeheader()
    writer.writerow(receipt)
print(json.dumps(receipt))
