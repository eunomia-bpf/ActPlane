#!/usr/bin/env python3
"""Record immutable hashes of the previously accepted type/topic decisions."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import HERE, digest, read_csv, write_csv


def fingerprint(rows):
    values = sorted((r['statement_id'], r['type'], r['topic']) for r in rows)
    return digest(json.dumps(values, ensure_ascii=False, separators=(',', ':')))


def main():
    path = HERE / 'rescue/retained_axes.csv'
    rows = []
    for name in ['labels.csv', 'labels_qwen.csv', 'labels_glm.csv']:
        source = read_csv(HERE / name)
        rows.append(dict(source_file=name, rows=len(source),
                         type_topic_sha256=fingerprint(source)))
    if path.exists():
        assert read_csv(path) == [{k: str(v) for k, v in r.items()} for r in rows], 'Retained axes changed'
    else:
        assert not (HERE / 'rescue/deployment_gates.csv').exists(), 'Freeze axes before deployment'
        write_csv(path, rows)


if __name__ == '__main__':
    main()
