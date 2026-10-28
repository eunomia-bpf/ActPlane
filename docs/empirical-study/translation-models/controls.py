#!/usr/bin/env python3
"""Require kernel positive controls before interpreting any negative replay."""
import argparse
import json
from pathlib import Path

from prepare import DEFAULT_RAW, HERE, csv_write
from replay import replay_one


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    ap.add_argument('--loader', type=Path)
    ap.add_argument('--tag', default='host19')
    args = ap.parse_args()
    statement = args.raw / 'control-input/fixture/rule'
    statement.mkdir(parents=True, exist_ok=True)
    repo = args.raw / 'repos/fixture'
    repo.mkdir(exist_ok=True)
    rows = []
    cases = [
        ('exec_positive', 'notify exec "true" if AGENT', 'Bash', {'command': '/bin/true'}),
        ('exec_unconditional', 'notify exec "true" if true', 'Bash', {'command': '/bin/true'}),
        ('write_positive', 'notify write file "*" if AGENT', 'Write', {'file_path': 'canary.txt', 'content': 'canary\n'}),
        ('write_negative', 'notify write file "*" if SECRET', 'Write', {'file_path': 'canary.txt', 'content': 'canary\n'}),
        ('suffix_positive', 'notify write file "**/*.txt" if AGENT', 'Write', {'file_path': 'canary.txt', 'content': 'canary\n'}),
        ('contains_positive', 'notify write file "protected/**" if AGENT', 'Write', {'file_path': 'protected/canary.txt', 'content': 'canary\n'}),
    ]
    for name, clause, tool, inp in cases:
        trace = statement / (name + '.jsonl')
        records = [{'type': 'ground_truth', 'violation': name != 'write_negative'},
                   {'type': 'assistant', 'content': [{'type': 'tool_use', 'name': tool, 'input': inp}]}]
        trace.write_text('\n'.join(map(json.dumps, records)) + '\n')
        policy = 'source AGENT = exec "**"\nrule control:\n ' + clause + '\n because "kernel replay control"'
        out = args.raw / 'controls' / args.tag / name
        row = replay_one(args.raw, statement, trace, 'control', policy, out, loader_bin=args.loader)
        row['expected_fired'] = int(name != 'write_negative')
        row['control_passed'] = int(row['status'] == 'ok' and row['fired'] == row['expected_fired'])
        rows.append(row)
        print(name, row['status'], row['fired'], row['control_passed'], flush=True)
    fields = sorted(set().union(*(r.keys() for r in rows)))
    csv_write(HERE / ('controls-' + args.tag + '.csv'), [{k: r.get(k, '') for k in fields} for r in rows])
    raise SystemExit(0 if all(r['control_passed'] for r in rows) else 1)


if __name__ == '__main__':
    main()
