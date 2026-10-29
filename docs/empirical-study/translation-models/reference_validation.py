#!/usr/bin/env python3
"""Export reference/artifact agreement without assigning speculative causes."""
import csv
import json
from collections import defaultdict
from prepare import HERE, DEFAULT_RAW, csv_write


def main():
    path = HERE / 'replay-reference.csv'
    if not path.exists():
        return
    rows = list(csv.DictReader(path.open()))
    audit = []
    grouped = defaultdict(list)
    mismatches = []
    for r in rows:
        grouped[r['repo'], r['statement_id']].append(r)
        original_path = next((DEFAULT_RAW / 'artifact/docs/artifact/rq2-qwen-primary/results/actplane-opaque' / r['repo'] / r['statement_id'] / r['trace']).glob('*.json'))
        original = json.loads(original_path.read_text())
        trace_path = DEFAULT_RAW / 'artifact/docs/corpus-test' / r['repo'] / r['statement_id'] / r['trace']
        snapshot = [json.loads(line) for line in trace_path.read_text().splitlines()]
        old_tools = [t for t in original['tool_log'] if t.get('phase') == 'setup']
        tool_path = DEFAULT_RAW / 'replay/guest68-scored-v3/reference' / r['repo'] / r['statement_id'] / r['trace'] / 'tools.jsonl'
        new_tools = [json.loads(line) for line in tool_path.read_text().splitlines()] if tool_path.exists() else []
        audit.append(dict(repo=r['repo'], statement_id=r['statement_id'], trace=r['trace'], family=r['family'],
                          trace_snapshot_equal=int(original.get('trace_records_snapshot') == snapshot),
                          agreement=r['agreement'], artifact_tool_count=len(old_tools), replay_tool_count=len(new_tools),
                          artifact_nonzero_tools=sum(t.get('returncode', 0) != 0 for t in old_tools),
                          replay_nonzero_tools=sum(t.get('returncode', 0) != 0 for t in new_tools)))
        if r['status'] == 'ok' and r['agreement'] == '0':
            mismatches.append({k: r[k] for k in ('repo', 'statement_id', 'trace', 'family', 'violation',
                                                'artifact_fired', 'fired', 'tool_errors',
                                                'fixture_commit', 'loader_sha256', 'policy_sha256')})
    policies = []
    for key, part in sorted(grouped.items()):
        valid = [r for r in part if r['status'] == 'ok']
        policies.append(dict(repo=key[0], statement_id=key[1], traces=len(part), valid=len(valid),
                             agreements=sum(r['agreement'] == '1' for r in valid),
                             artifact_violations_detected=sum(r['violation'] == '1' and r['artifact_fired'] == '1' for r in valid),
                             replay_violations_detected=sum(r['violation'] == '1' and r['fired'] == '1' for r in valid),
                             artifact_false_triggers=sum(r['violation'] == '0' and r['artifact_fired'] == '1' for r in valid),
                             replay_false_triggers=sum(r['violation'] == '0' and r['fired'] == '1' for r in valid),
                             tool_error_traces=sum(int(r['tool_errors']) > 0 for r in valid)))
    csv_write(HERE / 'reference-validation-policies.csv', policies)
    csv_write(HERE / 'reference-execution-audit.csv', audit)
    csv_write(HERE / 'reference-validation-summary.csv', [dict(traces=len(audit),
              matching_trace_snapshots=sum(r['trace_snapshot_equal'] for r in audit),
              script_disagreements_old_nonzero_new_zero=sum(r['agreement'] == '0' and r['family'] == 'script_visible_violation' and r['artifact_nonzero_tools'] > 0 and r['replay_nonzero_tools'] == 0 for r in audit))])
    if mismatches:
        csv_write(HERE / 'reference-disagreements.csv', mismatches)


if __name__ == '__main__':
    main()
