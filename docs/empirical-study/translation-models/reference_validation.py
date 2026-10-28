#!/usr/bin/env python3
"""Export reference/artifact agreement without assigning speculative causes."""
import csv
from collections import defaultdict
from prepare import HERE, csv_write


def main():
    path = HERE / 'replay-reference.csv'
    if not path.exists():
        return
    rows = list(csv.DictReader(path.open()))
    grouped = defaultdict(list)
    mismatches = []
    for r in rows:
        grouped[r['repo'], r['statement_id']].append(r)
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
    if mismatches:
        csv_write(HERE / 'reference-disagreements.csv', mismatches)


if __name__ == '__main__':
    main()
