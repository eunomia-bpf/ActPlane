#!/usr/bin/env python3
"""Expose reference prediction changes between schema-repair implementations."""
from common import HERE, read_csv, write_csv


def main():
    dimensions = [r['dimension'] for r in read_csv(HERE / 'format_calibration_gates.csv')]
    output = []
    for model in ['qwen', 'glm', 'adjudicated']:
        old = {r['statement_id']: r for r in read_csv(HERE / 'calibration-v2' / ('format_calibration_' + model + '.csv'))}
        new = {r['statement_id']: r for r in read_csv(HERE / ('format_calibration_' + model + '.csv'))}
        pairs = [(row, new[sid]) for sid, row in old.items()
                 if row.get('status') == new.get(sid, {}).get('status') == 'ok']
        for dimension in dimensions:
            output.append(dict(model=model, dimension=dimension,
                old_statements=len(old), new_statements=len(new), paired_successful=len(pairs),
                changed_values=sum(left.get(dimension, '') != right.get(dimension, '') for left, right in pairs)))
    write_csv(HERE / 'calibration_protocol_comparison.csv', output)


if __name__ == '__main__':
    main()
