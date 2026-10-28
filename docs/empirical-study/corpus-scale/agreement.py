#!/usr/bin/env python3
"""Describe intermodel agreement on analyzed source spans, without gold claims."""
from collections import defaultdict

from sklearn.metrics import cohen_kappa_score

from common import HERE, read_csv, write_csv


def main():
    if not (HERE / 'analysis_statements.csv').exists():
        return
    source = read_csv(HERE / 'analysis_statements.csv')
    primary = {name: {r['statement_id']: r for r in read_csv(HERE / ('labels_' + name + '.csv'))}
               for name in ['qwen', 'glm']}
    gates = {r['dimension'] for r in read_csv(HERE / 'calibration_gates.csv') if r['passed'] == 'True'}
    if (HERE / 'format_calibration_gates.csv').exists():
        gates &= {r['dimension'] for r in read_csv(HERE / 'format_calibration_gates.csv') if r['passed'] == 'True'}
    dimensions = sorted(gates)
    families = defaultdict(set)
    for f in read_csv(HERE / 'corpus_manifest.csv'):
        if f['status'] == 'included':
            families[(f['repo'], f['content_sha256'])].add(f['family'])
    categories = {r['repo']: r['category'] for r in read_csv(HERE / 'repository_categories.csv') if r['status'] == 'ok'}
    groups = defaultdict(list)
    for row in source:
        groups[('overall', 'all')].append(row)
        groups[('category', categories.get(row['repo'], 'unclassified'))].append(row)
        for family in families[(row['repo'], row['content_sha256'])]:
            groups[('family', family)].append(row)
    output = []
    for (group_type, group), rows in sorted(groups.items()):
        pairs = [(primary['qwen'].get(r['statement_id'], {}), primary['glm'].get(r['statement_id'], {})) for r in rows]
        pairs = [(left, right) for left, right in pairs if left.get('status') == right.get('status') == 'ok']
        for dim in [*dimensions, 'any_scaled_axis']:
            disagreement = sum(any(left.get(d, '') != right.get(d, '') for d in dimensions)
                               if dim == 'any_scaled_axis' else left.get(dim, '') != right.get(dim, '')
                               for left, right in pairs)
            kappa = ''
            if dim != 'any_scaled_axis' and pairs:
                left, right = [[pair[i].get(dim, '') or '__NA__' for pair in pairs] for i in [0, 1]]
                if len(set(left + right)) > 1:
                    kappa = float(cohen_kappa_score(left, right))
            output.append(dict(group_type=group_type, group=group, dimension=dim,
                eligible_statements=len(rows), paired_statements=len(pairs), missing_pairs=len(rows) - len(pairs),
                disagreements=disagreement, agreement=1 - disagreement / len(pairs) if pairs else '', kappa=kappa))
    write_csv(HERE / 'scaled_model_agreement.csv', output)


if __name__ == '__main__':
    main()
