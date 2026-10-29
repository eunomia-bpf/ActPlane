#!/usr/bin/env python3
"""Render historical-data smoke tests outside git and verify font/gate behavior."""
import argparse
import re
from pathlib import Path

from common import DEFAULT_RAW, HERE, read_csv, write_csv
import figures


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    a = p.parse_args()
    results = []
    original_save = figures.save
    def save_preview(fig, name):
        figures.OUT.mkdir(parents=True, exist_ok=True)
        fig.savefig(figures.OUT / (name + '.png'), dpi=120, bbox_inches='tight')
        original_save(fig, name)
    figures.save = save_preview
    for mode in ['all_dimensions', 'type_only']:
        root = a.raw / 'figure-smoke' / mode
        root.mkdir(parents=True, exist_ok=True)
        write_csv(root / 'analysis_statements.csv', read_csv(HERE / 'paper_labels.csv'))
        gates = [dict(dimension=d, passed=(mode == 'all_dimensions' or d == 'type'))
                 for d in ['type', 'topic', 'enforceability', 'context_required']]
        write_csv(root / 'calibration_gates.csv', gates)
        figures.HERE, figures.OUT, figures.DATA = root, root / 'figures', []
        figures.main()
        pdfs = list((root / 'figures').glob('*.pdf'))
        type3 = sum(len(re.findall(rb'/Subtype\s*/Type3\b', path.read_bytes())) for path in pdfs)
        withheld = sum(r['group'] == 'withheld' for r in figures.DATA)
        results.extend([dict(mode=mode, check='pdf_count', expected=6, actual=len(pdfs)),
                        dict(mode=mode, check='type3_fonts', expected=0, actual=type3),
                        dict(mode=mode, check='withheld_count', expected=0 if mode == 'all_dimensions' else 5, actual=withheld)])
    for r in results:
        r['passed'] = r['expected'] == r['actual']
    write_csv(HERE / 'figure_validation.csv', results)
    if not all(r['passed'] for r in results):
        raise SystemExit('Figure validation failed')
    print(results)


if __name__ == '__main__':
    main()
