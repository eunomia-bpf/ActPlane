#!/usr/bin/env python3
"""Check actual PDF fonts, calibration status, and analyzed-snapshot metadata."""
import argparse
import re

import pymupdf

from common import DEFAULT_RAW, HERE, read_csv, write_csv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-interim', action='store_true')
    parser.add_argument('--previews', action='store_true', help='Rasterize the actual PDFs to PNGs outside git.')
    args = parser.parse_args()
    results = []
    def record(check, expected, actual):
        results.append(dict(mode='interim' if args.allow_interim else 'final', check=check,
                            expected=expected, actual=actual, passed=expected == actual))
    coverage = read_csv(HERE / 'analysis_coverage.csv')[0]
    complete = coverage['analyzed_repositories'] == coverage['collected_repositories']
    if not args.allow_interim:
        record('complete_snapshot', True, complete)
        record('at_least_300_analyzed_repositories', True, int(coverage['analyzed_repositories']) >= 300)
    from effective_gates import load_gates
    gates = load_gates()
    dependencies = {2: ['type'], 3: ['type', 'topic'], 4: ['type', 'enforceability'],
                    5: ['type', 'topic', 'enforceability'],
                    6: ['type', 'enforceability', 'context_required'],
                    7: ['type', 'enforceability', 'context_required']}
    manifest = read_csv(HERE / 'figure_manifest.csv')
    record('paper_figure_numbers', list(dependencies), sorted(int(r['paper_figure']) for r in manifest))
    for row in manifest:
        number = int(row['paper_figure'])
        prefix = 'figure_' + str(number) + '_'
        path = HERE / row['file']
        record(prefix + 'exists', True, path.is_file())
        failed = {d for d in dependencies[number] if not gates.get(d, False)}
        record(prefix + 'failed_axes', sorted(failed), sorted(filter(None, row['failed_dimensions'].split(','))))
        record(prefix + 'status', 'withheld' if failed else 'ready' if complete else 'interim', row['status'])
        record(prefix + 'repository_count', coverage['analyzed_repositories'], row['repositories'])
        record(prefix + 'statement_count', coverage['analyzed_statements'], row['statements'])
        record(prefix + 'fonttype_setting', 42, int(float(row['matplotlib_pdf_fonttype'])))
        if path.is_file():
            data = path.read_bytes()
            types = re.findall(rb'/Subtype\s*/(\w+)', data)
            record(prefix + 'type3_fonts', 0, types.count(b'Type3'))
            record(prefix + 'embedded_truetype', True, b'CIDFontType2' in types and b'/FontFile2' in data)
            with pymupdf.open(path) as document:
                record(prefix + 'page_count', 1, len(document))
                visible = document[0].get_text()
                record(prefix + 'withheld_content', bool(failed), 'Result withheld' in visible)
                if number == 2 and not failed:
                    record(prefix + 'visible_repository_count', True,
                           f'{int(coverage["analyzed_repositories"]):,} repositories' in visible)
                    record(prefix + 'visible_statement_count', True,
                           f'{int(coverage["analyzed_statements"]):,} statements' in visible)
                if args.previews:
                    root = DEFAULT_RAW / 'figure-pdf-preview'
                    root.mkdir(parents=True, exist_ok=True)
                    document[0].get_pixmap(dpi=180).save(root / (path.stem + '.png'))
    corrected = HERE / 'rescue/figures/corrected-prevalence.pdf'
    if corrected.exists():
        data = corrected.read_bytes()
        types = re.findall(rb'/Subtype\s*/(\w+)', data)
        record('corrected_type3_fonts', 0, types.count(b'Type3'))
        record('corrected_embedded_truetype', True, b'CIDFontType2' in types and b'/FontFile2' in data)
        with pymupdf.open(corrected) as document:
            record('corrected_page_count', 1, len(document))
            visible = document[0].get_text()
            record('corrected_transfer_caveat', True, 'transfer assumptions unverified' in visible)
            record('corrected_figure_metric_cells', 4, len(read_csv(HERE / 'rescue/corrected_figure_data.csv')))
            if args.previews:
                root = DEFAULT_RAW / 'figure-pdf-preview'
                root.mkdir(parents=True, exist_ok=True)
                document[0].get_pixmap(dpi=180).save(root / 'corrected-prevalence.png')
    write_csv(HERE / 'figure_production_validation.csv', results)
    if not all(row['passed'] for row in results):
        raise SystemExit('Production figure validation failed')
    if args.previews:
        print('Actual-PDF raster previews:', DEFAULT_RAW / 'figure-pdf-preview')
    print('All actual-PDF font, gating, and snapshot checks passed.')


if __name__ == '__main__':
    main()
