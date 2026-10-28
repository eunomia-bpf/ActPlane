#!/usr/bin/env python3
"""Check actual PDF fonts, calibration status, and analyzed-snapshot metadata."""
import argparse
import re
import shutil

from common import DEFAULT_RAW, HERE, read_csv, write_csv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-interim', action='store_true')
    parser.add_argument('--previews', action='store_true', help='Render input-matched PNG previews outside git.')
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
    gates = {r['dimension']: r['passed'] == 'True' for r in read_csv(HERE / 'calibration_gates.csv')}
    if (HERE / 'format_calibration_gates.csv').exists():
        for row in read_csv(HERE / 'format_calibration_gates.csv'):
            gates[row['dimension']] = gates.get(row['dimension'], False) and row['passed'] == 'True'
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
        record(prefix + 'failed_axes', failed, set(filter(None, row['failed_dimensions'].split(','))))
        record(prefix + 'status', 'withheld' if failed else 'ready' if complete else 'interim', row['status'])
        record(prefix + 'repository_count', coverage['analyzed_repositories'], row['repositories'])
        record(prefix + 'statement_count', coverage['analyzed_statements'], row['statements'])
        record(prefix + 'fonttype_setting', 42, int(float(row['matplotlib_pdf_fonttype'])))
        if path.is_file():
            data = path.read_bytes()
            types = re.findall(rb'/Subtype\s*/(\w+)', data)
            record(prefix + 'type3_fonts', 0, types.count(b'Type3'))
            record(prefix + 'embedded_truetype', True, b'CIDFontType2' in types and b'/FontFile2' in data)
    write_csv(HERE / 'figure_production_validation.csv', results)
    if not all(row['passed'] for row in results):
        raise SystemExit('Production figure validation failed')
    if args.previews:
        root = DEFAULT_RAW / 'figure-production-preview'
        root.mkdir(parents=True, exist_ok=True)
        for name in ['analysis_statements.csv', 'analysis_coverage.csv', 'calibration_gates.csv', 'format_calibration_gates.csv']:
            if (HERE / name).exists():
                shutil.copy2(HERE / name, root / name)
        import figures
        figures.HERE, figures.OUT, figures.DATA = root, root / 'figures', []
        original_save = figures.save
        def save_preview(fig, name):
            figures.OUT.mkdir(parents=True, exist_ok=True)
            fig.savefig(figures.OUT / (name + '.png'), dpi=180, bbox_inches='tight')
            original_save(fig, name)
        figures.save = save_preview
        figures.main()
        print('Input-matched previews:', root / 'figures')
    print('All actual-PDF font, gating, and snapshot checks passed.')


if __name__ == '__main__':
    main()
