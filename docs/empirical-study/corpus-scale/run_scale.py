#!/usr/bin/env python3
"""Gate-controlled, restartable scaled labeling. Run after calibration completes."""
import subprocess
import sys

from common import HERE, read_csv
from analyze import calibration


def run(script, *args):
    subprocess.run([sys.executable, str(HERE / script), *args], check=True)


def main():
    gates = read_csv(HERE / 'calibration_gates.csv')
    dimensions = [r['dimension'] for r in gates if r['passed'] == 'True']
    if 'type' not in dimensions:
        raise SystemExit('Type calibration did not pass; no automated scaling is justified.')
    if len(dimensions) < 4:
        # Recheck the exact reduced output schema before deploying it at scale.
        validation = ['--input', str(HERE / 'paper_labels.csv'), '--dimensions', ','.join(dimensions)]
        commands = [[sys.executable, str(HERE / 'label.py'), *validation,
                     '--model', model, '--workers', '4', '--batch-size', '16',
                     '--output', str(HERE / f'format_calibration_{name}.csv')]
                    for model, name in [('qwen3.8-27b-nvfp4', 'qwen'), ('zai/glm-5.3', 'glm')]]
        processes = [subprocess.Popen(c) for c in commands]
        results = [p.wait() for p in processes]
        if any(results):
            raise SystemExit('Output-format calibration failed to run.')
        run('label.py', *validation, '--model', 'qwen3.8-27b-nvfp4', '--workers', '4',
            '--primary', str(HERE / 'format_calibration_qwen.csv'),
            '--other', str(HERE / 'format_calibration_glm.csv'),
            '--output', str(HERE / 'format_calibration_adjudicated.csv'))
        format_gates = calibration('format_calibration', dimensions)
        if not all(r['passed'] for r in format_gates):
            raise SystemExit('Reduced-schema calibration failed; inspect before changing the deployment schema.')
    run('extract.py', '--workers', '4')
    run('categorize.py')
    run('scope_files.py', '--workers', '4')
    shared = ['--input', str(HERE / 'statements.csv'), '--dimensions', ','.join(dimensions)]
    commands = [
        [sys.executable, str(HERE / 'label.py'), *shared, '--model', 'qwen3.8-27b-nvfp4',
         '--workers', '4', '--batch-size', '24', '--output', str(HERE / 'labels_qwen.csv')],
        [sys.executable, str(HERE / 'label.py'), *shared, '--model', 'zai/glm-5.3',
         '--workers', '4', '--batch-size', '24', '--output', str(HERE / 'labels_glm.csv')]]
    processes = [subprocess.Popen(c) for c in commands]
    results = [p.wait() for p in processes]
    if any(results):
        raise SystemExit('A primary labeler failed; restart after inspecting raw logs.')
    run('label.py', *shared, '--model', 'qwen3.8-27b-nvfp4', '--workers', '4',
        '--primary', str(HERE / 'labels_qwen.csv'), '--other', str(HERE / 'labels_glm.csv'),
        '--output', str(HERE / 'labels.csv'))
    run('analyze.py')
    run('figures.py')
    run('audit_runs.py')
    run('validate.py', '--require-complete')
    run('report.py')


if __name__ == '__main__':
    main()
