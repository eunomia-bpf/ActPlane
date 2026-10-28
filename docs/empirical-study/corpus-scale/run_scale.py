#!/usr/bin/env python3
"""Gate-controlled, restartable scaled labeling. Run after calibration completes."""
import subprocess
import sys

from common import HERE, read_csv


def run(script, *args):
    subprocess.run([sys.executable, str(HERE / script), *args], check=True)


def main():
    gates = read_csv(HERE / 'calibration_gates.csv')
    dimensions = [r['dimension'] for r in gates if r['passed'] == 'True']
    if 'type' not in dimensions:
        raise SystemExit('Type calibration did not pass; no automated scaling is justified.')
    run('extract.py', '--workers', '4')
    run('categorize.py')
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
    run('report.py')


if __name__ == '__main__':
    main()
