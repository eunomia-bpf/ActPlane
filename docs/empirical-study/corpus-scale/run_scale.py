#!/usr/bin/env python3
"""Gate-controlled, restartable scaled labeling. Run after calibration completes."""
import subprocess
import sys
import argparse
import time

from common import DEFAULT_RAW, HERE, log, now, read_csv, write_csv
from analyze import calibration


def run(script, *args):
    subprocess.run([sys.executable, str(HERE / script), *args], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit-checkpoints', action='store_true')
    args = parser.parse_args()
    gates = read_csv(HERE / 'calibration_gates.csv')
    dimensions = [r['dimension'] for r in gates if r['passed'] == 'True']
    if 'type' not in dimensions:
        raise SystemExit('Type calibration did not pass; no automated scaling is justified.')
    if len(dimensions) < 4:
        # Recheck the exact reduced output schema before deploying it at scale.
        validation = ['--input', str(HERE / 'paper_labels.csv'), '--dimensions', ','.join(dimensions),
                      '--retry-policy', 'invalid']
        commands = [[sys.executable, str(HERE / 'label.py'), *validation,
                     '--model', model, '--workers', '4' if name == 'qwen' else '2',
                     '--batch-size', '48' if name == 'qwen' else '24',
                     '--output', str(HERE / f'format_calibration_{name}.csv')]
                    for model, name in [('qwen3.8-27b-nvfp4', 'qwen'), ('zai/glm-5.3', 'glm')]]
        processes = [subprocess.Popen(c) for c in commands]
        results = [p.wait() for p in processes]
        if any(results):
            raise SystemExit('Output-format calibration failed to run.')
        run('label.py', *validation, '--model', 'qwen3.8-27b-nvfp4', '--workers', '4',
            '--batch-size', '48',
            '--primary', str(HERE / 'format_calibration_qwen.csv'),
            '--other', str(HERE / 'format_calibration_glm.csv'),
            '--output', str(HERE / 'format_calibration_adjudicated.csv'))
        format_gates = calibration('format_calibration', dimensions)
        if not all(r['passed'] for r in format_gates):
            raise SystemExit('Reduced-schema calibration failed; inspect before changing the deployment schema.')
        protocol_path = HERE / 'retry_protocol.csv'
        if protocol_path.exists():
            protocols = read_csv(protocol_path)
            for protocol in protocols:
                if protocol['version'] == 'v3':
                    protocol['status'] = 'validated_and_deployed_for_' + '_'.join(dimensions)
                    protocol['reference_commit'] = subprocess.check_output(
                        ['git', '-C', str(HERE), 'rev-parse', 'HEAD'], text=True).strip()
            write_csv(protocol_path, protocols)
        if (HERE / 'calibration-v2').exists():
            run('compare_reference_versions.py')
    run('extract.py', '--workers', '4')
    run('categorize.py')
    # Give primary measurements the available local slots. Scope classification
    # is optional and resumes after both primary labelers finish.
    shared = ['--input', str(HERE / 'statements.csv'), '--dimensions', ','.join(dimensions),
              '--retry-policy', 'invalid']
    commands = [
        [sys.executable, str(HERE / 'label.py'), *shared, '--model', 'qwen3.8-27b-nvfp4',
         '--workers', '6', '--batch-size', '48', '--output', str(HERE / 'labels_qwen.csv')],
        [sys.executable, str(HERE / 'label.py'), *shared, '--model', 'zai/glm-5.3',
         '--workers', '2', '--batch-size', '24', '--output', str(HERE / 'labels_glm.csv')]]
    processes = [subprocess.Popen(c) for c in commands]
    last_checkpoint = time.monotonic()
    while any(p.poll() is None for p in processes):
        time.sleep(30)
        if time.monotonic() - last_checkpoint < 1800:
            continue
        if all((HERE / f'labels_{name}.csv').exists() for name in ('qwen', 'glm')):
            workers = '2' if processes[0].poll() is None else '6'
            run('label.py', *shared, '--model', 'qwen3.8-27b-nvfp4', '--workers', workers,
                '--batch-size', '48',
                '--primary', str(HERE / 'labels_qwen.csv'), '--other', str(HERE / 'labels_glm.csv'),
                '--output', str(HERE / 'labels.csv'))
            run('analyze.py')
            coverage = read_csv(HERE / 'analysis_coverage.csv')[0]
            if int(coverage['analyzed_repositories']) > 0:
                run('figures.py')
                run('audit_runs.py')
                run('report.py')
                if args.commit_checkpoints:
                    from complete import checkpoint
                    checkpoint('Checkpoint fully labeled repository subset during corpus scaling')
        last_checkpoint = time.monotonic()
    results = [p.returncode for p in processes]
    if any(results):
        raise SystemExit('A primary labeler failed; restart after inspecting raw logs.')
    scope_process = subprocess.Popen([sys.executable, str(HERE / 'scope_files.py'), '--workers', '3'])
    run('label.py', *shared, '--model', 'qwen3.8-27b-nvfp4', '--workers', '4',
        '--batch-size', '48',
        '--primary', str(HERE / 'labels_qwen.csv'), '--other', str(HERE / 'labels_glm.csv'),
        '--output', str(HERE / 'labels.csv'))
    if scope_process.poll() is None:
        # The noncoding scope slice is optional. Keep the completed judgments
        # and explicitly mark the remaining files as unclassified.
        scope_process.terminate()
        scope_process.wait()
        log(DEFAULT_RAW / 'optional-processes.jsonl', dict(at=now(),
            operation='scope_classification', status='partial_at_primary_completion'))
    run('analyze.py')
    run('figures.py')
    run('audit_runs.py')
    run('validate.py', '--require-complete')
    run('validate_figures.py')
    run('report.py')


if __name__ == '__main__':
    main()
