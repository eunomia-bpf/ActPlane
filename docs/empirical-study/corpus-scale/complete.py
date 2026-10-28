#!/usr/bin/env python3
"""Finish this finite study pipeline, optionally waiting for current lane jobs."""
import argparse
import os
import subprocess
import sys
import time

from common import HERE

BRANCH = 'experiments/corpus-scale-20261028'


def checkpoint(message):
    branch = subprocess.check_output(['git', '-C', str(HERE), 'branch', '--show-current'], text=True).strip()
    if branch != BRANCH:
        raise RuntimeError('Refusing to write another branch: ' + branch)
    subprocess.run(['git', '-C', str(HERE), 'add', '--', '.'], check=True)
    subprocess.run(['git', '-C', str(HERE), 'diff', '--cached', '--check'], check=True)
    if subprocess.run(['git', '-C', str(HERE), 'diff', '--cached', '--quiet']).returncode:
        subprocess.run(['git', '-C', str(HERE), 'commit', '-m', message], check=True)
        subprocess.run(['git', '-C', str(HERE), 'push', 'origin', BRANCH], check=True)


def run(script, *args):
    subprocess.run([sys.executable, str(HERE / script), *args], check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wait-pids', type=int, nargs='*', default=[])
    p.add_argument('--commit-checkpoints', action='store_true')
    a = p.parse_args()
    # Resume only missing/failed rows. Completed model outputs are unchanged.
    run('label.py', '--model', 'qwen3.8-27b-nvfp4', '--workers', '4',
        '--retry-policy', 'batch',
        '--output', str(HERE / 'calibration_qwen.csv'))
    run('label.py', '--model', 'zai/glm-5.3', '--workers', '2', '--batch-size', '12',
        '--retry-policy', 'batch',
        '--output', str(HERE / 'calibration_glm.csv'))
    # The remote calibration can overlap local source extraction. Wait before
    # starting local adjudication so endpoint concurrency remains bounded.
    remaining = set(a.wait_pids)
    while remaining:
        for pid in list(remaining):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                remaining.remove(pid)
        if remaining:
            time.sleep(15)
    run('label.py', '--model', 'qwen3.8-27b-nvfp4', '--workers', '4',
        '--retry-policy', 'batch',
        '--primary', str(HERE / 'calibration_qwen.csv'), '--other', str(HERE / 'calibration_glm.csv'),
        '--output', str(HERE / 'calibration_adjudicated.csv'))
    run('analyze.py', '--calibration-only')
    run('analyze.py')
    run('audit_runs.py')
    run('report.py')
    if a.commit_checkpoints:
        checkpoint('Complete historical two-model calibration and adjudication')
    run('run_scale.py', *(['--commit-checkpoints'] if a.commit_checkpoints else []))
    if a.commit_checkpoints:
        checkpoint('Complete calibrated scaled corpus characterization and figures')
    run('handoff.py')


if __name__ == '__main__':
    main()
