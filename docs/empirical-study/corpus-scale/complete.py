#!/usr/bin/env python3
"""Finish this finite study pipeline, optionally waiting for current lane jobs."""
import argparse
import os
import subprocess
import sys
import time

from common import HERE


def run(script, *args):
    subprocess.run([sys.executable, str(HERE / script), *args], check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wait-pids', type=int, nargs='*', default=[])
    a = p.parse_args()
    remaining = set(a.wait_pids)
    while remaining:
        for pid in list(remaining):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                remaining.remove(pid)
        if remaining:
            time.sleep(15)
    # Resume only missing/failed rows. Completed model outputs are unchanged.
    run('label.py', '--model', 'qwen3.8-27b-nvfp4', '--workers', '4',
        '--output', str(HERE / 'calibration_qwen.csv'))
    run('label.py', '--model', 'zai/glm-5.3', '--workers', '4', '--batch-size', '12',
        '--output', str(HERE / 'calibration_glm.csv'))
    run('label.py', '--model', 'qwen3.8-27b-nvfp4', '--workers', '4',
        '--primary', str(HERE / 'calibration_qwen.csv'), '--other', str(HERE / 'calibration_glm.csv'),
        '--output', str(HERE / 'calibration_adjudicated.csv'))
    run('analyze.py', '--calibration-only')
    run('run_scale.py')


if __name__ == '__main__':
    main()
