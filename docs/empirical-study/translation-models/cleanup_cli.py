#!/usr/bin/env python3
"""Reap orphaned trial CLIs from the pre-fix worker without interrupting it.

Only PPid=1 processes whose cwd is this lane's raw translation directory qualify.
New cli_call invocations use private process groups and do not need this bridge.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import time
from prepare import DEFAULT_RAW, HERE, csv_write, json_write


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--until-parent', type=int, required=True)
    args = parser.parse_args()
    audit = DEFAULT_RAW / 'orphaned-cli-processes.json'
    rows = json.loads(audit.read_text()) if audit.exists() else []
    root = (DEFAULT_RAW / 'translations').resolve()
    while True:
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                if '\nPPid:\t1\n' not in (proc / 'status').read_text():
                    continue
                cwd = (proc / 'cwd').resolve(strict=True)
                if not cwd.is_relative_to(root):
                    continue
                cmd = (proc / 'cmdline').read_bytes().split(b'\0')
                if not cmd or b'codex' not in cmd[0] or b'exec' not in cmd:
                    continue
                os.kill(int(proc.name), signal.SIGTERM)
                rows.append(dict(pid=proc.name, cwd=str(cwd.relative_to(root)),
                                 recorded_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                                 action='terminate_orphaned_timeout_child', usage='unknown'))
                json_write(audit, rows)
                csv_write(HERE / 'orphaned-cli-processes.csv', rows)
                print('Terminated orphaned trial CLI', proc.name, flush=True)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        parent = Path('/proc') / str(args.until_parent) / 'cmdline'
        if not parent.exists() or b'translate.py' not in parent.read_bytes():
            break
        time.sleep(5)


if __name__ == '__main__':
    main()
