#!/usr/bin/env python3
"""Restore the committed snapshot from immutable raw-file URLs, without searching."""
import argparse
import hashlib
import time
from pathlib import Path
from urllib.parse import quote

import requests

from common import DEFAULT_RAW, HERE, digest, log, now, read_csv, write_csv


def verify(content, row):
    blob = b'blob ' + str(len(content)).encode() + b'\0' + content
    if digest(content) != row['content_sha256']:
        raise ValueError('sha256_mismatch')
    if hashlib.sha1(blob).hexdigest() != row['blob_sha']:
        raise ValueError('git_blob_sha1_mismatch')
    if len(content) != int(row['bytes']):
        raise ValueError('size_mismatch')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, default=HERE / 'corpus_manifest.csv')
    p.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    p.add_argument('--output', type=Path, default=HERE / 'source_restore_validation.csv')
    a = p.parse_args()
    a.raw.mkdir(parents=True, exist_ok=True)
    results, last_request = [], 0.0
    with requests.Session() as session:
        for row in read_csv(a.manifest):
            if row['status'] != 'included':
                continue
            target = a.raw / row['raw_relpath']
            result = {k: row[k] for k in ['repo', 'commit', 'file_path', 'content_sha256', 'blob_sha']}
            attempts, cache_error = 0, ''
            try:
                if target.exists():
                    try:
                        verify(target.read_bytes(), row)
                        result.update(status='cached_ok', attempts=0, cache_error='', error='')
                        results.append(result)
                        continue
                    except ValueError as e:
                        cache_error = str(e)
                url = ('https://raw.githubusercontent.com/' + row['repo'] + '/' + row['commit']
                       + '/' + quote(row['file_path'], safe='/'))
                for attempts in range(1, 4):
                    time.sleep(max(0, 1.05 - (time.monotonic() - last_request)))
                    last_request = time.monotonic()
                    try:
                        response = session.get(url, timeout=60)
                        log(a.raw / 'source-restore.jsonl', dict(at=now(), url=url,
                            attempt=attempts, status=response.status_code))
                        response.raise_for_status()
                        content = response.content
                        verify(content, row)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        temporary = target.with_suffix('.restore.tmp')
                        temporary.write_bytes(content)
                        temporary.replace(target)
                        result.update(status='downloaded_ok', attempts=attempts, cache_error=cache_error, error='')
                        break
                    except (requests.RequestException, ValueError) as e:
                        log(a.raw / 'source-restore.jsonl', dict(at=now(), url=url,
                            attempt=attempts, error=type(e).__name__))
                        if attempts == 3:
                            raise
                        delay = 2 ** attempts
                        if getattr(e, 'response', None) is not None and e.response.status_code in (403, 429):
                            try:
                                delay = max(60, float(e.response.headers.get('Retry-After', 60)))
                            except ValueError:
                                delay = 60
                        while delay > 0:
                            step = min(60, delay)
                            time.sleep(step)
                            delay -= step
            except (requests.RequestException, ValueError, OSError) as e:
                result.update(status='failed', attempts=attempts, cache_error=cache_error,
                              error=str(e) if isinstance(e, ValueError) else type(e).__name__)
            results.append(result)
            write_csv(a.output, results)
    write_csv(a.output, results)
    failed = sum(r['status'] == 'failed' for r in results)
    print(f'Checked {len(results)} selected paths; failures={failed}.')
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
