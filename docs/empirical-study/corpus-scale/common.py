"""Shared CSV, provenance, and HTTP helpers. Secrets never enter logs."""
import csv
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
DEFAULT_RAW = Path('/workspaces/.agent-state/actplane-research/raw/corpus-scale-20261028')
LOCK = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def digest(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def read_csv(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields=None):
    rows = list(rows)
    fields = fields or list(dict.fromkeys(k for r in rows for k in r))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore', lineterminator='\n')
        w.writeheader()
        w.writerows(rows)
    tmp.replace(path)


def log(path, row):
    with LOCK:
        with Path(path).open('a') as f:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')


class GitHub:
    """Sequential, cached API reads with rate-limit and retry accounting."""
    def __init__(self, raw):
        self.raw = Path(raw)
        self.cache = self.raw / 'github'
        self.cache.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if token:
            self.session.headers['Authorization'] = 'Bearer ' + token
        self.session.headers.update({'Accept': 'application/vnd.github+json',
                                     'X-GitHub-Api-Version': '2022-11-28'})
        self.last = 0

    def get(self, endpoint, params=None):
        key = digest(json.dumps([endpoint, params], sort_keys=True))
        cache = self.cache / (key + '.json')
        if cache.exists():
            return json.loads(cache.read_text())
        for attempt in range(1, 7):
            # Lower than both the primary and secondary documented API limits.
            time.sleep(max(0, 1.05 - (time.monotonic() - self.last)))
            self.last = time.monotonic()
            try:
                r = self.session.get('https://api.github.com/' + endpoint.lstrip('/'),
                                     params=params, timeout=90)
            except requests.RequestException as e:
                log(self.raw / 'github-requests.jsonl', dict(at=now(), endpoint=endpoint,
                    params=params, attempt=attempt, error=type(e).__name__))
                time.sleep(min(60, 2 ** attempt))
                continue
            log(self.raw / 'github-requests.jsonl', dict(at=now(), endpoint=endpoint,
                params=params, attempt=attempt, status=r.status_code,
                remaining=r.headers.get('X-RateLimit-Remaining'),
                reset=r.headers.get('X-RateLimit-Reset')))
            if r.status_code == 404:
                return None
            if r.status_code in (403, 429):
                delay = max(float(r.headers.get('Retry-After', 60)),
                    float(r.headers.get('X-RateLimit-Reset', time.time())) - time.time() + 2
                    if r.headers.get('X-RateLimit-Remaining') == '0' else 60)
                # Short sleeps keep interrupted jobs responsive.
                for _ in range(int(delay // 30) + 1):
                    time.sleep(min(30, delay))
                    delay -= min(30, delay)
                continue
            if r.status_code >= 500:
                time.sleep(min(60, 2 ** attempt))
                continue
            r.raise_for_status()
            value = r.json()
            cache.write_text(json.dumps(value))
            return value
        raise RuntimeError('GitHub retries exhausted: ' + endpoint)
