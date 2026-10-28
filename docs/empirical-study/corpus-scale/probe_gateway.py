#!/usr/bin/env python3
"""Probe the optional OpenCode routes with the requested session header."""
import os
import time
import uuid

import requests

from common import DEFAULT_RAW, HERE, digest, write_csv


def main():
    rows = []
    for model in ['opencode-go/gpt-5.6-luna', 'opencode-go/grok-4.6']:
        session = 'actplane-corpus-scale-' + uuid.uuid4().hex
        payload = dict(model=model, temperature=0, max_tokens=128,
                       messages=[dict(role='user', content='Return JSON only: {"ok": true}')])
        started = time.monotonic()
        row = dict(requested_model=model, session_header_sent=True, status='',
                   returned_model='', elapsed_s='', error_class='')
        try:
            response = requests.post(os.environ['LITELLM_BASE_URL'].rstrip('/') + '/chat/completions',
                headers={'Authorization': 'Bearer ' + os.environ['LITELLM_API_KEY'],
                         'x-opencode-session': session}, json=payload, timeout=60)
            row['status'] = response.status_code
            row['elapsed_s'] = round(time.monotonic() - started, 3)
            if response.ok:
                row['returned_model'] = response.json().get('model', '')
            else:
                row['error_class'] = 'session_header_not_forwarded_or_rejected' if 'x-opencode-session' in response.text else 'provider_error'
            (DEFAULT_RAW / ('gateway-probe-' + digest(model)[:12] + '.json')).write_text(response.text)
        except requests.RequestException as e:
            row['error_class'] = type(e).__name__
        rows.append(row)
    write_csv(HERE / 'gateway_probes.csv', rows)
    print(rows)


if __name__ == '__main__':
    main()
