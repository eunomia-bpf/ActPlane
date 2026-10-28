#!/usr/bin/env python3
"""Read-only endpoint identity probes. No deployment or configuration changes."""
import os

import requests

from common import HERE, write_csv


def main():
    rows = []
    for host in ['glm53-flash.models.svc.cluster.local', 'qwen38-flash-next.models.svc.cluster.local']:
        for mode in ['unauthenticated', 'gateway_key']:
            headers = {'Authorization': 'Bearer ' + os.environ['LITELLM_API_KEY']} if mode == 'gateway_key' else {}
            row = dict(endpoint=host, port=8000, authentication=mode, status='', models='')
            try:
                response = requests.get('http://' + host + ':8000/v1/models', headers=headers, timeout=10)
                row['status'] = response.status_code
                if response.ok:
                    row['models'] = '|'.join(x['id'] for x in response.json().get('data', []))
            except requests.RequestException as e:
                row['status'] = type(e).__name__
            rows.append(row)
    write_csv(HERE / 'endpoint_probes.csv', rows)


if __name__ == '__main__':
    main()
