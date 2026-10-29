"""Read-only guest route probe; no credentials, response bodies, or headers emitted."""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

parts = urllib.parse.urlsplit(os.environ['LITELLM_BASE_URL'])
assert parts.scheme == 'http', 'This probe is only for the observed plaintext internal gateway'
address = sys.argv[1]
port = parts.port or 80
url = urllib.parse.urlunsplit((parts.scheme, f'{address}:{port}', parts.path.rstrip('/') + '/models', '', ''))
request = urllib.request.Request(url, headers={
    'Host': parts.netloc,
    'Authorization': 'Bearer ' + os.environ['LITELLM_API_KEY'],
})
result = dict(original_hostname=parts.hostname, probe_address=address, port=port)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        result['status'] = response.status
except Exception as error:
    result.update(error_type=type(error).__name__, status=getattr(error, 'code', None),
                  reason_type=type(getattr(error, 'reason', None)).__name__)
print(json.dumps(result, sort_keys=True))
