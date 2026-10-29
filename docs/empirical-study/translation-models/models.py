#!/usr/bin/env python3
"""Model adapters and auditable identity/access probes. Never print credentials."""
import argparse
import concurrent.futures
import json
import os
import re
import signal
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import uuid

from prepare import HERE, DEFAULT_RAW, csv_write

MODELS = {
    'qwen3.8-27b-nvfp4': ('http://qwen38-vllm.models.svc.cluster.local:8000/v1', 'local'),
    'glm-5.3-flash-nvfp4': ('http://glm53-flash.models.svc.cluster.local:8000/v1', 'local-auth'),
    'qwen3.8-flash-next-nvfp4': ('http://qwen38-flash-next.models.svc.cluster.local:8000/v1', 'local-auth'),
    'zai/glm-5.3': (None, 'gateway'),
    'zai/glm-5.3-flash': (None, 'gateway'),
    'zai/glm-4.7-flash': (None, 'gateway'),
    'zai/glm-4.5-air': (None, 'gateway'),
    'opencode-go/gpt-5.6-luna': (None, 'gateway'),
    'opencode-go/grok-4.6': (None, 'gateway'),
    'gpt-5.5': (None, 'codex'),
    'gpt-6-astra': (None, 'codex'),
    'claude-opus-4-6': (None, 'claude'),
}
SYSTEM = 'You translate natural-language repository policies into ActPlane DSL. Return only the requested policy. Do not use tools.'
REQUEST_TIMEOUT_S = 360


def identity_ok(requested, returned):
    return str(returned).split('/')[-1].lower().replace('_', '-') == requested.split('/')[-1].lower().replace('_', '-')


def api_call(model, messages, max_tokens=8192, session=None, header_mode='both'):
    base, kind = MODELS[model]
    base = base or os.environ['LITELLM_BASE_URL']
    headers = {'Content-Type': 'application/json'}
    if kind in ('gateway', 'local-auth'):
        headers['Authorization'] = 'Bearer ' + os.environ['LITELLM_API_KEY']
    body = dict(model=model, messages=messages, temperature=0, max_tokens=max_tokens, stream=False)
    if model.startswith('opencode-go/') and session:
        if header_mode in ('header', 'both'):
            headers['x-opencode-session'] = session
        if header_mode in ('body', 'both'):
            body['extra_headers'] = {'x-opencode-session': session}
    req = urllib.request.Request(base.rstrip('/') + '/chat/completions', data=json.dumps(body).encode(), headers=headers)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as r:
            data = json.load(r)
        return dict(status='ok', elapsed_s=time.monotonic() - start, response=data,
                    response_model=data.get('model', ''), identity_verified=identity_ok(model, data.get('model', '')))
    except urllib.error.HTTPError as e:
        # Headers are intentionally excluded because gateway headers can carry
        # provider credentials. The sanitized response body is useful evidence.
        error = e.read().decode(errors='replace')[:8000]
        for key in ('LITELLM_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'):
            if os.environ.get(key):
                error = error.replace(os.environ[key], '[REDACTED]')
        return dict(status='http_error', http_status=e.code, elapsed_s=time.monotonic() - start,
                    error=error, response_model='', identity_verified=False)
    except Exception as e:
        return dict(status='transport_error', elapsed_s=time.monotonic() - start,
                    error=f'{type(e).__name__}: {e}', response_model='', identity_verified=False)


def cli_call(model, prompt, out):
    out.mkdir(parents=True, exist_ok=True)
    cwd = out / 'empty-cwd'
    cwd.mkdir(exist_ok=True)
    if MODELS[model][1] == 'codex':
        # Explicit user-requested translator. No delegated repository work.
        args = ['codex', 'exec', '--dangerously-bypass-approvals-and-sandbox', '--ignore-user-config',
                '--skip-git-repo-check', '--ephemeral', '-m', model, '--json',
                '-c', 'model_reasoning_effort="medium"', '-c', 'features.shell_tool=false',
                '-c', 'features.apply_patch_freeform=false', '-c', 'features.multi_agent=false',
                '-c', 'features.apps=false', '-c', 'web_search="disabled"',
                '-c', 'developer_instructions="' + SYSTEM + '"', '-']
    else:
        args = ['claude', '-p', '--model', model, '--tools', '', '--disable-slash-commands',
                '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
                '--setting-sources', '', '--settings', '{"disableAllHooks":true}',
                '--no-session-persistence', '--output-format', 'json', '--system-prompt', SYSTEM]
    start = time.monotonic()
    try:
        env = dict(os.environ)
        if MODELS[model][1] == 'codex':
            # Protocol-only tracing exposes incoming server response.model.
            # Never retain raw frames: they also contain opaque session state.
            env['RUST_LOG'] = 'tungstenite::protocol=trace'
        # The installed CLI is a shell wrapper. Killing only that wrapper on a
        # timeout leaves its native child issuing requests after our call ends.
        child = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True)
        try:
            stdout, stderr = child.communicate(prompt, timeout=REQUEST_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise
        proc = subprocess.CompletedProcess(args, child.returncode, stdout, stderr)
        (out / 'stdout.json').write_text(proc.stdout)
        (out / 'stderr.txt').write_text(proc.stderr if MODELS[model][1] != 'codex' else
                                       'Raw protocol frames discarded. See server-responses.json for safe identity and usage evidence.\n')
        result = dict(status='ok' if not proc.returncode else 'cli_error', returncode=proc.returncode,
                      elapsed_s=time.monotonic() - start, response_model='', identity_verified=False)
        if MODELS[model][1] == 'claude':
            data = json.loads(proc.stdout)
            result['response'] = data
            models = list(data.get('modelUsage', {}))
            result['response_model'] = ','.join(models)
            result['identity_verified'] = len(models) == 1 and identity_ok(model, models[0])
            result['text'] = data.get('result', '')
            if data.get('is_error'):
                result.update(status='cli_error', error=data.get('result'))
            elif data.get('num_turns') != 1 or len(data.get('usage', {}).get('iterations', [])) != 1:
                result.update(status='protocol_error', error='CLI did not report exactly one model iteration')
        else:
            events = [json.loads(x) for x in proc.stdout.splitlines() if x.startswith('{')]
            result['response'] = events
            result['text'] = '\n'.join(e.get('item', {}).get('text', '') for e in events
                                       if e.get('type') == 'item.completed' and e.get('item', {}).get('type') == 'agent_message')
            result['usage'] = next((e.get('usage') for e in events if e.get('type') == 'turn.completed'), {})
            result['tool_calls'] = [e for e in events if e.get('item', {}).get('type') in ('command_execution', 'mcp_tool_call', 'web_search')]
            result['error'] = ('\n'.join(e.get('message', '') for e in events if e.get('type') == 'error') or f'Codex exited {proc.returncode}') if proc.returncode else ''
            server = codex_server_evidence(proc.stderr)
            (out / 'server-responses.json').write_text(json.dumps(server, indent=2) + '\n')
            result['server_responses'] = server
            inferences = [r for r in server if r.get('generate') is not False]
            returned = sorted({r.get('model', '') for r in inferences})
            result['response_model'] = ','.join(returned)
            result['identity_verified'] = bool(returned) and all(identity_ok(model, m) for m in returned)
            allowed = {'message', 'reasoning'}
            if proc.returncode == 0 and (len(inferences) != 1 or result['tool_calls'] or
                                        any(set(r['output_types']) - allowed for r in inferences)):
                result.update(status='protocol_error', error='CLI did not complete exactly one inference without tool calls')

        return result
    except Exception as e:
        return dict(status='cli_error', elapsed_s=time.monotonic() - start,
                    error=f'{type(e).__name__}: {e}', response_model='', identity_verified=False)


def codex_server_evidence(stderr):
    """Parse only incoming completed response objects, excluding raw headers."""
    rows = []
    for line in stderr.splitlines():
        marker = 'Received message '
        if marker not in line:
            continue
        try:
            event = json.loads(line.split(marker, 1)[1])
        except json.JSONDecodeError:
            continue
        if event.get('type') != 'response.completed':
            continue
        response = event.get('response', {})
        row = {k: response.get(k) for k in ('id', 'model', 'status', 'generate', 'usage')}
        row['output_types'] = [o.get('type') for o in response.get('output', [])]
        if not any(old['id'] == row['id'] for old in rows):
            rows.append(row)
    return rows


def probe(model, raw, refresh=False):
    out = raw / 'probes' / model.replace('/', '__')
    out.mkdir(parents=True, exist_ok=True)
    prompt = 'Return exactly the word READY. Do not use tools or inspect files.'
    if (out / 'probe.json').exists() and not refresh:
        attempts = json.loads((out / 'probe.json').read_text())
        for d in attempts:
            d['identity_verified'] = identity_ok(model, d.get('response_model', ''))
            if model == 'gpt-5.5' and d.get('status') != 'ok':
                d['error'] = '\n'.join(e.get('message', '') for e in d.get('response', []) if e.get('type') == 'error')
    elif MODELS[model][1] in ('codex', 'claude'):
        attempts = [cli_call(model, prompt, out)]
    else:
        attempts = [api_call(model, [{'role': 'user', 'content': prompt}], max_tokens=128)]
        if model.startswith('opencode-go/') and attempts[-1]['status'] != 'ok':
            for mode in ('header', 'both'):
                attempts.append(api_call(model, [{'role': 'user', 'content': prompt}], max_tokens=128,
                                         session=str(uuid.uuid4()), header_mode=mode))
                if attempts[-1]['status'] == 'ok':
                    break
    (out / 'probe.json').write_text(json.dumps(attempts, indent=2) + '\n')
    d = attempts[-1]
    row = dict(model=model, access=MODELS[model][1], status=d['status'],
               response_model=d['response_model'], identity_verified=int(d['identity_verified']),
               probe_attempts=len(attempts), elapsed_s=round(sum(x['elapsed_s'] for x in attempts), 4),
               error=d.get('error', '')[:500].replace('\n', ' '))
    print(model, row['status'], row['response_model'], row['identity_verified'], flush=True)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    ap.add_argument('--models', nargs='+', choices=list(MODELS), default=list(MODELS))
    ap.add_argument('--refresh', action='store_true')
    args = ap.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(lambda m: probe(m, args.raw, args.refresh), args.models))
    csv_write(HERE / 'model-access.csv', rows)


if __name__ == '__main__':
    main()
