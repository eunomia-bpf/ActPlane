"""Export independent intervention evidence; keep uncertain competing flows unknown."""
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import zipfile

ROOT = Path(os.environ['WS_RAW']) / 'replay'
OUT = ROOT.parent.parent / 'replay/results'

def sealed_inputs(event, original, calls, plan):
    run=ROOT/event.get('raw_condition',event['condition'])/'dynamic/runs'/event['dynamic_id']
    environment=json.loads((run/'environment.json').read_text()).get('variables',{})
    options=('PIP_CLIENT_CERT','PIP_CERT','PIP_CONFIG_FILE','SSL_CERT_FILE','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE','PYTHONPATH')
    configs=[]
    for path in ('/etc/pip.conf','/etc/xdg/pip/pip.conf'):
        file=Path(path);content=file.read_bytes() if file.is_file() else None
        configs.append(dict(path=path,present=content is not None,sha256=hashlib.sha256(content).hexdigest() if content else '',
            client_certificate_option=bool(content and b'client-cert' in content.lower())))
    base=['git','--git-dir',str(ROOT/'input/dynamic/git-cache'/plan['repository'].replace('/','__'))]
    listing=subprocess.check_output(base+['ls-tree','-rz',plan['base_commit']])
    aliases=[]
    for item in listing.split(b'\0'):
        if not item.startswith(b'120000 '):continue
        name=item.split(b'\t',1)[1].decode(errors='replace')
        if name.endswith(('.env','.env.local','.env.production','.pem','.key','id_rsa','id_ed25519','credentials.json')):
            aliases.append(name)
    suspicious=[]
    for (trajectory,index),call in calls.items():
        if trajectory!=event['trajectory_id'] or index>int(event['call_index']):continue
        text=json.dumps(call['args']).lower()
        if any(word in text for word in ('client-cert','pip.conf','pip_cert','pip_config','ssl_cert','sitecustomize','usercustomize','symlink','ln -s')):
            suspicious.append(index)
    return dict(harness_clearenv=True,configured_home=environment.get('HOME'),present_tls_python_options=[key for key in options if key in environment],
        readonly_global_configs_at_audit=configs,pinned_repository_candidate_symlinks=aliases,
        prior_configuration_or_alias_call_indices=suspicious,
        caveat='Root/home/venv runtime snapshots are removed by the copied harness; these facts alone do not prove absence of every competing open.')


def review(events, sources):
    if not events:
        return []
    by_trajectory = {}
    wanted = {r['trajectory_id'] for r in events}
    plans={r['dynamic_id']:r for r in csv.DictReader((OUT/'cohort.csv').open())}
    with gzip.open(ROOT / 'input/classified_calls.jsonl.gz', 'rt') as stream:
        for line in stream:
            row = json.loads(line)
            if row['trajectory_id'] in wanted:
                by_trajectory[(row['trajectory_id'], row['call_index'])] = row
    bundles = {}
    published = {}
    for wheel in (ROOT / 'input/dynamic/toolchains').glob('*/lib/python*/ensurepip/_bundled/pip-*.whl'):
        version = wheel.name.split('-')[1]
        if version not in published:
            url = 'https://pypi.org/pypi/pip/' + version + '/json'
            cache = ROOT / ('pip-' + version + '-pypi.json')
            if not cache.exists():
                with urllib.request.urlopen(url, timeout=30) as response:
                    cache.write_bytes(response.read())
            published[version] = {r['filename']: dict(sha256=r['digests']['sha256'], url=r['url'],
                metadata_url=url, metadata_sha256=hashlib.sha256(cache.read_bytes()).hexdigest())
                for r in json.loads(cache.read_text())['urls']}
        proof = published[version][wheel.name]
        wheel_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        assert wheel_digest == proof['sha256'], 'Bundled wheel differs from the official published artifact'
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if name.endswith('certifi/cacert.pem'):
                    data = archive.read(name)
                    digest = hashlib.sha256(data).hexdigest()
                    bundles.setdefault(digest, []).append(dict(wheel=str(wheel.relative_to(ROOT)), member=name,
                        wheel_sha256=wheel_digest, **proof))
    rows = []
    for event in events:
        condition, dynamic_id = event['condition'], event['dynamic_id']
        prior = [r for r in sources if r['condition'] == condition and r['dynamic_id'] == dynamic_id
                 and int(r['timestamp_ns']) <= int(event['timestamp_ns'])]
        paths = sorted({(r['path'], r['classification'], r['sha256']) for r in prior})
        original = by_trajectory.get((event['trajectory_id'], int(event['call_index'])), {}) if event['call_index'] else {}
        row = dict(condition=condition, dynamic_id=dynamic_id, timestamp_ns=event['timestamp_ns'],
            call_index=event['call_index'], pid=event['pid'], source_path=event['source_path'],
            source_sha256=event['source_sha256'], matching_bundled_wheel=json.dumps(bundles.get(event['source_sha256'], []), sort_keys=True),
            prior_source_paths=json.dumps(paths), original_args=json.dumps(original.get('args', {}), sort_keys=True),
            sealed_input_evidence=json.dumps(sealed_inputs(event,original,by_trajectory,plans[dynamic_id]),sort_keys=True) if event['call_index'] else '',
            adjudication='unknown', evidence='Independent provenance/context review pending')
        if (event['coverage'] == 'complete' and int(event['intervened']) == 1 and prior
                and event['source_sha256'] in bundles
                and all(r['classification'] == 'public_certificate' and r['sha256'] in bundles
                        and int(r['path_maybe_truncated']) == 0 for r in prior)):
            row.update(adjudication='unknown', evidence=(
                'Observed provenance bytes equal the certifi public CA bundle in a pip wheel whose SHA256 '
                'matches official PyPI release metadata. Every independently observed prior declared-source '
                'read in this trajectory is a verified public CA bundle. This establishes a candidate false '
                'taint, but the resolved-read filter does not exclude raw-name aliases or opened-but-unread '
                'competing sources. Independent open/configuration audit is required before confirming false.'))
        rows.append(row)
    print('Adjudicated', len(rows), 'events:', sum(r['adjudication']=='false_intervention' for r in rows),
          'confirmed false;', sum(r['adjudication']=='unknown' for r in rows), 'unknown', flush=True)
    return rows


def save(rows,output=OUT):
    fields = list(rows[0]) if rows else ['condition', 'dynamic_id', 'timestamp_ns', 'call_index', 'pid', 'source_path',
        'source_sha256', 'matching_bundled_wheel', 'prior_source_paths', 'original_args', 'sealed_input_evidence', 'adjudication', 'evidence']
    with (output / 'adjudication_evidence.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    events = list(csv.DictReader((OUT / 'interventions.csv').open()))
    sources = list(csv.DictReader((OUT / 'source_read_accesses.csv').open()))
    save(review(events, sources))


if __name__ == '__main__':
    main()
