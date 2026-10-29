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
import datetime

ROOT = Path(os.environ['WS_RAW']) / 'replay'
OUT = ROOT.parent.parent / 'replay/results'

def reviewed_annotations():
    path=Path(__file__).with_name('reviewed_interventions.csv')
    return {(r['raw_condition'],r['dynamic_id'],r['timestamp_ns']):r for r in csv.DictReader(path.open())} if path.exists() else {}

def project_reviews():
    path=Path(__file__).with_name('project_action_review.csv')
    return {r['dynamic_id']:r for r in csv.DictReader(path.open())} if path.exists() else {}

def reviewed_cases():
    """Human case judgments apply only to explicitly frozen logs and calls."""
    path=Path(__file__).with_name('reviewed_cases.csv')
    cases={}
    if not path.exists():return cases
    for row in csv.DictReader(path.open()):
        log=ROOT/row['raw_condition']/'dynamic/runs'/row['dynamic_id']/'engine.jsonl'
        if hashlib.sha256(log.read_bytes()).hexdigest()!=row['engine_sha256']:
            raise RuntimeError('Reviewed case engine log changed: '+str(log))
        if row['adjudication'] not in ('false_intervention','true_violation','unknown'):
            raise ValueError('Unsupported reviewed case verdict')
        for index in row['call_indices'].split(';'):
            key=(row['raw_condition'],row['dynamic_id'],index)
            if key in cases:raise ValueError('Overlapping reviewed case calls')
            cases[key]=row
    return cases

def readonly_system_origin(raw_path, started_utc, published):
    """Resolve only unchanged readonly OS sources, preserving raw engine spelling."""
    if not started_utc:return {}
    began=int(datetime.datetime.strptime(started_utc,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()*1000000000)
    names=[(raw_path,'verbatim')]
    try:
        decoded=raw_path.encode('latin1').decode('utf8')
        if decoded!=raw_path and not Path(raw_path).exists() and not Path(raw_path).is_symlink():
            names.append((decoded,'Latin1-to-UTF8 alternate spelling; verbatim path absent'))
    except (UnicodeError,AttributeError):pass
    for name,mapping in names:
        path=Path(name)
        if not name.startswith(('/usr/','/etc/','/lib/')):continue
        try:
            target=path.resolve()
            if not any(target.is_relative_to(Path(prefix)) for prefix in ('/usr','/etc','/lib')):continue
            if not target.is_file():continue
            ctime=max(path.lstat().st_ctime_ns,target.stat().st_ctime_ns)
            if ctime>=began:continue
            digest=hashlib.sha256(target.read_bytes()).hexdigest()
            if digest not in published:continue
            return dict(retained_system_source_path=str(path),retained_system_source_sha256=digest,
                retained_system_source_ctime_ns=ctime,retained_system_source_mapping=mapping)
        except OSError:continue
    return {}

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
    reviewed=reviewed_annotations()
    cases=reviewed_cases()
    projects=project_reviews()
    published={r['member_sha256']:r for r in csv.DictReader((OUT/'public-artifacts.csv').open())} if (OUT/'public-artifacts.csv').exists() else {}
    system_cache={}
    receipt_file=OUT/'readonly-system-source-receipts.csv'
    system_receipts={(r['raw_condition'],r['dynamic_id'],r['source_path']):r for r in csv.DictReader(receipt_file.open())} if receipt_file.exists() else {}
    checked_system_logs={}
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
        project=projects.get(dynamic_id,{})
        applicable=str(event['call_index']) in project.get('call_indices','').split(';')
        row.update(project_verdict=project.get('project_verdict','unknown') if applicable else 'unknown',
            project_evidence=project.get('evidence','') if applicable else 'Actual action not covered by current project review',
            secret_source_provenance='verified_public_artifact' if event['source_sha256'] in published else 'unresolved',
            public_source_artifact=json.dumps(published.get(event['source_sha256'],{}),sort_keys=True))
        run=ROOT/event.get('raw_condition',condition)/'dynamic/runs'/dynamic_id
        done=json.loads((run/'done.json').read_text()) if (run/'done.json').exists() else {}
        key=(event.get('raw_condition',condition),dynamic_id,event['source_path'])
        if key not in system_cache:system_cache[key]=readonly_system_origin(event['source_path'],done.get('started_utc',''),published)
        system=system_cache[key]
        frozen=system_receipts.get(key)
        row['system_source_revalidation']=''
        if frozen:
            # Validate live bytes without replacing the earlier observation's
            # inode timestamps with those of a recreated container filesystem.
            log=run/'engine.jsonl'
            if log not in checked_system_logs:checked_system_logs[log]=hashlib.sha256(log.read_bytes()).hexdigest()
            if checked_system_logs[log]!=frozen['engine_sha256']:
                raise RuntimeError('Frozen readonly source engine log differs')
            for field in ('retained_system_source_sha256','retained_system_source_path','retained_system_source_mapping'):
                if system.get(field)!=frozen[field]:
                    raise RuntimeError('Frozen readonly system source differs from live revalidation: '+field)
            row['system_source_revalidation']='Live bytes/mapped path spelling/mapping match; original pre-restart inode timestamp retained from engine-bound committed receipt'
            system={name:value for name,value in frozen.items() if name.startswith('retained_system_source_')}
        for name in ('retained_system_source_path','retained_system_source_sha256','retained_system_source_ctime_ns','retained_system_source_mapping'):row[name]=system.get(name,'')
        if system:
            row.update(secret_source_provenance='verified_public_readonly_system_artifact',
                public_source_artifact=json.dumps(published[system['retained_system_source_sha256']],sort_keys=True))
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
        annotation=reviewed.get((event.get('raw_condition',condition),dynamic_id,str(event['timestamp_ns'])))
        if not annotation:
            annotation=cases.get((event.get('raw_condition',condition),dynamic_id,str(event['call_index'])))
        if annotation:row.update(adjudication=annotation['adjudication'],evidence=annotation['evidence'])
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
