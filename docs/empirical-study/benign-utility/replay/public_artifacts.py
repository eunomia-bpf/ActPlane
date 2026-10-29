"""Verify observed CA bytes against public release artifacts, independently of labels."""
import csv
import hashlib
import json
import os
from pathlib import Path
import urllib.request
import zipfile
import subprocess
import tarfile
import io
import re
import tomllib

ROOT=Path(os.environ['WS_RAW'])/'replay'
OUT=ROOT.parent.parent/'replay/results'
# Versions observed in retained installed METADATA / frozen ensurepip inputs.
RELEASES=(('pip','23.0.1','pip/_vendor/certifi/cacert.pem'),
          ('certifi','2026.10.23','certifi/cacert.pem'),
          ('grpcio','1.85.0','grpc/_cython/_credentials/roots.pem'))

def capacity(needed=0):
    space=os.statvfs(ROOT)
    used=(space.f_blocks-space.f_bavail)*space.f_frsize
    if used+needed>=space.f_blocks*space.f_frsize*.85:
        raise RuntimeError('workspace85percent capacity guard before public artifact download')


def main():
    directory=ROOT/'public-artifacts';directory.mkdir(exist_ok=True)
    rows=[]
    # t00's pinned uv.lock supplies the versions for its distinct public trust
    # bundles and packaged test/public keys. Public provenance alone does not
    # establish the eventual action-level intervention judgment.
    plan=next(r for r in csv.DictReader((ROOT/'harness/dynamic_plan.csv').open()) if r['dynamic_id']=='t00')
    lock=subprocess.check_output(['git','--git-dir',str(ROOT/'input/dynamic/git-cache'/plan['repository'].replace('/','__')),
                                  'show',plan['base_commit']+':uv.lock'])
    versions={r['name']:r['version'] for r in tomllib.loads(lock.decode())['package']}
    members={'certifi':'certifi/cacert.pem','grpcio':'grpc/_cython/_credentials/roots.pem',
             'botocore':'botocore/cacert.pem','litellm':'litellm/proxy/auth/public_key.pem',
             'tornado':'tornado/test/test.key'}
    releases=list(RELEASES)+[(package,versions[package],member) for package,member in members.items()]
    for package,version,member in releases:
        url=f'https://pypi.org/pypi/{package}/{version}/json'
        metadata=directory/f'{package}-{version}.json'
        if not metadata.exists():
            capacity()
            with urllib.request.urlopen(url,timeout=60) as response:metadata.write_bytes(response.read())
        release=json.loads(metadata.read_text())
        wheels=[r for r in release['urls'] if r['filename'].endswith('.whl')]
        # A byte match to any published artifact establishes that data's public
        # provenance; it need not assert the installed wheel's platform tag.
        artifact=min(wheels,key=lambda r:(not r['filename'].endswith('none-any.whl'),
            not ('cp313-cp313-manylinux' in r['filename'] and 'x86_64' in r['filename']),r['size']))
        wheel=directory/artifact['filename']
        if not wheel.exists():
            capacity(artifact['size'])
            with urllib.request.urlopen(artifact['url'],timeout=120) as response:wheel.write_bytes(response.read())
        actual=hashlib.sha256(wheel.read_bytes()).hexdigest()
        if actual!=artifact['digests']['sha256']:raise RuntimeError('public artifact SHA256 differs from official release metadata')
        with zipfile.ZipFile(wheel) as archive:data=archive.read(member)
        rows.append(dict(package=package,version=version,metadata_url=url,
            metadata_sha256=hashlib.sha256(metadata.read_bytes()).hexdigest(),
            artifact_filename=wheel.name,artifact_url=artifact['url'],artifact_sha256=actual,
            member=member,member_sha256=hashlib.sha256(data).hexdigest(),member_bytes=len(data),
            verification='whole-artifact SHA256 matches official PyPI metadata; member bytes hashed independently'))
    # The readonly OS trust store is also a concrete source in native Node
    # traces. Download its existing public distribution package, never install.
    package='ca-certificates'
    version=subprocess.check_output(['dpkg-query','-W','-f=${Version}',package],text=True).strip()
    listing=subprocess.check_output(['apt-cache','show',package+'='+version],text=True)
    fields=dict(line.split(': ',1) for line in listing.splitlines() if ': ' in line and not line.startswith(' '))
    metadata=directory/(package+'-'+version+'.apt.txt');metadata.write_text(listing)
    url='https://deb.debian.org/debian/'+fields['Filename']
    artifact=directory/Path(fields['Filename']).name
    if not artifact.exists():
        capacity(int(fields['Size']))
        with urllib.request.urlopen(url,timeout=120) as response:artifact.write_bytes(response.read())
    actual=hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual!=fields['SHA256']:raise RuntimeError('CA distribution package differs from retained APT metadata')
    payload=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(artifact)])
    certificate_blocks=set()
    pem=re.compile(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',re.S)
    with tarfile.open(fileobj=io.BytesIO(payload),mode='r:') as archive:
        for entry in archive:
            if not entry.isfile() or not entry.name.startswith('./usr/share/ca-certificates/mozilla/') or not entry.name.endswith('.crt'):continue
            data=archive.extractfile(entry).read()
            certificate_blocks.update(pem.findall(data))
            rows.append(dict(package=package,version=version,metadata_url='retained APT package metadata',
                metadata_sha256=hashlib.sha256(metadata.read_bytes()).hexdigest(),artifact_filename=artifact.name,
                artifact_url=url,artifact_sha256=actual,member=entry.name,member_sha256=hashlib.sha256(data).hexdigest(),member_bytes=len(data),
                verification='public Debian distribution package SHA256 matches retained APT metadata; certificate member independently hashed'))
    bundle=Path('/etc/ssl/certs/ca-certificates.crt')
    if bundle.exists():
        data=bundle.read_bytes();blocks=pem.findall(data)
        unmatched=[block for block in blocks if block not in certificate_blocks]
        if blocks and not unmatched and not pem.sub(b'',data).strip():
            rows.append(dict(package=package,version=version,metadata_url='retained APT package metadata',
                metadata_sha256=hashlib.sha256(metadata.read_bytes()).hexdigest(),artifact_filename=artifact.name,
                artifact_url=url,artifact_sha256=actual,member='generated readonly '+str(bundle),
                member_sha256=hashlib.sha256(data).hexdigest(),member_bytes=len(data),
                verification='Every complete PEM certificate block equals a public package block; all remaining bundle bytes are whitespace'))
        else:print('Readonly CA bundle has unmatched certificate blocks:',len(unmatched),flush=True)
    go_env=Path('/usr/bin/go').resolve().parent.parent/'go.env'
    if go_env.exists():
        package=subprocess.check_output(['dpkg-query','-S',str(go_env)],text=True).split(': ',1)[0]
        version=subprocess.check_output(['dpkg-query','-W','-f=${Version}',package],text=True).strip()
        listing=subprocess.check_output(['apt-cache','show',package+'='+version],text=True)
        fields=dict(line.split(': ',1) for line in listing.splitlines() if ': ' in line and not line.startswith(' '))
        metadata=directory/(package.replace(':','_')+'-'+version+'.apt.txt');metadata.write_text(listing)
        url='https://deb.debian.org/debian/'+fields['Filename'];artifact=directory/Path(fields['Filename']).name
        if not artifact.exists():
            capacity(int(fields['Size']))
            with urllib.request.urlopen(url,timeout=120) as response:artifact.write_bytes(response.read())
        actual=hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual!=fields['SHA256']:raise RuntimeError('Go distribution package differs from retained APT metadata')
        payload=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(artifact)])
        with tarfile.open(fileobj=io.BytesIO(payload),mode='r:') as archive:
            member='.'+str(go_env);data=archive.extractfile(member).read()
        rows.append(dict(package=package,version=version,metadata_url='retained APT package metadata',
            metadata_sha256=hashlib.sha256(metadata.read_bytes()).hexdigest(),artifact_filename=artifact.name,
            artifact_url=url,artifact_sha256=actual,member=member,member_sha256=hashlib.sha256(data).hexdigest(),member_bytes=len(data),
            verification='public Debian distribution package SHA256 matches retained APT metadata; go.env member independently hashed'))
    with (OUT/'public-artifacts.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    print('Verified public members:',len(rows),'packages:',', '.join(sorted({r['package'] for r in rows})),flush=True)


if __name__=='__main__':main()
