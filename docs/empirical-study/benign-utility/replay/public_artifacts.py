"""Verify observed CA bytes against public release artifacts, independently of labels."""
import csv
import hashlib
import json
import os
from pathlib import Path
import urllib.request
import zipfile

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
    for package,version,member in RELEASES:
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
    with (OUT/'public-artifacts.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    for row in rows:print(row['package'],row['version'],row['member_sha256'],flush=True)


if __name__=='__main__':main()
