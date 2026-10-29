"""Verified public verifier dependencies; official task and test bytes stay intact."""
import argparse
import csv
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request
from urllib.parse import quote

BASE = Path('/workspaces/exp/benign-utility/raw/benchmark')
ROOT = BASE / 'dependencies'
PUBLIC = ROOT / 'public'
VERSION = '0.9.5'
ARCHIVE = 'uv-x86_64-unknown-linux-gnu.tar.gz'
RELEASE = f'https://github.com/astral-sh/uv/releases/download/{VERSION}'
PYTHON_BUILD = '20251014'
PYTHON_ARCHIVE = 'cpython-3.13.9+20251014-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz'
PYTHON_RELEASE = f'https://github.com/astral-sh/python-build-standalone/releases/download/{PYTHON_BUILD}'
HOST = '172.29.77.1'  # Existing lane Docker bridge gateway, no daemon changes.
PORT = 38765
URL = f'http://{HOST}:{PORT}'
TASKS = ('cancel-async-tasks', 'git-leak-recovery', 'log-summary-date-ranges',
         'openssl-selfsigned-cert', 'sanitize-git-repo', 'vulnerable-secret')


def download(url, target):
    if target.exists():
        return
    temporary = target.with_suffix(target.suffix + '.partial')
    subprocess.run(['curl', '-fLsS', '--retry', '2', '-o', str(temporary), url], check=True)
    temporary.replace(target)


def prepare_python():
    folder = PUBLIC / 'python' / PYTHON_BUILD
    folder.mkdir(parents=True, exist_ok=True)
    download(f'{PYTHON_RELEASE}/SHA256SUMS', folder / 'SHA256SUMS')
    expected = next(line.split()[0] for line in (folder / 'SHA256SUMS').read_text().splitlines()
                    if line.split()[-1].lstrip('*') == PYTHON_ARCHIVE)
    artifact_url = f'{PYTHON_RELEASE}/{quote(PYTHON_ARCHIVE)}'
    download(artifact_url, folder / PYTHON_ARCHIVE)
    actual = hashlib.sha256((folder / PYTHON_ARCHIVE).read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError('Official default Python runtime checksum mismatch')
    (ROOT / 'python-provenance.json').write_text(json.dumps(dict(
        version='3.13.9', build=PYTHON_BUILD, archive=PYTHON_ARCHIVE, sha256=actual,
        official_artifact_url=artifact_url, checksum_url=f'{PYTHON_RELEASE}/SHA256SUMS',
        env='UV_PYTHON_INSTALL_MIRROR',
        supported_by='https://github.com/astral-sh/uv/blob/0.9.5/crates/uv-static/src/env_vars.rs#L398-L403',
    ), indent=2))


def prepare():
    stat = os.statvfs('/workspaces')
    if 1 - stat.f_bavail / stat.f_blocks >= .85:
        raise RuntimeError('Shared disk at or above 85%; defer dependency downloads')
    PUBLIC.mkdir(parents=True, exist_ok=True)
    for name in (ARCHIVE, ARCHIVE + '.sha256'):
        download(f'{RELEASE}/{name}', PUBLIC / name)
    expected = (PUBLIC / (ARCHIVE + '.sha256')).read_text().split()[0]
    actual = hashlib.sha256((PUBLIC / ARCHIVE).read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError('Official uv release checksum mismatch')
    download(f'https://astral.sh/uv/{VERSION}/install.sh', PUBLIC / 'install.sh')
    provenance = dict(version=VERSION, archive=ARCHIVE, official_release=RELEASE,
        sha256=actual, official_checksum_url=f'{RELEASE}/{ARCHIVE}.sha256',
        installer_url=f'https://astral.sh/uv/{VERSION}/install.sh',
        installer_sha256=hashlib.sha256((PUBLIC / 'install.sh').read_bytes()).hexdigest())
    (ROOT / 'provenance.json').write_text(json.dumps(provenance, indent=2))
    prepare_python()
    try:
        with urllib.request.urlopen(f'{URL}/{ARCHIVE}.sha256', timeout=3) as response:
            if response.read().decode().split()[0] != expected:
                raise RuntimeError('Existing dependency listener serves a different checksum')
    except OSError:
        with (ROOT / 'server.log').open('a') as stream:
            server = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()), '--serve'],
                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        (ROOT / 'server.pid').write_text(str(server.pid))
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError('Private public-artifact server failed to start')
            try:
                with urllib.request.urlopen(f'{URL}/{ARCHIVE}.sha256', timeout=1) as response:
                    if response.read().decode().split()[0] == expected:
                        return
            except OSError:
                time.sleep(.1)
        raise RuntimeError('Private public-artifact server did not become ready')


def verifier_env():
    """Native JobConfig verifier.env override for uv installer public transport."""
    prepare()
    return {'UV_DOWNLOAD_URL': URL, 'UV_PYTHON_INSTALL_MIRROR': URL + '/python'}


def control(image):
    env = verifier_env()
    folder = ROOT / ('control-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
    folder.mkdir(exist_ok=True)
    (folder / 'test_dependencies.py').write_text(
        'import importlib.metadata, json, platform, sys\n'
        'from pathlib import Path\n'
        'def test_exact_packages():\n'
        '    assert sys.version_info[:2] == (3, 13)\n'
        '    Path("/control/runtime.json").write_text(json.dumps(dict(version=platform.python_version(), executable=sys.executable)))\n'
        '    for name, version in (("pytest", "8.4.1"), ("pytest-json-ctrf", "0.3.5"), ("gitpython", "3.1.44")):\n'
        '        assert importlib.metadata.version(name) == version\n')
    command = (
        'set -e; apt-get update; apt-get install -y curl; '
        'curl -LsSf https://astral.sh/uv/0.9.5/install.sh | sh; '
        'source $HOME/.local/bin/env; uv --version; uv python list --only-installed; '
        'uvx -p 3.13 -w pytest==8.4.1 -w gitpython==3.1.44 '
        '-w pytest-json-ctrf==0.3.5 pytest --ctrf /control/ctrf.json '
        '/control/test_dependencies.py -rA'
    )
    docker_env = {**os.environ, 'DOCKER_HOST': 'unix://' + str(BASE / 'docker.sock'),
                  'DOCKER_CONFIG': str(BASE / 'docker-config')}
    args = ['docker', 'run', '--rm', '--name', 'bu-verifier-dependency-control',
            '--env', 'UV_DOWNLOAD_URL=' + env['UV_DOWNLOAD_URL'],
            '--env', 'UV_PYTHON_INSTALL_MIRROR=' + env['UV_PYTHON_INSTALL_MIRROR'],
            '--volume', str(folder) + ':/control', '--workdir', '/app', image, 'bash', '-lc', command]
    with (folder / 'stdout.txt').open('w') as stream:
        result = subprocess.run(args, env=docker_env, stdout=stream, stderr=subprocess.STDOUT)
    ctrf = json.loads((folder / 'ctrf.json').read_text()) if (folder / 'ctrf.json').exists() else {}
    summary = ctrf.get('results', {}).get('summary', {})
    row = dict(control='dependency-only, not benchmark task', image=image,
        raw_path=str(folder), uv_version=VERSION, pytest_version='8.4.1', ctrf_plugin_version='0.3.5',
        gitpython_version='3.1.44', returncode=result.returncode,
        tests=summary.get('tests', 0), passed=summary.get('passed', 0),
        uv_sha256=json.loads((ROOT / 'provenance.json').read_text())['sha256'])
    runtime_path = folder / 'runtime.json'
    runtime = json.loads(runtime_path.read_text()) if runtime_path.exists() else {}
    row.update(python_runtime=runtime.get('version', ''), python_executable=runtime.get('executable', ''),
        python_mirror=env['UV_PYTHON_INSTALL_MIRROR'],
        python_archive_sha256=json.loads((ROOT / 'python-provenance.json').read_text())['sha256'])
    evidence = BASE.parent.parent / 'benchmark/cli/results'
    evidence.mkdir(parents=True, exist_ok=True)
    proof = evidence / 'dependency-control.csv'
    previous = list(csv.DictReader(proof.open())) if proof.exists() else []
    with proof.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row), lineterminator='\n')
        writer.writeheader(); writer.writerows(previous + [row])
    shutil.copyfile(ROOT / 'python-provenance.json', evidence / 'dependency-python-provenance.json')
    inventory = []
    for task in TASKS:
        text = (BASE / 'terminal-bench-2' / task / 'tests/test.sh').read_text()
        inventory.append(dict(task=task, test_sha256=hashlib.sha256(text.encode()).hexdigest(),
            uv_version=VERSION, python='3.13', pytest='8.4.1', ctrf_plugin='0.3.5',
            extra='gitpython==3.1.44' if 'gitpython==3.1.44' in text else '',
            ctrf_path='/logs/verifier/ctrf.json'))
    with (evidence / 'verifier-dependencies.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(inventory[0]))
        writer.writeheader(); writer.writerows(inventory)
    print(json.dumps(row), flush=True)
    if result.returncode or summary.get('passed') != 1:
        raise RuntimeError('Exact verifier dependency control did not pass; inspect raw stdout')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--serve', action='store_true')
    parser.add_argument('--control-image')
    args = parser.parse_args()
    if args.serve:
        handler = functools.partial(SimpleHTTPRequestHandler, directory=str(PUBLIC))
        ThreadingHTTPServer((HOST, PORT), handler).serve_forever()
    elif args.control_image:
        control(args.control_image)
    else:
        print(json.dumps(verifier_env()))
