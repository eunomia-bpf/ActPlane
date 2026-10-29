"""Retain read-only reset/resource evidence without exposing credentials."""
import datetime
import csv
import json
import os
from pathlib import Path
import socket
import subprocess
import urllib.request
import ssl

out = Path('/workspaces/exp/benign-utility/raw/benchmark/expanded/vm/reset-20261029T1954')
out.mkdir(parents=True, exist_ok=True)
facts = {'captured_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
for name in ('/proc/1/stat', '/proc/1/cgroup', '/proc/self/cgroup', '/proc/self/mountinfo',
             '/proc/meminfo', '/proc/sys/kernel/random/boot_id', '/proc/uptime'):
    try: facts[name] = Path(name).read_text()
    except OSError as e: facts[name] = str(e)
for key, args in {
    'processes': ['ps', '-eo', 'pid,ppid,lstart,rss,args'],
    'filesystems': ['df', '-h', '/workspaces', '/tmp'],
    'mounts': ['findmnt', '-R', '/sys/fs/cgroup'],
    'kernel_log': ['dmesg', '--ctime'],
}.items():
    p = subprocess.run(args, text=True, capture_output=True)
    text = p.stdout + p.stderr
    if key == 'processes':
        text = '\n'.join(line for line in text.splitlines()
                         if any(x in line.lower() for x in ('qemu', 'matrix', 'coordinator', 'sshd', 'init', 'supervis', 'coder')))
    if key == 'kernel_log':
        text = '\n'.join(line for line in text.splitlines() if any(x in line.lower() for x in ('oom', 'out of memory', 'killed process', 'memory cgroup')))[-25000:]
    facts[key] = {'returncode': p.returncode, 'text': text}
facts['runtime_exists'] = Path('/tmp/benign-utility-vm').exists()
facts['runtime_files'] = [p.name for p in Path('/tmp/benign-utility-vm').glob('*')]
facts['cgroup_files'] = {}
cg = Path('/sys/fs/cgroup')
relative = Path('/proc/self/cgroup').read_text().strip().split('::')[-1].lstrip('/')
current = cg / relative
while current == cg or cg in current.parents:
    for name in ('memory.max','memory.events','memory.current','memory.peak','memory.swap.max','memory.high','memory.stat','cgroup.events'):
        path = current / name
        try: facts['cgroup_files'][str(path)] = path.read_text()
        except OSError as e: facts['cgroup_files'][str(path)] = str(e)
    if current == cg: break
    current = current.parent
sa = Path('/var/run/secrets/kubernetes.io/serviceaccount')
facts['kubernetes'] = {'hostname': socket.gethostname(), 'serviceaccount_available': (sa/'token').exists()}
if (sa/'token').exists():
    try:
        namespace = (sa/'namespace').read_text().strip()
        url = 'https://' + os.environ.get('KUBERNETES_SERVICE_HOST', 'kubernetes.default.svc') + ':' + os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS', '443')
        req = urllib.request.Request(url+'/api/v1/namespaces/'+namespace+'/pods/'+socket.gethostname(),
            headers={'Authorization': 'Bearer '+(sa/'token').read_text().strip()})
        with urllib.request.urlopen(req, context=ssl.create_default_context(cafile=str(sa/'ca.crt')), timeout=10) as response:
            pod = json.load(response)
        facts['kubernetes'].update(namespace=namespace, uid=pod['metadata']['uid'],
            created=pod['metadata'].get('creationTimestamp'), node=pod['spec'].get('nodeName'),
            qos=pod['status'].get('qosClass'), statuses=pod['status'].get('containerStatuses'),
            resources=[{'name': c['name'], 'resources': c.get('resources')} for c in pod['spec']['containers']])
    except Exception as e:
        facts['kubernetes']['error'] = str(e)
(out/'diagnostic.json').write_text(json.dumps(facts, indent=2)+'\n')
mem = {line.split(':')[0]: int(line.split()[1]) for line in facts['/proc/meminfo'].splitlines()}
row = dict(captured_utc=facts['captured_utc'],host_boot_id=facts['/proc/sys/kernel/random/boot_id'].strip(),
    mem_total_kib=mem['MemTotal'],mem_available_kib=mem['MemAvailable'],
    previous_guest_memory_mib=3*24576,recovery_guest_memory_mib=8192,recovery_workers=1,
    global_oom_confirmed='global_oom' in facts['kernel_log']['text'],
    own_pod_group_kill_confirmed='are going to be killed due to memory.oom.group set' in facts['kernel_log']['text'],
    old_runtime_exists=facts['runtime_exists'],kubernetes_status_available='statuses' in facts['kubernetes'],
    source_receipt=str(out/'diagnostic.json'))
with (out/'reset-summary.csv').open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(row));writer.writeheader();writer.writerow(row)
print(json.dumps({key:value for key,value in facts.items() if key not in ('/proc/self/mountinfo',)}, indent=2))
