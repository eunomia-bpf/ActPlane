"""Export only small recovery facts without overwriting the original guest epoch."""
import csv
import json
from pathlib import Path
import shutil

root=Path('/workspaces/exp/benign-utility')
raw=root/'raw/benchmark/expanded/vm'
out=root/'benchmark/expanded/vm/results/recovery-20261029T2005'
out.mkdir(parents=True,exist_ok=True)
for name in ('image.json','template.json','workers-launch.json','worker1-environment.json','worker1-environment.csv'):
    shutil.copy2(raw/'recovery-20261029T2005'/name,out/name)
facts=json.loads((raw/'reset-20261029T1954/diagnostic.json').read_text())
mem={line.split(':')[0]: int(line.split()[1]) for line in facts['/proc/meminfo'].splitlines()}
fault=dict(captured_utc=facts['captured_utc'],host_boot_id=facts['/proc/sys/kernel/random/boot_id'].strip(),
    mem_total_kib=mem['MemTotal'],mem_available_kib=mem['MemAvailable'],
    previous_guest_memory_mib=3*24576,recovery_guest_memory_mib=8192,recovery_workers=1,
    global_oom_confirmed='global_oom' in facts['kernel_log']['text'],
    own_pod_group_kill_confirmed='are going to be killed due to memory.oom.group set' in facts['kernel_log']['text'],
    old_runtime_exists=facts['runtime_exists'],kubernetes_status_available='statuses' in facts['kubernetes'],
    source_receipt=str(raw/'reset-20261029T1954/diagnostic.json'))
with (out/'reset-summary.csv').open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(fault));writer.writeheader();writer.writerow(fault)
rows=[{key:value for key,value in row.items() if key!='command'} for row in json.loads((out/'workers-launch.json').read_text())]
with (out/'workers-launch.csv').open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print('Published separate recovery epoch, preserving all original metadata.')
