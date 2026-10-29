"""Pause only this lane's scheduler; an active native trial keeps running."""
import argparse,csv,json,os,signal,time
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark/network')
OUT=RAW.parents[2]/'benchmark/network/results'
parser=argparse.ArgumentParser();parser.add_argument('action',choices=['pause','resume']);parser.add_argument('--reason',default='shared capacity coordination');args=parser.parse_args()
hold=RAW/'admission-hold.json'
if args.action=='pause':
 pid=int((RAW/'matrix.lock').read_text());start=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]
else:
 data=json.loads(hold.read_text());pid=data['pid'];start=data['starttime']
cmd=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
assert b'benchmark.network.matrix' in cmd,'Refuse to signal a different/reused PID'
assert Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]==start,'Scheduler identity changed'
os.kill(pid,signal.SIGSTOP if args.action=='pause' else signal.SIGCONT)
row=dict(utc=time.strftime('%FT%TZ',time.gmtime()),action=args.action,pid=pid,starttime=start,reason=args.reason,scope='scheduler only; native child not signaled')
if args.action=='pause':hold.write_text(json.dumps(row,indent=2)+'\n')
receipt=OUT/'admission-holds.csv';exists=receipt.exists()
with receipt.open('a',newline='') as handle:
 writer=csv.DictWriter(handle,fieldnames=list(row))
 if not exists:writer.writeheader()
 writer.writerow(row)
print(json.dumps(row),flush=True)
