"""Export all native setup-only failures/successes without giving them task scores."""
import csv,json
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark/network')
OUT=BASE.parents[2]/'benchmark/network/results'
rows=[]
for result in sorted((BASE/'instrumentation-preflights').glob('*/*/result.json')):
 native=json.loads(result.read_text());receipt=result.parent/'agent/instrumentation-preflight.json'
 evidence=json.loads(receipt.read_text()) if receipt.exists() else {}
 exception=native.get('exception_info') or {}
 assert native.get('agent_execution') is None and native.get('verifier_result') is None,'Setup-only control unexpectedly entered task execution'
 rows.append(dict(job=result.parent.parent.name,trial_id=result.parent.name,passed=int(evidence.get('passed') is True),exception_type=exception.get('exception_type',''),exception_message=exception.get('exception_message',''),agent_run_entered=0,task_verifier_entered=0,trace_verified=evidence.get('trace_verified','not_established'),detach_background_pid_check=evidence.get('detach_preserved_background_child','not_established'),kernel_root_pid=evidence.get('kernel_root_pid',''),workspace_root_pid=evidence.get('workspace_root_pid',''),container_root_pid=evidence.get('container_root_pid',''),native_result=str(result),receipt_path=str(receipt) if receipt.exists() else '',metric_admission='excluded setup-only preflight; not a task outcome'))
if rows:
 with (OUT/'instrumentation-preflights.csv').open('w',newline='') as handle:
  writer=csv.DictWriter(handle,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print('Native setup-only receipts',len(rows),'passed',sum(r['passed'] for r in rows))
