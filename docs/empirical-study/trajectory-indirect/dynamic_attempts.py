#!/usr/bin/env python3
"""Account for primary, pilot, invalidated-development and instrumentation attempts."""
import argparse
import csv
import json
from pathlib import Path

from analyze import HERE,write_csv
from dynamic_effects import parse_observer


def summarize(raw):
    plans={p['dynamic_id']:p for p in csv.DictReader((HERE/'dynamic_plan.csv').open())}
    rows=[]
    for scope in ('pilot-runs','diagnostic-runs-v1','environment-attempts','instrumentation-attempts','runs'):
        for receipt in sorted((raw/'dynamic'/scope).glob('*/done.json')):
            run=receipt.parent;done=json.loads(receipt.read_text())
            plan=plans[done['dynamic_id']]
            counts,bytes_,errors=parse_observer(run/'observer.jsonl')
            records=[json.loads(line) for line in (run/'calls.jsonl').read_text().splitlines()] if (run/'calls.jsonl').exists() else []
            retry=json.loads((run/'retry_reason.json').read_text()) if (run/'retry_reason.json').exists() else {}
            metadata=json.loads((run/'observer_metadata.json').read_text()) if (run/'observer_metadata.json').exists() else {}
            rows.append(dict(scope=scope,primary=int(scope=='runs'),dynamic_id=done['dynamic_id'],
                trajectory_id=done['trajectory_id'],framework=plan['framework'],model=plan['model'],
                receipt=str(receipt.relative_to(raw)),recorded_calls=done['recorded_calls'],executed_calls=done['executed_calls'],
                completed_call_receipts=len(records),observed_dispatcher_tags=len({tag for tag,kind,path in counts if kind==9}),
                exit_zero_calls=sum(r.get('exit_code')==0 for r in records),fatal=done['fatal'],
                setup_steps=done['setup_steps'],setup_failed_steps=done['setup_failed_steps'],
                observer_exit=done['observer_exit'],observer_errors=len(errors),observer_error_detail='; '.join(errors[:10]),
                observer_string_bytes=metadata.get('config',{}).get('observer_string_bytes',''),
                observer_sha256=metadata.get('observer_sha256',''),
                exclusion_reason='' if scope=='runs' else retry.get('reason') or done.get('invalidated_reason') or 'Development pilot. Not part of final effect estimates.',
                elapsed_s=done['elapsed_s'],finished_utc=done['finished_utc']))
    write_csv(HERE/'dynamic_attempts.csv',rows)
    print(f'Accounted for {len(rows)} attempts; {sum(r["primary"] for r in rows)} primary replay receipts')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    summarize(p.parse_args().raw)
