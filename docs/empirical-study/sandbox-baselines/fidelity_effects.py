#!/usr/bin/env python3
"""Observe the original worker without changing its execution or tool code."""
import csv
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys

from study import RAW, SOURCE_RAW, HERE, dump, manifest, replay
from analyze import load, logtext, tools, writecsv
from effect_oracle import evaluate

def observe(payload):
    out=Path(payload['out']); sd=Path(payload['statement'])
    replay.ROOT=Path('/workspaces/lanes/translation-models')
    original_copy=replay.copy_fixture
    original_remove=replay.remove_checkout
    def copied(source,work,archive=None):
        original_copy(source,work,archive)
        dump(out/'before.json',manifest(work))
    def removed(work):
        if work.exists():dump(out/'after.json',manifest(work))
        original_remove(work)
    # Observe only the trusted coordinator's fixture lifetime. The original
    # worker, namespaces, environment and all tool statements execute unchanged.
    replay.copy_fixture=copied
    replay.remove_checkout=removed
    row=replay.replay_one(SOURCE_RAW,sd,Path(payload['trace']),'fidelity-effects',
        'source AGENT = exec "python3"\nrule audit:\n notify exec "__never__" if AGENT\n because "control"',
        out,no_engine=True)
    if row['status']!='ok':raise RuntimeError(row['error'])

def main():
    if len(sys.argv)>1:
        observe(json.loads(Path(sys.argv[1]).read_text()));return
    results=[]
    for s in sorted((SOURCE_RAW/'artifact/docs/corpus-test').glob('*/*/statement.json')):
        sd=s.parent
        for name in json.loads(s.read_text())['trace_files']:
            out=RAW/'fidelity-effects'/sd.parent.name/sd.name/Path(name).stem
            out.mkdir(parents=True,exist_ok=True)
            if not (out/'result.json').exists():
                payload=dict(statement=str(sd),trace=str(sd/name),out=str(out))
                dump(out/'payload.json',payload)
                p=subprocess.run(['strace','-f','-qq','-s','2000','-e','trace=%file,%process',
                    '-o',str(out/'syscalls.log'),'python3',str(HERE/'fidelity_effects.py'),str(out/'payload.json')],
                    text=True,capture_output=True,timeout=300,
                    env=dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME='/root',LANG='C.UTF-8'))
                (out/'stderr.txt').write_text(p.stderr)
                if p.returncode:raise RuntimeError(p.stderr)
            records=[json.loads(x) for x in (sd/name).read_text().splitlines()]
            original=evaluate(sd.parent.name,sd.name,records,load(out/'before.json'),load(out/'after.json'),logtext(out/'syscalls.log'),tools(out/'tools.jsonl'))
            control=RAW/'final/control'/sd.parent.name/sd.name/Path(name).stem
            adapted=evaluate(sd.parent.name,sd.name,records,load(control/'before.json'),load(control/'after.json'),logtext(control/'syscalls.log'),tools(control/'tools.jsonl'))
            results.append(dict(repo=sd.parent.name,statement_id=sd.name,trace=name,
                violation=int(records[0]['violation']),original_effect=original['effect_observed'],
                adapter_effect=adapted['effect_observed'],effect_equal=int(original['effect_observed']==adapted['effect_observed']),
                original_evidence=original['evidence'],adapter_evidence=adapted['evidence']))
            for file in ('before.json','after.json','syscalls.log'):
                p=out/file
                if p.exists():
                    with p.open('rb') as src,gzip.open(str(p)+'.gz','wb',compresslevel=3) as dst:
                        import shutil
                        shutil.copyfileobj(src,dst)
                    p.unlink()
    writecsv('fidelity-effects.csv',results)
    print('original/adapted effects equal',sum(r['effect_equal'] for r in results),'/',len(results),flush=True)

if __name__=='__main__':main()
