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
            out=RAW/'fidelity-files'/sd.parent.name/sd.name/Path(name).stem
            out.mkdir(parents=True,exist_ok=True)
            if not (out/'result.json').exists():
                payload=dict(statement=str(sd),trace=str(sd/name),out=str(out))
                dump(out/'payload.json',payload)
                p=subprocess.run(['python3',str(HERE/'fidelity_effects.py'),str(out/'payload.json')],
                    text=True,capture_output=True,timeout=300,
                    env=dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME='/root',LANG='C.UTF-8'))
                (out/'stderr.txt').write_text(p.stderr)
                if p.returncode:raise RuntimeError(p.stderr)
            records=[json.loads(x) for x in (sd/name).read_text().splitlines()]
            control=RAW/'final/control'/sd.parent.name/sd.name/Path(name).stem
            def changed_paths(directory):
                before,after=load(directory/'before.json'),load(directory/'after.json')
                if before is None or after is None:raise RuntimeError('missing fidelity filesystem observation')
                ignored=('.eval-safe-bin/','.eval-fixtures/','.eval-home/')
                def content(r):return (r or {}).get('sha256',(r or {}).get('link'))
                return sorted(p for p in before.keys()|after.keys() if not p.startswith(ignored)
                    and (content(before.get(p))!=content(after.get(p)) or ((p in before)!=(p in after))))
            original,adapted=changed_paths(out),changed_paths(control)
            differences=set(original)^set(adapted)
            git_only=bool(differences) and all(p.startswith('.git/objects/') for p in differences)
            if any(not p.startswith('.git/objects/') for p in differences):
                print('non-object path difference',sd.parent.name,sd.name,name,sorted(differences),flush=True)
                for location in (out,control):
                    print(location,[(t.get('stdout','')[-1500:],t.get('stderr','')[-1500:])
                          for t in tools(location/'tools.jsonl') if t['tool']=='Bash'],flush=True)
            results.append(dict(repo=sd.parent.name,statement_id=sd.name,trace=name,
                violation=int(records[0]['violation']),changed_paths_equal=int(original==adapted),
                changed_paths_equal_without_git_objects=int({p for p in original if not p.startswith('.git/objects/')}=={p for p in adapted if not p.startswith('.git/objects/')}),
                difference_reason='git object names only' if git_only else 'none' if not differences else 'other changed paths',
                original_changed=json.dumps(original),adapter_changed=json.dumps(adapted)))
            for file in ('before.json','after.json','syscalls.log'):
                p=out/file
                if p.exists():
                    with p.open('rb') as src,gzip.open(str(p)+'.gz','wb',compresslevel=3) as dst:
                        import shutil
                        shutil.copyfileobj(src,dst)
                    p.unlink()
    writecsv('fidelity-files.csv',results)
    print('original/adapted persistent changed paths equal',sum(r['changed_paths_equal'] for r in results),'/',len(results),flush=True)
    print('equal excluding git object names',sum(r['changed_paths_equal_without_git_objects'] for r in results),'/',len(results),flush=True)

if __name__=='__main__':main()
