"""Pause only metadata coordinator while native trial children keep running."""
import argparse,csv,hashlib,json,os,signal,time
from pathlib import Path
from benchmark.expanded.prepare import BASE,RAW,ROOT,prepare

def identity(pid):
    path=Path('/proc')/str(pid)
    text=(path/'stat').read_text().rsplit(')',1)[1].split()
    return dict(pid=pid,starttime=text[19],state=text[0],cmdline=(path/'cmdline').read_bytes().replace(b'\0',b' ').decode())

def main(pid):
    before=identity(pid)
    assert '-m benchmark.expanded.matrix' in before['cmdline']
    children=[]
    for process in Path('/proc').glob('[0-9]*'):
        try:
            data=(process/'stat').read_text().rsplit(')',1)[1].split()
            if int(data[1])==pid and '-m benchmark.expanded.run' in (process/'cmdline').read_bytes().replace(b'\0',b' ').decode():children.append(identity(int(process.name)))
        except OSError:pass
    old_seals={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'task-seals').glob('*.json')}
    assert len(children)==3 and all(c['state']!='Z' for c in children),'Wait for all three worker threads to be blocked in live native trial children'
    receipt=dict(purpose='metadata-only coordinator pause; native trial processes are not signaled',coordinator_before=before,native_children_before=children,begin_utc=time.strftime('%FT%TZ',time.gmtime()),completed=[],skipped_started_or_sealed=[],errors=[])
    target=RAW/'inventory-coordinator-repair.json'
    def save():target.write_text(json.dumps(receipt,indent=2)+'\n')
    def terminate(signum,frame):raise SystemExit('Repair interrupted by signal '+str(signum))
    signal.signal(signal.SIGTERM,terminate);signal.signal(signal.SIGINT,terminate)
    save();os.kill(pid,signal.SIGSTOP)
    try:
        assert identity(pid)['starttime']==before['starttime']
        other=[]
        for process in Path('/proc').glob('[0-9]*'):
            try:
                data=(process/'stat').read_text().rsplit(')',1)[1].split()
                if int(data[1])==pid and int(process.name) not in {c['pid'] for c in children}:other.append(identity(int(process.name)))
            except OSError:pass
        assert not other,'Non-native coordinator child may still mutate shared metadata: '+str(other)
        for fd in (Path('/proc')/str(pid)/'fd').iterdir():
            try:
                path=Path(os.readlink(fd));flags=int(next(x for x in (fd.parent.parent/'fdinfo'/fd.name).read_text().splitlines() if x.startswith('flags:')).split()[1],8)
                assert not (path.is_relative_to(ROOT/'results') and path.suffix=='.csv' and flags & os.O_ACCMODE),'Coordinator stopped with a writable CSV open'
            except (FileNotFoundError,OSError):pass
        receipt['metadata_writer_quiescence_verified']=True;save()
        for task in csv.DictReader((ROOT/'results/tasks.csv').open()):
            if (ROOT/'task-seals'/f"{task['task']}.json").exists():receipt['skipped_started_or_sealed'].append(task['task']);continue
            try:prepare(task['task']);receipt['completed'].append(task['task'])
            except Exception as error:receipt['errors'].append(dict(task=task['task'],error=repr(error)))
            save()
        for path,digest in old_seals.items():assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
    finally:
        if identity(pid)['starttime']==before['starttime']:os.kill(pid,signal.SIGCONT)
        receipt['finished_utc']=time.strftime('%FT%TZ',time.gmtime())
        receipt['coordinator_after']=identity(pid)
        receipt['native_children_after']=[]
        for child in children:
            try:receipt['native_children_after'].append(identity(child['pid']))
            except OSError:receipt['native_children_after'].append(dict(pid=child['pid'],state='already_finished_without_repair_signal'))
        save()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('coordinator_pid',type=int);args=parser.parse_args();main(args.coordinator_pid)
