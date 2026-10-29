#!/usr/bin/env python3
"""Check the retained, namespace-isolated observer calibration and diagnostics.

The calibration command was run with launch apti6e999999 inside bubblewrap:
  printf visible > direct.txt
  Python writes hidden.txt, writev([a,b]) + pwrite(c) to vector.txt,
  truncates hidden.txt, execs /bin/true and /bin/false, and uses
  os.copy_file_range to copy one byte into copied.txt.
The first /bin/bash dispatcher exec is observed separately and excluded.
"""
import argparse
import hashlib
from pathlib import Path

from analyze import HERE,write_csv
from dynamic_effects import parse_observer


def check(raw,evidence=None):
    evidence=evidence or raw/'dynamic/calibration/observer-identity.jsonl'
    counts,byte_counts,errors=parse_observer(evidence)
    expected={(1,'/project/direct.txt'):1,(1,'/project/hidden.txt'):1,(1,'/project/vector.txt'):2,(1,'/project/copied.txt'):1,
              (2,'/usr/bin/python3'):1,(2,'/bin/true'):1,(2,'/bin/false'):1,(3,'/project/hidden.txt'):1,(9,'/bin/bash'):1}
    rows=[]
    for (kind,path),want in expected.items():
        got=counts.get(('apti6e999999',kind,path),0)
        rows.append(dict(probe_case='namespace-scalar-vector-pwrite-copy-truncate-descendants',kind=kind,path=path,
                         expected=want,observed=got,observed_bytes=byte_counts.get(('apti6e999999',kind,path),0),
                         passed=int(got==want),observer_sha256=hashlib.sha256((HERE/'observer.bt').read_bytes()).hexdigest(),
                         evidence=str(evidence.relative_to(raw))))
    false_writes=sum(n for (tag,kind,path),n in counts.items() if tag=='apti6e999998' and kind==1)
    rows.append(dict(probe_case='preallocation-followed-by-stdout-is-not-data-write',kind=1,path='allocated-only',
                     expected=0,observed=false_writes,observed_bytes=0,passed=int(false_writes==0),
                     observer_sha256=hashlib.sha256((HERE/'observer.bt').read_bytes()).hexdigest(),
                     evidence=str(evidence.relative_to(raw))))
    if (evidence.parent/'failed-write.sh').exists():
        failed_writes=sum(n for (tag,kind,path),n in counts.items() if tag=='apti6e999997' and kind==1)
        rows.append(dict(probe_case='zero-byte-and-rejected-regular-file-writes-are-excluded',kind=1,path='failed-write.txt',
                         expected=0,observed=failed_writes,observed_bytes=0,passed=int(failed_writes==0),
                         observer_sha256=hashlib.sha256((HERE/'observer.bt').read_bytes()).hexdigest(),
                         evidence=str(evidence.relative_to(raw))))
    assert not errors and all(r['passed'] for r in rows),'calibration failed'
    write_csv(HERE/'dynamic_calibration.csv',rows)
    preflight=[
        ('bpftrace_begin','passed','Host BPF programs can load.'),
        ('path_at_kprobe','failed','bpf_d_path is restricted at arbitrary VFS probes; moved path capture to security_file_permission.'),
        ('namespace_tid_builtin','failed','Namespace-relative tid emitted EINVAL outside the container; now use curtask->pid in the initial namespace.'),
        ('vectored_write_coverage','failed_then_corrected','Added vfs_writev, copy_file_range, sendfile and clone hooks after calibration exposed missing writev.'),
        ('development_pilot_map_capacity','failed','A development pilot exceeded 65536 keys. Main capacity increased to 262144; overflow diagnostics retained in pilot outputs.'),
        ('development_pilot_cache_policy','corrected','Shared cache made paired cases warm. Main runs use private caches with disposable dependency trees.'),
        ('negative_preallocation_stdout','failed_then_corrected','Preallocation left a stale permission-path cache. File-identity guards prevent later stdout writes from being assigned to that file. Earlier replay batches are retained as diagnostics and the same fixed cohort is rerun.'),
        ('sandbox_calibration','passed','Observed scalar, vectored, positioned, copied and truncated file effects and descendant execs in a fresh PID/mount namespace.')]
    write_csv(HERE/'dynamic_preflight.csv',[dict(check=k,status=s,detail=d) for k,s,d in preflight])
    print('Calibration counts verified; development diagnostics retained')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    check(p.parse_args().raw)
