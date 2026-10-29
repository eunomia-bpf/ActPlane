#!/usr/bin/env python3
"""Finite test-once and scale run, bounded to eight local/four remote clients."""
import json,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,DEFAULT_RAW,read_csv,digest,log,now
OUT=HERE/'rescue'

def main():
 selection=json.loads((OUT/'frozen_selection.json').read_text());rev=selection['revision']
 assert digest((OUT/'label_rescue.py').read_bytes())==selection['engine_sha256']
 assert digest((OUT/'build_inputs.py').read_bytes())==selection['context_builder_sha256']
 assert digest((OUT/'test_inputs.csv').read_bytes())==selection['test_inputs_sha256']
 shared=[sys.executable,str(OUT/'label_rescue.py'),'--guide',str(OUT/f'codebook-{rev}.txt'),'--examples',str(OUT/f'examples-{rev}.csv'),'--revision',rev,'--batch-size','48','--max-chars','60000','--remote-tokens','20000','--remote-timeout','600']
 def command(stage,name,workers,adj=False):
  source=DEFAULT_RAW/'rescue-source-inputs.csv' if stage=='source' else OUT/'test_inputs.csv'
  output=OUT/(f'source-{name}.csv' if stage=='source' else f'test-{rev}-{name}.csv')
  cmd=shared+['--input',str(source),'--output',str(output),'--stage',stage,'--model','zai/glm-5.3' if name=='glm' else 'qwen3.8-27b-nvfp4','--workers',str(workers)]
  if adj:cmd+=['--primary',str(OUT/('source-qwen.csv' if stage=='source' else f'test-{rev}-qwen.csv')),'--other',str(OUT/('source-glm.csv' if stage=='source' else f'test-{rev}-glm.csv'))]
  return cmd
 testq=subprocess.Popen(command('test','qwen',3));testg=subprocess.Popen(command('test','glm',4));sourceq=subprocess.Popen(command('source','qwen',5))
 sourceg=None;testa=None;test_done=False;last_checkpoint=time.monotonic()
 while True:
  if testg.poll() is not None and sourceg is None:
   assert testg.returncode==0;sourceg=subprocess.Popen(command('source','glm',4))
  if testq.poll() is not None and testg.poll() is not None and testa is None:
   assert testq.returncode==testg.returncode==0
   testa=subprocess.Popen(command('test','adjudicated',3 if sourceq.poll() is None else 6,True))
  if testa is not None and testa.poll() is not None and not test_done:
   assert testa.returncode==0
   subprocess.run([sys.executable,str(OUT/'evaluate.py'),'--stage','test','--revision',rev],check=True)
   test_done=True
   from complete import checkpoint
   checkpoint('Report the frozen rescue holdout once without further codebook tuning')
  if time.monotonic()-last_checkpoint>1800:
   local_used=(3 if testq.poll() is None else 0)+(5 if sourceq.poll() is None else 0)+(3 if testa is not None and testa.poll() is None and sourceq.poll() is None else 6 if testa is not None and testa.poll() is None else 0)
   available=min(6,8-local_used)
   if sourceg is not None and available>0:
    subprocess.run(command('source','adjudicated',available,True),check=True)
   from complete import checkpoint
   checkpoint('Checkpoint contextual rescue predictions during corpus scaling')
   last_checkpoint=time.monotonic()
  if sourceg is not None and sourceq.poll() is not None and sourceg.poll() is not None and test_done:break
  time.sleep(15)
 assert sourceq.returncode==sourceg.returncode==0
 subprocess.run(command('source','adjudicated',6,True),check=True)
 expected=len(read_csv(DEFAULT_RAW/'rescue-source-inputs.csv'))
 for name in ['qwen','glm','adjudicated']:
  rows=read_csv(OUT/f'source-{name}.csv');assert len(rows)==expected and all(r['status']=='ok' for r in rows),name+' incomplete'
 log(DEFAULT_RAW/'rescue-controller.jsonl',dict(at=now(),event='inference_completed',revision=rev,directives=expected))
 from complete import checkpoint
 checkpoint('Complete frozen contextual rescue labels for the expanded corpus')
 print('Frozen rescue inference complete. Run deployment, correction and final reporting.',flush=True)
if __name__=='__main__':main()
