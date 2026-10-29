#!/usr/bin/env python3
"""Run a declared revision on dev only, then anonymized adjudication."""
import argparse,subprocess,sys
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--revision',default='r1');a=p.parse_args()
shared=[sys.executable,str(OUT/'label_rescue.py'),'--input',str(OUT/'dev_inputs.csv'),'--guide',str(OUT/f'codebook-{a.revision}.txt'),'--examples',str(OUT/f'examples-{a.revision}.csv'),'--revision',a.revision,'--stage','dev','--batch-size','32']
models=[('qwen','qwen3.8-27b-nvfp4','4'),('glm','zai/glm-5.3','2')]
ps=[subprocess.Popen(shared+['--model',model,'--workers',workers,'--output',str(OUT/f'dev-{a.revision}-{name}.csv')]) for name,model,workers in models]
assert all(p.wait()==0 for p in ps)
subprocess.run(shared+['--model','qwen3.8-27b-nvfp4','--workers','6','--primary',str(OUT/f'dev-{a.revision}-qwen.csv'),'--other',str(OUT/f'dev-{a.revision}-glm.csv'),'--output',str(OUT/f'dev-{a.revision}-adjudicated.csv')],check=True)
