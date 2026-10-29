"""Resolve immutable original gates plus an explicitly validated rescue deployment."""
from common import HERE,read_csv

def load_gates():
 gates={r['dimension']:r['passed']=='True' for r in read_csv(HERE/'calibration_gates.csv')}
 if (HERE/'format_calibration_gates.csv').exists():
  for r in read_csv(HERE/'format_calibration_gates.csv'):gates[r['dimension']]=gates.get(r['dimension'],False) and r['passed']=='True'
 path=HERE/'rescue/deployment_gates.csv'
 if path.exists():
  tests={r['dimension']:r for r in read_csv(HERE/'rescue/test_gates.csv')}
  for r in read_csv(path):
   assert r['dimension'] in ['enforceability','context_required']
   t=tests[r['dimension']]
   if r['passed']=='True':assert t['passed']=='True' and float(t['test_kappa'])>=float(t['min_test_kappa']) and float(t['coverage'])>=float(t['min_coverage'])
   gates[r['dimension']]=r['passed']=='True'
 if not gates.get('type',False):gates.update(topic=False,enforceability=False,context_required=False)
 if not gates.get('enforceability',False):gates['context_required']=False
 return gates
