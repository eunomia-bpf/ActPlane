#!/usr/bin/env python3
"""Known-answer checks for the error-correction estimator, without study labels."""
import sys
from pathlib import Path
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parent))
from correct_prevalence import matrix,fit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,write_csv
checks=[]
def record(name,value):
 checks.append(dict(check=name,passed=bool(value)));assert value,name
m=np.array([[.9,.2],[.1,.8]])
p=np.array([.3,.7]);found,flag=fit(m,m@p)
record('binary_known_prevalence',np.allclose(found,p,atol=1e-7))
found,flag=fit(np.eye(4),np.array([12,25,33,30]))
record('identity_multiclass',np.allclose(found,[.12,.25,.33,.30]))
found,flag=fit(m,[0,100])
record('boundary_is_constrained',np.all(found>=0) and np.isclose(found.sum(),1) and bool(flag))
mat,error=matrix(np.array([[1,0],[0,0]]));record('missing_reference_class_retained',mat is None and error=='missing_reference_class')
mat,error=matrix(np.ones((2,2)));record('rank_deficiency_retained',mat is None and error=='rank_deficient_confusion')
found,flag=fit(m,[0,0]);record('empty_target_is_undefined',found is None and flag=='empty_target_group')
mat,error=matrix(np.array([[90,20],[10,80]]));record('matrix_orientation_prediction_by_gold',np.allclose(mat,m))
write_csv(HERE/'rescue/correction_validation.csv',checks)
print('Known-answer correction checks passed:',len(checks))
