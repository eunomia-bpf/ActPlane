"""Use shared, unchanged-default CSV logic with explicit separate cohort paths."""
import os,runpy
from pathlib import Path
HERE=Path(__file__).resolve().parent
os.environ.update(BU_ANALYSIS_RAW='/workspaces/exp/benign-utility/raw/benchmark/network',BU_ANALYSIS_OUT='/workspaces/exp/benign-utility/benchmark/network/results',BU_ANALYSIS_COHORT='network_exposure_followup')
for filename in ('analyze.py','scope_audit.py','analyze.py'):runpy.run_path(str(HERE.parent/filename),run_name='__main__')
