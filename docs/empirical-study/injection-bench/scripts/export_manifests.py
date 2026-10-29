"""Copy the disjoint frozen manifests to small result artifacts."""
import os
from pathlib import Path
import shutil
raw=Path(os.environ['WS_RAW']);out=raw.parent/'results'
out.mkdir(exist_ok=True)
for run,name in [('main-v1','planned.csv'),('frontier-v1','frontier-planned.csv')]:
    shutil.copyfile(raw/'runs'/run/'planned.csv',out/name)
print('Frozen manifests exported without modifying their source files')
