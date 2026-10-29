#!/usr/bin/env python3
import csv
import hashlib
import json
from pathlib import Path
import subprocess
from study import LANE
out=LANE/'results'
pdf=out/'comparison.pdf'
commands={name:subprocess.check_output([cmd,str(pdf)],text=True) for name,cmd in [('pdfinfo','pdfinfo'),('fonts','pdffonts')]}
commands['sha256']=hashlib.sha256(pdf.read_bytes()).hexdigest()
(out/'figure-verification.json').write_text(json.dumps(commands,indent=2)+'\n')
assert 'TrueType' in commands['fonts']
assert 'Type 3' not in commands['fonts']
with (out/'figure-settings.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=['setting','value']);w.writeheader()
 w.writerows([dict(setting='pdf.fonttype',value=42),dict(setting='embedded_truetype',value=1)])
print(commands['pdfinfo'])
print(commands['fonts'])
