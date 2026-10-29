#!/usr/bin/env python3
"""Render final PDF for visual review without copying a PNG to the laptop."""
import base64
import io
from pathlib import Path
import subprocess
from PIL import Image
from study import LANE,RAW
subprocess.run(['pdftoppm','-singlefile','-png','-scale-to','1000',
                str(LANE/'results/comparison.pdf'),str(RAW/'pdf-render')],check=True)
im=Image.open(RAW/'pdf-render.png').convert('RGB').quantize(colors=32)
b=io.BytesIO();im.save(b,format='PNG',optimize=True)
print(base64.b64encode(b.getvalue()).decode())
