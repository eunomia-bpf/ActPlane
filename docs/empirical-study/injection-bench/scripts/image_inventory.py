"""Read the remote ZIP directory without downloading the OSWorld image."""
import json
import os
from pathlib import Path
import struct
import urllib.request

url='https://huggingface.co/datasets/xlangai/ubuntu_osworld/resolve/main/Ubuntu.qcow2.zip'
size=12273896463
req=urllib.request.Request(url,headers={'Range':f'bytes={size-65536}-{size-1}'})
with urllib.request.urlopen(req,timeout=40) as r:
    if r.status != 206:
        raise RuntimeError(f'Range not honored: {r.status}; refusing whole-image download')
    data=r.read(65537)
entries=[]
start=0
while True:
    i=data.find(b'PK\x01\x02',start)
    if i < 0: break
    vals=struct.unpack_from('<4s6H3I5H2I',data,i)
    n,e,c=vals[10:13]
    compressed,uncompressed=vals[8:10]
    extra=data[i+46+n:i+46+n+e]
    off=0
    while off+4 <= len(extra):
        tag,length=struct.unpack_from('<HH',extra,off)
        body=extra[off+4:off+4+length]
        if tag==1:
            p=0
            if uncompressed==0xffffffff:
                uncompressed=struct.unpack_from('<Q',body,p)[0]; p+=8
            if compressed==0xffffffff:
                compressed=struct.unpack_from('<Q',body,p)[0]
        off+=4+length
    entries.append({'name':data[i+46:i+46+n].decode(errors='replace'),'compressed':compressed,'uncompressed':uncompressed})
    start=i+46+n+e+c
out={'zip_bytes':size,'entries':entries}
(Path(os.environ['WS_RAW'])/'image_inventory.json').write_text(json.dumps(out,indent=2))
print(json.dumps(out,indent=2))
