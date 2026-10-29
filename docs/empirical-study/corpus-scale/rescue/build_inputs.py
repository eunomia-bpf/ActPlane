#!/usr/bin/env python3
"""Attach deterministic unannotated source context, with no test-label selection."""
import re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,DEFAULT_RAW,read_csv,write_csv,digest
OUT=HERE/'rescue'

def context(row,source):
 lines=source.splitlines(keepends=True)
 start,end=int(row['start_line'])-1,int(row['end_line'])-1
 probe=next((i for i in range(start,min(end,len(lines))) if lines[i].strip() and not re.match(r'^\s*#{1,6}\s',lines[i])),start)
 heads=[];fence=False
 for line in lines[:probe+1]:
  if re.match(r'^\s*(```|~~~)',line):fence=not fence
  m=re.match(r'^\s*(#{1,6})\s+(.+?)\s*#*\s*$',line)
  if m and not fence:
   level=len(m[1]);heads=[x for x in heads if x[0]<level];heads.append((level,m[2]))
 a,b=probe,probe+1
 while a>0 and lines[a-1].strip() and not re.match(r'^\s*#{1,6}\s',lines[a-1]):a-=1
 while b<len(lines) and lines[b].strip() and not re.match(r'^\s*#{1,6}\s',lines[b]):b+=1
 paragraph=''.join(lines[a:b])
 extra = a<start or b>end
 if not extra or re.sub(r'\s+','',paragraph) in re.sub(r'\s+','',row['text']):paragraph=''
 if len(paragraph)>2000:
  offset=sum(map(len,lines[a:probe]));left=max(0,min(offset-750,len(paragraph)-2000));paragraph=paragraph[left:left+2000]
 heading=' / '.join(h for _,h in heads)[-500:]
 return heading,paragraph

def main():
 splits={r['repo']:r['split'] for r in read_csv(OUT/'repository_split.csv')}
 audit=[]
 for source_name in ['paper','source']:
  rows=read_csv(HERE/('paper_labels.csv' if source_name=='paper' else 'statements.csv'))
  accepted={r['statement_id']:r for r in read_csv(HERE/'labels.csv')} if source_name=='source' else {}
  outputs=[];cache={}
  for r in rows:
   fixed=r if source_name=='paper' else accepted[r['statement_id']]
   if fixed['type']!='directive':continue
   if source_name=='paper':
    relative=Path('original/docs/corpus')/r['repo'].replace('/','__')/Path(r['file_path']).name
   else:relative=Path('files')/r['content_sha256']
   if relative not in cache:cache[relative]=(DEFAULT_RAW/relative).read_bytes().decode('utf-8')
   heading,paragraph=context(r,cache[relative])
   path=r['file_path'].removeprefix(r['repo']+'/') if source_name=='paper' else r['file_path']
   item=dict(statement_id=r['statement_id'],repo=r['repo'],file_path=path,heading=heading,paragraph=paragraph,text=r['text'],type='directive',topic=fixed['topic'],split=splits[r['repo']] if source_name=='paper' else 'source')
   item['context_sha256']=digest(str([path,heading,paragraph,r['text']]))
   outputs.append(item)
   audit.append(dict(statement_id=r['statement_id'],source=source_name,source_relpath=str(relative),source_sha256=digest(cache[relative]),context_sha256=item['context_sha256'],heading_characters=len(heading),paragraph_characters=len(paragraph)))
  write_csv((DEFAULT_RAW/'rescue-source-inputs.csv') if source_name=='source' else OUT/(source_name+'_inputs.csv'),outputs)
  if source_name=='paper':
   for split in ['dev','test']:write_csv(OUT/(split+'_inputs.csv'),[r for r in outputs if r['split']==split])
 write_csv(OUT/'context_audit.csv',audit)
 print('Context audit rows',len(audit))
if __name__=='__main__':main()
