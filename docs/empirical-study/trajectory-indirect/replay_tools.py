#!/usr/bin/env python3
"""Minimal, explicit tool semantics used to replay recorded file/read operations.

This is a substitute implementation, not a claim of reproducing proprietary tool
internals. Shell strings are dispatched separately without editing their text.
"""
import fnmatch
import json
from pathlib import Path
import re
import sys


def apply_patch(text):
    lines=text.splitlines()
    if not lines or lines[0]!='*** Begin Patch':
        raise ValueError('unsupported patch framing')
    i=1
    while i<len(lines):
        line=lines[i]
        if line=='*** End Patch':
            return
        match=re.fullmatch(r'\*\*\* (Add|Update|Delete) File: (.+)',line)
        if not match:
            raise ValueError('unsupported patch header: '+line)
        op,name=match.groups();path=Path(name);i+=1
        end=i
        while end<len(lines) and not lines[end].startswith('*** '):
            end+=1
        body=lines[i:end]
        if op=='Delete':
            path.unlink()
        elif op=='Add':
            if path.exists():
                raise ValueError('add target already exists: '+name)
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('\n'.join(x[1:] for x in body if x.startswith('+'))+'\n')
        else:
            source=path.read_text()
            hunks=[];h=[]
            for entry in body:
                if entry.startswith('@@'):
                    if h:hunks.append(h)
                    h=[]
                else:h.append(entry)
            if h:hunks.append(h)
            for hunk in hunks:
                old='\n'.join(x[1:] for x in hunk if x.startswith((' ','-')))
                new='\n'.join(x[1:] for x in hunk if x.startswith((' ','+')))
                if not old or old not in source:
                    raise ValueError('patch context does not match: '+name)
                source=source.replace(old,new,1)
            path.write_text(source)
        i=end
    raise ValueError('missing End Patch')


def run(tool,args):
    tool=tool.lower()
    path=Path(args.get('file_path',args.get('path','/nonexistent')))
    op=args.get('command','')
    if tool in ('write','write_file') or op=='create':
        if op=='create' and path.exists():
            raise ValueError('create target exists')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(args.get('content',args.get('file_text',args.get('text',''))))
    elif tool in ('edit','edit_file','str_replace_editor','str_replace_based_edit_tool') and op!='view':
        content=path.read_text()
        if op=='insert':
            lines=content.splitlines(keepends=True)
            lines.insert(int(args['insert_line']),args['new_str']+'\n')
            updated=''.join(lines)
        else:
            old=args.get('old_string',args.get('old_str',''))
            new=args.get('new_string',args.get('new_str',''))
            if not old or old not in content:
                raise ValueError('edit source string absent')
            if not args.get('replace_all') and content.count(old)!=1:
                raise ValueError('edit source string not unique')
            updated=content.replace(old,new,-1 if args.get('replace_all') else 1)
        path.write_text(updated)
    elif 'apply_patch' in tool:
        apply_patch(args.get('text',args.get('patch',args.get('input',''))))
    elif tool in ('read','read_file') or op=='view':
        if path.is_dir():
            print('\n'.join(str(x) for x in list(path.iterdir())[:500]))
        else:
            lines=path.read_text(errors='replace').splitlines()
            start=max(0,int(args.get('offset',1))-1)
            print('\n'.join(lines[start:start+int(args.get('limit',2000))]))
    elif tool in ('grep','glob'):
        # Fixed-call replay does not consume observations to choose later calls.
        # A bounded in-process read/search avoids inventing child tool processes.
        root=Path(args.get('path','.'))
        expression=args.get('pattern',args.get('glob','*'))
        paths=[root] if root.is_file() else root.rglob('*')
        n=0
        for p in paths:
            if '.git' in p.parts:continue
            if tool=='glob':
                if fnmatch.fnmatch(str(p),expression):print(p)
            elif p.is_file():
                try:
                    for number,line in enumerate(p.read_text(errors='replace').splitlines()):
                        if re.search(expression,line):print(f'{p}:{number+1}:{line[:500]}')
                except (OSError,re.error):pass
            n+=1
            if n>=5000:break
    elif tool in ('finish','think','todowrite','todo_write'):
        print('Control operation recorded')
    else:
        raise NotImplementedError('unsupported replay tool: '+tool)


if __name__=='__main__':
    try:
        if len(sys.argv)>1 and sys.argv[1]=='--patch-stdin':
            apply_patch(sys.stdin.read())
        else:
            request=json.loads(Path(sys.argv[1]).read_text())
            run(request['tool'],request['args'])
    except Exception as exc:
        print(type(exc).__name__+': '+str(exc),file=sys.stderr)
        sys.exit(1)
