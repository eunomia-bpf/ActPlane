#!/usr/bin/env python3
from study import RAW
for pattern in ('*hermes*/s01_use_test_wrapper/trace_visible_violation','*Skill*/local-fast-test-scope/trace_visible_violation'):
 for d in (RAW/'main/control').glob(pattern):
  print(d, (d/'tools.jsonl').read_text())
  for line in (d/'syscalls.log').read_text().splitlines():
   if 'execve(' in line and ('pytest' in line or 'python' in line):print(line[:1600])
