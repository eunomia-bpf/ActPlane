#!/usr/bin/env python3
"""Choose recorded source candidates by tool preconditions, never detector outcomes.

Original evaluated checkout SHAs are absent. Compare the instruction-file commit
and the last upstream commit before the artifact date against Read/Edit inputs.
All traces and all models use the same chosen source per repository.
"""
import json
from pathlib import Path

from prepare import DEFAULT_RAW, HERE, csv_write
from replay import tools_in_trace


def preconditions(repo, traces):
    edits = reads = edit_ok = read_ok = 0
    for trace in traces:
        state = {}
        for tool in tools_in_trace(list(map(json.loads, trace.read_text().splitlines()))):
            name, inp = tool['name'], tool['input']
            if name not in ('Read', 'Edit', 'Write'):
                continue
            path = inp['file_path'].lstrip('/')
            if name == 'Write':
                state[path] = inp['content']
                continue
            p = repo / path
            if path not in state and p.is_file():
                state[path] = p.read_text(errors='replace')
            if name == 'Read':
                reads += 1
                read_ok += path in state
            else:
                edits += 1
                ok = path in state and inp['old_string'] in state[path]
                edit_ok += ok
                if ok:
                    state[path] = state[path].replace(inp['old_string'], inp['new_string'], 1)
    return dict(edit_preconditions=edits, edit_matches=edit_ok, read_preconditions=reads, read_matches=read_ok)


def main():
    raw = DEFAULT_RAW
    rows, chosen = [], []
    names = sorted({p.parent.parent.name for p in (raw / 'artifact/docs/corpus-test').glob('*/*/statement.json')})
    for name in names:
        current = raw / 'repos' / name
        if not current.is_symlink():
            commit = (current / '.fixture-ready').read_text().strip()
            saved = raw / 'repository-candidates' / name / commit
            saved.parent.mkdir(parents=True, exist_ok=True)
            current.rename(saved)
        candidates = sorted(set((raw / 'repository-candidates' / name).glob('*')) |
                            set((raw / 'previous-fixtures' / name).glob('*')))
        traces = sorted((raw / 'artifact/docs/corpus-test' / name).glob('*/trace*.jsonl'))
        scores = []
        for p in candidates:
            r = dict(repo=name, commit=p.name, **preconditions(p, traces))
            scores.append((r['edit_matches'], r['read_matches'], p.name, p, r))
        _, _, _, selected, result = max(scores, key=lambda s: s[:3])
        if current.is_symlink():
            current.unlink()
        current.symlink_to(selected, target_is_directory=True)
        for *_, p, r in scores:
            r['selected'] = int(p == selected)
            rows.append(r)
        chosen.append(result.copy())
    csv_write(HERE / 'fixture-candidates.csv', rows)
    csv_write(HERE / 'selected-fixtures.csv', chosen)
    print('selected fixture sources by Read/Edit preconditions')


if __name__ == '__main__':
    main()
