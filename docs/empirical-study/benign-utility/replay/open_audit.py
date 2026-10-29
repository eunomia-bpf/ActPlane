"""Summarize separate standard strace verification replays; never infer labels."""
import ast
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
from collections import defaultdict
from adjudicate import reviewed_annotations

ROOT = Path(os.environ['WS_RAW']) / 'replay'
OUT = ROOT.parent.parent / 'replay/results'
# Retained engine bpf/process.h: MAX_FILENAME_LEN=127, including the NUL.
ENGINE_PATH_BYTES = 126
SYSCALLS = ('open', 'openat', 'openat2', 'creat', 'truncate', 'rename', 'renameat', 'renameat2')


def write(name, rows, fields):
    with (OUT / name).open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def match(path, rule):
    pattern = rule['compiled_literal'].encode()
    mode = rule['compiled_match_mode']
    return (path == pattern if mode == 0 else path.startswith(pattern) if mode == 1
            else path.endswith(pattern) if mode == 2 else True if mode == 3
            else pattern in path if mode == 4 else False)


def host_path(run, plan, path):
    for prefix, directory in ((plan['sandbox_workdir'], 'repo'), ('/venv', 'venv'),
                              ('/root', 'home'), ('/tmp', 'tmp'), ('/cache', 'cache')):
        if path == prefix or path.startswith(prefix + '/'):
            return run / directory / path[len(prefix):].lstrip('/')
    # Other mounts in the copied sandbox are host read-only mounts.
    return Path(path) if path.startswith(('/usr/', '/etc/', '/opt/', '/lib/')) else None


def main():
    plans = {r['dynamic_id']: r for r in csv.DictReader((OUT / 'cohort.csv').open())}
    candidates, summaries, interventions, unparsed_rows = [], [], [], []
    reviewed=reviewed_annotations()
    for run in sorted(ROOT.glob('open-audit-*/dynamic/runs/t*')):
        trace = run / 'successful-opens.strace'
        if not trace.exists():
            continue
        plan = plans[run.name]
        done = json.loads((run / 'done.json').read_text()) if (run / 'done.json').exists() else {}
        rules = [r for r in json.loads((run / 'compiled-sources.json').read_text())
                 if r['label'] == 'SECRET'] if (run / 'compiled-sources.json').exists() else []
        pending, parsed, unparsed, failed = {}, 0, 0, 0
        selected = []
        archive = None
        retained_data = {}
        for number, line in enumerate(trace.read_text(errors='replace').splitlines(), 1):
            header = re.match(r'^(\d+)\s+(\d+\.\d+)\s+(.*)$', line)
            if not header:
                if any(word + '(' in line for word in SYSCALLS):
                    unparsed += 1
                    unparsed_rows.append(dict(audit_condition=run.parents[2].name,dynamic_id=run.name,
                        line=number,reason='header',record=line))
                continue
            pid, timestamp, body = header.groups()
            if '<unfinished ...>' in body:
                pending[pid] = (number, timestamp, body.split('<unfinished ...>')[0])
                continue
            if body.startswith('<... '):
                previous = pending.pop(pid, None)
                resumed = re.match(r'^<\.\.\. \w+ resumed>(.*)$', body)
                if not previous or not resumed:
                    unparsed += 1
                    unparsed_rows.append(dict(audit_condition=run.parents[2].name,dynamic_id=run.name,
                        line=number,reason='resumed record without matching start',record=line))
                    continue
                number, timestamp, start = previous
                body = start + resumed.group(1)
            if re.match(r'^(' + '|'.join(SYSCALLS) + r')\(.*\)\s+=\s+-\d+', body):
                failed += 1
                continue
            call = re.match(r'^(' + '|'.join(SYSCALLS) + r')\((.*)\)\s+=\s+(\d+)(?:<(.*)>)?(?:\(deleted\))?$', body)
            if not call:
                if any(word + '(' in body for word in SYSCALLS):
                    unparsed += 1
                    unparsed_rows.append(dict(audit_condition=run.parents[2].name,dynamic_id=run.name,
                        line=number,reason='return format',record=body))
                continue
            syscall, arguments, result_fd, resolved = call.groups()
            parsed += 1
            names = list(re.finditer(r'"(?:[^"\\]|\\.)*"', arguments))
            if not names:
                unparsed += 1
                unparsed_rows.append(dict(audit_condition=run.parents[2].name,dynamic_id=run.name,
                    line=number,reason='no decoded pathname',record=body))
            for name_index, quoted in enumerate(names):
                try:
                    raw = ast.literal_eval('b' + quoted.group())
                except (SyntaxError, ValueError):
                    unparsed += 1
                    unparsed_rows.append(dict(audit_condition=run.parents[2].name,dynamic_id=run.name,
                        line=number,reason='pathname C-string syntax',record=body))
                    continue
                engine_path = raw[:ENGINE_PATH_BYTES]
                matching = [r['pattern'] for r in rules if match(engine_path, r)]
                # Preserve resolved-only candidates too: file-flow state can use
                # an inode reached through a different raw spelling.
                resolved_matching = [r['pattern'] for r in rules
                                     if resolved and match(resolved.encode()[:ENGINE_PATH_BYTES], r)]
                if not matching and not resolved_matching:
                    continue
                path = raw.decode(errors='surrogateescape')
                file = host_path(run, plan, resolved or path)
                if file in retained_data:
                    data=retained_data[file]
                else:
                    try:
                        data = file.read_bytes() if file and file.is_file() else None
                    except OSError:
                        data = None
                    if data is None and file and file.is_relative_to(run) and (run/'runtime.tar.gz').exists():
                        if archive is None:archive=tarfile.open(run/'runtime.tar.gz','r:gz')
                        try:
                            member=archive.extractfile(file.relative_to(run).as_posix())
                            data=member.read() if member else None
                        except (KeyError,OSError):pass
                    retained_data[file]=data
                selected.append(dict(audit_condition=run.parents[2].name, dynamic_id=run.name,
                    line=number, pid=pid, timestamp_epoch=timestamp, syscall=syscall, name_index=name_index,
                    raw_path=path, engine_path=engine_path.decode(errors='replace'),
                    resolved_path=resolved or '', source_patterns=json.dumps(matching),
                    resolved_source_patterns=json.dumps(resolved_matching),
                    flags=arguments[quoted.end():].lstrip(', '), result=result_fd,
                    retained_sha256=hashlib.sha256(data).hexdigest() if data is not None else '',
                    retained_bytes=len(data) if data is not None else '',
                    retained_public_certificates=int(bool(data and b'-----BEGIN CERTIFICATE-----' in data
                        and b'PRIVATE KEY-----' not in data)),
                    evidence_limit='Retained end-of-replay bytes; no automatic primary-event adjudication'))
        candidates.extend(selected)
        if archive is not None:archive.close()
        owners = defaultdict(list)
        prefix = 'apti6e' + run.name[1:]
        if (run / 'sources.jsonl').exists():
            for line in (run / 'sources.jsonl').read_text(errors='replace').splitlines():
                try:
                    message = json.loads(line).get('data', '')
                    kind, timestamp, tag, pid, payload = message.strip().split('|', 4)
                    if kind not in ('EXEC', 'FORK') or not tag.startswith(prefix):
                        continue
                    timestamp, pid, index = int(timestamp), int(pid), int(tag[len(prefix):])
                except (ValueError, AttributeError, json.JSONDecodeError):
                    continue
                owners[pid].append((timestamp, index))
                if kind == 'FORK':
                    owners[int(payload)].append((timestamp, index))
        if (run / 'engine.jsonl').exists():
            for line in (run / 'engine.jsonl').read_text(errors='replace').splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get('event') != 'TAINT_VIOLATION':
                    continue
                timestamp = int(event['timestamp'])
                lineage = [entry for pid in (int(event['pid']), int(event.get('ppid', 0)))
                           for entry in owners[pid] if entry[0] <= timestamp]
                index = max(lineage)[1] if lineage else ''
                interventions.append(dict(audit_condition=run.parents[2].name, dynamic_id=run.name,
                    call_index=index, timestamp_ns=timestamp, pid=event['pid'],
                    blocked=int(bool(event.get('blocked'))), killed=int(bool(event.get('killed'))),
                    intervened=int(bool(event.get('blocked') or event.get('killed'))),
                    source_path=(event.get('provenance') or {}).get('target', ''),
                    target=event.get('target', ''), adjudication='unknown',
                    evidence='Separate forensic replay; source/configuration evidence requires individual review'))
                annotation=reviewed.get((run.parents[2].name,run.name,str(timestamp)))
                if annotation:interventions[-1].update(adjudication=annotation['adjudication'],evidence=annotation['evidence'])
        summaries.append(dict(audit_condition=run.parents[2].name, dynamic_id=run.name,
            terminal=int(bool(done)), recorded_calls=done.get('recorded_calls', ''),
            executed_calls=done.get('executed_calls', ''), fatal=done.get('fatal', ''),
            trace_bytes=trace.stat().st_size, trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
            parsed_successful_file_calls=parsed, unparsed_file_records=unparsed,
            failed_file_calls=failed, unfinished_file_records=len(pending), candidate_file_names=len(selected),
            candidate_paths=len({r['raw_path'] for r in selected}),
            evidence_limit='Separate verification replay; its timings and events excluded from primary cohort'))
    write('open-audit-candidates.csv', candidates, list(candidates[0]) if candidates else [
        'audit_condition', 'dynamic_id', 'line', 'pid', 'timestamp_epoch', 'syscall', 'name_index', 'raw_path',
        'engine_path', 'resolved_path', 'source_patterns', 'resolved_source_patterns', 'flags',
        'result', 'retained_sha256', 'retained_bytes', 'retained_public_certificates', 'evidence_limit'])
    write('open-audit-summary.csv', summaries, list(summaries[0]) if summaries else [
        'audit_condition', 'dynamic_id', 'terminal', 'recorded_calls', 'executed_calls', 'fatal',
        'trace_bytes', 'trace_sha256', 'parsed_successful_file_calls', 'unparsed_file_records', 'failed_file_calls',
        'unfinished_file_records', 'candidate_file_names', 'candidate_paths', 'evidence_limit'])
    write('open-audit-interventions.csv', interventions, list(interventions[0]) if interventions else [
        'audit_condition', 'dynamic_id', 'call_index', 'timestamp_ns', 'pid', 'blocked', 'killed',
        'intervened', 'source_path', 'target', 'adjudication', 'evidence'])
    write('open-audit-unparsed.csv',unparsed_rows,['audit_condition','dynamic_id','line','reason','record'])
    print('Separate open audits:', len(summaries), 'candidate opens:', len(candidates))


if __name__ == '__main__':
    main()
