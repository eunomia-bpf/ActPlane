#!/usr/bin/env python3
"""Record reference compatibility with the current compiler independently of BPF."""
import json
import subprocess
import yaml

from prepare import DEFAULT_RAW, ROOT, HERE, csv_write, sha
from translate import compile_policy


def main():
    raw = DEFAULT_RAW
    rows = []
    cli_hash = sha((ROOT / 'target/release/actplane').read_bytes())
    for p in sorted((raw / 'artifact/docs/corpus-test').glob('*/*/rule.yaml')):
        policy = yaml.safe_load(p.read_text())['policy']
        out = raw / 'reference-compilation' / p.parent.parent.name / p.parent.name
        out.mkdir(parents=True, exist_ok=True)
        cached = out / 'compile-result.json'
        old = json.loads(cached.read_text()) if cached.exists() else {}
        if old.get('policy_sha256') == sha(policy.encode()) and old.get('cli_sha256') == cli_hash:
            d = old['result']
        else:
            d = compile_policy(policy, out)
            cached.write_text(json.dumps(dict(policy_sha256=sha(policy.encode()), cli_sha256=cli_hash, result=d), indent=2) + '\n')
        clauses = d['report'].get('backend_support', {}).get('clauses', [])
        rows.append(dict(repo=p.parent.parent.name, statement_id=p.parent.name,
                         compiled=int(d['ok']), policy_sha256=sha(policy.encode()),
                         rule_count=d['report'].get('rule_count', ''),
                         unsupported_clauses=sum(not c['supported'] for c in clauses),
                         elapsed_s=d['elapsed_s'], error=d['error']))
    csv_write(HERE / 'reference-compilation.csv', rows)
    d = json.loads((raw / 'provenance.json').read_text())
    row = dict(artifact_commit=d['artifact_commit'], dsl_ref=d['dsl_ref'],
               dsl_sha256=d['dsl_sha256'], artifact_dsl_sha256=d['artifact_dsl_sha256'],
               compiler_source_commit=subprocess.check_output(['git', 'rev-parse', 'origin/master'], cwd=ROOT, text=True).strip(),
               cli_sha256=sha((ROOT / 'target/release/actplane').read_bytes()),
               default_loader_sha256=sha((ROOT / 'bpf/process').read_bytes()))
    csv_write(HERE / 'provenance.csv', [row])
    csv_write(HERE / 'engine-build.csv', [json.loads((raw / 'bounded-loader/metadata.json').read_text())])


if __name__ == '__main__':
    main()
