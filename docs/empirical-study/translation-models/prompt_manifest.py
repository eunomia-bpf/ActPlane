#!/usr/bin/env python3
"""Audit shared model-independent inputs without committing prompt text."""
from prepare import DEFAULT_RAW, HERE, csv_write, sha
import inspect
from models import MODELS, api_call, REQUEST_TIMEOUT_S
from translate import inputs, make_prompt, request_workers, transport_budget


def main():
    rows = []
    for corpus in ('rq2', 'rq1'):
        for item in inputs(DEFAULT_RAW, corpus):
            prompt = make_prompt(DEFAULT_RAW, item)
            files = []
            for name in ('AGENTS.md', 'CLAUDE.md'):
                for family in ('corpus', 'corpus-raw-full'):
                    p = DEFAULT_RAW / 'artifact/docs' / family / item['repo_dir'] / name
                    if p.exists():
                        files.append(str(p.relative_to(DEFAULT_RAW / 'artifact')))
                        break
            rows.append(dict(corpus=corpus, uid=item['uid'], repo=item['repo_dir'],
                             prompt_sha256=sha(prompt.encode()), prompt_chars=len(prompt),
                             directive_chars=len(item['directive']), context_files='|'.join(files),
                             context_file_count=len(files)))
    csv_write(HERE / 'prompt-manifest.csv', rows)
    sample, corpus = inputs(DEFAULT_RAW, 'rq2'), inputs(DEFAULT_RAW, 'rq1')
    sample_ids = {(r['repo_dir'], str(r['statement_id'])) for r in sample}
    corpus_ids = {(r['repo_dir'], str(r['statement_id'])) for r in corpus}
    csv_write(HERE / 'corpus-overlap.csv', [dict(behavioral_policies=len(sample), compilation_policies=len(corpus),
              behavioral_repositories=len({r['repo_dir'] for r in sample}),
              compilation_repositories=len({r['repo_dir'] for r in corpus}),
              matching_repo_statement_ids=len(sample_ids & corpus_ids),
              matching_directive_text=len({r['directive'] for r in sample} & {r['directive'] for r in corpus}))])
    cap = inspect.signature(api_call).parameters['max_tokens'].default
    settings = []
    for model, (_, kind) in MODELS.items():
        cli = kind in ('claude', 'codex')
        settings.append(dict(model=model, adapter=kind, api_max_output_tokens='' if cli else cap,
                             api_io_timeout_s='' if cli else REQUEST_TIMEOUT_S,
                             cli_wall_timeout_s=REQUEST_TIMEOUT_S if cli else '',
                             temperature='CLI default' if cli else '0',
                             reasoning='medium' if kind == 'codex' else 'provider default',
                             compiler_feedback_format='serialized JSON history in user text' if cli else 'native chat history',
                             sample_transport_budget=transport_budget('rq2'),
                             corpus_transport_budget=transport_budget('rq1'),
                             corpus_transport_backoff_s='15|30|60',
                             current_sample_worker_limit=request_workers('rq2', model),
                             corpus_worker_limit=request_workers('rq1', model)))
    csv_write(HERE / 'model-settings.csv', settings)


if __name__ == '__main__':
    main()
