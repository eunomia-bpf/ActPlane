#!/usr/bin/env python3
"""Audit shared model-independent inputs without committing prompt text."""
from prepare import DEFAULT_RAW, HERE, csv_write, sha
from translate import inputs, make_prompt


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


if __name__ == '__main__':
    main()
