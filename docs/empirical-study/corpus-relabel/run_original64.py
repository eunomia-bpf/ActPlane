"""Run unchanged procedure 2 on the original 64 repositories, redirecting paths."""
import concurrent.futures as cf
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import time

HERE = Path(__file__).resolve().parent


def main():
    source = HERE / 'shard2'
    out = HERE / 'original64'
    out.mkdir(exist_ok=True)
    spec = importlib.util.spec_from_file_location('procedure2', source / 'run_review.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.OUT = out
    m.SOURCE = HERE / 'shards/original64.csv'
    m.META_PATH = out / 'run_metadata.json'
    m.START = (json.loads(m.META_PATH.read_text())['started_epoch']
               if m.META_PATH.exists() else time.time())
    shutil.copyfile(source / 'response_schema.json', out / 'response_schema.json')
    codebook = (source / 'shared_codebook.txt').read_text(encoding='utf-8')
    examples = json.loads((source / 'original_examples.json').read_text(encoding='utf-8'))
    marker = 'ORIGINAL WORKED EXAMPLES (one from every original repository, plus axis combinations):\n'
    selected = json.loads(codebook.split(marker, 1)[1])
    meta = [len({r['source'] for r in examples}), len(examples), len(selected)]
    with m.SOURCE.open(encoding='utf-8-sig', newline='') as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len({r['statement_id'] for r in rows}) == 2116
    assert len({r['repo'].casefold() for r in rows}) == 64
    batches = [rows[i:i+150] for i in range(0, len(rows), 150)]
    metadata = dict(started_epoch=m.START, parallel=m.PARALLEL, batches=len(batches),
                    rows=len(rows), model='gpt-5.6-sol', batch_size=150,
                    procedure='unchanged imported shard2.review_one, validate and write_final',
                    source_sha256=hashlib.sha256(m.SOURCE.read_bytes()).hexdigest(),
                    reference_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in [source / 'run_review.py', source / 'shared_codebook.txt',
                                                source / 'response_schema.json', source / 'original_examples.json']})
    m.META_PATH.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    results = []
    print(f'Starting {len(batches)} unchanged procedure-2 batches, {m.PARALLEL} workers', flush=True)
    with cf.ThreadPoolExecutor(max_workers=m.PARALLEL) as pool:
        futures = [pool.submit(m.review_one, i, batch, codebook) for i, batch in enumerate(batches)]
        for future in cf.as_completed(futures):
            result = future.result()
            results.append(result)
            m.write_final(rows, results, meta, False)
            print(f'Batch {result[0]:03d}: {len(result[1])} validated; attempt={result[2]}; error={result[3]}; {len(results)}/{len(batches)}', flush=True)
    complete = len(results) == len(batches) and all(not r[3] for r in results)
    m.write_final(rows, results, meta, complete)
    status = out / 'STATUS.md'
    text = status.read_text(encoding='utf-8').replace('# Shard 2 second-pass review', '# Original 64 repositories: procedure 2 review')
    text = text.replace('gpt-5.6-sol (installed default gpt-6.1-sol was rejected by the CLI ChatGPT backend; failed preflight requests produced no annotations)',
                        'gpt-5.6-sol (unchanged procedure-2 model)')
    text += ('\nProcedure 2 was imported unchanged with input/output paths redirected. Its legacy prompt still says shard 2 / added repositories; this wording was intentionally preserved. '
             'Historical worked examples include original-corpus statements, so this is an operator-authorized accuracy review, not an independent held-out accuracy evaluation.\n')
    status.write_text(text, encoding='utf-8')
    metadata.update(finished_epoch=time.time(), elapsed_seconds=time.time()-m.START, complete=complete)
    m.META_PATH.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    return 0 if complete else 1


if __name__ == '__main__':
    raise SystemExit(main())
