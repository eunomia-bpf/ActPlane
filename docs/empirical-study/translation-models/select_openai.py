#!/usr/bin/env python3
"""Record account catalog evidence and the operator-authorized OpenAI selection."""
import json
import os
from pathlib import Path
from prepare import DEFAULT_RAW, HERE, csv_write
from models import probe


def main():
    cache = Path(os.environ['CODEX_HOME']) / 'models_cache.json'
    catalog = json.loads(cache.read_text())
    result = probe('gpt-6-astra', DEFAULT_RAW)
    if result['status'] != 'ok' or not result['identity_verified']:
        raise SystemExit('Strongest catalog candidate did not verify; inspect probe before selecting a fallback')
    rows = []
    for model in catalog['models']:
        rows.append(dict(model=model['slug'], description=model.get('description', ''),
                         catalog_fetched_at=catalog.get('fetched_at', ''),
                         selected=int(model['slug'] == 'gpt-6-astra'),
                         selection_source='https://developers.openai.com/api/docs/models/gpt-6-astra',
                         selection_reason='most capable model per official catalog; response-verified through this account' if model['slug'] == 'gpt-6-astra' else 'catalog alternative, not selected'))
    csv_write(HERE / 'openai-model-selection.csv', rows)


if __name__ == '__main__':
    main()
