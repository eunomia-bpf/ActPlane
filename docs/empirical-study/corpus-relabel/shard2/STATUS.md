# Shard 2 second-pass review

- Status: complete
- Statements in input: 9200
- Statements reviewed and validated: 9200
- Rows changed (any label): 3000
- Type changes: 432
- Topic changes: 400
- Enforceability changes: 1705
- Context-required changes: 2374
- Boundary flags: 2167 (spans preserved)
- Failed/missing rows: 0
- Batches validated: 62/62
- Failed batches after retries: 0
- Re-run attempts in finished batches: 0
- Parallel Codex worker limit: 24
- Review model: gpt-5.6-sol (installed default gpt-6.1-sol was rejected by the CLI ChatGPT backend; failed preflight requests produced no annotations)
- Wall-clock time: 1073.4 seconds (17.89 minutes), controller start to current assembly
- Input SHA256: ab0d0d8c3994e1d510b0d24bdfd9dee62eae71db1fc4c343bdc6f1022c0eebd3
- Method: each statement read by a second-pass Codex call; all four labels explicitly returned, no pattern-based classification. Shared materials: supplied taxonomy, original empirical.md sections 4.2-4.5, 129 unchanged worked examples selected from all 64 original files (2116 total original statements available in original_examples.json).
- Validation: exact ID set, no duplicates, legal values, enforcement/context applicability, nonempty correction reasons, original input columns and row order preserved.
- No source spans, other shards, paper files, or Git state modified. Only read-only git show/ls-tree used for specified original materials.

- Root-agent semantic adjudications: 3 individually read rows; recorded in adjudications.json. Original batch returns retained unchanged.
- Independent final CSV verification: PASS; all 9,200 IDs exactly once, input fields and order identical, changed flags and reasons consistent.
