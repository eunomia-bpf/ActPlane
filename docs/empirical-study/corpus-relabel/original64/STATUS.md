# Original 64 repositories: procedure 2 review

- Status: complete
- Statements in input: 2116
- Statements reviewed and validated: 2116
- Rows changed (any label): 799
- Type changes: 150
- Topic changes: 156
- Enforceability changes: 478
- Context-required changes: 619
- Boundary flags: 81 (spans preserved)
- Failed/missing rows: 0
- Batches validated: 15/15
- Failed batches after retries: 0
- Re-run attempts in finished batches: 1
- Parallel Codex worker limit: 24
- Review model: gpt-5.6-sol (unchanged procedure-2 model)
- Wall-clock time: 260.1 seconds (4.34 minutes), controller start to current assembly
- Input SHA256: 0b5bcb314c11f5bed3ea4766f8874cd35d3cc92606ccb0206e5ef6190c22d03c
- Method: each statement read by a second-pass Codex call; all four labels explicitly returned, no pattern-based classification. Shared materials: supplied taxonomy, original empirical.md sections 4.2-4.5, 129 unchanged worked examples selected from all 64 original files (2116 total original statements available in original_examples.json).
- Validation: exact ID set, no duplicates, legal values, enforcement/context applicability, nonempty correction reasons, original input columns and row order preserved.
- No source spans, other shards, paper files, or Git state modified. Only read-only git show/ls-tree used for specified original materials.

Procedure 2 was imported unchanged with input/output paths redirected. Its legacy prompt still says shard 2 / added repositories; this wording was intentionally preserved. Historical worked examples include original-corpus statements, so this is an operator-authorized accuracy review, not an independent held-out accuracy evaluation.
