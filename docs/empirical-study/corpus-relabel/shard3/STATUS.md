# Shard 3 second-pass review

- Statements reviewed: 9200 / 9200
- Rows changed (any label): 2940
- Type changes: 418
- Topic changes: 212
- Enforceability changes: 1741
- Context-required changes: 2405
- Boundary flags (spans unchanged): 971
- Failed or missing rows: 0
- Failed batches remaining: []
- Wall-clock time, including setup and startup recovery: 1240.8 seconds (20.68 minutes)
- Task start UTC: 2026-10-29T22:55:35+00:00
- Finished UTC: 2026-10-29T23:16:15.785465+00:00
- Model: Codex CLI gpt-5.6-sol, configured high reasoning. Default gpt-6.1-sol was unsupported by the authenticated account; its startup attempts returned no annotations.
- Parallel execution: initially 16 Codex child processes; remaining unstarted batches launched concurrently to meet the deadline, preserving active calls and validated outputs. 62 batches, normally 150 statements each.
- Definitions: identical taxonomy.txt, original empirical.md sections 4.2-4.5, and actual worked examples from all 64 original repositories. Full original YAML snapshots retained in original-examples/.
- Review: individual semantic decisions on all four labels; no keyword/pattern label assignment or re-segmentation. Only failed or invalid batches retried.
- Validation: every statement_id exactly once; exact legal values and applicability; changed flags/reasons checked; all original columns/text/spans preserved in original order; final CSV round trip verified.
- Git: read-only show/ls-tree solely for requested definitions/examples; no Git state mutation, commit, push, pull, or paper edits.
