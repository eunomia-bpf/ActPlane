# Shard 1 second-pass review

- Statements reviewed: 9201 / 9201.
- Rows changed (any label): 2999.
- Rows changed, type: 494.
- Rows changed, topic: 330.
- Rows changed, enforceability: 1775.
- Rows changed, context_required: 2498.
- Boundary flags: 2144 (reason contains `boundary:`; original spans preserved).
- Failed batches: 0.
- Missing rows: 0.
- Duplicate returned statement IDs: 0 (validated within batches and disjoint input batches).
- Wall-clock time: 1169.4 seconds (19.49 minutes), from batch preparation.
- Method: individual semantic second-pass review by 16 parallel local Codex CLI processes, 150 statements per batch (last batch smaller), identical shared codebook and original sections 4.2-4.5. Original worked-example YAMLs read from all 64 files; representative examples shared identically. No keyword/pattern label assignment.
- Validation: exact batch ID coverage, unique IDs, legal labels, applicability of enforceability/context, reason consistency, and original input columns preserved. Only failed batches retried.
- Input SHA-256: `23ae799299d27ebe20b61d90f283edfbb064375efc45311f182e1ed039a35fec`.
- Finished: 2026-10-29T16:17:30.593490-07:00.

Final output audit:

- Codex model: `gpt-5.6-sol`, high reasoning effort, identical for all 62 accepted batches. The configured default `gpt-6.1-sol` was rejected by the account during preflight, before any review result was accepted.
- Retried batches with returned second-attempt output: 019, 024, 048, 049. Only failed batches were retried.
- Individually read and adjudicated after return: 47 specific statements, recorded in `manual_adjudications.json`; explicit reference-file access and a run-command directive were corrected using the codebook's observable-operation rule.
- Final CSV round-trip and full original-column equality: passed for all 9201 rows, including text, repository, path, line spans, and original labels.
- Final exact statement-ID coverage and uniqueness: passed; missing 0, extra 0, duplicate 0.
- Final label vocabulary, applicability, changed flags, and reason consistency: passed.
- Wall-clock from orchestration script creation through final audit: 1252.4 seconds (20.87 minutes), including local model troubleshooting.
- Final audit time: 2026-10-29T16:17:51.643773-07:00.
- Reviewed CSV SHA-256: `f08c167644de44cb597f6813b06862b05fcf420d73686bd92e82a1218997a947`.
