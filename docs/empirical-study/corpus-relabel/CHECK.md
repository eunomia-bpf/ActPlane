# Procedure consistency and original-reference checks

DO NOT ACCEPT the merged reviewed labels as method-consistent. Original-reference failures: procedure1, procedure2, procedure3. Best relative agreement: procedure2. All three procedures deviate from the original reference. Recommend re-running all affected shards with procedure2 only after its remaining original-reference failures are resolved and independently revalidated. Its relative ranking is not a pass. No shard was re-run.

The main failures affect all three procedures: added-sample context kappas are 0.610–0.710 between procedures. Against original labels, enforcement kappas are 0.556–0.571 and context kappas 0.349–0.478. Procedure 2 also misses the type threshold (0.7875). The historical estimated 5–8% error band implies roughly 92–95% raw agreement; original-reference enforcement agreement here is only 67.3–68.2%, so the decision also fails that historical bar. These diagnostics do not isolate a single faulty shard. The independent Claude check used first-party claude-opus-5-5 and has 79% exact four-label agreement, without changing labels.

The original study reports an estimated 5–8% post-correction error rate but explicitly says no formal inter-rater agreement. No original per-label kappa or reusable double-annotation table was recovered. The operational bar is therefore the requested kappa >= 0.80 on every label, using all rows for type/topic, original directives for enforcement, and original system-observable directives for context. Predicted inapplicability counts as disagreement. Pairwise applicability is conditioned on the left procedure; the all-row scores additionally count empty labels as a category and are fully symmetric. Exact match requires all four labels. The decision uses pairwise added-sample and original-reference checks; pairwise original-sample checks are also reported.

Each original runner file and stored instruction text was imported/read unchanged. Only the output-directory global was redirected. Original 150-row batch sizes, schemas, model, CLI flags, validation and retry functions were retained (two simultaneous batches per procedure per cohort). There were no post-return semantic adjudications in this check. Shards 1 and 2 had such adjudications in their original completed labels, so this checks the automated procedures, not those additional interventions. Procedure 3 retains access to all 64 reference YAMLs. Worked examples embedded in any of the three prompts were excluded by exact text from the original sample; the complete original reference remained available to procedure 3 by its unchanged design, so this is not a blinded holdout.

Method identity cannot be certified. Historical sections name Claude Opus 4.6, temperature 0 and a fixed seed; the three review runners use Codex gpt-5.6-sol with their configured reasoning/default sampling and different examples/output instructions. The added corpus also has broader discovery, eligibility, eight file families, automated segmentation, and different first-pass annotators (documented in corpus-merge/README.md). These differences predate this task. Counts below describe the requested frozen merge and must not be presented as a validated same-method replication if the consistency gate fails.

## Applicable-label agreement

| check | left | right | label | n | agreement | kappa | change_rate |
|---|---|---|---|---|---|---|---|
| pairwise_added | procedure1 | procedure2 | type | 300 | 0.9600 | 0.8847 | 0.0400 |
| pairwise_added | procedure1 | procedure2 | topic | 300 | 0.9267 | 0.9197 | 0.0733 |
| pairwise_added | procedure1 | procedure2 | enforceability | 231 | 0.8485 | 0.7863 | 0.1515 |
| pairwise_added | procedure1 | procedure2 | context_required | 204 | 0.7549 | 0.6098 | 0.2451 |
| pairwise_added | procedure1 | procedure3 | type | 300 | 0.9733 | 0.9223 | 0.0267 |
| pairwise_added | procedure1 | procedure3 | topic | 300 | 0.9267 | 0.9197 | 0.0733 |
| pairwise_added | procedure1 | procedure3 | enforceability | 231 | 0.9221 | 0.8895 | 0.0779 |
| pairwise_added | procedure1 | procedure3 | context_required | 204 | 0.8186 | 0.7096 | 0.1814 |
| pairwise_added | procedure2 | procedure3 | type | 300 | 0.9867 | 0.9603 | 0.0133 |
| pairwise_added | procedure2 | procedure3 | topic | 300 | 0.9133 | 0.9051 | 0.0867 |
| pairwise_added | procedure2 | procedure3 | enforceability | 235 | 0.8851 | 0.8356 | 0.1149 |
| pairwise_added | procedure2 | procedure3 | context_required | 211 | 0.7962 | 0.6768 | 0.2038 |
| pairwise_original | procedure1 | procedure2 | type | 300 | 0.9833 | 0.9522 | 0.0167 |
| pairwise_original | procedure1 | procedure2 | topic | 300 | 0.9467 | 0.9410 | 0.0533 |
| pairwise_original | procedure1 | procedure2 | enforceability | 232 | 0.9009 | 0.8585 | 0.0991 |
| pairwise_original | procedure1 | procedure2 | context_required | 207 | 0.8019 | 0.6739 | 0.1981 |
| pairwise_original | procedure1 | procedure3 | type | 300 | 0.9733 | 0.9239 | 0.0267 |
| pairwise_original | procedure1 | procedure3 | topic | 300 | 0.9567 | 0.9521 | 0.0433 |
| pairwise_original | procedure1 | procedure3 | enforceability | 232 | 0.8491 | 0.7833 | 0.1509 |
| pairwise_original | procedure1 | procedure3 | context_required | 207 | 0.8502 | 0.7597 | 0.1498 |
| pairwise_original | procedure2 | procedure3 | type | 300 | 0.9700 | 0.9140 | 0.0300 |
| pairwise_original | procedure2 | procedure3 | topic | 300 | 0.9567 | 0.9521 | 0.0433 |
| pairwise_original | procedure2 | procedure3 | enforceability | 233 | 0.8455 | 0.7800 | 0.1545 |
| pairwise_original | procedure2 | procedure3 | context_required | 208 | 0.8221 | 0.7102 | 0.1779 |
| original_reference | original | procedure1 | type | 300 | 0.9300 | 0.8148 | 0.0700 |
| original_reference | original | procedure1 | topic | 300 | 0.9000 | 0.8896 | 0.1000 |
| original_reference | original | procedure1 | enforceability | 217 | 0.6774 | 0.5667 | 0.3226 |
| original_reference | original | procedure1 | context_required | 181 | 0.6464 | 0.3641 | 0.3536 |
| original_reference | original | procedure2 | type | 300 | 0.9200 | 0.7875 | 0.0800 |
| original_reference | original | procedure2 | topic | 300 | 0.9233 | 0.9154 | 0.0767 |
| original_reference | original | procedure2 | enforceability | 217 | 0.6820 | 0.5712 | 0.3180 |
| original_reference | original | procedure2 | context_required | 181 | 0.7514 | 0.4779 | 0.2486 |
| original_reference | original | procedure3 | type | 300 | 0.9233 | 0.7971 | 0.0767 |
| original_reference | original | procedure3 | topic | 300 | 0.9333 | 0.9264 | 0.0667 |
| original_reference | original | procedure3 | enforceability | 217 | 0.6728 | 0.5556 | 0.3272 |
| original_reference | original | procedure3 | context_required | 181 | 0.6354 | 0.3491 | 0.3646 |
| claude_crosscheck | reviewed | claude | type | 100 | 0.9800 | 0.9436 | 0.0200 |
| claude_crosscheck | reviewed | claude | topic | 100 | 0.9300 | 0.9235 | 0.0700 |
| claude_crosscheck | reviewed | claude | enforceability | 76 | 0.9079 | 0.8739 | 0.0921 |
| claude_crosscheck | reviewed | claude | context_required | 64 | 0.8750 | 0.8033 | 0.1250 |

## Exact four-label agreement

| check | left | right | n | exact_match_rate |
|---|---|---|---|---|
| pairwise_added | procedure1 | procedure2 | 300 | 0.6733 |
| pairwise_added | procedure1 | procedure3 | 300 | 0.7467 |
| pairwise_added | procedure2 | procedure3 | 300 | 0.7200 |
| pairwise_original | procedure1 | procedure2 | 300 | 0.7633 |
| pairwise_original | procedure1 | procedure3 | 300 | 0.7600 |
| pairwise_original | procedure2 | procedure3 | 300 | 0.7333 |
| original_reference | original | procedure1 | 300 | 0.5433 |
| original_reference | original | procedure2 | 300 | 0.5833 |
| original_reference | original | procedure3 | 300 | 0.5333 |
| claude_crosscheck | reviewed | claude | 100 | 0.7900 |

## Procedure ranking (selection uses this diagnostic sample)

| procedure | minimum_original_kappa | mean_original_kappa | mean_pairwise_kappa |
|---|---|---|---|
| procedure2 | 0.4779 | 0.6880 | 0.8223 |
| procedure1 | 0.3641 | 0.6588 | 0.8302 |
| procedure3 | 0.3491 | 0.6571 | 0.8524 |

All full-denominator and applicable-denominator results are in agreement.csv. Every changed label and returned rationale is in disagreements.csv. Claude cross-check is independent of Codex and did not change any label. Original labels are a reference convention, not human ground truth. Stratified agreement is sample-conditional, not an estimate of corpus prevalence. Both all-row and applicable-label scores must meet the decision bar. Claude CLI response metadata (including model usage) is retained in checks/claude/response.json.
