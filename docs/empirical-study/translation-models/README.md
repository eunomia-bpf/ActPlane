# Policy translation across models

Work in progress on `experiments/translation-models-20261028`. The operator will
consolidate experiment branches. This lane does not open or update pull requests.

The study separates compiler acceptance from deterministic kernel detection.
Models receive the same directive, source evidence, artifact instruction-file
context, and the DSL reference from the recorded master revision. They receive
compiler diagnostics on revisions. Trace labels and reference translations are
never included in translation prompts. There is no agent continuation or LLM
judge.

Current committed evidence:

* `model-access.csv`: response model identifiers and access exclusions.
* `controls-host19.csv` and `controls-guest68.csv`: kernel replay controls. Host
  negatives are invalid because the container PID namespace differs from the
  kernel-visible namespace. The unmodified loader passes the guest controls.
* `repository-fixtures.csv`, `fixture-candidates.csv`, `selected-fixtures.csv`:
  recovered source revisions and tool-precondition selection. The artifact did
  not preserve evaluated repository checkout SHAs. Candidate selection uses
  Read/Edit preconditions, never detector outcomes or ground-truth labels.
* `matcher-equivalence.csv`: native comparisons for an experiment-only bounded
  matcher implementation. These checks do not establish whole-engine equivalence.

Reference validation is not complete. The unmodified current engine rejects
corpus path matchers at its verifier instruction limit on both host and guest.
The CLI singleton path also encounters a verifier stack limit. Experimental
matcher builds are isolated in the raw directory and have not yet passed the
expanded guest controls. Consequently this checkpoint makes no detection-rate,
false-trigger-rate, F1, or translation-accuracy claim.

Raw inputs, responses, compiler logs, kernel verifier logs, and fixture checkouts
remain under `/workspaces/.agent-state/actplane-research/raw/translation-models-20261028`.
No credentials are committed. Optional local services require unavailable service
credentials. OpenCode requests get past the session-header error when it is
forwarded in the request body, then fail because provider credentials expired.
The requested GPT model is rejected by the ChatGPT-authenticated CLI. See
`model-access.csv` and the lane state `BLOCKED.md` for the exact exclusions.

Reproduction starts with `prepare.py`, `models.py`, and `select_fixtures.py`.
Build the current CLI with `make` and validate with `make test`.
`guest.py` runs commands in the recorded KVM guest. `controls.py` gates replay
interpretation. `replay.py` converts effects to notify and starts a fresh engine
and fixture checkout per trace. `translate.py` records each call and compiler
revision, then exports per-policy CSVs. Protocol checks run with:

```bash
python3 -m unittest discover -s docs/empirical-study/translation-models -p 'test_*.py'
```
