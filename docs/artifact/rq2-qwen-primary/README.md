# RQ2 Primary Qwen Selected Results

This directory contains the selected raw runner outputs and matching
llama.cpp judge files used to recompute the primary Qwen RQ2 table.

## Files

- `selected_runner_results.txt`: tab-separated selected result manifest. The
  final column is the canonical copied runner-result path under this directory.
- `results/`: 950 runner result JSON files plus 950 matching judge JSON files
  for `prompt-filter`, `tool-regex`, `tool-ifc`, `actplane`, and
  `actplane-opaque`.

The selected manifest consolidates the paper-facing cells from the original
full run and later repair/rerun cells. It is a canonical verification manifest,
not a complete historical run directory. Historical full-run context remains in
the raw backup branch listed in `docs/ARTIFACT.md`.

Some runner outputs include observed shell commands or ActPlane feedback payloads
with host paths from the original run. These strings are preserved as trajectory
content. The verifier does not dereference them; it follows only the manifest
paths and judge `source_result` fields in this directory.
