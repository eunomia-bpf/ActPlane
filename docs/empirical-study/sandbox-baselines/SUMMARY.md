# Lane summary

Measured official default Codex workspace-write, standalone Anthropic SRT,
and Docker security configurations, plus a separately labeled SRT cwd-write
analogue. Reused the translation lane's traces, fixtures and unchanged tool
replay code. All baseline configurations reached terminal replay outcomes.

| System | Metric | Direct | Script | Hidden | Total | Compliant trigger |
| --- | --- | --- | --- | --- | --- | --- |
| Codex workspace-write | effect prevention | 5/37 | 5/37 | 5/37 | 15/111 | 6/76 |
| SRT standalone defaults | effect prevention | 28/37 | 37/37 | 28/37 | 93/111 | 72/76 |
| SRT cwd-write analogue | effect prevention | 0/37 | 33/37 | 0/37 | 33/111 | 1/76 |
| Docker default security | effect prevention | 0/37 | 0/37 | 0/37 | 0/111 | 0/76 |
| AgPlane reference | detection (imported) | 27/38 | 27/38 | 26/38 | 80/114 | 13/76 |
| AgPlane zai/glm-4.5-air | detection (imported) | 19/38 | 20/38 | 19/38 | 58/114 | 10/76 |

These are different metric types: baseline rows measure control-validated
persistent effect/prohibited-invocation prevention, AgPlane rows are imported
notification detections. Read conditional denominators and compliant collateral
denials together. The result supports resource-boundary versus action-policy
coverage on this corpus, not general sandbox failure or measured agent confusion.

Main files: README.md, results/comparison.csv, results/per-trace.csv,
results/errors.csv, results/exclusions.csv, results/fidelity.csv,
results/agplane-import.csv, results/comparison.pdf. Scripts and source/config
snapshots are in this lane. Large raw outputs remain under
`/workspaces/exp/sandbox-baselines/raw/`.

Open caveats: author-generated corpus, safe shims instead of real public
disclosure, persistent-effect oracle scope, imported guest kernel/filesystem
differences, SRT standalone versus Claude enabled-policy distinction, and nested
Docker bridge DNS. Optional gVisor and injection-bench availability are recorded
in results/optional-lanes.csv; neither blocks this matrix. No paper changes,
pushes, model scaling or tuned per-rule policies were performed.
