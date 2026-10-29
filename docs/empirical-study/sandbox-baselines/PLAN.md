# Matched RQ2 sandbox comparison

This supporting experiment addresses reviewer D's request for independent
baselines and tests whether shipping resource boundaries prevent repository
action-policy violations. A positive result narrows the claimed advantage to
policy-specific actions that default boundaries leave available. A contrary
result requires acknowledging protection already supplied by standard sandboxes.
Failures to start and unresolved effects cannot support either conclusion.

Reuse the translation-models lane's frozen RQ2 corpus, selected fixture packs,
and byte-identical deterministic replayer. Preserve its source hashes. The
corpus is an author-created labeled evaluation, not an external standard attack
benchmark. No new attacks, policies, or weighted metrics are introduced.

Run all traces under Codex's explicit workspace-write preset with network off,
Anthropic SRT standalone built-in defaults, Docker default security settings,
and a matched unsandboxed control. Optionally also report the documented
cwd-write SRT configuration used by an enabled Claude harness, clearly separate
from standalone defaults. Docker workload mounts provide the frozen inputs and
working checkout and do not change its security policy. Do not tune by rule.

The adapter prepares the original private /tmp/repo and fixture permissions
outside each sandbox. It executes the original worker's environment assignments,
tool loop, and output loop directly from the unchanged source AST, without its
privileged mount setup or eBPF synchronization. The selected nodes are unchanged.
Compare a real original-worker control with the adapter before full execution.
This adapter deviation is disclosed, not called byte-identical execution.

Record per-trace tool results and actual errors, filesystem snapshots, and
process/file syscall observations. A prohibited effect needs rule-specific
evidence, never just a nonzero exit code. Report unresolved effects as unknown.
False triggers are new permission-denied tool outcomes on labeled compliant
traces relative to the matched control. Report default-protected configuration
paths separately in interpretation. Effects prevented by blocking preparation
still count as prevention but reveal collateral disruption in compliant rows.

Import the reference and best translation by frozen translation-lane full-trace
F1, breaking ties by lower false-trigger rate. These are notify-mode detection
rows, not enforcement measurements. Show their metric type explicitly next to
the effect-prevention results. No claim about agent confusion follows from
opaque error text alone because no agent continuation is measured.

Save all failures and retries remotely. Produce committed per-trace CSVs,
aggregate CSV, PDF (fonttype 42), README and SUMMARY through committed scripts.
All execution is in actplane-dev; no paper changes or pushes.
