# Policy authority boundary experiment

This experiment addresses the policy-trust concern in reviews B and D. An
untrusted agent may be able to propose a selectively weak policy, so a result
obtained from one compiled policy does not establish that policy generation or
declassification is trustworthy.

## Hypothesis and evidence gap

The concrete hypothesis is that a policy installed by the trusted parent stays
effective when an injected child submits correctly shaped, allowlisted-looking
metadata with a weakening delta. The child should still be able to add a local
restriction. This separates monotonic kernel authority from the distinct static
metadata approval gate.

Existing declassification and long-session runs do not answer this question.
They exercise one frozen policy and show label propagation or an explicit gate,
but they do not submit a policy mutation from the protected child. Unit tests of
individual capability checks also do not show the end-to-end local-control
identity, admission, audit, file-read, and final enforcement path together.

## One comparison matrix

| Case | Actor and delta | Prediction | Meaning |
|---|---|---|---|
| Child declassification | Bound child, `declassify SECRET`, allowlisted-looking metadata | Reject | Child lacks `AUTH_DECLASSIFY` |
| Parent mutation | Bound child targets the parent domain | Reject | Child cannot target its parent |
| Child tightening | Bound child adds a local notify rule | Accept and fire | Delegation permits monotonic restriction |
| Frozen behavior | Child reads a real file source, then executes the frozen sink | Notify | Rejected weakening did not remove the parent rule |
| Missing approval | Trusted parent omits required metadata | Reject | Static approval gate is active |
| Allowlisted metadata | Trusted parent supplies all allowlisted strings | Accept, audit `external_verified=false` | Metadata is declarative, not a signature |

A fully positive result supports only the implemented authority boundary. If a
child weakening is accepted or the frozen sink stops firing, the monotonicity
claim fails. If child tightening is rejected, authority is safe but unusably
coarse. A mixed result in the approval rows localizes the limitation to policy
provenance rather than kernel mutation authority. In particular, acceptance of
allowlisted strings does not prove that the approver, generator, redactor, or
policy semantics are trustworthy.

## Reproduction and raw evidence

Run the real Ubuntu guest matrix from the repository root:

```bash
bash docs/empirical-study/run_policy_authority_boundary_vm.sh /path/to/raw-output
```

The runner builds the exact ignored integration test, boots the newest local
generic kernel under KVM (with a TCG fallback), runs the seven asserted outcomes,
and writes `console.log`, `console.clean.log`, `counts.tsv`, build logs, QEMU
stderr, and binary/source hashes. A build, boot, or partial matrix is retained as
failure evidence and is not reported as a research result.

The OpenAgentSafety artifact was considered first for an unseen non-coding
independent-baseline experiment. Its runner exposes only `baseline` and
`actplane`, the official task checkout is not present in the current tree, and
the historical per-task ActPlane outcomes are explicitly absent. Therefore this
experiment does not substitute the same-agent condition for an independent
strong baseline, and it does not claim held-out non-coding generalization.
