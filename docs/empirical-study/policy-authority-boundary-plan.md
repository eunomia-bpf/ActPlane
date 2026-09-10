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

Here, "frozen" is experimental shorthand for the effective parent policy that
was installed before the child started and was not changed during the child
cases. ActPlane does not implement an immutable-policy-file or freeze-bit
primitive, and this experiment does not test policy-file replacement.

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

## Result (2026-09-10)

The strengthened matrix at `7da27390` completed under KVM on Ubuntu kernel
6.8.0-138-generic. All seven predictions matched. The bound child was rejected
when it requested `AUTH_DECLASSIFY` (`lacks runtime authority 0x20`) and when it
targeted the parent domain. Its local tightening was accepted and fired. After a
real read of the configured secret file, the inherited frozen rule also fired,
with the feedback record attributing `SECRET` to that read. The trusted parent
without required metadata was rejected, while allowlisted metadata was accepted
with `external_verified=false` and `signature=null` in the audit record.

The first five guest attempts are retained as negative engineering evidence.
They exposed a missing guest mount applet and then Ubuntu 6.8 combined-stack
verifier failures in the shared `recvfrom`/`recvmsg` exit path. The socket exit
paths were split and the SCM_RIGHTS scan was isolated before the successful
matrix. These load failures are not counted as experimental observations.

Raw evidence is under:

```text
/workspaces/.agent-state/actplane-research/raw/authority-boundary-20260910T1340Z/
  attempt1/ ... attempt6/
  final-7da27390/{console.clean.log,counts.tsv,metadata.tsv}
```

This result supports the child-domain monotonicity boundary, not trustworthy
natural-language policy generation. The static approval row is deliberately a
negative boundary result: an allowlisted string is audit metadata and is not
external identity verification.
