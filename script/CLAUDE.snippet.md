<!-- 把以下内容粘进项目的 CLAUDE.md 或 AGENTS.md，接通 ActPlane 通道 (a1)。 -->

## ActPlane OS-level guardrails

This workspace is protected by **ActPlane**, an OS-level (kernel) enforcer. Some
operations are blocked below the tool layer — they fail no matter how you invoke
them (tool call, `bash -c`, subprocess, or a direct syscall). Retrying the exact
same operation will not succeed.

**When any command fails with `EPERM` / `Operation not permitted`, or you see a
`[ActPlane]` message:** read `.actplane/last-violation.txt` in the workspace
root. It contains the rule that fired, *why*, and *how to proceed* (an
actionable alternative or a precondition to satisfy first). Follow that guidance
to change course — do not blindly retry the blocked operation.

- If the feedback says **retry is not useful**, find the suggested alternative
  path instead of repeating the operation.
- If it describes a **precondition (gate)** — e.g. "run the tests first" — do
  that step, then retry the original operation.
