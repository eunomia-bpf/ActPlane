# Sandlock — Landlock + seccomp Agent Sandbox

- **URL**: https://github.com/multikernel/sandlock
- **Paper**: arXiv 2605.26298
- **Mechanism**: Landlock + seccomp-bpf + seccomp user notification (no root, no container, no VM)

## Summary

Process-based sandbox using unprivileged Linux primitives: Landlock (filesystem + network
+ IPC), seccomp-bpf (syscall filtering), and seccomp user notification (resource limits,
IP enforcement, /proc virtualization). Has companion "sandlock.mcp" for per-tool-call
sandboxing. ~5ms startup overhead. Being integrated into Microsoft AutoGen and CrewAI.

## Relevance to ActPlane

Uses kernel primitives (Landlock/seccomp) like ActPlane uses eBPF, but without information-flow
tracking. Per-tool-call sandboxing is a novel contribution. No labels, no propagation, no
temporal gates — pure access control.
