# eBPF for AI Agent Enforcement (ARMO Blog, March 2026)

- **Source**: ARMO blog
- **URL**: https://www.armosec.io/blog/ebpf-based-ai-agent-enforcement/
- **Date**: March 2026

## Summary

Discusses the "semantic gap" problem in eBPF-based agent enforcement: eBPF sees
syscalls but not intent. Effective agent enforcement requires layering
application-aware monitoring on top of eBPF's kernel substrate.

## Key argument

Pure kernel-level enforcement (eBPF/LSM) catches low-level violations (file access,
network egress) but cannot reason about higher-level semantics (tool-call intent,
prompt injection, task boundaries). A complete agent enforcement stack needs both:
- Kernel layer: unbypassable syscall-level enforcement (eBPF)
- Application layer: semantic understanding of agent actions

## Relevance to ActPlane

ActPlane partially bridges this gap through labeled information-flow control — labels
carry semantic meaning (SECRET, AGENT, REVIEWED) that elevates raw syscall events to
policy-relevant categories. The corrective-feedback mechanism further bridges the gap
by translating kernel-detected violations into model-readable explanations.
