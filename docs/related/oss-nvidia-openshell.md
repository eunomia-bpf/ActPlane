# NVIDIA OpenShell — Declarative YAML + OPA Agent Runtime

- **URL**: https://github.com/NVIDIA/OpenShell
- **Blog**: https://blogs.nvidia.com/blog/secure-autonomous-ai-agents-openshell/
- **Mechanism**: Declarative YAML policies + kernel-level enforcement (4 protection domains) + OPA network proxy

## Summary

A safe, private runtime for autonomous AI agents. Policies are declarative YAML with
static sections (filesystem, process) locked at creation and dynamic sections (network,
inference) hot-reloaded. Network goes through an HTTP CONNECT proxy evaluated by Open
Policy Agent in real-time. Credentials are injected as env vars at runtime, never on
the sandbox filesystem.

## Relevance to ActPlane

Closest to ActPlane's approach of compiling a policy DSL to OS-level enforcement.
Uses OPA (Rego) for network policy rather than eBPF. No information-flow tracking —
static access control with dynamic network policy.
