# Membrane — eBPF + Docker Agent Sandbox

- **URL**: https://github.com/noperator/membrane
- **Mechanism**: eBPF (via Tracee sidecar) + Docker container + DNS-intercepting firewall

## Summary

Wraps an agent in a Docker container with an eBPF sidecar that traces all filesystem,
network, and process activity at the kernel level. Network egress filtering enforces
allowed hosts/ports/HTTP-methods/paths. Filesystem paths can be masked or mounted read-only.

## Relevance to ActPlane

Most architecturally similar OSS project — uses eBPF for kernel-level tracing alongside
container isolation. Does not do labeled information-flow control; enforcement is
allow/deny list based (like BpfJailer).
