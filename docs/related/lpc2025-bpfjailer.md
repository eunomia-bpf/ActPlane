# BpfJailer: eBPF based Mandatory Access Control (LPC 2025)

- **Speaker**: Liam Wisehart (Meta)
- **Venue**: Linux Plumbers Conference 2025, Tokyo, eBPF Track
- **Talk page**: https://lpc.events/event/19/contributions/2159/
- **Slides**: https://lpc.events/event/19/contributions/2159/attachments/1833/3929/BpfJailer%20LPC%202025.pdf
- **YouTube**: https://www.youtube.com/watch?v=o78vnXfih8E

## Summary

BpfJailer is Meta's eBPF-based mandatory access control framework that dynamically
sandboxes processes — including internal AI agents — using BPF LSM hooks. It restricts
access to networks, filesystems, and IPC for untrusted execution environments.

In Meta Private Processing scenarios, it prevents even root users from tampering with
processes inside Confidential VMs.

## Policy model

- **RBAC with allow/deny lists** — no information-flow tracking or label propagation.
- Policy format: flat JSON with roles, file path patterns, network rules, domain rules.
- Process-to-role binding via executable path, cgroup path, xattr, or Unix socket enrollment.
- Stacked pods: up to 4 layers of cumulative role evaluation.
- Scale: ~10MB policy per service, 100K+ developers, 10K+ simultaneous pods.

Example policy structure (from open-source reimplementation `gen0sec/jailer`):
```json
{
  "roles": {
    "ai_agent": {
      "file_paths": [{"pattern": "/.ssh/", "allow": false}],
      "network_rules": [{"protocol": "tcp", "port": 443, "allow": true}],
      "domain_rules": [{"domain": "api.anthropic.com", "allow": true}]
    }
  }
}
```

## Key techniques

- Binary signing and command-line argument validation
- Path matching via state machines in BPF
- Protection of eBPF programs from tampering
- Jailing in initrd (immutable policy) for Confidential VMs

## Comparison with ActPlane

| Dimension | BpfJailer | ActPlane |
|-----------|-----------|----------|
| Policy model | RBAC (role allow/deny) | Labeled IFC (taint propagation) |
| Policy format | JSON | Custom DSL |
| Label propagation | None | fork/exec/read/write/connect |
| Cross-channel tracking | No | Yes |
| Temporal gates | No | `after G since S` |
| Pattern matching | Path state machine | fnv1a exact/prefix/suffix |
| Scale | Fleet-wide (100K+) | Single-host |
| Open source | Planned 2026; reimpl: github.com/gen0sec/jailer | Available now |

## Related

- [Kernel-Resident Regex and Jails](lpc2025-kernel-regex-jails.md) — companion Meta talk
- [ARMO eBPF Agent Enforcement](armo-ebpf-agent-enforcement.md) — semantic gap discussion
