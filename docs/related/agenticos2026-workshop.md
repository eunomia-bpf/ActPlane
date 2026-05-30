# AgenticOS 2026 Workshop (ASPLOS 2026)

- **Venue**: Co-located with ASPLOS 2026
- **Website**: https://os-for-agent.github.io/asplos-2026.html
- **Focus**: OS-level mechanisms for AI agent security, isolation, and resource control

## Accepted papers (relevant subset)

### Grimlock: Guarding High-Agency Systems with eBPF and Attested Channels

- Authors: Qiancheng Wu, Wenhui Zhang, et al.
- Vision paper using eBPF to protect AI agent systems with attestation mechanisms.
- Details: TBD — need to fetch full paper from workshop proceedings.

### AgentCgroup: Understanding and Controlling OS Resources of AI Agents

- Authors: Yusheng Zheng, Jiakun Fan, et al.
- Intent-driven eBPF-based resource controller using cgroup structures aligned with
  tool-call boundaries, sched_ext, and memcg_bpf_ops.
- Key finding: OS-level overhead accounts for 56-74% of end-to-end latency in agent workflows.
- Code: https://github.com/eunomia-bpf/agentcgroup
- Arxiv: https://arxiv.org/html/2602.09345v2

### Execute-Only Agents: Architectural Defense Against Prompt Injection

- Authors: Rahul Tiwari, Dan Williams
- Security architecture for sandboxing agents against prompt injection at the OS level.

## Relevance to ActPlane

The workshop CFP explicitly called for work on "dynamic sandboxing and lightweight
runtimes" and "security and isolation mechanisms for agent-invoked tools" — directly
aligned with ActPlane's scope. Grimlock's attested-channel approach and AgentCgroup's
resource-control angle are complementary to ActPlane's information-flow enforcement.
