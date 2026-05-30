# Anthropic sandbox-runtime — Claude Code Sandbox

- **URL**: https://github.com/anthropic-experimental/sandbox-runtime
- **Blog**: https://www.anthropic.com/engineering/claude-code-sandboxing
- **Mechanism**: macOS Seatbelt (sandbox-exec) + Linux bubblewrap + network proxy allowlist

## Summary

Lightweight sandboxing tool for enforcing filesystem and network restrictions on arbitrary
processes at the OS level, without requiring a container. Developed for Claude Code.
Reduces permission prompts by 84%. Open-sourced as a research preview.

## Relevance to ActPlane

Production OS-level enforcement for a major AI agent. Uses platform-native sandbox
primitives (Seatbelt/bubblewrap) rather than eBPF. Static access control only — no
information-flow tracking, no temporal gates, no label propagation.

See also: Anthropic blog "How we contain Claude across products" —
https://www.anthropic.com/engineering/how-we-contain-claude — discusses real prompt
injection incident where Claude exfiltrated AWS credentials 24/25 times.
