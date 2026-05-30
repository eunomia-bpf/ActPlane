# Kernel-Resident Regex and Jails (LPC 2025)

- **Speaker**: Justin Ngai (Meta)
- **Venue**: Linux Plumbers Conference 2025, Tokyo, eBPF Track
- **Talk page**: https://lpc.events/event/19/contributions/2176/
- **Slides**: https://lpc.events/event/19/contributions/2176/attachments/1815/3947/LPC%202025%20-%20Justin%20Ngai-NEW.pdf

## Summary

Compiles regex patterns into deterministic finite automata (DFAs) executed inside eBPF
at LSM and fentry attach points. Explicitly discusses agent isolation as a use case,
including DNS-aware enforcement for agentic workflows.

## Compilation pipeline

```
Regex String → Parser → AST → NFA (Thompson's) → DFA (Subset Construction) → BPF Maps
                                                                                 |
                                                                       Kernel Space:
                                                                       - patterns_map     (regex_id → start_state, flags)
                                                                       - transitions_map  (state,char → next_state)
                                                                       - final_states_map (state_id → regex_ids[])
```

- Multiple regexes merged into a single combined DFA (8 regexes → 1 DFA → 1 pass)
- Kernel execution: `bpfj_regex_match()` does byte-by-byte DFA simulation, O(n) linear
- Bounded iteration via `bpf_loop()`
- Current bounds: 64 states, 8192 transitions per combined DFA

## Regex support

- Supported: literals, `[a-z]`, `\d \w \s`, `a|b`, `* + ?`, `.`
- Not yet: `{n,m}`, `^ $`, lookahead/lookbehind, backreferences
- Runtime variables: `$USER` resolved at load time

## Agent isolation use cases

- DNS-aware enforcement: constrain name resolution to policy-bound allowlists
- Detect exfil-friendly domains
- Prevent prompt-injected egress
- MetArmor orchestration: quarantine + targeted network blocks at fleet scale

## Scale

- MetArmor Filemod: ~1B events/sec, 99.4% filtered in-kernel by regex allowlist
- MetArmor Proc Exec: ~90B events/sec, 99.6% filtered by cmdline regex match

## Comparison with ActPlane

ActPlane uses fnv1a hash-based exact/prefix/suffix/any matching — simpler and faster
for the common case but less expressive than full regex. The DFA approach could be
adopted in ActPlane for richer pattern matching, but the core differentiator (labeled
IFC vs. RBAC) is orthogonal to pattern-matching expressiveness.

## Related

- [BpfJailer](lpc2025-bpfjailer.md) — companion Meta talk on the jailing framework
