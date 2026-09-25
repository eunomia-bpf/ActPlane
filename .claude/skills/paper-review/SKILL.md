---
name: paper-review
description: Review and fix academic writing in a LaTeX paper section. Checks sentence-level antipatterns, terminology consistency, and systems-paper conventions.
when_to_use: Review paper writing, fix academic prose, check terminology consistency, find writing antipatterns
argument-hint: [section-file-path]
allowed-tools: Read Edit Bash(grep *) Bash(wc *)
---

# Academic Paper Writing Review & Fix

Review the LaTeX file at `$ARGUMENTS` sentence by sentence for academic writing quality. If no argument is given, ask which section to review.

## Review process

1. Read the entire file
2. Check terminology consistency (Section T below) FIRST
3. For each paragraph, analyze every sentence against the checklist below
4. Report issues grouped by severity: **Must fix** (clarity/logic errors), **Should fix** (antipatterns), **Consider** (style preferences)
5. For each issue, give the line number, quote the problematic text, explain the problem, and suggest a concrete rewrite
6. Ask user which fixes to apply, then use Edit tool

## Critical rules (for fixes)

House style (em-dashes, semicolons, why-before-what, example-before-abstraction)
is defined once in `CLAUDE.md` under Paper Writing Rules — apply it here, do
not restate it. In addition, when fixing this section:

- **NEVER delete design decisions or technical content.** Compression means better prose, not less information.
- **NEVER change the meaning** of a sentence. If unsure, ask.
- **NEVER remove a scope-bearing hedge** (`suggest ... on the selected subset`, `in our setting`, `up to`): it protects the claim from outrunning its evidence (/paper-logic A4/A5). Only collapse stacked hedges down to one.
- **Always diff-check** after multiple edits to ensure no content was lost.

---

## Section T: Terminology Consistency (NEW - check FIRST)

Terminology drift confuses readers more than awkward prose. Run these checks before sentence-level review.

### T1: Same concept, same term

Grep for near-synonyms. If the same concept uses multiple terms, unify to one.

```bash
grep -oE '(policy|rule|constraint|directive)' file.tex | sort | uniq -c
```

Common drift pairs to check:
- policy / rule / constraint / directive
- harness / runtime / framework
- enforce / check / validate / verify
- block / deny / prevent / reject

### T2: Compound adjective hyphenation

Compound adjectives before nouns need hyphens; standalone uses do not.

| Context | Correct | Wrong |
|---------|---------|-------|
| Before noun | tool-call guardrails | tool call guardrails |
| After verb | operates at the OS level | operates at the OS-level |
| Before noun | cross-event policy | cross event policy |

Check common compounds:
```bash
grep -oE '(tool|cross|per|intent|system|application|kernel)[- ](call|event|level)' file.tex | sort | uniq -c
```

### T3: Redundant `*-level` qualifiers

Many `*-level` compounds are redundant. Check if removing `-level` loses meaning:

| Often redundant | Usually needed |
|-----------------|----------------|
| system-level (just "system") | OS-level (vs tool-level) |
| kernel-level (just "kernel") | intent-level (vs syscall-level) |
| application-level (just "application") | enforcement-level (classification) |

Test: "system actions" vs "system-level actions" — if both mean the same, drop `-level`.

### T4: Capitalization consistency

Check proper nouns and acronyms:
```bash
grep -oE '(eBPF|EBPF|ebpf|BPF)' file.tex | sort | uniq -c
```

Common issues:
- eBPF (not EBPF, ebpf)
- GitHub (not Github, github)
- macOS (not MacOS, macos)

### T5: Spelling variants

Pick one and stick to it:
- runtime vs run-time
- pre-defined vs predefined
- sub-agent vs subagent

---

## Sentence-level antipatterns

### Semicolons joining independent clauses
Semicolons that join two independent clauses should be rewritten as:
- Two sentences (period)
- One sentence with a conjunction (", and", ", but", ", so")
- One sentence with a causal connector ("because", "since", "therefore")
Semicolons ARE acceptable inside parenthetical lists.

**Bad:** `The engine propagates labels; rules fire at each event.`
**Good:** `The engine propagates labels, and rules fire at each event.`
**Good:** `Because the engine propagates labels, rules fire at each event.`

### Note-like prose (short declarative sentences strung together)
Academic prose uses causal connectors, subordinate clauses, and flowing sentences. Short declarative sentences read like bullet points, not a paper.

**Bad:** `Labels propagate at fork. The child inherits the parent mask. Rules check the mask at each event.`
**Good:** `Labels propagate at fork, so the child inherits the parent mask and rules can check it at each event.`

Tie-breaker: this rule targets runs of three or more short declaratives. A pair of sentences produced by splitting an overlong sentence (e.g., to fix subject-verb separation) is fine — do not re-merge it.

### Missing "why" before "what"
Every design decision must explain its motivation before describing the mechanism. Readers need to understand the problem before the solution.

**Bad:** `We use monotonic labels. Labels are never removed once added.`
**Good:** `To ensure no history is lost across the session, labels are monotonic: propagation adds labels but never removes them.`

### Em-dashes (---)
Never use em-dashes in paper text. Use commas, parentheses, semicolons (in lists), or restructure the sentence. Table cells using `---` for "not applicable" are acceptable.

### Colons before non-lists
Colons may introduce lists, definitions, and elaborations of the claim just made (`labels are monotonic: propagation adds labels but never removes them`). Avoid colons that splice two clauses with no claim-elaboration relationship.

**Bad:** `The engine uses eBPF: the verifier imposes a stack limit.` (the second clause does not elaborate the first; use "so" or two sentences)
**Good:** `The engine has three effects: notify (observe only), block (pre-operation denial), and kill (process termination).`
**Good:** `Labels are monotonic: propagation adds labels but never removes them.`

## Word-level antipatterns

| Antipattern | Fix |
|---|---|
| "in order to" | "to" |
| "utilize" / "utilization" | "use" |
| "it is important to note that" | delete or rephrase |
| "it should be noted that" | delete or rephrase |
| "there is/are ... that" | rewrite with real subject |
| "due to the fact that" | "because" |
| "a number of" | "several" or the actual count |
| "in the case of" | "for" or "when" |
| "is able to" | "can" |
| "has the ability to" | "can" |
| "prior to" | "before" |
| "subsequent to" | "after" |
| "with respect to" | "for" or "about" |
| "in terms of" | rephrase directly |
| "the fact that" | delete or use "that" |

## Sentence structure antipatterns

### Weak openings
Avoid starting sentences with "It is", "There is/are", "This is". Use a concrete subject.

**Bad:** `There are three hooks that the engine attaches to.`
**Good:** `The engine attaches to three hooks.`

### Subject-verb separation (Gopen & Swan)
Keep the grammatical subject within 7 words of its verb. Long intervening clauses force the reader to hold the subject in memory.

**Bad:** `The protocol, which was developed over three years by a distributed team working across four time zones, handles failover.`
**Good:** `The protocol handles failover. A distributed team developed it over three years across four time zones.`

### Topic position / stress position (Gopen & Swan)
Put old/known information at the sentence start (backward link). Put the new, emphatic information at the sentence end (stress position).

**Bad:** `A 40\% reduction in latency results from label caching.`
**Good:** `Label caching reduces latency by 40\%.`

### Dangling modifiers
The modifier must attach to the grammatical subject.

**Bad:** `Using eBPF, the policy is enforced at the kernel level.`
**Good:** `Using eBPF, the engine enforces the policy at the kernel level.`

### Passive voice (when the agent matters)
Passive is fine for methodology when the actor is obvious and irrelevant ("traces were collected"), but use active voice when the actor matters for understanding.

**Bad:** `Labels are propagated by the engine at each system event.`
**Good:** `The engine propagates labels at each system event.`

Exception: verification and judgment steps ("samples were verified", "results were reviewed") must name the actor and criterion even in methodology — an agentless verification claim is unfalsifiable (see /paper-logic C6).

### Nominalizations (turning verbs into nouns)
Use the verb form when possible. "make assumption" -> "assume"; "perform analysis" -> "analyze"; "is a requirement" -> "requires".

**Bad:** `The propagation of labels occurs at fork events.`
**Good:** `Labels propagate at fork events.`

### Redundant hedging
One hedge per claim is enough. Remove stacked hedges. Do not hedge your own measurements or established facts.

**Bad:** `This may potentially suggest that the overhead could possibly be acceptable.`
**Good:** `This suggests the overhead is acceptable.`

**Protected hedges — never remove:** a hedge that carries claim scope (`suggest ... on the 12 selected workloads`, `in our setting`, `up to`) is protecting the claim from outrunning its evidence. Removing it creates a logic error worse than the wordiness (see /paper-logic A4/A5). Remove the stack, keep one scope-bearing hedge.

### Vague referents
"This", "it", "they" must have an unambiguous antecedent. If unclear, name the referent.

**Bad:** `The engine checks labels and fires rules. This improves compliance.`
**Good:** `The engine checks labels and fires rules. This label-checking mechanism improves compliance.`

### Unnecessary adverbs
Cut "very", "extremely", "basically", "actually", "really", "significantly" unless they carry measurable meaning. Replace vague intensifiers with numbers.

**Bad:** `significantly reduces latency`
**Good:** `reduces latency by 40\%`

### Excessive parentheticals
Max two parenthetical remarks per page. If a parenthetical carries important information, promote it to the main text or cut it.

## Paragraph-level checks

1. **Topic sentence**: Does the first sentence state the paragraph's claim?
2. **One idea per paragraph**: Does the paragraph contain exactly one main point?
3. **Old-to-new thread**: Each sentence should begin with something the reader already knows and end with the new point. Violations cause "garden path" confusion.
4. **Logical connectors**: Are paragraphs linked by transitions that show the relationship (contrast, consequence, elaboration)?
5. **No redundancy across paragraphs**: Is the same fact stated in multiple places? "In other words" signals you should rewrite the first version, not add a second.

## Systems paper conventions (Levin & Redell, SPJ, Irene Zhang)

1. **Concrete before abstract**: Show an example, then generalize. "Once the reader has the intuition, they can follow the details." (SPJ)
2. **Numbers are claims**: Every number needs a source (measurement, citation, or derivation). Always state: repetitions, duration, object sizes, hardware.
3. **Consistent terminology**: The same concept uses the same term throughout (don't alternate between "policy", "rule", "constraint" for the same thing)
4. **Forward references earn their keep**: Only forward-reference if the reader needs the promise to follow the current paragraph
5. **Declare system status upfront**: Do not bury "this is a simulation" or "this is future work" at the end (Levin & Redell)
6. **Evaluation isolates decisions**: Include breakdown experiments showing each design choice's contribution, not just end-to-end comparisons (Irene Zhang)
7. **Cite by author**: "Smith et al. [1] showed" not "[1] shows". Place citation near the name.

## Quick self-edit pass (apply to every sentence)

1. Can I delete the first word/phrase without losing meaning? ("It is", "There are", "Note that")
2. Is a verb hidden inside a noun? Undo the nominalization.
3. Is the subject more than 7 words from its verb? Restructure.
4. Does the sentence end on the most important new information?
5. Does the sentence start with something the reader already knows?
6. Is an adverb doing the work a number should do?
7. Am I hedging my own result? Remove the hedge.
8. Is this passive? Can I name the actor?

---

## Fix priority (apply in this order)

### Priority 1: Logic and clarity
- Missing motivation for design decisions (add "why" before "what")
- Vague referents ("this", "it" with unclear antecedent)
- Dangling modifiers
- Incorrect or misleading claims

### Priority 2: Sentence structure
- Semicolons joining independent clauses -> rewrite with connectors
- Note-like short declarative sentences -> merge with causal connectors
- Weak "There is/It is" openings -> concrete subjects
- Passive voice where actor matters -> active voice
- Nominalizations -> verb forms

### Priority 3: Word choice
- "in order to" -> "to"
- "utilize" -> "use"
- "due to the fact that" -> "because"
- "is able to" -> "can"
- Other verbose phrases (see word-level antipatterns table)

### Priority 4: Punctuation
- Colons before non-lists -> restructure
- Em-dashes -> commas, parentheses, or restructured sentences

## Rewrite patterns

### Semicolons -> flowing prose
When replacing semicolons, don't just swap punctuation. Rewrite the sentence to flow:

Before: `Labels propagate at fork; the child inherits the parent mask.`
After: `Labels propagate at fork, so the child inherits the parent mask.`

Choose the connector based on the logical relationship:
- **Cause/effect**: "because", "since", "so", "therefore"
- **Addition**: ", and"
- **Contrast**: ", but", "however," (new sentence), "although"
- **Elaboration**: restructure as a relative clause or appositive

### Note-like -> academic prose
Before: `The DSL has three components. Sources identify objects. Targets are operations. Effects decide outcomes.`
After: `Each rule in the DSL encodes three components: a source identifies which objects the rule applies to, a target names the operation being constrained, and an effect determines whether the engine blocks, kills, or notifies.`

### Missing why
Before: `Labels are monotonic.`
After: `To ensure no history is lost across the session, labels are monotonic.`

### Vague referent
Before: `The engine checks labels and propagates them. This improves safety.`
After: `The engine checks and propagates labels. This monotonic tracking improves safety.`

## Output format

For each issue found:
```
L<line>: "<quoted text>"
  Problem: <what's wrong>
  Fix: "<suggested rewrite>"
```

End with a summary: total issues by severity, and the top 3 most impactful changes.

After reporting, ask: "Apply fixes? [all / select / none]"

After all fixes, provide:
- Number of sentences changed
- Categories of changes made
- Any sentences you flagged but did NOT change (and why)
